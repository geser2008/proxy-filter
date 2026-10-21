from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile

from .engine import EngineBackend, EngineError
from .model import ProxyConfig


@dataclass(slots=True)
class SpeedResult:
    ok: bool
    mbps: float | None = None
    bytes_transferred: int | None = None
    time_seconds: float | None = None
    http_code: int | None = None
    error: str | None = None


def _parse_curl_metrics(stdout: str) -> tuple[int, float, int]:
    fields = stdout.strip().split("\t")
    if len(fields) != 3:
        raise ValueError(f"unexpected curl output: {stdout!r}")
    size = int(float(fields[0]))
    elapsed = float(fields[1])
    http_code = int(fields[2])
    if size <= 0:
        raise ValueError("curl transferred zero bytes")
    if elapsed <= 0:
        raise ValueError("curl reported non-positive transfer time")
    return size, elapsed, http_code


def _mbps(size_bytes: int, elapsed_seconds: float) -> float:
    return (float(size_bytes) * 8.0) / elapsed_seconds / 1_000_000.0


def _download_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    curl_command: str,
) -> SpeedResult:
    session = None
    try:
        session = engine.start(proxy)
        proc = subprocess.run(
            [
                curl_command,
                "--silent",
                "--show-error",
                "--fail",
                "--output",
                "/dev/null",
                "--proxy",
                session.socks_url,
                "--connect-timeout",
                str(timeout),
                "--max-time",
                str(timeout),
                "--write-out",
                "%{size_download}\t%{time_total}\t%{http_code}",
                url,
            ],
            text=True,
            capture_output=True,
            timeout=timeout + 5,
        )
        if proc.returncode != 0:
            return SpeedResult(False, error=(proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}")
        size, elapsed, http_code = _parse_curl_metrics(proc.stdout)
        return SpeedResult(True, _mbps(size, elapsed), size, elapsed, http_code)
    except (EngineError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return SpeedResult(False, error=str(exc))
    finally:
        if session is not None:
            engine.stop(session)


def _upload_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    payload_path: Path,
    timeout: float,
    curl_command: str,
) -> SpeedResult:
    session = None
    try:
        session = engine.start(proxy)
        proc = subprocess.run(
            [
                curl_command,
                "--silent",
                "--show-error",
                "--fail",
                "--output",
                "/dev/null",
                "--proxy",
                session.socks_url,
                "--connect-timeout",
                str(timeout),
                "--max-time",
                str(timeout),
                "--header",
                "Content-Type: application/octet-stream",
                "--data-binary",
                f"@{payload_path}",
                "--write-out",
                "%{size_upload}\t%{time_total}\t%{http_code}",
                url,
            ],
            text=True,
            capture_output=True,
            timeout=timeout + 5,
        )
        if proc.returncode != 0:
            return SpeedResult(False, error=(proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}")
        size, elapsed, http_code = _parse_curl_metrics(proc.stdout)
        return SpeedResult(True, _mbps(size, elapsed), size, elapsed, http_code)
    except (EngineError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return SpeedResult(False, error=str(exc))
    finally:
        if session is not None:
            engine.stop(session)


def _run_many(proxies: list[ProxyConfig], workers: int, probe, label: str) -> list[tuple[ProxyConfig, SpeedResult]]:
    results: list[tuple[ProxyConfig, SpeedResult]] = []
    total = len(proxies)
    checked = 0

    if workers <= 1:
        for proxy in proxies:
            results.append((proxy, probe(proxy)))
            checked += 1
            print(f"[{label}] checked={checked}/{total}")
        return results

    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        futures = {pool.submit(probe, proxy): proxy for proxy in proxies}
        for future in as_completed(futures):
            proxy = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = SpeedResult(False, error=str(exc))
            results.append((proxy, result))
            checked += 1
            print(f"[{label}] checked={checked}/{total}")
    return results


def check_download_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    min_mbps: float,
    workers: int = 1,
    curl_command: str = "curl",
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.download_url is required")

    def probe(proxy: ProxyConfig) -> SpeedResult:
        return _download_one(proxy, engine, url=url, timeout=timeout, curl_command=curl_command)

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for proxy, result in _run_many(proxies, workers, probe, "download"):
        proxy.tests.download_mbps = result.mbps
        threshold_ok = result.ok and result.mbps is not None and result.mbps >= min_mbps
        proxy.tests.download = {
            "status": "pass" if threshold_ok else "fail",
            "mbps": result.mbps,
            "bytes": result.bytes_transferred,
            "time_seconds": result.time_seconds,
            "http_code": result.http_code,
            "error": result.error,
            "method": "curl-socks5h",
        }
        if not result.ok:
            proxy.tests.status = "rejected_download_error"
            rejected.append(proxy)
        elif not threshold_ok:
            proxy.tests.status = "rejected_download_threshold"
            rejected.append(proxy)
        else:
            proxy.tests.status = "download_pass"
            passed.append(proxy)

    passed.sort(key=lambda proxy: proxy.tests.download_mbps if proxy.tests.download_mbps is not None else -1, reverse=True)
    return passed, rejected


def check_upload_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    *,
    url: str,
    upload_bytes: int,
    timeout: float,
    min_mbps: float,
    workers: int = 1,
    curl_command: str = "curl",
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.upload_url is required")
    if upload_bytes <= 0:
        raise ValueError("speed.upload_bytes must be greater than zero")

    with tempfile.NamedTemporaryFile(prefix="proxy-filter-upload-", delete=True) as payload:
        payload.truncate(upload_bytes)
        payload.flush()
        payload_path = Path(payload.name)

        def probe(proxy: ProxyConfig) -> SpeedResult:
            return _upload_one(
                proxy,
                engine,
                url=url,
                payload_path=payload_path,
                timeout=timeout,
                curl_command=curl_command,
            )

        measured = _run_many(proxies, workers, probe, "upload")

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for proxy, result in measured:
        proxy.tests.upload_mbps = result.mbps
        threshold_ok = result.ok and result.mbps is not None and result.mbps >= min_mbps
        proxy.tests.upload = {
            "status": "pass" if threshold_ok else "fail",
            "mbps": result.mbps,
            "bytes": result.bytes_transferred,
            "time_seconds": result.time_seconds,
            "http_code": result.http_code,
            "error": result.error,
            "method": "curl-socks5h",
        }
        if not result.ok:
            proxy.tests.status = "rejected_upload_error"
            rejected.append(proxy)
        elif not threshold_ok:
            proxy.tests.status = "rejected_upload_threshold"
            rejected.append(proxy)
        else:
            proxy.tests.status = "upload_pass"
            passed.append(proxy)

    passed.sort(key=lambda proxy: proxy.tests.upload_mbps if proxy.tests.upload_mbps is not None else -1, reverse=True)
    return passed, rejected
