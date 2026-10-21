from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import subprocess
from typing import Any

from .engine import EngineBackend, EngineError
from .model import ProxyConfig


@dataclass(slots=True)
class LatencyResult:
    ok: bool
    latency_ms: float | None = None
    http_code: int | None = None
    error: str | None = None


def _probe_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    curl_command: str,
) -> LatencyResult:
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
                "%{time_total}\t%{http_code}",
                url,
            ],
            text=True,
            capture_output=True,
            timeout=timeout + 5,
        )
        if proc.returncode != 0:
            return LatencyResult(False, error=(proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}")

        fields = proc.stdout.strip().split("\t")
        if len(fields) != 2:
            return LatencyResult(False, error=f"unexpected curl output: {proc.stdout!r}")
        latency_ms = float(fields[0]) * 1000.0
        http_code = int(fields[1])
        return LatencyResult(True, latency_ms=latency_ms, http_code=http_code)
    except (EngineError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return LatencyResult(False, error=str(exc))
    finally:
        if session is not None:
            engine.stop(session)


def check_latency_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    max_ms: float,
    workers: int,
    curl_command: str = "curl",
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []

    def apply(proxy: ProxyConfig, result: LatencyResult) -> None:
        proxy.tests.latency_ms = result.latency_ms
        proxy.tests.latency = {
            "status": "pass" if result.ok and result.latency_ms is not None and result.latency_ms <= max_ms else "fail",
            "latency_ms": result.latency_ms,
            "http_code": result.http_code,
            "error": result.error,
        }
        if not result.ok:
            proxy.tests.status = "rejected_latency_error"
            rejected.append(proxy)
        elif result.latency_ms is None or result.latency_ms > max_ms:
            proxy.tests.status = "rejected_latency_threshold"
            rejected.append(proxy)
        else:
            proxy.tests.status = "latency_pass"
            passed.append(proxy)

    if workers <= 1:
        for proxy in proxies:
            apply(proxy, _probe_one(proxy, engine, url=url, timeout=timeout, curl_command=curl_command))
        return passed, rejected

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_probe_one, proxy, engine, url=url, timeout=timeout, curl_command=curl_command): proxy
            for proxy in proxies
        }
        for future in as_completed(futures):
            proxy = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # keep one broken worker from aborting the source
                result = LatencyResult(False, error=str(exc))
            apply(proxy, result)

    return passed, rejected
