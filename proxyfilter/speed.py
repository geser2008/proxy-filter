from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from .engine import EngineBackend, EngineError
from .model import ProxyConfig


DEFAULT_DOWNLOAD_STREAM_STAGES = (1, 2, 4, 8)


@dataclass(slots=True)
class SpeedResult:
    ok: bool
    mbps: float | None = None
    bytes_transferred: int | None = None
    time_seconds: float | None = None
    http_code: int | None = None
    error: str | None = None
    url: str | None = None
    expect_disabled: bool = False
    expected_bytes: int | None = None
    payload_valid: bool | None = None
    attempts: list[dict] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)


def _normalize_download_stream_stages(value) -> tuple[int, ...]:
    """Validate configurable aggregate download stages while preserving order."""
    raw = DEFAULT_DOWNLOAD_STREAM_STAGES if value is None else value
    if isinstance(raw, (int, str)) and not isinstance(raw, bool):
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        raise ValueError("speed.download_streams must be a non-empty list of positive integers")

    stages: list[int] = []
    seen: set[int] = set()
    for item in raw:
        if isinstance(item, bool):
            raise ValueError("speed.download_streams must contain positive integers")
        try:
            streams = int(item)
        except (TypeError, ValueError) as exc:
            raise ValueError("speed.download_streams must contain positive integers") from exc
        if streams <= 0 or str(item).strip() != str(streams):
            raise ValueError("speed.download_streams must contain positive integers")
        if streams in seen:
            raise ValueError(f"speed.download_streams contains duplicate stage: {streams}")
        seen.add(streams)
        stages.append(streams)
    return tuple(stages)


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


def _parse_curl_writeout(stdout: str) -> tuple[int | None, float | None, int | None]:
    fields = stdout.strip().split("\t")
    if len(fields) != 3:
        return None, None, None
    try:
        size = int(float(fields[0]))
        elapsed = float(fields[1])
        http_code = int(fields[2])
    except ValueError:
        return None, None, None
    return size, elapsed, http_code


def _mbps(size_bytes: int, elapsed_seconds: float) -> float:
    return (float(size_bytes) * 8.0) / elapsed_seconds / 1_000_000.0


def _expected_download_bytes(url: str) -> int | None:
    """Return a trustworthy expected payload size for known speed-test URLs."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None

    host = (parsed.hostname or "").lower()
    if host == "speed.cloudflare.com" and parsed.path == "/__down":
        values = parse_qs(parsed.query).get("bytes", [])
        if len(values) == 1:
            try:
                expected = int(values[0])
            except ValueError:
                return None
            return expected if expected > 0 else None

    if host == "cachefly.cachefly.net" and parsed.path.rsplit("/", 1)[-1].lower() in {
        "50mb.test",
        "100mb.test",
    }:
        return 100 * 1024 * 1024

    return None


def _cloudflare_download_url(url: str, size_bytes: int) -> str | None:
    """Return the same Cloudflare speed URL with a deterministic byte count."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if (parsed.hostname or "").lower() != "speed.cloudflare.com" or parsed.path != "/__down":
        return None
    query = parse_qs(parsed.query, keep_blank_values=True)
    query["bytes"] = [str(size_bytes)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), parsed.fragment))


def _split_download_urls(url: str, streams: int) -> list[str]:
    """Split a known Cloudflare payload across streams while keeping stage bytes constant.

    For unknown endpoints the URL is repeated unchanged because their payload size
    cannot be adjusted safely without changing source semantics.
    """
    if streams <= 0:
        raise ValueError("download stream count must be greater than zero")
    total = _expected_download_bytes(url)
    if total is None:
        return [url] * streams
    adjusted = _cloudflare_download_url(url, total)
    if adjusted is None:
        return [url] * streams

    base, remainder = divmod(total, streams)
    if base <= 0:
        raise ValueError("download payload is too small for requested stream count")
    urls: list[str] = []
    for index in range(streams):
        size = base + (1 if index < remainder else 0)
        candidate = _cloudflare_download_url(url, size)
        assert candidate is not None
        urls.append(candidate)
    return urls


def _attempt_dict(result: SpeedResult) -> dict:
    return {
        "url": result.url,
        "ok": result.ok,
        "mbps": result.mbps,
        "bytes": result.bytes_transferred,
        "expected_bytes": result.expected_bytes,
        "payload_valid": result.payload_valid,
        "time_seconds": result.time_seconds,
        "http_code": result.http_code,
        "error": result.error,
        "expect_disabled": result.expect_disabled,
    }


def _download_via_socks(
    socks_url: str,
    *,
    url: str,
    timeout: float,
    curl_command: str,
) -> SpeedResult:
    expected_bytes = _expected_download_bytes(url)
    try:
        proc = subprocess.run(
            [
                curl_command,
                "--silent",
                "--show-error",
                "--fail",
                "--output",
                "/dev/null",
                "--proxy",
                socks_url,
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
            size, elapsed, http_code = _parse_curl_writeout(proc.stdout)
            error = (proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}"
            return SpeedResult(
                False,
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=error,
                url=url,
                expected_bytes=expected_bytes,
            )
        size, elapsed, http_code = _parse_curl_metrics(proc.stdout)
        if expected_bytes is not None and size != expected_bytes:
            return SpeedResult(
                False,
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=f"invalid download payload: expected {expected_bytes} bytes, received {size}",
                url=url,
                expected_bytes=expected_bytes,
                payload_valid=False,
            )
        return SpeedResult(
            True,
            _mbps(size, elapsed),
            size,
            elapsed,
            http_code,
            url=url,
            expected_bytes=expected_bytes,
            payload_valid=True if expected_bytes is not None else None,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return SpeedResult(False, error=str(exc), url=url, expected_bytes=expected_bytes)


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
        return _download_via_socks(
            session.socks_url,
            url=url,
            timeout=timeout,
            curl_command=curl_command,
        )
    except EngineError as exc:
        return SpeedResult(False, error=str(exc), url=url, expected_bytes=_expected_download_bytes(url))
    finally:
        if session is not None:
            engine.stop(session)


def _download_parallel_stage(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    streams: int,
    timeout: float,
    curl_command: str,
) -> SpeedResult:
    """Measure aggregate bandwidth using concurrent transfers through one session."""
    session = None
    stream_urls = _split_download_urls(url, streams)
    try:
        session = engine.start(proxy)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=streams) as pool:
            futures = [
                pool.submit(
                    _download_via_socks,
                    session.socks_url,
                    url=stream_url,
                    timeout=timeout,
                    curl_command=curl_command,
                )
                for stream_url in stream_urls
            ]
            stream_results = [future.result() for future in futures]
        elapsed = time.monotonic() - started
    except (EngineError, OSError, ValueError) as exc:
        return SpeedResult(False, error=str(exc), url=url)
    finally:
        if session is not None:
            engine.stop(session)

    total_bytes = sum(result.bytes_transferred or 0 for result in stream_results)
    expected_values = [result.expected_bytes for result in stream_results]
    expected_total = sum(value for value in expected_values if value is not None) if all(
        value is not None for value in expected_values
    ) else None
    all_ok = all(result.ok for result in stream_results)
    payload_valid = all(result.payload_valid is not False for result in stream_results)
    first_failure = next((result for result in stream_results if not result.ok), None)

    aggregate = _mbps(total_bytes, elapsed) if total_bytes > 0 and elapsed > 0 else None
    result = SpeedResult(
        all_ok,
        mbps=aggregate,
        bytes_transferred=total_bytes,
        time_seconds=elapsed,
        http_code=200 if all_ok else (first_failure.http_code if first_failure else None),
        error=None if all_ok else (first_failure.error if first_failure else "parallel download failed"),
        url=url,
        expected_bytes=expected_total,
        payload_valid=payload_valid if expected_total is not None else None,
        attempts=[_attempt_dict(item) for item in stream_results],
    )
    return result


def _download_with_fallbacks(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    fallback_urls: list[str],
    fallback_http_codes: set[int],
    timeout: float,
    curl_command: str,
) -> SpeedResult:
    attempts: list[dict] = []
    urls = [url, *fallback_urls]
    result: SpeedResult | None = None

    for index, candidate_url in enumerate(urls):
        result = _download_one(
            proxy,
            engine,
            url=candidate_url,
            timeout=timeout,
            curl_command=curl_command,
        )
        attempts.append(_attempt_dict(result))

        if result.ok:
            result.attempts = attempts
            return result

        retryable = result.payload_valid is False or result.http_code in fallback_http_codes
        if not retryable:
            result.attempts = attempts
            return result

        if index + 1 < len(urls):
            reason = "invalid_payload" if result.payload_valid is False else f"http={result.http_code}"
            print(
                f"[download] fallback proxy={proxy.ensure_id()[:12]} "
                f"reason={reason} next={urls[index + 1]}"
            )

    assert result is not None
    result.attempts = attempts
    return result


def _download_staged(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    fallback_urls: list[str],
    fallback_http_codes: set[int],
    timeout: float,
    curl_command: str,
    stream_stages: tuple[int, ...] = DEFAULT_DOWNLOAD_STREAM_STAGES,
) -> SpeedResult:
    """Run configured stream stages and return the highest measured aggregate rate.

    A failure in the first configured stage keeps the historical fallback behavior.
    A later stage failure stops escalation but does not discard a successful earlier stage.
    """
    stages = _normalize_download_stream_stages(stream_stages)
    stage_records: list[dict] = []
    best: SpeedResult | None = None

    for index, streams in enumerate(stages):
        result = _download_parallel_stage(
            proxy,
            engine,
            url=url,
            streams=streams,
            timeout=timeout,
            curl_command=curl_command,
        )
        stage_records.append(
            {
                "streams": streams,
                "ok": result.ok,
                "mbps": result.mbps,
                "bytes": result.bytes_transferred,
                "expected_bytes": result.expected_bytes,
                "payload_valid": result.payload_valid,
                "time_seconds": result.time_seconds,
                "http_code": result.http_code,
                "error": result.error,
                "stream_results": result.attempts,
            }
        )

        if not result.ok:
            if index == 0:
                retryable = result.payload_valid is False or result.http_code in fallback_http_codes
                if retryable and fallback_urls:
                    fallback = _download_with_fallbacks(
                        proxy,
                        engine,
                        url=url,
                        fallback_urls=fallback_urls,
                        fallback_http_codes=fallback_http_codes,
                        timeout=timeout,
                        curl_command=curl_command,
                    )
                    fallback.stages = stage_records
                    return fallback
                result.stages = stage_records
                return result
            break

        if best is None or (result.mbps or -1) > (best.mbps or -1):
            best = result

    if best is None:
        result.stages = stage_records
        return result
    best.stages = stage_records
    return best


def _upload_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    payload_path: Path,
    timeout: float,
    curl_command: str,
    disable_expect: bool = False,
) -> SpeedResult:
    session = None
    try:
        session = engine.start(proxy)
        command = [
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
        ]
        if disable_expect:
            command.extend(["--header", "Expect:"])
        command.extend(
            [
                "--data-binary",
                f"@{payload_path}",
                "--write-out",
                "%{size_upload}\t%{time_total}\t%{http_code}",
                url,
            ]
        )
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout + 5,
        )
        if proc.returncode != 0:
            size, elapsed, http_code = _parse_curl_writeout(proc.stdout)
            return SpeedResult(
                False,
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=(proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}",
                url=url,
                expect_disabled=disable_expect,
            )
        size, elapsed, http_code = _parse_curl_metrics(proc.stdout)
        return SpeedResult(
            True,
            _mbps(size, elapsed),
            size,
            elapsed,
            http_code,
            url=url,
            expect_disabled=disable_expect,
        )
    except (EngineError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return SpeedResult(False, error=str(exc), url=url, expect_disabled=disable_expect)
    finally:
        if session is not None:
            engine.stop(session)


def _is_incomplete_upload_after_continue(result: SpeedResult) -> bool:
    return (
        not result.ok
        and result.http_code == 100
        and result.bytes_transferred is not None
        and result.bytes_transferred > 0
    )


def _is_transient_upload_failure(result: SpeedResult) -> bool:
    return (
        not result.ok
        and result.http_code in {None, 0}
        and result.bytes_transferred in {None, 0}
    )


def _upload_with_fallbacks(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    fallback_urls: list[str],
    fallback_http_codes: set[int],
    payload_path: Path,
    timeout: float,
    curl_command: str,
) -> SpeedResult:
    attempts: list[dict] = []

    result = _upload_one(
        proxy,
        engine,
        url=url,
        payload_path=payload_path,
        timeout=timeout,
        curl_command=curl_command,
        disable_expect=False,
    )
    attempts.append(_attempt_dict(result))
    if result.ok:
        result.attempts = attempts
        return result

    if _is_incomplete_upload_after_continue(result):
        print(
            f"[upload] retry proxy={proxy.ensure_id()[:12]} "
            "reason=incomplete-after-100 expect=disabled"
        )
        result = _upload_one(
            proxy,
            engine,
            url=url,
            payload_path=payload_path,
            timeout=timeout,
            curl_command=curl_command,
            disable_expect=True,
        )
        attempts.append(_attempt_dict(result))
        if result.ok:
            result.attempts = attempts
            return result

    if _is_transient_upload_failure(result):
        print(
            f"[upload] retry proxy={proxy.ensure_id()[:12]} "
            "reason=transient-zero-byte"
        )
        retry_disable_expect = result.expect_disabled
        result = _upload_one(
            proxy,
            engine,
            url=url,
            payload_path=payload_path,
            timeout=timeout,
            curl_command=curl_command,
            disable_expect=retry_disable_expect,
        )
        attempts.append(_attempt_dict(result))
        if result.ok:
            result.attempts = attempts
            return result

    retryable = _is_incomplete_upload_after_continue(result) or result.http_code in fallback_http_codes
    if not retryable:
        result.attempts = attempts
        return result

    for fallback_url in fallback_urls:
        print(
            f"[upload] fallback proxy={proxy.ensure_id()[:12]} "
            f"http={result.http_code} next={fallback_url}"
        )
        result = _upload_one(
            proxy,
            engine,
            url=fallback_url,
            payload_path=payload_path,
            timeout=timeout,
            curl_command=curl_command,
            disable_expect=True,
        )
        attempts.append(_attempt_dict(result))
        if result.ok:
            result.attempts = attempts
            return result
        if not (_is_incomplete_upload_after_continue(result) or result.http_code in fallback_http_codes):
            break

    result.attempts = attempts
    return result


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
    fallback_urls: list[str] | None = None,
    fallback_http_codes: set[int] | None = None,
    stream_stages=None,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.download_url is required")

    clean_fallbacks = [item for item in (fallback_urls or []) if item and item != url]
    retry_codes = set(fallback_http_codes or {429})
    normalized_stages = _normalize_download_stream_stages(stream_stages)

    def probe(proxy: ProxyConfig) -> SpeedResult:
        return _download_staged(
            proxy,
            engine,
            url=url,
            fallback_urls=clean_fallbacks,
            fallback_http_codes=retry_codes,
            timeout=timeout,
            curl_command=curl_command,
            stream_stages=normalized_stages,
        )

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for proxy, result in _run_many(proxies, workers, probe, "download"):
        proxy.tests.download_mbps = result.mbps
        threshold_ok = result.ok and result.mbps is not None and result.mbps >= min_mbps
        single_stage = next((stage for stage in result.stages if stage.get("streams") == 1), None)
        proxy.tests.download = {
            "status": "pass" if threshold_ok else "fail",
            "mbps": result.mbps,
            "single_mbps": single_stage.get("mbps") if single_stage else None,
            "aggregate_mbps": result.mbps,
            "stream_stages": list(normalized_stages),
            "bytes": result.bytes_transferred,
            "expected_bytes": result.expected_bytes,
            "payload_valid": result.payload_valid,
            "time_seconds": result.time_seconds,
            "http_code": result.http_code,
            "error": result.error,
            "url": result.url,
            "attempts": result.attempts,
            "stages": result.stages,
            "method": "curl-socks5h-staged-parallel",
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
    fallback_urls: list[str] | None = None,
    fallback_http_codes: set[int] | None = None,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.upload_url is required")
    if upload_bytes <= 0:
        raise ValueError("speed.upload_bytes must be greater than zero")

    clean_fallbacks = [item for item in (fallback_urls or []) if item and item != url]
    retry_codes = set(fallback_http_codes or {429, 500, 502, 503, 504})

    with tempfile.NamedTemporaryFile(prefix="proxy-filter-upload-", delete=True) as payload:
        payload.truncate(upload_bytes)
        payload.flush()
        payload_path = Path(payload.name)

        def probe(proxy: ProxyConfig) -> SpeedResult:
            return _upload_with_fallbacks(
                proxy,
                engine,
                url=url,
                fallback_urls=clean_fallbacks,
                fallback_http_codes=retry_codes,
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
            "url": result.url,
            "attempts": result.attempts,
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
