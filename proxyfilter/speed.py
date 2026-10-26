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
DEFAULT_DOWNLOAD_MIN_STREAM_BYTES = 5_000_000
DEFAULT_SPEED_CONNECT_TIMEOUT = 10.0


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
    backend: str | None = None


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


def _partial_mbps(size: int | None, elapsed: float | None, http_code: int | None) -> float | None:
    """Keep a usable speed measurement from an interrupted transfer.

    Provider HTTP errors (for example 429/5xx) are not measurements. A timeout
    or other transport failure after a normal transfer response may still have
    enough bytes/time data to evaluate the configured speed threshold.
    """
    if size is None or elapsed is None or size <= 0 or elapsed <= 0:
        return None
    if http_code not in {None, 0, 100, 200, 201, 202, 204, 206}:
        return None
    return _mbps(size, elapsed)


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


def _download_backend(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "generic"
    host = (parsed.hostname or "").lower()
    if host == "speed.cloudflare.com" and parsed.path == "/__down":
        return "cloudflare"
    if host == "cachefly.cachefly.net":
        return "cachefly"
    return "generic"


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


def _split_sizes(total: int, streams: int) -> list[int]:
    if streams <= 0:
        raise ValueError("download stream count must be greater than zero")
    base, remainder = divmod(total, streams)
    if base <= 0:
        raise ValueError("download payload is too small for requested stream count")
    return [base + (1 if index < remainder else 0) for index in range(streams)]


def _stage_requests(
    url: str,
    streams: int,
    *,
    total_bytes: int | None = None,
) -> list[tuple[str, list[str], int | None]]:
    """Build per-stream URL/header/expected-byte requests for a download stage."""
    backend = _download_backend(url)

    if backend == "cloudflare":
        total = total_bytes if total_bytes is not None else _expected_download_bytes(url)
        if total is None:
            return [(url, [], None)] * streams
        requests: list[tuple[str, list[str], int | None]] = []
        for size in _split_sizes(total, streams):
            candidate = _cloudflare_download_url(url, size)
            assert candidate is not None
            requests.append((candidate, [], size))
        return requests

    if backend == "cachefly" and total_bytes is not None:
        file_bytes = _expected_download_bytes(url)
        if file_bytes is None:
            raise ValueError("CacheFly staged fallback requires a known-size test file")
        if total_bytes > file_bytes:
            raise ValueError(
                f"CacheFly test file is too small: need {total_bytes} bytes, have {file_bytes}"
            )
        requests = []
        offset = 0
        for size in _split_sizes(total_bytes, streams):
            last = offset + size - 1
            requests.append((url, [f"Range: bytes={offset}-{last}"], size))
            offset = last + 1
        return requests

    expected = _expected_download_bytes(url)
    return [(url, [], expected)] * streams


def _split_download_urls(url: str, streams: int) -> list[str]:
    """Backward-compatible URL splitter used by existing tests/callers."""
    requests = _stage_requests(url, streams)
    return [request_url for request_url, _headers, _expected in requests]


def _attempt_dict(result: SpeedResult) -> dict:
    return {
        "backend": result.backend,
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


def _resolved_connect_timeout(timeout: float, connect_timeout: float | None) -> float:
    value = timeout if connect_timeout is None else float(connect_timeout)
    if value <= 0:
        raise ValueError("speed.connect_timeout_seconds must be greater than zero")
    return value


def _max_operation_time(transfer_timeout: float, connect_timeout: float) -> float:
    if transfer_timeout <= 0:
        raise ValueError("speed.transfer_timeout_seconds must be greater than zero")
    return float(connect_timeout) + float(transfer_timeout)


def _download_via_socks(
    socks_url: str,
    *,
    url: str,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None = None,
    headers: list[str] | None = None,
    expected_bytes: int | None = None,
    backend: str | None = None,
) -> SpeedResult:
    if expected_bytes is None:
        expected_bytes = _expected_download_bytes(url)
    backend = backend or _download_backend(url)
    connect_timeout = _resolved_connect_timeout(timeout, connect_timeout)
    max_time = _max_operation_time(timeout, connect_timeout)
    try:
        command = [
            curl_command,
            "--silent",
            "--show-error",
            "--fail",
            "--output",
            "/dev/null",
            "--proxy",
            socks_url,
            "--connect-timeout",
            str(connect_timeout),
            "--max-time",
            str(max_time),
        ]
        for header in headers or []:
            command.extend(["--header", header])
        command.extend(
            [
                "--write-out",
                "%{size_download}\t%{time_total}\t%{http_code}",
                url,
            ]
        )
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=max_time + 5,
        )
        if proc.returncode != 0:
            size, elapsed, http_code = _parse_curl_writeout(proc.stdout)
            error = (proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}"
            return SpeedResult(
                False,
                mbps=_partial_mbps(size, elapsed, http_code),
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=error,
                url=url,
                expected_bytes=expected_bytes,
                backend=backend,
            )
        size, elapsed, http_code = _parse_curl_metrics(proc.stdout)
        if expected_bytes is not None and size != expected_bytes:
            return SpeedResult(
                False,
                mbps=_partial_mbps(size, elapsed, http_code),
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=f"invalid download payload: expected {expected_bytes} bytes, received {size}",
                url=url,
                expected_bytes=expected_bytes,
                payload_valid=False,
                backend=backend,
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
            backend=backend,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        return SpeedResult(
            False,
            error=str(exc),
            url=url,
            expected_bytes=expected_bytes,
            backend=backend,
        )


def _download_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None = None,
) -> SpeedResult:
    session = None
    try:
        session = engine.start(proxy)
        return _download_via_socks(
            session.socks_url,
            url=url,
            timeout=timeout,
            curl_command=curl_command,
            connect_timeout=connect_timeout,
        )
    except EngineError as exc:
        return SpeedResult(
            False,
            error=str(exc),
            url=url,
            expected_bytes=_expected_download_bytes(url),
            backend=_download_backend(url),
        )
    finally:
        if session is not None:
            engine.stop(session)


def _download_with_fallbacks(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    fallback_urls: list[str],
    fallback_http_codes: set[int],
    timeout: float,
    curl_command: str,
    connect_timeout: float | None = None,
) -> SpeedResult:
    """Backward-compatible single-stream fallback helper."""
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
            connect_timeout=connect_timeout,
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


def _download_parallel_stage(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    streams: int,
    timeout: float,
    curl_command: str,
    total_bytes: int | None = None,
    connect_timeout: float | None = None,
) -> SpeedResult:
    """Measure aggregate bandwidth using concurrent transfers through one session."""
    session = None
    backend = _download_backend(url)
    requests = _stage_requests(url, streams, total_bytes=total_bytes)
    try:
        session = engine.start(proxy)
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=streams) as pool:
            futures = [
                pool.submit(
                    _download_via_socks,
                    session.socks_url,
                    url=request_url,
                    timeout=timeout,
                    curl_command=curl_command,
                    connect_timeout=connect_timeout,
                    headers=headers,
                    expected_bytes=expected,
                    backend=backend,
                )
                for request_url, headers, expected in requests
            ]
            stream_results = [future.result() for future in futures]
        elapsed = time.monotonic() - started
    except (EngineError, OSError, ValueError) as exc:
        return SpeedResult(False, error=str(exc), url=url, backend=backend)
    finally:
        if session is not None:
            engine.stop(session)

    total_transferred = sum(result.bytes_transferred or 0 for result in stream_results)
    expected_values = [result.expected_bytes for result in stream_results]
    expected_total = (
        sum(value for value in expected_values if value is not None)
        if all(value is not None for value in expected_values)
        else None
    )
    all_ok = all(result.ok for result in stream_results)
    payload_valid = all(result.payload_valid is not False for result in stream_results)
    first_failure = next((result for result in stream_results if not result.ok), None)
    http_codes = {result.http_code for result in stream_results if result.http_code is not None}
    aggregate = _mbps(total_transferred, elapsed) if total_transferred > 0 and elapsed > 0 else None

    return SpeedResult(
        all_ok,
        mbps=aggregate,
        bytes_transferred=total_transferred,
        time_seconds=elapsed,
        http_code=(
            next(iter(http_codes))
            if all_ok and len(http_codes) == 1
            else (first_failure.http_code if first_failure else None)
        ),
        error=None if all_ok else (first_failure.error if first_failure else "parallel download failed"),
        url=url,
        expected_bytes=expected_total,
        payload_valid=payload_valid if expected_total is not None else None,
        attempts=[_attempt_dict(item) for item in stream_results],
        backend=backend,
    )


def _stage_record(streams: int, result: SpeedResult, *, skipped: bool = False) -> dict:
    return {
        "backend": result.backend,
        "streams": streams,
        "skipped": skipped,
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


def _run_staged_backend(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    stream_stages: tuple[int, ...],
    total_bytes: int | None,
    min_stream_bytes: int,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None = None,
) -> tuple[SpeedResult, bool]:
    """Run one backend only; return result and whether its failure is retryable upstream."""
    stage_records: list[dict] = []
    best: SpeedResult | None = None
    last_result: SpeedResult | None = None
    backend = _download_backend(url)

    for streams in stream_stages:
        if total_bytes is not None and total_bytes // streams < min_stream_bytes:
            skipped = SpeedResult(
                False,
                error=(
                    f"stage skipped: {total_bytes // streams} bytes/stream is below "
                    f"download_min_stream_bytes={min_stream_bytes}"
                ),
                url=url,
                expected_bytes=total_bytes,
                backend=backend,
            )
            stage_records.append(_stage_record(streams, skipped, skipped=True))
            continue

        result = _download_parallel_stage(
            proxy,
            engine,
            url=url,
            streams=streams,
            timeout=timeout,
            curl_command=curl_command,
            total_bytes=total_bytes,
            connect_timeout=connect_timeout,
        )
        last_result = result
        stage_records.append(_stage_record(streams, result))

        if not result.ok:
            result.stages = stage_records
            retryable = result.payload_valid is False
            if best is not None:
                best.stages = stage_records
                return best, retryable
            return result, retryable

        if best is None or (result.mbps or -1) > (best.mbps or -1):
            best = result

    if best is not None:
        best.stages = stage_records
        return best, False

    if last_result is None:
        last_result = SpeedResult(
            False,
            error="all download stages were skipped",
            url=url,
            expected_bytes=total_bytes,
            backend=backend,
        )
    last_result.stages = stage_records
    return last_result, False


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
    min_stream_bytes: int = DEFAULT_DOWNLOAD_MIN_STREAM_BYTES,
    connect_timeout: float | None = None,
) -> SpeedResult:
    """Run staged primary download and retry the whole staged test on fallback backends."""
    stages = _normalize_download_stream_stages(stream_stages)
    if min_stream_bytes <= 0:
        raise ValueError("speed.download_min_stream_bytes must be greater than zero")
    connect_timeout = _resolved_connect_timeout(timeout, connect_timeout)

    total_bytes = _expected_download_bytes(url)
    primary, _ = _run_staged_backend(
        proxy,
        engine,
        url=url,
        stream_stages=stages,
        total_bytes=total_bytes,
        min_stream_bytes=min_stream_bytes,
        timeout=timeout,
        curl_command=curl_command,
        connect_timeout=connect_timeout,
    )

    failed_stage = next(
        (stage for stage in primary.stages if not stage.get("ok") and not stage.get("skipped")),
        None,
    )
    if failed_stage is None:
        return primary

    retryable = (
        failed_stage.get("payload_valid") is False
        or failed_stage.get("http_code") in fallback_http_codes
    )
    if not retryable or not fallback_urls:
        return primary

    primary_best = primary if primary.ok else None
    all_stages = list(primary.stages)
    reason = (
        "invalid_payload"
        if failed_stage.get("payload_valid") is False
        else f"http={failed_stage.get('http_code')}"
    )
    last_fallback: SpeedResult | None = None

    for fallback_url in fallback_urls:
        print(
            f"[download] fallback proxy={proxy.ensure_id()[:12]} "
            f"reason={reason} next={fallback_url} mode=staged"
        )
        fallback, _ = _run_staged_backend(
            proxy,
            engine,
            url=fallback_url,
            stream_stages=stages,
            total_bytes=total_bytes,
            min_stream_bytes=min_stream_bytes,
            timeout=timeout,
            curl_command=curl_command,
            connect_timeout=connect_timeout,
        )
        fallback_stages = list(fallback.stages)
        all_stages.extend(fallback_stages)
        fallback.stages = list(all_stages)
        last_fallback = fallback

        if fallback.ok:
            return fallback

        fallback_failed = next(
            (stage for stage in fallback_stages if not stage.get("ok") and not stage.get("skipped")),
            None,
        )
        if fallback_failed is None:
            if primary_best is not None:
                primary_best.stages = list(all_stages)
                return primary_best
            return fallback

        retryable = (
            fallback_failed.get("payload_valid") is False
            or fallback_failed.get("http_code") in fallback_http_codes
        )
        if not retryable:
            if primary_best is not None:
                primary_best.stages = list(all_stages)
                return primary_best
            return fallback

        reason = (
            "invalid_payload"
            if fallback_failed.get("payload_valid") is False
            else f"http={fallback_failed.get('http_code')}"
        )

    if primary_best is not None:
        primary_best.stages = list(all_stages)
        return primary_best
    assert last_fallback is not None
    return last_fallback


def _upload_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    payload_path: Path,
    timeout: float,
    curl_command: str,
    disable_expect: bool = False,
    connect_timeout: float | None = None,
) -> SpeedResult:
    session = None
    connect_timeout = _resolved_connect_timeout(timeout, connect_timeout)
    max_time = _max_operation_time(timeout, connect_timeout)
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
            str(connect_timeout),
            "--max-time",
            str(max_time),
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
            timeout=max_time + 5,
        )
        if proc.returncode != 0:
            size, elapsed, http_code = _parse_curl_writeout(proc.stdout)
            return SpeedResult(
                False,
                mbps=_partial_mbps(size, elapsed, http_code),
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
    connect_timeout: float | None = None,
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
        connect_timeout=connect_timeout,
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
            connect_timeout=connect_timeout,
        )
        attempts.append(_attempt_dict(result))
        if result.ok:
            result.attempts = attempts
            return result

    if _is_transient_upload_failure(result):
        print(f"[upload] retry proxy={proxy.ensure_id()[:12]} reason=transient-zero-byte")
        retry_disable_expect = result.expect_disabled
        result = _upload_one(
            proxy,
            engine,
            url=url,
            payload_path=payload_path,
            timeout=timeout,
            curl_command=curl_command,
            disable_expect=retry_disable_expect,
            connect_timeout=connect_timeout,
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
            connect_timeout=connect_timeout,
        )
        attempts.append(_attempt_dict(result))
        if result.ok:
            result.attempts = attempts
            return result
        if not (
            _is_incomplete_upload_after_continue(result)
            or result.http_code in fallback_http_codes
        ):
            break

    result.attempts = attempts
    return result


def _run_many(
    proxies: list[ProxyConfig], workers: int, probe, label: str
) -> list[tuple[ProxyConfig, SpeedResult]]:
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
    min_stream_bytes: int = DEFAULT_DOWNLOAD_MIN_STREAM_BYTES,
    connect_timeout: float | None = DEFAULT_SPEED_CONNECT_TIMEOUT,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.download_url is required")
    if min_stream_bytes <= 0:
        raise ValueError("speed.download_min_stream_bytes must be greater than zero")
    connect_timeout = _resolved_connect_timeout(timeout, connect_timeout)
    max_time = _max_operation_time(timeout, connect_timeout)

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
            min_stream_bytes=min_stream_bytes,
            connect_timeout=connect_timeout,
        )

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for proxy, result in _run_many(proxies, workers, probe, "download"):
        proxy.tests.download_mbps = result.mbps
        has_measurement = result.mbps is not None
        threshold_ok = has_measurement and result.mbps >= min_mbps
        single_stage = next(
            (
                stage
                for stage in result.stages
                if stage.get("streams") == 1
                and stage.get("backend") == result.backend
                and stage.get("ok")
            ),
            None,
        )
        proxy.tests.download = {
            "status": "pass" if threshold_ok else "fail",
            "backend": result.backend,
            "mbps": result.mbps,
            "single_mbps": single_stage.get("mbps") if single_stage else None,
            "aggregate_mbps": result.mbps,
            "stream_stages": list(normalized_stages),
            "min_stream_bytes": min_stream_bytes,
            "connect_timeout_seconds": connect_timeout,
            "transfer_timeout_seconds": timeout,
            "max_time_seconds": max_time,
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
        if not has_measurement:
            proxy.tests.status = "rejected_download_error"
            rejected.append(proxy)
        elif not threshold_ok:
            proxy.tests.status = "rejected_download_threshold"
            rejected.append(proxy)
        else:
            proxy.tests.status = "download_pass"
            passed.append(proxy)

    passed.sort(
        key=lambda proxy: proxy.tests.download_mbps
        if proxy.tests.download_mbps is not None
        else -1,
        reverse=True,
    )
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
    connect_timeout: float | None = DEFAULT_SPEED_CONNECT_TIMEOUT,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.upload_url is required")
    if upload_bytes <= 0:
        raise ValueError("speed.upload_bytes must be greater than zero")
    connect_timeout = _resolved_connect_timeout(timeout, connect_timeout)
    max_time = _max_operation_time(timeout, connect_timeout)

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
                connect_timeout=connect_timeout,
            )

        measured = _run_many(proxies, workers, probe, "upload")

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for proxy, result in measured:
        proxy.tests.upload_mbps = result.mbps
        has_measurement = result.mbps is not None
        threshold_ok = has_measurement and result.mbps >= min_mbps
        proxy.tests.upload = {
            "status": "pass" if threshold_ok else "fail",
            "mbps": result.mbps,
            "connect_timeout_seconds": connect_timeout,
            "transfer_timeout_seconds": timeout,
            "max_time_seconds": max_time,
            "bytes": result.bytes_transferred,
            "time_seconds": result.time_seconds,
            "http_code": result.http_code,
            "error": result.error,
            "url": result.url,
            "attempts": result.attempts,
            "method": "curl-socks5h",
        }
        if not has_measurement:
            proxy.tests.status = "rejected_upload_error"
            rejected.append(proxy)
        elif not threshold_ok:
            proxy.tests.status = "rejected_upload_threshold"
            rejected.append(proxy)
        else:
            proxy.tests.status = "upload_pass"
            passed.append(proxy)

    passed.sort(
        key=lambda proxy: proxy.tests.upload_mbps
        if proxy.tests.upload_mbps is not None
        else -1,
        reverse=True,
    )
    return passed, rejected
