from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile
import time

from .engine import EngineBackend, EngineError
from .model import ProxyConfig
from . import speed as base


DEFAULT_UPLOAD_STREAM_STAGES = (1, 2, 4, 10)
DEFAULT_UPLOAD_MIN_STREAM_BYTES = 1_000_000


@dataclass(slots=True)
class _BackendOutcome:
    result: base.SpeedResult
    best_success: base.SpeedResult | None
    terminal_failure: base.SpeedResult | None
    stages: list[dict]


def _is_timeout_error(error: str | None) -> bool:
    if not error:
        return False
    text = error.lower()
    if "operation too slow" in text or ("bytes/sec" in text and "less than" in text):
        return False
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def _attempt_is_timeout(attempt: dict) -> bool:
    reason = attempt.get("failure_reason")
    if reason is not None:
        return reason == "timeout"
    return _is_timeout_error(attempt.get("error"))


def _result_is_timeout(result: base.SpeedResult) -> bool:
    failures = [attempt for attempt in result.attempts if not attempt.get("ok")]
    if failures:
        return all(_attempt_is_timeout(attempt) for attempt in failures)
    if result.failure_reason is not None:
        return not result.ok and result.failure_reason == "timeout"
    return not result.ok and _is_timeout_error(result.error)


def _stage_is_timeout(stage: dict) -> bool:
    reason = stage.get("failure_reason")
    if reason is not None:
        return reason == "timeout"
    return _is_timeout_error(stage.get("error"))


def _final_backend_timed_out(result: base.SpeedResult) -> bool:
    stages = [
        stage
        for stage in result.stages
        if not stage.get("skipped") and stage.get("backend") == result.backend
    ]
    return bool(stages) and not any(stage.get("ok") for stage in stages) and all(
        _stage_is_timeout(stage) for stage in stages
    )


def _best_partial(stages: list[dict]) -> tuple[float | None, int | None, str | None]:
    candidates = [
        stage
        for stage in stages
        if not stage.get("skipped")
        and not stage.get("ok")
        and stage.get("mbps") is not None
        and _stage_is_timeout(stage)
    ]
    if not candidates:
        return None, None, None
    best = max(candidates, key=lambda stage: float(stage["mbps"]))
    return float(best["mbps"]), int(best["streams"]), best.get("backend")


def _pick_faster(
    first: base.SpeedResult | None,
    second: base.SpeedResult | None,
) -> base.SpeedResult | None:
    if first is None:
        return second
    if second is None:
        return first
    return second if (second.mbps or -1.0) > (first.mbps or -1.0) else first


def _run_download_backend(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    stream_stages: tuple[int, ...],
    total_bytes: int | None,
    min_stream_bytes: int,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None,
) -> _BackendOutcome:
    stage_records: list[dict] = []
    best: base.SpeedResult | None = None
    last: base.SpeedResult | None = None
    terminal: base.SpeedResult | None = None
    backend = base._download_backend(url)

    for streams in stream_stages:
        if total_bytes is not None and total_bytes // streams < min_stream_bytes:
            skipped = base.SpeedResult(
                False,
                error=(
                    f"stage skipped: {total_bytes // streams} bytes/stream is below "
                    f"download_min_stream_bytes={min_stream_bytes}"
                ),
                url=url,
                expected_bytes=total_bytes,
                backend=backend,
            )
            stage_records.append(base._stage_record(streams, skipped, skipped=True))
            continue

        result = base._download_parallel_stage(
            proxy,
            engine,
            url=url,
            streams=streams,
            timeout=timeout,
            curl_command=curl_command,
            total_bytes=total_bytes,
            connect_timeout=connect_timeout,
        )
        last = result
        stage_records.append(base._stage_record(streams, result))

        if result.ok:
            best = _pick_faster(best, result)
            continue

        # A timeout is a performance result, not a terminal backend error.
        # Continue with more parallel streams for both Cloudflare and CacheFly.
        if _result_is_timeout(result):
            continue

        terminal = result
        break

    if best is not None:
        best.stages = list(stage_records)
        chosen = best
    elif last is not None:
        last.stages = list(stage_records)
        chosen = last
    else:
        chosen = base.SpeedResult(
            False,
            error="all download stages were skipped",
            url=url,
            expected_bytes=total_bytes,
            backend=backend,
            stages=list(stage_records),
        )

    return _BackendOutcome(chosen, best, terminal, stage_records)


def _download_staged(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    fallback_urls: list[str],
    fallback_http_codes: set[int],
    timeout: float,
    curl_command: str,
    stream_stages: tuple[int, ...] = base.DEFAULT_DOWNLOAD_STREAM_STAGES,
    min_stream_bytes: int = base.DEFAULT_DOWNLOAD_MIN_STREAM_BYTES,
    connect_timeout: float | None = None,
) -> base.SpeedResult:
    del fallback_http_codes  # fallback policy is intentionally timeout-vs-non-timeout now
    stages = base._normalize_download_stream_stages(stream_stages)
    if min_stream_bytes <= 0:
        raise ValueError("speed.download_min_stream_bytes must be greater than zero")
    connect_timeout = base._resolved_connect_timeout(timeout, connect_timeout)
    total_bytes = base._expected_download_bytes(url)

    primary = _run_download_backend(
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

    all_stages = list(primary.stages)
    best_overall = primary.best_success

    # Timeout exhaustion never switches backend. If there was a successful
    # earlier stage, keep it; otherwise the caller classifies timeout exhaustion
    # as a speed rejection rather than a transport error.
    if primary.terminal_failure is None:
        primary.result.stages = all_stages
        return primary.result

    # Cloudflare -> CacheFly (or any configured fallback) only after a
    # non-timeout terminal failure: HTTP errors, invalid payload, TLS/SOCKS/EOF,
    # connection reset, etc. A timeout itself never triggers fallback.
    if not fallback_urls:
        primary.result.stages = all_stages
        return primary.result

    failure = primary.terminal_failure
    reason = (
        "invalid_payload"
        if failure.payload_valid is False
        else f"http={failure.http_code}"
        if failure.http_code not in {None, 0}
        else (failure.error or "non-timeout-failure")
    )
    last_result = primary.result

    for fallback_url in fallback_urls:
        print(
            f"[download] fallback proxy={proxy.ensure_id()[:12]} "
            f"reason={reason} next={fallback_url} mode=staged"
        )
        fallback = _run_download_backend(
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
        all_stages.extend(fallback.stages)
        best_overall = _pick_faster(best_overall, fallback.best_success)
        last_result = fallback.result

        if fallback.terminal_failure is None:
            chosen = best_overall or fallback.result
            chosen.stages = list(all_stages)
            return chosen

        failure = fallback.terminal_failure
        reason = (
            "invalid_payload"
            if failure.payload_valid is False
            else f"http={failure.http_code}"
            if failure.http_code not in {None, 0}
            else (failure.error or "non-timeout-failure")
        )

    chosen = best_overall or last_result
    chosen.stages = list(all_stages)
    return chosen


def _upload_via_socks(
    socks_url: str,
    *,
    url: str,
    payload_path: Path,
    expected_bytes: int,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None,
    disable_expect: bool = False,
) -> base.SpeedResult:
    connect_timeout = base._resolved_connect_timeout(timeout, connect_timeout)
    max_time = base._max_operation_time(timeout, connect_timeout)
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
            *base._curl_stall_args(),
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
            size, elapsed, http_code = base._parse_curl_writeout(proc.stdout)
            mbps = (
                base._mbps(size, elapsed)
                if size is not None and size > 0 and elapsed is not None and elapsed > 0
                else None
            )
            error = (proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}"
            return base.SpeedResult(
                False,
                mbps=mbps,
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=error,
                url=url,
                expect_disabled=disable_expect,
                expected_bytes=expected_bytes,
                failure_reason=base._curl_failure_reason(proc.returncode, error),
                curl_exit_code=proc.returncode,
            )

        size, elapsed, http_code = base._parse_curl_metrics(proc.stdout)
        if size != expected_bytes:
            return base.SpeedResult(
                False,
                mbps=base._mbps(size, elapsed),
                bytes_transferred=size,
                time_seconds=elapsed,
                http_code=http_code,
                error=f"invalid upload payload: expected {expected_bytes} bytes, sent {size}",
                url=url,
                expect_disabled=disable_expect,
                expected_bytes=expected_bytes,
                payload_valid=False,
                failure_reason="invalid_payload",
            )
        return base.SpeedResult(
            True,
            mbps=base._mbps(size, elapsed),
            bytes_transferred=size,
            time_seconds=elapsed,
            http_code=http_code,
            url=url,
            expect_disabled=disable_expect,
            expected_bytes=expected_bytes,
            payload_valid=True,
        )
    except subprocess.TimeoutExpired as exc:
        return base.SpeedResult(
            False,
            error=str(exc),
            url=url,
            expect_disabled=disable_expect,
            expected_bytes=expected_bytes,
            failure_reason="process_timeout",
        )
    except (OSError, ValueError) as exc:
        return base.SpeedResult(
            False,
            error=str(exc),
            url=url,
            expect_disabled=disable_expect,
            expected_bytes=expected_bytes,
            failure_reason="probe_error",
        )


def _upload_stream_with_retries(
    socks_url: str,
    *,
    url: str,
    payload_path: Path,
    expected_bytes: int,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None,
) -> base.SpeedResult:
    attempts: list[dict] = []
    result = _upload_via_socks(
        socks_url,
        url=url,
        payload_path=payload_path,
        expected_bytes=expected_bytes,
        timeout=timeout,
        curl_command=curl_command,
        connect_timeout=connect_timeout,
        disable_expect=False,
    )
    attempts.append(base._attempt_dict(result))

    if base._is_incomplete_upload_after_continue(result):
        result = _upload_via_socks(
            socks_url,
            url=url,
            payload_path=payload_path,
            expected_bytes=expected_bytes,
            timeout=timeout,
            curl_command=curl_command,
            connect_timeout=connect_timeout,
            disable_expect=True,
        )
        attempts.append(base._attempt_dict(result))
    elif base._is_transient_upload_failure(result) and not _result_is_timeout(result):
        result = _upload_via_socks(
            socks_url,
            url=url,
            payload_path=payload_path,
            expected_bytes=expected_bytes,
            timeout=timeout,
            curl_command=curl_command,
            connect_timeout=connect_timeout,
            disable_expect=result.expect_disabled,
        )
        attempts.append(base._attempt_dict(result))

    result.attempts = attempts
    return result


def _upload_parallel_stage(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    streams: int,
    total_bytes: int,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None,
) -> base.SpeedResult:
    sizes = base._split_sizes(total_bytes, streams)
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix="proxy-filter-upload-stage-") as tmpdir:
            payloads: list[Path] = []
            for index, size in enumerate(sizes):
                path = Path(tmpdir) / f"payload-{index}.bin"
                with path.open("wb") as fh:
                    fh.truncate(size)
                payloads.append(path)

            session = engine.start(proxy)
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=streams) as pool:
                futures = [
                    pool.submit(
                        _upload_stream_with_retries,
                        session.socks_url,
                        url=url,
                        payload_path=path,
                        expected_bytes=size,
                        timeout=timeout,
                        curl_command=curl_command,
                        connect_timeout=connect_timeout,
                    )
                    for path, size in zip(payloads, sizes)
                ]
                stream_results = [future.result() for future in futures]
            elapsed = time.monotonic() - started
    except (EngineError, OSError, ValueError) as exc:
        return base.SpeedResult(
            False,
            error=str(exc),
            url=url,
            backend="upload",
            failure_reason="probe_error",
        )
    finally:
        if session is not None:
            engine.stop(session)

    total_transferred = sum(result.bytes_transferred or 0 for result in stream_results)
    all_ok = all(result.ok for result in stream_results)
    failures = [result for result in stream_results if not result.ok]
    first_failure = failures[0] if failures else None
    aggregate = (
        base._mbps(total_transferred, elapsed)
        if total_transferred > 0 and elapsed > 0
        else None
    )
    http_codes = {result.http_code for result in stream_results if result.http_code is not None}
    payload_valid = all(result.payload_valid is not False for result in stream_results)

    return base.SpeedResult(
        all_ok,
        mbps=aggregate,
        bytes_transferred=total_transferred,
        time_seconds=elapsed,
        http_code=(
            next(iter(http_codes))
            if all_ok and len(http_codes) == 1
            else (first_failure.http_code if first_failure else None)
        ),
        error=None if all_ok else (first_failure.error if first_failure else "parallel upload failed"),
        url=url,
        expected_bytes=total_bytes,
        payload_valid=payload_valid,
        attempts=[base._attempt_dict(result) for result in stream_results],
        backend="upload",
        failure_reason=first_failure.failure_reason if first_failure else None,
        curl_exit_code=first_failure.curl_exit_code if first_failure else None,
    )


def _upload_stage_record(streams: int, result: base.SpeedResult, *, skipped: bool = False) -> dict:
    record = base._stage_record(streams, result, skipped=skipped)
    record["backend"] = "upload"
    return record


def _run_upload_backend(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    stream_stages: tuple[int, ...],
    total_bytes: int,
    min_stream_bytes: int,
    timeout: float,
    curl_command: str,
    connect_timeout: float | None,
) -> _BackendOutcome:
    stage_records: list[dict] = []
    best: base.SpeedResult | None = None
    last: base.SpeedResult | None = None
    terminal: base.SpeedResult | None = None

    for streams in stream_stages:
        if total_bytes // streams < min_stream_bytes:
            skipped = base.SpeedResult(
                False,
                error=(
                    f"stage skipped: {total_bytes // streams} bytes/stream is below "
                    f"upload_min_stream_bytes={min_stream_bytes}"
                ),
                url=url,
                expected_bytes=total_bytes,
                backend="upload",
            )
            stage_records.append(_upload_stage_record(streams, skipped, skipped=True))
            continue

        result = _upload_parallel_stage(
            proxy,
            engine,
            url=url,
            streams=streams,
            total_bytes=total_bytes,
            timeout=timeout,
            curl_command=curl_command,
            connect_timeout=connect_timeout,
        )
        last = result
        stage_records.append(_upload_stage_record(streams, result))

        if result.ok:
            best = _pick_faster(best, result)
            continue
        if _result_is_timeout(result):
            continue
        terminal = result
        break

    if best is not None:
        best.stages = list(stage_records)
        chosen = best
    elif last is not None:
        last.stages = list(stage_records)
        chosen = last
    else:
        chosen = base.SpeedResult(
            False,
            error="all upload stages were skipped",
            url=url,
            expected_bytes=total_bytes,
            backend="upload",
            stages=list(stage_records),
        )
    return _BackendOutcome(chosen, best, terminal, stage_records)


def _upload_staged(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    upload_bytes: int,
    timeout: float,
    curl_command: str,
    stream_stages: tuple[int, ...] = DEFAULT_UPLOAD_STREAM_STAGES,
    min_stream_bytes: int = DEFAULT_UPLOAD_MIN_STREAM_BYTES,
    connect_timeout: float | None = None,
    fallback_urls: list[str] | None = None,
) -> base.SpeedResult:
    stages = base._normalize_download_stream_stages(stream_stages)
    if upload_bytes <= 0:
        raise ValueError("speed.upload_bytes must be greater than zero")
    if min_stream_bytes <= 0:
        raise ValueError("speed.upload_min_stream_bytes must be greater than zero")
    connect_timeout = base._resolved_connect_timeout(timeout, connect_timeout)

    primary = _run_upload_backend(
        proxy,
        engine,
        url=url,
        stream_stages=stages,
        total_bytes=upload_bytes,
        min_stream_bytes=min_stream_bytes,
        timeout=timeout,
        curl_command=curl_command,
        connect_timeout=connect_timeout,
    )
    all_stages = list(primary.stages)
    best_overall = primary.best_success

    if primary.terminal_failure is None or not fallback_urls:
        primary.result.stages = all_stages
        return primary.result

    last = primary.result
    for fallback_url in fallback_urls:
        fallback = _run_upload_backend(
            proxy,
            engine,
            url=fallback_url,
            stream_stages=stages,
            total_bytes=upload_bytes,
            min_stream_bytes=min_stream_bytes,
            timeout=timeout,
            curl_command=curl_command,
            connect_timeout=connect_timeout,
        )
        all_stages.extend(fallback.stages)
        best_overall = _pick_faster(best_overall, fallback.best_success)
        last = fallback.result
        if fallback.terminal_failure is None:
            chosen = best_overall or fallback.result
            chosen.stages = list(all_stages)
            return chosen

    chosen = best_overall or last
    chosen.stages = list(all_stages)
    return chosen


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
    min_stream_bytes: int = base.DEFAULT_DOWNLOAD_MIN_STREAM_BYTES,
    connect_timeout: float | None = base.DEFAULT_SPEED_CONNECT_TIMEOUT,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("speed.download_url is required")
    if min_stream_bytes <= 0:
        raise ValueError("speed.download_min_stream_bytes must be greater than zero")
    connect_timeout = base._resolved_connect_timeout(timeout, connect_timeout)
    max_time = base._max_operation_time(timeout, connect_timeout)
    clean_fallbacks = [item for item in (fallback_urls or []) if item and item != url]
    retry_codes = set(fallback_http_codes or {429})
    normalized_stages = base._normalize_download_stream_stages(stream_stages)

    def probe(proxy: ProxyConfig) -> base.SpeedResult:
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
    for proxy, result in base._run_many(proxies, workers, probe, "download"):
        proxy.tests.download_mbps = result.mbps
        threshold_ok = result.ok and result.mbps is not None and result.mbps >= min_mbps
        timed_out_by_speed = not result.ok and _final_backend_timed_out(result)
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
        partial_mbps, partial_streams, partial_backend = _best_partial(result.stages)
        proxy.tests.download = {
            "status": "pass" if threshold_ok else "fail",
            "backend": result.backend,
            "mbps": result.mbps,
            "single_mbps": single_stage.get("mbps") if single_stage else None,
            "aggregate_mbps": result.mbps,
            "best_partial_mbps": partial_mbps,
            "best_partial_streams": partial_streams,
            "best_partial_backend": partial_backend,
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
        if not result.ok and not timed_out_by_speed:
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
    connect_timeout: float | None = base.DEFAULT_SPEED_CONNECT_TIMEOUT,
    stream_stages=None,
    min_stream_bytes: int = DEFAULT_UPLOAD_MIN_STREAM_BYTES,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    del fallback_http_codes
    if not url:
        raise ValueError("speed.upload_url is required")
    if upload_bytes <= 0:
        raise ValueError("speed.upload_bytes must be greater than zero")
    connect_timeout = base._resolved_connect_timeout(timeout, connect_timeout)
    max_time = base._max_operation_time(timeout, connect_timeout)
    normalized_stages = base._normalize_download_stream_stages(
        DEFAULT_UPLOAD_STREAM_STAGES if stream_stages is None else stream_stages
    )
    clean_fallbacks = [item for item in (fallback_urls or []) if item and item != url]

    def probe(proxy: ProxyConfig) -> base.SpeedResult:
        return _upload_staged(
            proxy,
            engine,
            url=url,
            upload_bytes=upload_bytes,
            timeout=timeout,
            curl_command=curl_command,
            stream_stages=normalized_stages,
            min_stream_bytes=min_stream_bytes,
            connect_timeout=connect_timeout,
            fallback_urls=clean_fallbacks,
        )

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    for proxy, result in base._run_many(proxies, workers, probe, "upload"):
        proxy.tests.upload_mbps = result.mbps
        threshold_ok = result.ok and result.mbps is not None and result.mbps >= min_mbps
        timed_out_by_speed = not result.ok and _final_backend_timed_out(result)
        single_stage = next(
            (
                stage
                for stage in result.stages
                if stage.get("streams") == 1 and stage.get("ok")
            ),
            None,
        )
        partial_mbps, partial_streams, _ = _best_partial(result.stages)
        proxy.tests.upload = {
            "status": "pass" if threshold_ok else "fail",
            "mbps": result.mbps,
            "single_mbps": single_stage.get("mbps") if single_stage else None,
            "aggregate_mbps": result.mbps,
            "best_partial_mbps": partial_mbps,
            "best_partial_streams": partial_streams,
            "stream_stages": list(normalized_stages),
            "min_stream_bytes": min_stream_bytes,
            "connect_timeout_seconds": connect_timeout,
            "transfer_timeout_seconds": timeout,
            "max_time_seconds": max_time,
            "stall_limit_bps": base.DEFAULT_SPEED_STALL_LIMIT_BPS,
            "stall_time_seconds": base.DEFAULT_SPEED_STALL_TIME_SECONDS,
            "bytes": result.bytes_transferred,
            "expected_bytes": result.expected_bytes,
            "payload_valid": result.payload_valid,
            "time_seconds": result.time_seconds,
            "http_code": result.http_code,
            "error": result.error,
            "failure_reason": result.failure_reason,
            "curl_exit_code": result.curl_exit_code,
            "url": result.url,
            "attempts": result.attempts,
            "stages": result.stages,
            "method": "curl-socks5h-staged-parallel",
        }
        if not result.ok and not timed_out_by_speed:
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