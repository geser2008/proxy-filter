from __future__ import annotations

from dataclasses import dataclass

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed as base


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
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def _stage_classification(result: base.SpeedResult) -> str:
    """Classify a failed multi-stream stage by what actually happened.

    A timeout with real data transfer is a performance result even when some
    sibling streams fail with transport errors. Provider-specific HTTP errors
    and invalid payloads are classified separately so they may use fallback.
    Pure zero-transfer transport failures remain technical errors.
    """
    if result.ok:
        return "success"

    attempts = result.attempts or []
    failures = [attempt for attempt in attempts if not attempt.get("ok")]
    transferred = result.bytes_transferred or 0

    if failures:
        timeout_with_transfer = any(
            _is_timeout_error(attempt.get("error"))
            and (attempt.get("bytes") or 0) > 0
            for attempt in failures
        )
        if timeout_with_transfer or (
            transferred > 0
            and any(_is_timeout_error(attempt.get("error")) for attempt in failures)
        ):
            return "performance_timeout"

        if any(attempt.get("payload_valid") is False for attempt in failures):
            return "provider_failure"

        http_codes = [attempt.get("http_code") for attempt in failures]
        if any(code not in {None, 0} for code in http_codes):
            return "provider_failure"

        return "transport_error"

    if _is_timeout_error(result.error) and transferred > 0:
        return "performance_timeout"
    if result.payload_valid is False:
        return "provider_failure"
    if result.http_code not in {None, 0}:
        return "provider_failure"
    return "transport_error"


def _fallback_allowed(result: base.SpeedResult, fallback_http_codes: set[int]) -> bool:
    """Allow backend fallback only for destination/provider-specific failures."""
    if result.payload_valid is False:
        return True

    codes: set[int] = set()
    if result.http_code not in {None, 0}:
        codes.add(int(result.http_code))
    for attempt in result.attempts or []:
        code = attempt.get("http_code")
        if code not in {None, 0}:
            codes.add(int(code))
        if attempt.get("payload_valid") is False:
            return True

    return any(
        code in fallback_http_codes or 500 <= code <= 599
        for code in codes
    )


def _stage_record(streams: int, result: base.SpeedResult, *, skipped: bool = False) -> dict:
    record = base._stage_record(streams, result, skipped=skipped)
    record["classification"] = "skipped" if skipped else _stage_classification(result)
    return record


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
            stage_records.append(_stage_record(streams, skipped, skipped=True))
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
        classification = _stage_classification(result)
        stage_records.append(_stage_record(streams, result))

        if result.ok:
            best = _pick_faster(best, result)
            continue

        if classification == "performance_timeout":
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

    if primary.terminal_failure is None:
        primary.result.stages = all_stages
        return primary.result

    failure = primary.terminal_failure
    if not fallback_urls or not _fallback_allowed(failure, fallback_http_codes):
        primary.result.stages = all_stages
        return primary.result

    reason = (
        "invalid_payload"
        if failure.payload_valid is False
        else f"http={failure.http_code}"
        if failure.http_code not in {None, 0}
        else "provider_failure"
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
        if not _fallback_allowed(failure, fallback_http_codes):
            break

        reason = (
            "invalid_payload"
            if failure.payload_valid is False
            else f"http={failure.http_code}"
            if failure.http_code not in {None, 0}
            else "provider_failure"
        )

    chosen = best_overall or last_result
    chosen.stages = list(all_stages)
    return chosen


def _final_backend_is_performance_timeout(result: base.SpeedResult) -> bool:
    stages = [
        stage
        for stage in result.stages
        if not stage.get("skipped") and stage.get("backend") == result.backend
    ]
    return bool(stages) and not any(stage.get("ok") for stage in stages) and all(
        stage.get("classification") == "performance_timeout" for stage in stages
    )


def _best_partial(stages: list[dict]) -> tuple[float | None, int | None, str | None]:
    candidates = [
        stage
        for stage in stages
        if not stage.get("skipped")
        and not stage.get("ok")
        and stage.get("classification") == "performance_timeout"
        and stage.get("mbps") is not None
    ]
    if not candidates:
        return None, None, None
    best = max(candidates, key=lambda stage: float(stage["mbps"]))
    return float(best["mbps"]), int(best["streams"]), best.get("backend")


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
    retry_codes = set(fallback_http_codes or {403, 429})
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
        performance_timeout = not result.ok and _final_backend_is_performance_timeout(result)
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

        if not result.ok and not performance_timeout:
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
