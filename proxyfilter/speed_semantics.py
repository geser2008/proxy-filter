from __future__ import annotations

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed_staged
from .payload_semantics import normalize_payload_valid


_MEASUREMENT_HTTP_CODES = {None, 0, 200, 201, 202, 204, 206}


def _is_plain_timeout(error: str | None) -> bool:
    if not error:
        return False
    text = error.lower()
    if "operation too slow" in text or ("less than" in text and "bytes/sec" in text):
        return False
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def _stage_is_plain_timeout(stage: dict) -> bool:
    reason = stage.get("failure_reason")
    if reason is not None:
        return reason == "timeout"
    return _is_plain_timeout(stage.get("error"))


def _best_partial_timeout_stage(upload: dict) -> dict | None:
    candidates = [
        stage
        for stage in upload.get("stages") or []
        if not stage.get("skipped")
        and not stage.get("ok")
        and stage.get("mbps") is not None
        and _stage_is_plain_timeout(stage)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda stage: float(stage["mbps"]))


def _best_success_stage(upload: dict) -> dict | None:
    candidates = [
        stage
        for stage in upload.get("stages") or []
        if not stage.get("skipped")
        and stage.get("ok")
        and stage.get("mbps") is not None
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda stage: float(stage["mbps"]))


def _set_selected_success_stage(proxy: ProxyConfig) -> None:
    upload = proxy.tests.upload or {}
    best = _best_success_stage(upload)
    if best is None:
        return
    upload["selected_streams"] = best.get("streams")
    proxy.tests.upload = upload


def _apply_best_partial_timeout(proxy: ProxyConfig) -> None:
    """Use the fastest valid partial-timeout stage when no upload stage completed."""
    upload = proxy.tests.upload or {}
    if any(
        stage.get("ok")
        for stage in upload.get("stages") or []
        if not stage.get("skipped")
    ):
        return

    best = _best_partial_timeout_stage(upload)
    if best is None:
        return

    mbps = float(best["mbps"])
    proxy.tests.upload_mbps = mbps
    upload["mbps"] = mbps
    upload["aggregate_mbps"] = mbps
    upload["best_partial_mbps"] = mbps
    upload["best_partial_streams"] = best.get("streams")
    upload["selected_streams"] = best.get("streams")
    upload["bytes"] = best.get("bytes")
    upload["expected_bytes"] = best.get("expected_bytes")
    upload["payload_valid"] = best.get("payload_valid")
    upload["time_seconds"] = best.get("time_seconds")
    upload["http_code"] = best.get("http_code")
    upload["error"] = best.get("error")
    upload["failure_reason"] = best.get("failure_reason")
    upload["curl_exit_code"] = best.get("curl_exit_code")
    proxy.tests.upload = upload


def _has_usable_upload_measurement(proxy: ProxyConfig) -> bool:
    upload = proxy.tests.upload or {}
    mbps = proxy.tests.upload_mbps
    if mbps is None:
        return False
    if upload.get("payload_valid") is False:
        return False
    return upload.get("http_code") in _MEASUREMENT_HTTP_CODES


def _is_threshold_eligible_upload(proxy: ProxyConfig) -> bool:
    if not _has_usable_upload_measurement(proxy):
        return False

    upload = proxy.tests.upload or {}
    error = upload.get("error")
    if not error:
        return True

    # Structured failure_reason is authoritative for new probe results.
    # Only a normal max-time timeout may use a partial speed measurement.
    reason = upload.get("failure_reason")
    if reason is not None:
        return reason == "timeout"

    # Backward compatibility for old snapshots/results without failure_reason.
    return _is_plain_timeout(str(error))


def check_upload_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Apply the agreed partial-timeout speed policy to staged upload results."""
    min_mbps = float(kwargs["min_mbps"])
    passed, rejected = speed_staged.check_upload_many(proxies, engine, **kwargs)

    # Record which completed stage supplied the selected aggregate rate. This is
    # diagnostic metadata only and does not change acceptance.
    for proxy in [*passed, *rejected]:
        _set_selected_success_stage(proxy)

    # speed_staged historically returned the last configured timeout stage when
    # every stage timed out. With configurable stages such as [1, 8], the last
    # stage is not necessarily the best measurement. Re-select the fastest
    # threshold-eligible partial timeout before making the final decision.
    for proxy in rejected:
        _apply_best_partial_timeout(proxy)

    still_rejected: list[ProxyConfig] = []
    for proxy in rejected:
        if not _is_threshold_eligible_upload(proxy):
            proxy.tests.status = "rejected_upload_error"
            proxy.tests.upload["status"] = "fail"
            still_rejected.append(proxy)
            continue

        mbps = float(proxy.tests.upload_mbps)
        if mbps < min_mbps:
            proxy.tests.status = "rejected_upload_threshold"
            proxy.tests.upload["status"] = "fail"
            still_rejected.append(proxy)
            continue

        proxy.tests.status = "upload_pass"
        proxy.tests.upload["status"] = "pass"
        passed.append(proxy)

    passed.sort(
        key=lambda proxy: proxy.tests.upload_mbps
        if proxy.tests.upload_mbps is not None
        else -1,
        reverse=True,
    )

    # Keep acceptance policy independent from diagnostic tri-state cleanup.
    # Normalize both the chosen aggregate and every stage so partial transfers
    # never appear payload-complete merely because no stream explicitly proved
    # an invalid payload.
    for proxy in [*passed, *still_rejected]:
        normalize_payload_valid(proxy.tests.upload)
        for stage in (proxy.tests.upload or {}).get("stages") or []:
            normalize_payload_valid(stage)

    return passed, still_rejected
