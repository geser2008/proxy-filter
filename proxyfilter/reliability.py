from __future__ import annotations

from .model import ProxyConfig


STABLE = "stable"
DEGRADED = "degraded"


def _is_timeout(error: str | None) -> bool:
    if not error:
        return False
    text = error.lower()
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def analyze_stream_reliability(stages: list[dict] | None) -> dict:
    """Summarize instability without deciding whether the speed test passes.

    Reliability is diagnostic metadata. Pass/fail remains controlled by the
    measured speed and the configured speed threshold.
    """
    mixed_stages: list[dict] = []
    total_streams = 0
    successful_streams = 0
    failed_streams = 0
    reasons_seen: set[str] = set()

    for stage in stages or []:
        streams = int(stage.get("streams") or 0)
        if streams <= 1 or stage.get("skipped"):
            continue

        results = list(stage.get("stream_results") or [])
        if not results:
            continue

        ok = [item for item in results if item.get("ok")]
        failed = [item for item in results if not item.get("ok")]
        total_streams += len(results)
        successful_streams += len(ok)
        failed_streams += len(failed)

        failure_timeouts = [item for item in failed if _is_timeout(item.get("error"))]
        failure_non_timeouts = [item for item in failed if not _is_timeout(item.get("error"))]
        transferred = sum(int(item.get("bytes") or 0) for item in results)

        reasons: list[str] = []
        if ok and failed:
            reasons.append("mixed_success_failure")
            reasons_seen.add("transport")
        if failure_timeouts and failure_non_timeouts and transferred > 0:
            reasons.append("mixed_timeout_transport")
            reasons_seen.add("transport")

        if reasons:
            mixed_stages.append(
                {
                    "backend": stage.get("backend"),
                    "streams": streams,
                    "successful_streams": len(ok),
                    "failed_streams": len(failed),
                    "bytes": transferred,
                    "classification": stage.get("classification"),
                    "reasons": reasons,
                }
            )

    degraded = bool(mixed_stages)
    reason = "+".join(sorted(reasons_seen)) if reasons_seen else None
    return {
        "status": DEGRADED if degraded else STABLE,
        "reason": reason,
        "degraded": degraded,
        "mixed_stage_count": len(mixed_stages),
        "successful_streams": successful_streams,
        "failed_streams": failed_streams,
        "total_streams": total_streams,
        "mixed_stages": mixed_stages,
    }


def annotate_download_reliability(proxy: ProxyConfig) -> dict:
    download = proxy.tests.download or {}
    reliability = analyze_stream_reliability(download.get("stages") or [])

    # Preserve the legacy download-level fields used by render/output policy.
    download["stream_reliability"] = reliability["status"]
    download["stream_reliability_details"] = reliability
    proxy.tests.download = download

    # Also expose reliability as its own test dimension. It is deliberately not
    # used to rewrite download/upload pass/fail results.
    proxy.tests.reliability = {
        "status": reliability["status"],
        "reason": reliability["reason"],
        "details": reliability,
    }
    return reliability


def is_unreliable(proxy: ProxyConfig) -> bool:
    status = (proxy.tests.reliability or {}).get("status")
    if status in {STABLE, DEGRADED}:
        return status == DEGRADED

    download = proxy.tests.download or {}
    legacy_status = download.get("stream_reliability")
    if legacy_status is None:
        legacy_status = annotate_download_reliability(proxy)["status"]
    return legacy_status == DEGRADED