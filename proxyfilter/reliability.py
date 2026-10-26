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
    """Summarize instability visible inside multi-stream download stages.

    A proxy is marked degraded only when a multi-stream stage shows inconsistent
    per-stream behavior: some streams succeed while siblings fail, or failures
    mix timeout and non-timeout transport outcomes while data was transferred.
    A uniformly slow stage where every stream simply times out is not, by itself,
    considered a reliability failure.
    """
    mixed_stages: list[dict] = []
    total_streams = 0
    successful_streams = 0
    failed_streams = 0

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
        if failure_timeouts and failure_non_timeouts and transferred > 0:
            reasons.append("mixed_timeout_transport")

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
    return {
        "status": DEGRADED if degraded else STABLE,
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
    download["stream_reliability"] = reliability["status"]
    download["stream_reliability_details"] = reliability
    proxy.tests.download = download
    return reliability


def is_unreliable(proxy: ProxyConfig) -> bool:
    download = proxy.tests.download or {}
    status = download.get("stream_reliability")
    if status is None:
        status = annotate_download_reliability(proxy)["status"]
    return status == DEGRADED
