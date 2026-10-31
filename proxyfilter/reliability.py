from __future__ import annotations

from .model import ProxyConfig


STABLE = "stable"
DEGRADED = "degraded"


def _is_timeout(error: str | None) -> bool:
    if not error:
        return False
    text = error.lower()
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def analyze_stream_reliability(
    stages: list[dict] | None,
    *,
    selected_backend: str | None = None,
) -> dict:
    """Summarize speed-test instability for the selected backend.

    Reliability is diagnostic metadata. Pass/fail remains controlled by the
    measured speed and the configured speed threshold. Provider attempts that
    were abandoned in favour of a fallback backend do not make the proxy itself
    unreliable.

    A proxy is degraded when either:
    - one multi-stream stage contains both successful and failed streams; or
    - executed stages of the selected backend have inconsistent outcomes, with
      at least one fully successful stage and at least one fully failed stage.
    """
    mixed_stages: list[dict] = []
    total_streams = 0
    successful_streams = 0
    failed_streams = 0
    successful_stage_count = 0
    failed_stage_count = 0
    ignored_stage_count = 0
    reasons_seen: set[str] = set()

    for stage in stages or []:
        stage_backend = stage.get("backend")
        if selected_backend and stage_backend and stage_backend != selected_backend:
            ignored_stage_count += 1
            continue
        if stage.get("skipped"):
            continue

        streams = int(stage.get("streams") or 0)
        results = list(stage.get("stream_results") or [])
        if not results:
            continue

        ok = [item for item in results if item.get("ok")]
        failed = [item for item in results if not item.get("ok")]

        # Stage-level consistency includes single-stream stages as well. A fully
        # successful stage followed by a fully failed stage (or vice versa) is a
        # sign that the proxy is not behaving consistently across measurements.
        if ok and not failed:
            successful_stage_count += 1
        elif failed and not ok:
            failed_stage_count += 1

        if streams <= 1:
            continue

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
                    "backend": stage_backend,
                    "streams": streams,
                    "successful_streams": len(ok),
                    "failed_streams": len(failed),
                    "bytes": transferred,
                    "classification": stage.get("classification"),
                    "reasons": reasons,
                }
            )

    mixed_stage_outcomes = successful_stage_count > 0 and failed_stage_count > 0
    if mixed_stage_outcomes:
        reasons_seen.add("stage_consistency")

    degraded = bool(mixed_stages) or mixed_stage_outcomes
    reason = "+".join(sorted(reasons_seen)) if reasons_seen else None
    return {
        "status": DEGRADED if degraded else STABLE,
        "reason": reason,
        "degraded": degraded,
        "selected_backend": selected_backend,
        "ignored_stage_count": ignored_stage_count,
        "mixed_stage_count": len(mixed_stages),
        "mixed_stage_outcomes": mixed_stage_outcomes,
        "successful_stage_count": successful_stage_count,
        "failed_stage_count": failed_stage_count,
        "successful_streams": successful_streams,
        "failed_streams": failed_streams,
        "total_streams": total_streams,
        "mixed_stages": mixed_stages,
    }


def annotate_download_reliability(proxy: ProxyConfig) -> dict:
    download = proxy.tests.download or {}
    stages = download.get("stages") or []
    selected_backend = download.get("backend")
    reliability = analyze_stream_reliability(
        stages,
        selected_backend=selected_backend,
    )

    attempted_backends = {
        stage.get("backend")
        for stage in stages
        if stage.get("backend") and not stage.get("skipped")
    }
    provider_fallback = bool(
        selected_backend
        and any(backend != selected_backend for backend in attempted_backends)
    )
    reliability["provider_fallback"] = provider_fallback

    # Preserve the legacy download-level fields used by render/output policy.
    download["stream_reliability"] = reliability["status"]
    download["stream_reliability_details"] = reliability
    download["provider_fallback"] = provider_fallback
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
