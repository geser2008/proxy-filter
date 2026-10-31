from __future__ import annotations

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed_policy
from .payload_semantics import normalize_payload_valid
from .reliability import annotate_download_reliability


def _is_plain_timeout(error: str | None) -> bool:
    if not error:
        return False
    text = error.lower()
    if "operation too slow" in text or ("less than" in text and "bytes/sec" in text):
        return False
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def _is_technical_download_failure(proxy: ProxyConfig) -> bool:
    download = proxy.tests.download or {}
    if download.get("payload_valid") is False:
        return True

    error = download.get("error")
    if not error:
        return False

    return not _is_plain_timeout(str(error))


def _apply_final_download_policy(
    passed: list[ProxyConfig],
    rejected: list[ProxyConfig],
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Apply transport-error policy after the raw speed threshold decision."""
    corrected_passed: list[ProxyConfig] = []
    corrected_rejected = list(rejected)
    for proxy in passed:
        if _is_technical_download_failure(proxy):
            proxy.tests.status = "rejected_download_error"
            proxy.tests.download["status"] = "fail"
            corrected_rejected.append(proxy)
        else:
            corrected_passed.append(proxy)

    for proxy in corrected_rejected:
        if _is_technical_download_failure(proxy):
            proxy.tests.status = "rejected_download_error"
            proxy.tests.download["status"] = "fail"

    return corrected_passed, corrected_rejected


def _download_recovery_eligible(proxy: ProxyConfig) -> bool:
    """Retry once only after a technical download failure.

    Threshold failures are real measurements and are not recovery candidates.
    Explicit provider failures are handled by the configured fallback backend,
    not by this same-primary retry.
    """
    if proxy.tests.status != "rejected_download_error":
        return False

    download = proxy.tests.download or {}
    if download.get("payload_valid") is False:
        return False

    stages = [stage for stage in download.get("stages") or [] if not stage.get("skipped")]
    if stages:
        return stages[-1].get("classification") == "transport_error"

    # Compatibility for synthetic/legacy records without stage diagnostics.
    return bool(download.get("error"))


def _set_recovery_metadata(
    proxy: ProxyConfig,
    *,
    enabled: bool,
    attempted: bool = False,
    recovered: bool = False,
    initial: dict | None = None,
) -> None:
    download = proxy.tests.download or {}
    download["recovery_enabled"] = bool(enabled)
    download["recovery_attempted"] = bool(attempted)
    download["recovered"] = bool(recovered)
    if initial is not None:
        download["recovery_initial_backend"] = initial.get("backend")
        download["recovery_initial_mbps"] = initial.get("mbps")
        download["recovery_initial_failure_reason"] = initial.get("failure_reason")
        download["recovery_initial_error"] = initial.get("error")
    proxy.tests.download = download


def check_download_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    recovery_enabled = bool(kwargs.pop("recovery_enabled", False))

    passed, rejected = speed_policy.check_download_many(proxies, engine, **kwargs)
    passed, rejected = _apply_final_download_policy(passed, rejected)

    for proxy in [*passed, *rejected]:
        _set_recovery_metadata(proxy, enabled=recovery_enabled)

    if recovery_enabled:
        recovery_candidates = [proxy for proxy in rejected if _download_recovery_eligible(proxy)]
        if recovery_candidates:
            initial_by_id = {
                proxy.ensure_id(): dict(proxy.tests.download or {})
                for proxy in recovery_candidates
            }
            print(f"[download-recovery] candidates={len(recovery_candidates)} retry=1")

            retry_passed, retry_rejected = speed_policy.check_download_many(
                recovery_candidates,
                engine,
                **kwargs,
            )
            retry_passed, retry_rejected = _apply_final_download_policy(retry_passed, retry_rejected)

            candidate_ids = {proxy.ensure_id() for proxy in recovery_candidates}
            rejected = [proxy for proxy in rejected if proxy.ensure_id() not in candidate_ids]
            passed.extend(retry_passed)
            rejected.extend(retry_rejected)

            for proxy in [*retry_passed, *retry_rejected]:
                initial = initial_by_id.get(proxy.ensure_id(), {})
                _set_recovery_metadata(
                    proxy,
                    enabled=True,
                    attempted=True,
                    recovered=proxy in retry_passed,
                    initial=initial,
                )

            print(
                f"[download-recovery] attempted={len(recovery_candidates)} "
                f"recovered={len(retry_passed)}"
            )

    # Normalize only after acceptance/error classification so this diagnostic
    # cleanup cannot change threshold or transport policy.
    for proxy in [*passed, *rejected]:
        normalize_payload_valid(proxy.tests.download)
        annotate_download_reliability(proxy)

    passed.sort(
        key=lambda proxy: proxy.tests.download_mbps
        if proxy.tests.download_mbps is not None
        else -1,
        reverse=True,
    )
    return passed, rejected
