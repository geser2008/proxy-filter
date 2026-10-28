from __future__ import annotations

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed_policy
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


def check_download_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed, rejected = speed_policy.check_download_many(proxies, engine, **kwargs)

    # speed_policy deliberately lets timeout measurements participate in the
    # speed threshold. Do not extend that rule to stalls or other transport
    # failures merely because they happened to produce a partial Mbps value.
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

    for proxy in [*corrected_passed, *corrected_rejected]:
        annotate_download_reliability(proxy)
    return corrected_passed, corrected_rejected
