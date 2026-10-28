from __future__ import annotations

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed_staged


_MEASUREMENT_HTTP_CODES = {None, 0, 200, 201, 202, 204, 206}


def _is_plain_timeout(error: str | None) -> bool:
    if not error:
        return False
    text = error.lower()
    if "operation too slow" in text or ("less than" in text and "bytes/sec" in text):
        return False
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


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

    # Only a normal max-time timeout may use a partial speed measurement.
    # Low-speed aborts (stalls) and all other curl/transport failures remain
    # technical errors even if curl reported bytes/time and therefore Mbps.
    return _is_plain_timeout(str(error))


def check_upload_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Apply the agreed partial-timeout speed policy to staged upload results."""
    min_mbps = float(kwargs["min_mbps"])
    passed, rejected = speed_staged.check_upload_many(proxies, engine, **kwargs)

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
    return passed, still_rejected
