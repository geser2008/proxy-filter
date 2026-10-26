from __future__ import annotations

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed_reliability, speed_staged


def _normalize_threshold_outcomes(
    passed: list[ProxyConfig],
    rejected: list[ProxyConfig],
    *,
    direction: str,
    min_mbps: float,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Apply the final speed decision from the measured numeric value.

    The low-level speed stages intentionally keep transport/provider diagnostics.
    For filtering, a numeric measurement has priority for timeout-style incomplete
    tests that were already classified as threshold failures by the staged tester:
    - numeric speed below threshold -> threshold reject;
    - numeric speed at/above threshold -> pass;
    - no numeric speed -> error reject.

    Non-threshold technical failures (invalid payload, TLS/SOCKS/provider errors,
    etc.) remain errors even if they happen to carry incidental byte counters.
    """
    normalized_passed = list(passed)
    normalized_rejected: list[ProxyConfig] = []
    metric_attr = f"{direction}_mbps"
    threshold_status = f"rejected_{direction}_threshold"
    error_status = f"rejected_{direction}_error"
    pass_status = f"{direction}_pass"

    for proxy in rejected:
        if proxy.tests.status != threshold_status:
            normalized_rejected.append(proxy)
            continue

        mbps = getattr(proxy.tests, metric_attr)
        test = getattr(proxy.tests, direction)
        if mbps is None:
            proxy.tests.status = error_status
            test["status"] = "fail"
            normalized_rejected.append(proxy)
        elif mbps < min_mbps:
            proxy.tests.status = threshold_status
            test["status"] = "fail"
            normalized_rejected.append(proxy)
        else:
            proxy.tests.status = pass_status
            test["status"] = "pass"
            normalized_passed.append(proxy)

    normalized_passed.sort(
        key=lambda proxy: getattr(proxy.tests, metric_attr)
        if getattr(proxy.tests, metric_attr) is not None
        else -1,
        reverse=True,
    )
    return normalized_passed, normalized_rejected


def check_download_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed, rejected = speed_reliability.check_download_many(proxies, engine, **kwargs)
    return _normalize_threshold_outcomes(
        passed,
        rejected,
        direction="download",
        min_mbps=float(kwargs["min_mbps"]),
    )


def check_upload_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed, rejected = speed_staged.check_upload_many(proxies, engine, **kwargs)
    return _normalize_threshold_outcomes(
        passed,
        rejected,
        direction="upload",
        min_mbps=float(kwargs["min_mbps"]),
    )
