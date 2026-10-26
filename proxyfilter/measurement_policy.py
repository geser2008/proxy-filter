from __future__ import annotations

from .model import ProxyConfig
from . import speed as base


def _apply_numeric_policy(
    passed: list[ProxyConfig],
    rejected: list[ProxyConfig],
    *,
    metric_attr: str,
    record_attr: str,
    min_mbps: float,
    pass_status: str,
    threshold_status: str,
    error_status: str,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    final_passed = list(passed)
    final_rejected: list[ProxyConfig] = []

    for proxy in rejected:
        mbps = getattr(proxy.tests, metric_attr)
        record = getattr(proxy.tests, record_attr)

        if mbps is None:
            proxy.tests.status = error_status
            final_rejected.append(proxy)
            continue

        if mbps >= min_mbps:
            record["status"] = "pass"
            proxy.tests.status = pass_status
            final_passed.append(proxy)
        else:
            record["status"] = "fail"
            proxy.tests.status = threshold_status
            final_rejected.append(proxy)

    final_passed.sort(
        key=lambda proxy: getattr(proxy.tests, metric_attr)
        if getattr(proxy.tests, metric_attr) is not None
        else -1,
        reverse=True,
    )
    return final_passed, final_rejected


def check_download_many(*args, min_mbps: float, **kwargs):
    passed, rejected = base.check_download_many(*args, min_mbps=min_mbps, **kwargs)
    return _apply_numeric_policy(
        passed,
        rejected,
        metric_attr="download_mbps",
        record_attr="download",
        min_mbps=min_mbps,
        pass_status="download_pass",
        threshold_status="rejected_download_threshold",
        error_status="rejected_download_error",
    )


def check_upload_many(*args, min_mbps: float, **kwargs):
    passed, rejected = base.check_upload_many(*args, min_mbps=min_mbps, **kwargs)
    return _apply_numeric_policy(
        passed,
        rejected,
        metric_attr="upload_mbps",
        record_attr="upload",
        min_mbps=min_mbps,
        pass_status="upload_pass",
        threshold_status="rejected_upload_threshold",
        error_status="rejected_upload_error",
    )
