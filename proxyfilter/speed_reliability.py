from __future__ import annotations

from .engine import EngineBackend
from .model import ProxyConfig
from . import speed_policy
from .reliability import annotate_download_reliability


def check_download_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    **kwargs,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed, rejected = speed_policy.check_download_many(proxies, engine, **kwargs)
    for proxy in [*passed, *rejected]:
        annotate_download_reliability(proxy)
    return passed, rejected
