from __future__ import annotations

from collections.abc import Callable

from .model import ProxyConfig


class RunDeduplicator:
    """Deduplicate all source inputs against one canonical registry for one run.

    The normal per-source dedup call is therefore also a cross-source dedup
    point, before TCP/core/urltest/speed tests. A later final merge is safe:
    canonical objects already stored in the registry are kept when the exact
    same object is seen again.
    """

    def __init__(
        self,
        base_deduplicate: Callable[[list[ProxyConfig]], tuple[list[ProxyConfig], list[ProxyConfig]]],
    ) -> None:
        self.base_deduplicate = base_deduplicate
        self.registry: dict[str, ProxyConfig] = {}
        self.cross_source_duplicates: list[ProxyConfig] = []

    def __call__(self, proxies: list[ProxyConfig]):
        local_unique, local_duplicates = self.base_deduplicate(proxies)
        unique: list[ProxyConfig] = []
        duplicates = list(local_duplicates)

        for proxy in local_unique:
            proxy_id = proxy.ensure_id()
            canonical = self.registry.get(proxy_id)
            if canonical is None:
                self.registry[proxy_id] = proxy
                unique.append(proxy)
                continue

            if canonical is proxy:
                unique.append(proxy)
                continue

            canonical.merge_sources_from(proxy)
            proxy.tests.status = "rejected_duplicate"
            duplicates.append(proxy)
            self.cross_source_duplicates.append(proxy)

        return unique, duplicates
