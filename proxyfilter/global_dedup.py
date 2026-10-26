from __future__ import annotations

from collections.abc import Callable

from .model import ProxyConfig


class RunDeduplicator:
    """Stateful deduplicator used for the per-source ingest calls in one run.

    The first ``source_calls`` invocations correspond to per-source dedup stages.
    They share one canonical registry, so a proxy seen in a later source is not
    sent through network tests again. The following invocation is the existing
    final merge dedup and delegates to the original implementation.
    """

    def __init__(
        self,
        base_deduplicate: Callable[[list[ProxyConfig]], tuple[list[ProxyConfig], list[ProxyConfig]]],
        source_calls: int,
    ) -> None:
        self.base_deduplicate = base_deduplicate
        self.source_calls = max(0, int(source_calls))
        self.calls = 0
        self.registry: dict[str, ProxyConfig] = {}
        self.cross_source_duplicates: list[ProxyConfig] = []

    def __call__(self, proxies: list[ProxyConfig]):
        self.calls += 1
        if self.calls > self.source_calls:
            return self.base_deduplicate(proxies)

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

            canonical.merge_sources_from(proxy)
            proxy.tests.status = "rejected_duplicate"
            duplicates.append(proxy)
            self.cross_source_duplicates.append(proxy)

        return unique, duplicates
