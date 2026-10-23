import unittest

from proxy_filter import deduplicate
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.render import format_output_name


class ProvenanceTests(unittest.TestCase):
    @staticmethod
    def _proxy(source_id: str) -> ProxyConfig:
        return ProxyConfig(
            SourceInfo(source_id, f"Source {source_id}", "plain"),
            "ss",
            "203.0.113.50",
            8388,
            "old",
            {"method": "aes-256-gcm", "password": "secret"},
        )

    def test_cross_source_dedup_merges_all_provenance(self):
        merged, duplicates = deduplicate([
            self._proxy("radikal"),
            self._proxy("delta"),
            self._proxy("third"),
        ])

        self.assertEqual(len(merged), 1)
        self.assertEqual(len(duplicates), 2)
        self.assertEqual(
            [source.id for source in merged[0].provenance_sources()],
            ["radikal", "delta", "third"],
        )

        name = format_output_name(
            merged[0],
            template="[{sources}] {source_count} {source}",
            include_original_name=False,
        )
        self.assertEqual(name, "[radikal+delta+third] 3 radikal")

    def test_provenance_survives_jsonl_round_trip(self):
        proxy = self._proxy("radikal")
        proxy.merge_sources_from(self._proxy("delta"))
        restored = ProxyConfig.from_dict(proxy.to_dict())

        self.assertEqual(
            [source.id for source in restored.provenance_sources()],
            ["radikal", "delta"],
        )

    def test_legacy_record_without_sources_keeps_primary_source(self):
        proxy = self._proxy("radikal")
        data = proxy.to_dict()
        data.pop("sources", None)
        restored = ProxyConfig.from_dict(data)

        self.assertEqual(
            [source.id for source in restored.provenance_sources()],
            ["radikal"],
        )


if __name__ == "__main__":
    unittest.main()
