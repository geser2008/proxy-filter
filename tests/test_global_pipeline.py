from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from proxyfilter.cli import _load_previous_working, deduplicate
from proxyfilter.io import write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo


class GlobalPipelineTests(unittest.TestCase):
    def _proxy(self, source_id: str, *, server: str = "example.com") -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo(source_id, source_id, "plain"),
            "vless",
            server,
            443,
            source_id,
            {"uuid": "00000000-0000-0000-0000-000000000001", "security": "tls"},
            "vless-uri",
            "",
        )
        proxy.ensure_id()
        return proxy

    def test_cross_source_dedup_merges_provenance(self) -> None:
        radikal = self._proxy("radikal")
        delta = self._proxy("delta")

        unique, duplicates = deduplicate([radikal, delta])

        self.assertEqual(len(unique), 1)
        self.assertEqual(len(duplicates), 1)
        self.assertEqual({source.id for source in unique[0].sources}, {"radikal", "delta"})

    def test_previous_working_is_filtered_for_source_selection(self) -> None:
        radikal = self._proxy("radikal", server="one.example")
        delta = self._proxy("delta", server="two.example")
        shared_a = self._proxy("radikal", server="shared.example")
        shared_b = self._proxy("delta", server="shared.example")
        shared, _ = deduplicate([shared_a, shared_b])

        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            write_jsonl(data_dir / "state" / "working.jsonl", [radikal, delta, shared[0]])

            selected, _ = _load_previous_working(data_dir, {"radikal"})
            selected_ids = {proxy.id for proxy in selected}

        self.assertIn(radikal.id, selected_ids)
        self.assertIn(shared[0].id, selected_ids)
        self.assertNotIn(delta.id, selected_ids)


if __name__ == "__main__":
    unittest.main()
