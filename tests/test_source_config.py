from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import yaml

from proxyfilter.source_config import load_sources_file, merged_config


class SourceConfigTests(unittest.TestCase):
    def _write(self, root: Path, name: str, data) -> Path:
        path = root / name
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        return path

    def test_load_sources_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write(root, "sources.yaml", {
                "sources": [
                    {"id": "a", "name": "A", "url": "https://example.com/a"},
                    {"id": "b", "name": "B", "url": "https://example.com/b"},
                ]
            })
            sources = load_sources_file(path)
            self.assertEqual([item["id"] for item in sources], ["a", "b"])

    def test_duplicate_source_id_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write(root, "sources.yaml", {
                "sources": [
                    {"id": "dup", "url": "https://example.com/a"},
                    {"id": "dup", "url": "https://example.com/b"},
                ]
            })
            with self.assertRaisesRegex(ValueError, "duplicate source id"):
                load_sources_file(path)

    def test_missing_url_is_rejected(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = self._write(root, "sources.yaml", {
                "sources": [{"id": "a"}]
            })
            with self.assertRaisesRegex(ValueError, "missing url"):
                load_sources_file(path)

    def test_external_sources_override_embedded_sources(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self._write(root, "config.yaml", {
                "paths": {"data_dir": "/tmp/data"},
                "sources": [{"id": "old", "url": "https://example.com/old"}],
            })
            sources_path = self._write(root, "sources.yaml", {
                "sources": [{"id": "new", "url": "https://example.com/new"}],
            })
            cfg = merged_config(config_path, sources_path)
            self.assertEqual(cfg["paths"]["data_dir"], "/tmp/data")
            self.assertEqual([item["id"] for item in cfg["sources"]], ["new"])


if __name__ == "__main__":
    unittest.main()
