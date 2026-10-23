from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import sys
import unittest

import yaml

import proxy_filter


class LauncherTests(unittest.TestCase):
    def _write_yaml(self, path: Path, data) -> None:
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    def test_external_sources_are_merged_before_cli(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            sources_path = root / "sources.yaml"
            self._write_yaml(config_path, {"paths": {"data_dir": "/tmp/data"}})
            self._write_yaml(sources_path, {
                "sources": [{"id": "barry", "url": "https://example.com/sub"}]
            })

            captured = {}

            def fake_main():
                self.assertEqual(sys.argv[1], "--config")
                merged_path = Path(sys.argv[2])
                captured["merged_path"] = merged_path
                captured["exists_during_call"] = merged_path.exists()
                captured["config"] = yaml.safe_load(merged_path.read_text(encoding="utf-8"))
                self.assertEqual(sys.argv[3:], ["--until", "publish"])
                return 17

            argv = [
                "proxy_filter.py",
                "--config", str(config_path),
                "--sources", str(sources_path),
                "--until", "publish",
            ]
            with patch.object(sys, "argv", argv), patch.object(proxy_filter.cli, "main", side_effect=fake_main):
                result = proxy_filter.main()

            self.assertEqual(result, 17)
            self.assertTrue(captured["exists_during_call"])
            self.assertEqual(captured["config"]["sources"][0]["id"], "barry")
            self.assertFalse(captured["merged_path"].exists())

    def test_without_sources_uses_legacy_config_path(self):
        argv = ["proxy_filter.py", "--config", "/tmp/config.yaml", "--until", "tcp"]
        with patch.object(sys, "argv", argv), patch.object(proxy_filter.cli, "main", return_value=9) as mocked:
            result = proxy_filter.main()
        self.assertEqual(result, 9)
        mocked.assert_called_once_with()
        self.assertEqual(sys.argv, argv)


if __name__ == "__main__":
    unittest.main()
