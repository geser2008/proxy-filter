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

    def test_deduplicate_remains_importable_from_launcher(self):
        self.assertIs(proxy_filter.deduplicate, proxy_filter.cli.deduplicate)

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

    def test_source_is_not_abbreviated_as_sources(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            sources_path = root / "sources.yaml"
            self._write_yaml(config_path, {"paths": {"data_dir": "/tmp/data"}})
            self._write_yaml(sources_path, {
                "sources": [{"id": "barry", "url": "https://example.com/sub"}]
            })

            def fake_main():
                self.assertEqual(sys.argv[1], "--config")
                self.assertEqual(sys.argv[3:], ["--source", "barry", "--until", "publish"])
                return 23

            argv = [
                "proxy_filter.py",
                "--config", str(config_path),
                "--sources", str(sources_path),
                "--source", "barry",
                "--until", "publish",
            ]
            with patch.object(sys, "argv", argv), patch.object(proxy_filter.cli, "main", side_effect=fake_main):
                result = proxy_filter.main()

            self.assertEqual(result, 23)

    def test_config_only_uses_default_sources_file(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.yaml"
            self._write_yaml(config_path, {"paths": {"data_dir": "/tmp/data"}})

            captured = {}

            def fake_merged(config, sources):
                captured["config"] = config
                captured["sources"] = sources
                return {"sources": []}

            argv = ["proxy_filter.py", "--config", str(config_path), "--until", "tcp"]
            with (
                patch.object(sys, "argv", argv),
                patch.object(proxy_filter, "merged_config", side_effect=fake_merged),
                patch.object(proxy_filter.yaml, "safe_dump"),
                patch.object(proxy_filter.cli, "main", return_value=9) as mocked,
            ):
                result = proxy_filter.main()

            self.assertEqual(result, 9)
            self.assertEqual(captured["config"], config_path)
            self.assertEqual(captured["sources"], Path(proxy_filter.DEFAULT_SOURCES_PATH))
            mocked.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
