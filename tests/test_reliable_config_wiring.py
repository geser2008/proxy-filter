from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import patch

import yaml

from proxyfilter import cli
from proxyfilter.io import write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo


class ReliableConfigWiringTests(unittest.TestCase):
    def test_cli_passes_reliable_config_to_global_publish(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            data_dir = root / "data"
            work_dir = data_dir / "work"
            work_dir.mkdir(parents=True)

            proxy = ProxyConfig(
                SourceInfo("source-a", "Source A", "plain"),
                "vless",
                "example.com",
                443,
                params={"uuid": "11111111-1111-1111-1111-111111111111"},
            )
            proxy.ensure_id()
            proxy.tests.render = {
                "status": "pass",
                "name": "test",
                "uri": "vless://11111111-1111-1111-1111-111111111111@example.com:443#test",
                "error": None,
            }
            write_jsonl(work_dir / "11-render-ok.jsonl", [proxy])

            config = {
                "paths": {"data_dir": str(data_dir)},
                "sources": [
                    {
                        "id": "source-a",
                        "name": "Source A",
                        "url": "https://example.invalid/sub",
                    }
                ],
                "diversity": {"enabled": False},
                "reliable": {
                    "enabled": True,
                    "min_confirmed_passes": 7,
                    "min_consecutive_passes": 4,
                },
            }
            config_path = root / "config.yaml"
            config_path.write_text(
                yaml.safe_dump(config, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )

            captured = {}

            def fake_publish_merged(data_dir_arg, proxies, diversity_cfg, **kwargs):
                captured["data_dir"] = data_dir_arg
                captured["diversity"] = diversity_cfg
                captured["reliable"] = kwargs.get("reliable_cfg")
                return data_dir_arg / "output" / "all.txt", None

            argv = [
                "proxy-filter",
                "--config",
                str(config_path),
                "--resume-from",
                "render",
                "--until",
                "publish",
            ]
            with patch.object(cli, "publish_merged", side_effect=fake_publish_merged), patch.object(
                sys, "argv", argv
            ):
                result = cli.main()

            self.assertEqual(result, 0)
            self.assertEqual(captured["data_dir"], data_dir)
            self.assertEqual(captured["diversity"], {"enabled": False})
            self.assertEqual(
                captured["reliable"],
                {
                    "enabled": True,
                    "min_confirmed_passes": 7,
                    "min_consecutive_passes": 4,
                },
            )


if __name__ == "__main__":
    unittest.main()
