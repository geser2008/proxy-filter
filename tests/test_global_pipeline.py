from __future__ import annotations

import tempfile
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import yaml

from proxyfilter import global_pipeline
from proxyfilter.model import ProxyConfig, SourceInfo


class GlobalPipelineTests(unittest.TestCase):
    @staticmethod
    def _proxy(source_id: str) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo(source_id, source_id, "plain"),
            "ss",
            "203.0.113.50",
            8388,
            source_id,
            {"method": "aes-256-gcm", "password": "secret"},
        )
        proxy.ensure_id()
        return proxy

    def test_cross_source_dedup_happens_before_network_stages(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "paths": {"data_dir": tmpdir},
                "sources": [
                    {"id": "one", "name": "one", "url": "https://one.invalid"},
                    {"id": "two", "name": "two", "url": "https://two.invalid"},
                ],
            }
            config_path = Path(tmpdir) / "config.yaml"
            config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

            p1 = self._proxy("one")
            p2 = self._proxy("two")

            class Engine:
                @staticmethod
                def version() -> str:
                    return "sing-box test"

            with (
                patch.object(global_pipeline.cli, "process_source", side_effect=[[p1], [p2]]) as process_source,
                patch.object(global_pipeline.cli, "build_engine", return_value=Engine()),
                patch.object(global_pipeline, "_run_global_stages") as run_global,
                patch.object(global_pipeline, "write_jsonl"),
                patch.object(global_pipeline, "write_json"),
                patch.object(sys, "argv", ["proxy-filter", "--config", str(config_path), "--until", "tcp"]),
            ):
                run_global.side_effect = lambda current, *_args, **_kwargs: current
                result = global_pipeline.main()

            self.assertEqual(result, 0)
            self.assertEqual(process_source.call_count, 2)
            current = run_global.call_args.args[0]
            self.assertEqual(len(current), 1)
            self.assertEqual(
                [source.id for source in current[0].provenance_sources()],
                ["one", "two"],
            )


if __name__ == "__main__":
    unittest.main()
