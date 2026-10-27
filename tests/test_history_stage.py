import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import proxy_filter
from proxyfilter.resume import STAGE_ORDER, validate_resume_range


class HistoryStageTests(unittest.TestCase):
    def _row(self, proxy_id="proxy-a"):
        return {
            "id": proxy_id,
            "source": {"id": "radikal", "name": "Radikal", "format": "plain"},
            "sources": [{"id": "radikal", "name": "Radikal", "format": "plain"}],
            "config": {
                "protocol": "vless",
                "server": "203.0.113.10",
                "port": 443,
                "name": "node",
                "params": {"uuid": "550e8400-e29b-41d4-a716-446655440000"},
            },
            "tests": {
                "security": {"status": "pass", "reasons": []},
                "tcp": {"status": "pass", "latency_ms": 10.0},
                "core": {"status": "pass", "error": None},
                "latency": {"status": "pass", "latency_ms": 20.0},
                "download": {"status": "pass", "mbps": 100.0, "stream_reliability": "stable"},
                "upload": {"status": "pass", "mbps": 40.0},
                "exit_ip_probe": {"status": "pass", "ip": "198.51.100.10", "error": None},
                "geo": {"status": "ok", "country_code": "NL", "asn": 64500},
                "render": {"status": "pass", "name": "node", "uri": "vless://example", "error": None},
                "latency_ms": 20.0,
                "download_mbps": 100.0,
                "upload_mbps": 40.0,
                "exit_ip": "198.51.100.10",
                "country": "Netherlands",
                "status": "published",
            },
            "original": {"format": "vless-uri", "raw": "vless://example"},
        }

    def _write_jsonl(self, path: Path, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    def test_history_is_last_pipeline_stage(self):
        self.assertEqual(STAGE_ORDER[-2:], ("publish", "history"))
        validate_resume_range("publish", "history")

    def test_snapshot_run_id_is_deterministic_and_changes_with_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            row = self._row()
            self._write_jsonl(work / "02-unique.jsonl", [row])
            self._write_jsonl(work / "12-published.jsonl", [row])

            first = proxy_filter._snapshot_run_id("radikal", work)
            second = proxy_filter._snapshot_run_id("radikal", work)
            self.assertEqual(first, second)

            row["tests"]["download_mbps"] = 120.0
            self._write_jsonl(work / "12-published.jsonl", [row])
            third = proxy_filter._snapshot_run_id("radikal", work)
            self.assertNotEqual(first, third)

    def test_history_import_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work" / "radikal"
            row = self._row()
            self._write_jsonl(work / "01-parsed.jsonl", [row])
            self._write_jsonl(work / "02-unique.jsonl", [row])
            self._write_jsonl(work / "12-published.jsonl", [row])

            cfg = {
                "paths": {"data_dir": str(root)},
                "history": {"database": "history/test.sqlite3"},
                "sources": [{"id": "radikal", "name": "Radikal", "url": "https://example.invalid/sub"}],
            }
            args = ["--source", "radikal"]

            self.assertEqual(proxy_filter._import_history_snapshot(cfg, args), 0)
            self.assertEqual(proxy_filter._import_history_snapshot(cfg, args), 0)

            db = root / "history" / "test.sqlite3"
            with sqlite3.connect(db) as conn:
                run_count = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
                observation_count = conn.execute("SELECT COUNT(*) FROM proxy_observations").fetchone()[0]
                schema_version = conn.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
            self.assertEqual(run_count, 1)
            self.assertEqual(observation_count, 1)
            self.assertEqual(schema_version, "3")

    def test_incomplete_snapshot_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self._write_jsonl(work / "02-unique.jsonl", [self._row()])
            with self.assertRaises(FileNotFoundError):
                proxy_filter._snapshot_run_id("radikal", work)


if __name__ == "__main__":
    unittest.main()
