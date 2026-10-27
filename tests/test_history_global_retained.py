import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from proxyfilter.history_global import record_global_source_run
from proxyfilter.io import write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo


class GlobalHistoryRetainedTests(unittest.TestCase):
    def test_retained_proxy_is_absent_from_source_but_keeps_test_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            db = root / "history.sqlite3"
            source = SourceInfo("iboxz", "iboxz", "plain")
            proxy = ProxyConfig(
                source,
                "vless",
                "203.0.113.20",
                443,
                params={"uuid": "550e8400-e29b-41d4-a716-446655440001"},
            )
            proxy.ensure_id()

            # Simulate carryover from known-working: not returned by current
            # source, but still part of the global candidate set and re-tested.
            write_jsonl(work / "01-parsed.jsonl", [])
            write_jsonl(work / "02-unique.jsonl", [proxy])
            proxy.tests.security = {"status": "pass", "reasons": []}
            proxy.tests.tcp = {"status": "pass", "latency_ms": 20.0}
            proxy.tests.core = {"status": "pass", "error": None}
            proxy.tests.latency = {"status": "pass", "latency_ms": 100.0}
            proxy.tests.latency_ms = 100.0
            proxy.tests.download = {"status": "pass", "mbps": 120.0, "stream_reliability": "stable"}
            proxy.tests.download_mbps = 120.0
            proxy.tests.upload = {"status": "pass", "mbps": 50.0}
            proxy.tests.upload_mbps = 50.0
            proxy.tests.reliability = {"status": "stable", "reason": None, "details": {}}
            proxy.tests.render = {"status": "pass", "name": "x", "uri": "vless://x", "error": None}
            proxy.tests.status = "qualified"
            write_jsonl(work / "12-qualified.jsonl", [proxy])
            proxy.tests.diversity = {"status": "selected", "reason": None}
            proxy.tests.status = "diversity_selected"
            write_jsonl(work / "13-diversity-selected.jsonl", [proxy])
            proxy.tests.status = "published"
            write_jsonl(work / "14-published.jsonl", [proxy])

            record_global_source_run(
                db,
                run_id="run1",
                source_id="iboxz",
                source_name="iboxz",
                work_dir=work,
                started_at="2026-10-27T00:00:00+00:00",
                finished_at="2026-10-27T00:10:00+00:00",
            )

            with closing(sqlite3.connect(db)) as conn:
                observation = conn.execute(
                    "SELECT present,availability_state,published,download_mbps "
                    "FROM proxy_observations WHERE proxy_id=?",
                    (proxy.id,),
                ).fetchone()
                source_state = conn.execute(
                    "SELECT seen_count,available_count,absent_count,current_streak_state "
                    "FROM proxy_source_state WHERE proxy_id=?",
                    (proxy.id,),
                ).fetchone()
                run = conn.execute(
                    "SELECT parsed_count,published_count FROM runs WHERE run_id='run1'"
                ).fetchone()

            self.assertEqual(observation, (0, "available", 1, 120.0))
            self.assertEqual(source_state, (0, 0, 1, "absent"))
            self.assertEqual(run, (0, 0))

    def test_parsed_count_preserves_duplicate_rows_before_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work = root / "work"
            db = root / "history.sqlite3"
            source = SourceInfo("iboxz", "iboxz", "plain")
            proxy = ProxyConfig(
                source,
                "vless",
                "203.0.113.30",
                443,
                params={"uuid": "550e8400-e29b-41d4-a716-446655440002"},
            )
            proxy.ensure_id()

            duplicate = ProxyConfig.from_dict(proxy.to_dict())
            write_jsonl(work / "01-parsed.jsonl", [proxy, duplicate])
            write_jsonl(work / "02-unique.jsonl", [proxy])

            record_global_source_run(
                db,
                run_id="run1",
                source_id="iboxz",
                source_name="iboxz",
                work_dir=work,
                started_at="2026-10-27T00:00:00+00:00",
                finished_at="2026-10-27T00:01:00+00:00",
            )

            with closing(sqlite3.connect(db)) as conn:
                run = conn.execute(
                    "SELECT parsed_count,unique_count FROM runs WHERE run_id='run1'"
                ).fetchone()

            self.assertEqual(run, (2, 1))


if __name__ == "__main__":
    unittest.main()
