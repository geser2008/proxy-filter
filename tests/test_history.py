import sqlite3
import tempfile
import unittest
from pathlib import Path

from proxyfilter.history import record_failed_run, record_source_run
from proxyfilter.io import write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db = self.root / "history.sqlite3"
        self.source = SourceInfo("radikal", "Radikal", "plain")

    def tearDown(self):
        self.tmp.cleanup()

    def _proxy(self, name="proxy"):
        proxy = ProxyConfig(
            self.source,
            "vless",
            "203.0.113.10",
            443,
            name,
            {"uuid": "550e8400-e29b-41d4-a716-446655440000"},
        )
        proxy.ensure_id()
        return proxy

    def _write_successful_run(self, work: Path, proxy: ProxyConfig, reliability="stable"):
        write_jsonl(work / "01-parsed.jsonl", [proxy])
        write_jsonl(work / "02-unique.jsonl", [proxy])

        proxy.tests.security = {"status": "pass", "reasons": []}
        proxy.tests.tcp = {"status": "pass", "latency_ms": 25.0, "error": None}
        proxy.tests.core = {"status": "pass", "error": None}
        proxy.tests.latency = {"status": "pass", "latency_ms": 120.0, "error": None}
        proxy.tests.latency_ms = 120.0
        proxy.tests.download = {
            "status": "pass",
            "mbps": 100.0,
            "backend": "cloudflare",
            "stream_reliability": reliability,
        }
        proxy.tests.download_mbps = 100.0
        proxy.tests.upload = {"status": "pass", "mbps": 50.0, "error": None}
        proxy.tests.upload_mbps = 50.0
        proxy.tests.exit_ip_probe = {"status": "pass", "ip": "198.51.100.10", "error": None}
        proxy.tests.exit_ip = "198.51.100.10"
        proxy.tests.geo = {"status": "ok", "country_code": "US", "asn": 64500}
        proxy.tests.render = {"status": "pass", "name": "x", "uri": "vless://x", "error": None}
        proxy.tests.status = "published"
        write_jsonl(work / "12-published.jsonl", [proxy])

    def test_available_proxy_is_recorded_and_state_is_aggregated(self):
        work = self.root / "run1"
        proxy = self._proxy()
        self._write_successful_run(work, proxy)

        record_source_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work,
            started_at="2026-10-26T00:00:00+00:00",
            finished_at="2026-10-26T00:10:00+00:00",
            store_details="failures",
        )

        with sqlite3.connect(self.db) as conn:
            obs = conn.execute(
                "SELECT availability_state, published, download_mbps, stream_reliability, details_json "
                "FROM proxy_observations WHERE proxy_id=?",
                (proxy.id,),
            ).fetchone()
            state = conn.execute(
                "SELECT seen_count, available_count, absent_count, current_streak_state "
                "FROM proxy_source_state WHERE proxy_id=?",
                (proxy.id,),
            ).fetchone()

        self.assertEqual(obs[:4], ("available", 1, 100.0, "stable"))
        self.assertIsNone(obs[4])
        self.assertEqual(state, (1, 1, 0, "available"))

    def test_missing_proxy_in_next_successful_source_run_is_absent(self):
        work1 = self.root / "run1"
        proxy = self._proxy()
        self._write_successful_run(work1, proxy)
        record_source_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work1,
            started_at="2026-10-26T00:00:00+00:00",
            finished_at="2026-10-26T00:10:00+00:00",
        )

        work2 = self.root / "run2"
        write_jsonl(work2 / "01-parsed.jsonl", [])
        write_jsonl(work2 / "02-unique.jsonl", [])
        record_source_run(
            self.db,
            run_id="run2",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work2,
            started_at="2026-10-27T00:00:00+00:00",
            finished_at="2026-10-27T00:10:00+00:00",
        )

        with sqlite3.connect(self.db) as conn:
            obs = conn.execute(
                "SELECT present, availability_state FROM proxy_observations "
                "WHERE run_id='run2' AND proxy_id=?",
                (proxy.id,),
            ).fetchone()
            state = conn.execute(
                "SELECT seen_count, absent_count, current_streak, current_streak_state "
                "FROM proxy_source_state WHERE proxy_id=?",
                (proxy.id,),
            ).fetchone()

        self.assertEqual(obs, (0, "absent"))
        self.assertEqual(state, (1, 1, 1, "absent"))

    def test_degraded_published_proxy_has_distinct_availability_state(self):
        work = self.root / "run1"
        proxy = self._proxy()
        self._write_successful_run(work, proxy, reliability="degraded")

        record_source_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work,
            started_at="2026-10-26T00:00:00+00:00",
            finished_at="2026-10-26T00:10:00+00:00",
        )

        with sqlite3.connect(self.db) as conn:
            obs = conn.execute(
                "SELECT availability_state, stream_reliability FROM proxy_observations WHERE proxy_id=?",
                (proxy.id,),
            ).fetchone()
            state = conn.execute(
                "SELECT available_count, last_availability_state FROM proxy_source_state WHERE proxy_id=?",
                (proxy.id,),
            ).fetchone()

        self.assertEqual(obs, ("degraded", "degraded"))
        self.assertEqual(state, (1, "degraded"))

    def test_failed_source_run_does_not_create_absent_observation(self):
        work = self.root / "run1"
        proxy = self._proxy()
        self._write_successful_run(work, proxy)
        record_source_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work,
            started_at="2026-10-26T00:00:00+00:00",
            finished_at="2026-10-26T00:10:00+00:00",
        )

        record_failed_run(
            self.db,
            run_id="run2",
            source_id="radikal",
            source_name="Radikal",
            started_at="2026-10-27T00:00:00+00:00",
            finished_at="2026-10-27T00:00:03+00:00",
            error="source fetch failed",
        )

        with sqlite3.connect(self.db) as conn:
            observation_count = conn.execute("SELECT COUNT(*) FROM proxy_observations").fetchone()[0]
            absent_count = conn.execute(
                "SELECT absent_count FROM proxy_source_state WHERE proxy_id=?",
                (proxy.id,),
            ).fetchone()[0]
            failed = conn.execute(
                "SELECT status, error FROM runs WHERE run_id='run2'"
            ).fetchone()

        self.assertEqual(observation_count, 1)
        self.assertEqual(absent_count, 0)
        self.assertEqual(failed, ("error", "source fetch failed"))


if __name__ == "__main__":
    unittest.main()
