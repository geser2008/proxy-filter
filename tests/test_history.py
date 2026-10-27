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
        proxy.tests.core = {"status": "pass", "reason": None, "error": None}
        proxy.tests.latency = {
            "status": "pass",
            "latency_ms": 120.0,
            "reason": None,
            "error": None,
            "method": "sing-box-clash-api",
            "attempts": [{"ok": True, "latency_ms": 120.0, "error": None}],
        }
        proxy.tests.latency_ms = 120.0
        proxy.tests.download = {
            "status": "pass",
            "mbps": 100.0,
            "single_mbps": 90.0,
            "aggregate_mbps": 100.0,
            "backend": "cloudflare",
            "reason": None,
            "stream_reliability": reliability,
            "stages": [{
                "backend": "cloudflare",
                "streams": 8,
                "skipped": False,
                "ok": True,
                "classification": "success",
                "mbps": 100.0,
                "bytes": 80_000_000,
                "expected_bytes": 80_000_000,
                "payload_valid": True,
                "time_seconds": 6.4,
                "http_code": 200,
                "error": None,
                "stream_results": [{
                    "backend": "cloudflare",
                    "url": "https://speed.cloudflare.com/__down?bytes=10000000",
                    "ok": True,
                    "mbps": 100.0,
                    "bytes": 10_000_000,
                    "expected_bytes": 10_000_000,
                    "payload_valid": True,
                    "time_seconds": 0.8,
                    "http_code": 200,
                    "error": None,
                    "expect_disabled": False,
                }],
            }],
        }
        proxy.tests.download_mbps = 100.0
        proxy.tests.upload = {
            "status": "pass",
            "mbps": 50.0,
            "reason": None,
            "error": None,
            "stages": [],
        }
        proxy.tests.upload_mbps = 50.0
        proxy.tests.reliability = {
            "status": reliability,
            "reason": "stage_consistency" if reliability == "degraded" else None,
            "details": {
                "status": reliability,
                "reason": "stage_consistency" if reliability == "degraded" else None,
                "provider_fallback": True,
                "mixed_stage_outcomes": reliability == "degraded",
                "successful_stage_count": 2,
                "failed_stage_count": 1 if reliability == "degraded" else 0,
            },
        }
        proxy.tests.exit_ip_probe = {"status": "pass", "ip": "198.51.100.10", "reason": None, "error": None}
        proxy.tests.exit_ip = "198.51.100.10"
        proxy.tests.geo = {"status": "ok", "country": "United States", "country_code": "US", "asn": 64500}
        proxy.tests.render = {"status": "pass", "name": "x", "uri": "vless://x", "error": None}

        proxy.tests.status = "qualified"
        write_jsonl(work / "12-qualified.jsonl", [proxy])
        proxy.tests.diversity = {"status": "selected", "reason": None}
        proxy.tests.status = "diversity_selected"
        write_jsonl(work / "13-diversity-selected.jsonl", [proxy])
        write_jsonl(work / "13-diversity-suppressed.jsonl", [])
        proxy.tests.status = "published"
        write_jsonl(work / "14-published.jsonl", [proxy])

    def test_available_proxy_records_current_pipeline_and_reliability(self):
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

        with sqlite3.connect(self.db) as conn:
            run = conn.execute(
                "SELECT qualified_count,diversity_selected_count,diversity_suppressed_count,"
                "published_count,stable_published_count,unstable_published_count FROM runs"
            ).fetchone()
            obs = conn.execute(
                "SELECT availability_state,published,download_mbps,reliability_status,"
                "reliability_provider_fallback,reliability_mixed_stage_outcomes FROM proxy_observations"
            ).fetchone()
            version = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]

        self.assertEqual(run, (1, 1, 0, 1, 1, 0))
        self.assertEqual(obs, ("available", 1, 100.0, "stable", 1, 0))
        self.assertEqual(version, "3")

    def test_failure_reason_prefers_normalized_reason_over_raw_error(self):
        work = self.root / "run1"
        proxy = self._proxy()
        write_jsonl(work / "01-parsed.jsonl", [proxy])
        write_jsonl(work / "02-unique.jsonl", [proxy])
        proxy.tests.security = {"status": "pass", "reasons": []}
        proxy.tests.tcp = {
            "status": "reject",
            "latency_ms": None,
            "reason": "connection_refused",
            "error": "[Errno 111] Connection refused",
        }
        proxy.tests.status = "rejected_tcp"
        write_jsonl(work / "04-rejected-tcp.jsonl", [proxy])

        record_source_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work,
            started_at="2026-10-26T00:00:00+00:00",
        )
        with sqlite3.connect(self.db) as conn:
            row = conn.execute(
                "SELECT tcp_reason,tcp_error,failure_stage,failure_reason FROM proxy_observations"
            ).fetchone()
        self.assertEqual(
            row,
            ("connection_refused", "[Errno 111] Connection refused", "tcp", "connection_refused"),
        )

    def test_degraded_published_proxy_records_reliability_details(self):
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
        )
        with sqlite3.connect(self.db) as conn:
            obs = conn.execute(
                "SELECT availability_state,reliability_status,reliability_reason,"
                "reliability_mixed_stage_outcomes,reliability_successful_stage_count,"
                "reliability_failed_stage_count FROM proxy_observations"
            ).fetchone()
            run = conn.execute(
                "SELECT stable_published_count,unstable_published_count FROM runs"
            ).fetchone()
        self.assertEqual(obs, ("degraded", "degraded", "stage_consistency", 1, 2, 1))
        self.assertEqual(run, (0, 1))

    def test_retained_proxy_can_be_tested_while_absent_from_source(self):
        work = self.root / "run1"
        proxy = self._proxy()
        self._write_successful_run(work, proxy)
        write_jsonl(work / "01-parsed.jsonl", [])

        record_source_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            work_dir=work,
            started_at="2026-10-26T00:00:00+00:00",
        )
        with sqlite3.connect(self.db) as conn:
            obs = conn.execute(
                "SELECT present,availability_state,published FROM proxy_observations"
            ).fetchone()
            state = conn.execute(
                "SELECT seen_count,available_count,absent_count,last_availability_state,current_streak_state "
                "FROM proxy_source_state"
            ).fetchone()
            run = conn.execute("SELECT parsed_count,published_count FROM runs").fetchone()

        self.assertEqual(obs, (0, "available", 1))
        self.assertEqual(state, (0, 0, 1, "absent", "absent"))
        self.assertEqual(run, (0, 0))

    def test_missing_proxy_in_next_run_is_absent(self):
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
        )
        with sqlite3.connect(self.db) as conn:
            obs = conn.execute(
                "SELECT present,availability_state FROM proxy_observations WHERE run_id='run2'"
            ).fetchone()
        self.assertEqual(obs, (0, "absent"))

    def test_schema_v2_is_migrated_in_place_to_v3(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT INTO schema_meta VALUES('schema_version','2')")
            conn.execute("CREATE TABLE runs(run_id TEXT PRIMARY KEY,source_id TEXT,source_name TEXT,started_at TEXT,finished_at TEXT,status TEXT,error TEXT)")
            conn.execute("CREATE TABLE proxy_observations(observation_id INTEGER PRIMARY KEY,run_id TEXT,source_id TEXT,proxy_id TEXT,observed_at TEXT,present INTEGER,availability_state TEXT,published INTEGER DEFAULT 0)")
            conn.execute("CREATE TABLE latency_attempts(observation_id INTEGER,attempt_index INTEGER)")
            conn.execute("CREATE TABLE transfer_stages(stage_id INTEGER PRIMARY KEY,observation_id INTEGER,direction TEXT,stage_index INTEGER)")
            conn.execute("CREATE TABLE transfer_attempts(attempt_id INTEGER PRIMARY KEY,stage_id INTEGER,attempt_index INTEGER,error_code INTEGER)")

        record_failed_run(
            self.db,
            run_id="run1",
            source_id="radikal",
            source_name="Radikal",
            started_at="2026-10-27T00:00:00+00:00",
            error="fetch failed",
        )
        with sqlite3.connect(self.db) as conn:
            version = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0]
            obs_columns = {row[1] for row in conn.execute("PRAGMA table_info(proxy_observations)")}
            stage_columns = {row[1] for row in conn.execute("PRAGMA table_info(transfer_stages)")}
        self.assertEqual(version, "3")
        self.assertIn("download_reason", obs_columns)
        self.assertIn("reliability_status", obs_columns)
        self.assertIn("reason", stage_columns)

    def test_schema_v1_database_is_rejected_without_mutation(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute("CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT INTO schema_meta VALUES('schema_version','1')")
        with self.assertRaisesRegex(RuntimeError, "schema v1.*schema v3"):
            record_failed_run(
                self.db,
                run_id="run1",
                source_id="radikal",
                source_name="Radikal",
                started_at="2026-10-27T00:00:00+00:00",
                error="fetch failed",
            )


if __name__ == "__main__":
    unittest.main()
