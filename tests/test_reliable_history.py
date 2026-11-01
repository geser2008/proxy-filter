from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.history import _connect as history_connect
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.reliable_history import (
    migrate_reliable_history,
    reliability_db_path,
    reliable_ids,
    reliability_rows,
    update_global_reliability,
)


def make_proxy(suffix: int, source_id: str = "source-a") -> ProxyConfig:
    proxy = ProxyConfig(
        SourceInfo(source_id, source_id, "plain"),
        "ss",
        f"203.0.113.{suffix}",
        8388,
        params={"method": "aes-256-gcm", "password": f"secret-{suffix}"},
    )
    proxy.ensure_id()
    return proxy


class ReliableHistoryTests(unittest.TestCase):
    def test_default_database_is_existing_history_database(self):
        data_dir = Path("/srv/proxy-filter/data")
        self.assertEqual(
            reliability_db_path(data_dir),
            data_dir / "history" / "proxy-history.sqlite3",
        )
        self.assertEqual(
            reliability_db_path(data_dir, {"database": "custom/history.sqlite3"}),
            data_dir / "custom" / "history.sqlite3",
        )
        self.assertEqual(
            reliability_db_path(data_dir, {"database": "/tmp/proxy-history.sqlite3"}),
            Path("/tmp/proxy-history.sqlite3"),
        )

    def test_migration_preserves_existing_history_data(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "proxy-history.sqlite3"
            with history_connect(db) as conn:
                conn.execute(
                    """
                    INSERT INTO runs(
                        run_id, source_id, source_name, started_at, finished_at, status
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        "existing-run",
                        "existing-source",
                        "Existing Source",
                        "2026-10-31T10:00:00+00:00",
                        "2026-10-31T10:05:00+00:00",
                        "ok",
                    ),
                )

            migrate_reliable_history(db)

            with closing(sqlite3.connect(db)) as conn:
                existing = conn.execute(
                    "SELECT source_id, status FROM runs WHERE run_id='existing-run'"
                ).fetchone()
                self.assertEqual(existing, ("existing-source", "ok"))
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                self.assertIn("proxy_global_reliability", tables)
                self.assertIn("proxy_global_reliability_runs", tables)
                feature_version = conn.execute(
                    """
                    SELECT version FROM feature_schema_meta
                    WHERE feature='global_reliability'
                    """
                ).fetchone()
                self.assertEqual(feature_version, (1,))
                core_version = conn.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()
                self.assertEqual(core_version, ("3",))

    def test_first_pass_is_not_reliable(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(1)
            update_global_reliability(db, [proxy], [])

            row = reliability_rows(db)[proxy.id]
            self.assertEqual(row["test_count"], 1)
            self.assertEqual(row["confirmed_passes"], 1)
            self.assertEqual(row["consecutive_passes"], 1)
            self.assertEqual(row["last_result"], "pass")
            self.assertNotIn(proxy.id, reliable_ids(db))

    def test_third_pass_becomes_reliable(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(2)
            start = datetime(2026, 10, 31, 10, 0, tzinfo=timezone.utc)
            for offset in range(3):
                update_global_reliability(
                    db,
                    [proxy],
                    [],
                    now=start + timedelta(hours=offset),
                )

            row = reliability_rows(db)[proxy.id]
            self.assertEqual(row["test_count"], 3)
            self.assertEqual(row["confirmed_passes"], 3)
            self.assertEqual(row["consecutive_passes"], 3)
            self.assertIn(proxy.id, reliable_ids(db))

    def test_failure_resets_consecutive_passes_and_removes_reliable(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(3)
            for _ in range(3):
                update_global_reliability(db, [proxy], [])
            self.assertIn(proxy.id, reliable_ids(db))

            update_global_reliability(db, [], [proxy])
            row = reliability_rows(db)[proxy.id]
            self.assertEqual(row["test_count"], 4)
            self.assertEqual(row["confirmed_passes"], 3)
            self.assertEqual(row["confirmed_failures"], 1)
            self.assertEqual(row["consecutive_passes"], 0)
            self.assertEqual(row["consecutive_failures"], 1)
            self.assertEqual(row["last_result"], "fail")
            self.assertNotIn(proxy.id, reliable_ids(db))

    def test_recovery_requires_configured_consecutive_passes(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(4)
            for _ in range(3):
                update_global_reliability(db, [proxy], [])
            update_global_reliability(db, [], [proxy])

            update_global_reliability(db, [proxy], [])
            self.assertNotIn(proxy.id, reliable_ids(db))
            update_global_reliability(db, [proxy], [])
            self.assertIn(proxy.id, reliable_ids(db))

    def test_same_proxy_from_multiple_sources_counts_once(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            from_a = make_proxy(5, "source-a")
            from_b = make_proxy(5, "source-b")
            self.assertEqual(from_a.id, from_b.id)

            counts = update_global_reliability(db, [from_a, from_b], [])
            row = reliability_rows(db)[from_a.id]
            self.assertEqual(
                counts,
                {"tested": 1, "passed": 1, "failed": 0, "skipped": 0},
            )
            self.assertEqual(row["test_count"], 1)
            self.assertEqual(row["confirmed_passes"], 1)

    def test_untested_proxy_is_not_modified(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            tested = make_proxy(6)
            absent = make_proxy(7)
            update_global_reliability(db, [tested], [])
            before = reliability_rows(db)[tested.id].copy()

            update_global_reliability(db, [], [])
            rows = reliability_rows(db)
            self.assertEqual(rows[tested.id], before)
            self.assertNotIn(absent.id, rows)

    def test_same_run_key_is_counted_only_once(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(9)
            first = update_global_reliability(db, [proxy], [], run_key="run-1")
            replay = update_global_reliability(db, [proxy], [], run_key="run-1")

            self.assertEqual(first["skipped"], 0)
            self.assertEqual(replay, {"tested": 0, "passed": 0, "failed": 0, "skipped": 1})
            self.assertEqual(reliability_rows(db)[proxy.id]["test_count"], 1)

    def test_different_run_keys_are_distinct_confirmations(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(10)
            update_global_reliability(db, [proxy], [], run_key="run-1")
            update_global_reliability(db, [proxy], [], run_key="run-2")
            self.assertEqual(reliability_rows(db)[proxy.id]["confirmed_passes"], 2)

    def test_overlap_is_rejected_as_ambiguous(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            proxy = make_proxy(8)
            with self.assertRaises(ValueError):
                update_global_reliability(db, [proxy], [proxy])

    def test_threshold_validation(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "history.sqlite3"
            with self.assertRaises(ValueError):
                reliable_ids(db, min_confirmed_passes=0)
            with self.assertRaises(ValueError):
                reliable_ids(db, min_consecutive_passes=0)


if __name__ == "__main__":
    unittest.main()
