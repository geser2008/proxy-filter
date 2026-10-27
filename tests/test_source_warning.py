from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from proxyfilter.history import _connect
from proxyfilter.history_global import record_global_source_run
from proxyfilter.source_status import (
    apply_warning_summary,
    build_source_status_rows,
    warning_source_ids,
    write_source_status,
)


class SourceWarningTests(unittest.TestCase):
    def test_source_status_work_file_and_summary_warning(self) -> None:
        sources = [
            {"id": "ok", "name": "OK", "url": "https://ok.invalid/sub"},
            {"id": "down", "name": "Down", "url": "https://down.invalid/sub"},
        ]
        summary = {
            "sources": {
                "ok": {"status": "ok", "parsed": 7, "parse_errors": 1, "format": "plain"},
                "down": {"status": "error", "error": "HTTP 503"},
            },
            "pipeline": {"status": "ok", "stage": "publish", "survivors": 3},
        }

        rows = build_source_status_rows(sources, summary)
        self.assertEqual(warning_source_ids(rows), {"down"})
        self.assertEqual(rows[1]["status"], "warning")
        self.assertEqual(rows[1]["reason"], "source_unavailable")
        self.assertFalse(rows[1]["fetched"])

        apply_warning_summary(summary, rows)
        self.assertEqual(summary["sources"]["down"]["status"], "warning")
        self.assertEqual(summary["pipeline"]["status"], "warning")
        self.assertEqual(summary["pipeline"]["warning_count"], 1)
        self.assertEqual(summary["pipeline"]["unavailable_sources"], ["down"])

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "work" / "00-source-status.jsonl"
            write_source_status(path, rows)
            saved = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(saved, rows)

    def test_warning_history_does_not_mark_previous_proxy_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "history.sqlite3"
            work = root / "work"
            work.mkdir()

            # Seed a previously seen source member.
            with _connect(db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO proxy_source_state(
                        source_id, proxy_id, first_seen_at, last_seen_at,
                        first_seen_run_id, last_seen_run_id, seen_count,
                        absent_count, last_status, last_availability_state,
                        current_streak, current_streak_state
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        "down", "proxy-1", "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z",
                        "old-run", "old-run", 1, 0, "published", "available", 1, "available",
                    ),
                )

            # No 01-parsed rows exist for the unavailable source. A warning run
            # must leave source membership state unchanged.
            record_global_source_run(
                db_path,
                run_id="warning-run",
                source_id="down",
                source_name="Down",
                work_dir=work,
                started_at="2026-10-27T12:00:00Z",
                finished_at="2026-10-27T12:01:00Z",
                source_available=False,
                run_status="warning",
                run_error="HTTP 503",
                warning_stage="fetch",
                warning_reason="source_unavailable",
                warning_message="Source could not be fetched; retained proxies were still tested",
            )

            with closing(sqlite3.connect(db_path)) as conn:
                run = conn.execute(
                    "SELECT status, error FROM runs WHERE run_id='warning-run'"
                ).fetchone()
                warning = conn.execute(
                    "SELECT stage, reason, error FROM run_warnings WHERE run_id='warning-run'"
                ).fetchone()
                state = conn.execute(
                    "SELECT seen_count, absent_count, last_seen_at FROM proxy_source_state "
                    "WHERE source_id='down' AND proxy_id='proxy-1'"
                ).fetchone()

        self.assertEqual(run, ("warning", "HTTP 503"))
        self.assertEqual(warning, ("fetch", "source_unavailable", "HTTP 503"))
        self.assertEqual(state, (1, 0, "2026-10-01T00:00:00Z"))


if __name__ == "__main__":
    unittest.main()
