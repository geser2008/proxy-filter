import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from proxyfilter.history import _connect, _insert_record
from proxyfilter.history_geo import sync_geo_history


class GeoHistoryTests(unittest.TestCase):
    def test_sync_adds_fallback_flag_and_attempt_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "history.sqlite3"
            work = root / "work"
            work.mkdir()

            row = {
                "id": "proxy-1",
                "source": {"id": "radikal", "name": "Radikal", "format": "plain"},
                "sources": [{"id": "radikal", "name": "Radikal", "format": "plain"}],
                "tests": {
                    "geo": {
                        "status": "ok",
                        "provider": "ipapi",
                        "fallback_used": True,
                        "reason": None,
                        "error": None,
                        "attempts": [
                            {
                                "provider": "ipwhois",
                                "url": "https://ipwho.is/203.0.113.7",
                                "ok": False,
                                "http_code": None,
                                "reason": "timeout",
                                "error": "curl: (28) timeout",
                            },
                            {
                                "provider": "ipapi",
                                "url": "https://ipapi.co/203.0.113.7/json/",
                                "ok": True,
                                "http_code": None,
                                "reason": None,
                                "error": None,
                            },
                        ],
                    }
                },
            }
            (work / "10-geo.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")

            with _connect(db) as conn:
                conn.execute(
                    "INSERT INTO runs(run_id,source_id,source_name,started_at,finished_at,status) VALUES(?,?,?,?,?,?)",
                    ("run1", "radikal", "Radikal", "2026-10-27T00:00:00Z", "2026-10-27T00:01:00Z", "ok"),
                )
                _insert_record(
                    conn,
                    "proxy_observations",
                    {
                        "run_id": "run1",
                        "source_id": "radikal",
                        "proxy_id": "proxy-1",
                        "observed_at": "2026-10-27T00:01:00Z",
                        "present": 1,
                        "availability_state": "available",
                        "geo_provider": "ipapi",
                        "published": 0,
                    },
                )

            sync_geo_history(
                db,
                run_id="run1",
                source_id="radikal",
                work_dir=work,
            )

            with closing(sqlite3.connect(db)) as conn:
                obs = conn.execute(
                    "SELECT geo_provider,geo_fallback_used,geo_reason,geo_error FROM proxy_observations"
                ).fetchone()
                attempts = conn.execute(
                    "SELECT attempt_index,provider,ok,reason,error FROM geo_attempts ORDER BY attempt_index"
                ).fetchall()
                view = conn.execute(
                    "SELECT geo_provider,geo_fallback_used FROM history"
                ).fetchone()

            self.assertEqual(obs, ("ipapi", 1, None, None))
            self.assertEqual(
                attempts,
                [
                    (0, "ipwhois", 0, "timeout", "curl: (28) timeout"),
                    (1, "ipapi", 1, None, None),
                ],
            )
            self.assertEqual(view, ("ipapi", 1))


if __name__ == "__main__":
    unittest.main()
