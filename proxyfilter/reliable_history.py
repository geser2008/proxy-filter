from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from .model import ProxyConfig


RESULT_PASS = "pass"
RESULT_FAIL = "fail"


def _iso_now(now: datetime | None = None) -> str:
    value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return value.isoformat(timespec="seconds")


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS proxy_global_reliability (
            proxy_id TEXT PRIMARY KEY,
            first_tested_at TEXT NOT NULL,
            last_tested_at TEXT NOT NULL,
            first_confirmed_at TEXT,
            last_confirmed_at TEXT,
            last_failed_at TEXT,
            test_count INTEGER NOT NULL DEFAULT 0,
            confirmed_passes INTEGER NOT NULL DEFAULT 0,
            confirmed_failures INTEGER NOT NULL DEFAULT 0,
            consecutive_passes INTEGER NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            last_result TEXT NOT NULL CHECK(last_result IN ('pass','fail'))
        );
        CREATE INDEX IF NOT EXISTS idx_proxy_global_reliability_rank
            ON proxy_global_reliability(
                confirmed_passes DESC,
                consecutive_passes DESC,
                last_confirmed_at DESC
            );
        """
    )
    conn.commit()


def _deduplicated_ids(proxies: list[ProxyConfig]) -> set[str]:
    return {proxy.ensure_id() for proxy in proxies}


def update_global_reliability(
    db_path: Path,
    passed: list[ProxyConfig],
    failed: list[ProxyConfig],
    *,
    now: datetime | None = None,
) -> dict[str, int]:
    """Record one complete global test outcome per proxy.

    A proxy is counted at most once per call even when it carries provenance
    from multiple sources. Only actually tested proxies should be supplied:
    source absence or fetch failure by itself is not a reliability failure.
    """
    passed_ids = _deduplicated_ids(passed)
    failed_ids = _deduplicated_ids(failed)
    overlap = passed_ids & failed_ids
    if overlap:
        raise ValueError(
            "global reliability outcome is ambiguous for proxy ids: "
            + ", ".join(sorted(overlap)[:10])
        )

    observed_at = _iso_now(now)
    with _connect(db_path) as conn:
        for proxy_id in sorted(passed_ids):
            conn.execute(
                """
                INSERT INTO proxy_global_reliability(
                    proxy_id,
                    first_tested_at,
                    last_tested_at,
                    first_confirmed_at,
                    last_confirmed_at,
                    last_failed_at,
                    test_count,
                    confirmed_passes,
                    confirmed_failures,
                    consecutive_passes,
                    consecutive_failures,
                    last_result
                ) VALUES(?,?,?,?,?,NULL,1,1,0,1,0,?)
                ON CONFLICT(proxy_id) DO UPDATE SET
                    last_tested_at=excluded.last_tested_at,
                    first_confirmed_at=COALESCE(
                        proxy_global_reliability.first_confirmed_at,
                        excluded.first_confirmed_at
                    ),
                    last_confirmed_at=excluded.last_confirmed_at,
                    test_count=proxy_global_reliability.test_count + 1,
                    confirmed_passes=proxy_global_reliability.confirmed_passes + 1,
                    consecutive_passes=proxy_global_reliability.consecutive_passes + 1,
                    consecutive_failures=0,
                    last_result=excluded.last_result
                """,
                (
                    proxy_id,
                    observed_at,
                    observed_at,
                    observed_at,
                    observed_at,
                    RESULT_PASS,
                ),
            )

        for proxy_id in sorted(failed_ids):
            conn.execute(
                """
                INSERT INTO proxy_global_reliability(
                    proxy_id,
                    first_tested_at,
                    last_tested_at,
                    first_confirmed_at,
                    last_confirmed_at,
                    last_failed_at,
                    test_count,
                    confirmed_passes,
                    confirmed_failures,
                    consecutive_passes,
                    consecutive_failures,
                    last_result
                ) VALUES(?,?,?,NULL,NULL,?,1,0,1,0,1,?)
                ON CONFLICT(proxy_id) DO UPDATE SET
                    last_tested_at=excluded.last_tested_at,
                    last_failed_at=excluded.last_failed_at,
                    test_count=proxy_global_reliability.test_count + 1,
                    confirmed_failures=proxy_global_reliability.confirmed_failures + 1,
                    consecutive_passes=0,
                    consecutive_failures=proxy_global_reliability.consecutive_failures + 1,
                    last_result=excluded.last_result
                """,
                (
                    proxy_id,
                    observed_at,
                    observed_at,
                    observed_at,
                    RESULT_FAIL,
                ),
            )

    return {
        "tested": len(passed_ids) + len(failed_ids),
        "passed": len(passed_ids),
        "failed": len(failed_ids),
    }


def reliability_rows(db_path: Path) -> dict[str, dict]:
    if not db_path.is_file():
        return {}
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM proxy_global_reliability ORDER BY proxy_id"
        ).fetchall()
    return {str(row["proxy_id"]): dict(row) for row in rows}


def reliable_ids(
    db_path: Path,
    *,
    min_confirmed_passes: int = 3,
    min_consecutive_passes: int = 2,
) -> set[str]:
    if min_confirmed_passes < 1:
        raise ValueError("reliable.min_confirmed_passes must be at least 1")
    if min_consecutive_passes < 1:
        raise ValueError("reliable.min_consecutive_passes must be at least 1")
    if not db_path.is_file():
        return set()

    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT proxy_id
            FROM proxy_global_reliability
            WHERE confirmed_passes >= ?
              AND consecutive_passes >= ?
              AND last_result = 'pass'
            """,
            (min_confirmed_passes, min_consecutive_passes),
        ).fetchall()
    return {str(row["proxy_id"]) for row in rows}
