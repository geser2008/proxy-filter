from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any

from .history import _STAGE_FILES, _read_jsonl


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def ensure_geo_history_schema(conn: sqlite3.Connection) -> None:
    if "geo_fallback_used" not in _column_names(conn, "proxy_observations"):
        conn.execute("ALTER TABLE proxy_observations ADD COLUMN geo_fallback_used INTEGER")

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS geo_attempts (
            observation_id INTEGER NOT NULL,
            attempt_index INTEGER NOT NULL,
            provider TEXT,
            url TEXT,
            ok INTEGER,
            http_code INTEGER,
            reason TEXT,
            error TEXT,
            PRIMARY KEY (observation_id, attempt_index),
            FOREIGN KEY (observation_id) REFERENCES proxy_observations(observation_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_geo_attempts_observation
            ON geo_attempts(observation_id, attempt_index);
        CREATE INDEX IF NOT EXISTS idx_geo_attempts_provider
            ON geo_attempts(provider);
        """
    )

    # Keep the convenience view aligned with the additive GeoIP fields. The
    # canonical schema version remains v3; these columns/tables are a compatible
    # extension and existing v3 databases are upgraded in place.
    conn.execute("DROP VIEW IF EXISTS history")
    conn.execute(
        """
        CREATE VIEW history AS
        SELECT
            run_id, source_id, proxy_id, observed_at, present,
            availability_state, final_status, furthest_stage,
            protocol, server, port,
            latency_ms, latency_reason,
            download_mbps, download_reason,
            upload_mbps, upload_reason,
            reliability_status, reliability_reason,
            reliability_provider_fallback, reliability_mixed_stage_outcomes,
            exit_ip, exit_ip_reason,
            geo_provider, geo_fallback_used, geo_reason, geo_error,
            country_code, asn,
            diversity_status, diversity_reason,
            published, failure_stage, failure_reason
        FROM proxy_observations
        """
    )
    conn.commit()


def _row_source_ids(row: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    source = row.get("source") or {}
    if isinstance(source, dict):
        source_id = str(source.get("id") or "")
        if source_id:
            result.add(source_id)
    for item in row.get("sources") or []:
        if isinstance(item, dict):
            source_id = str(item.get("id") or "")
            if source_id:
                result.add(source_id)
    return result


def _latest_source_rows(work_dir: Path, source_id: str) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for filename in _STAGE_FILES:
        for row in _read_jsonl(work_dir / filename):
            proxy_id = str(row.get("id") or "")
            if proxy_id and source_id in _row_source_ids(row):
                latest[proxy_id] = row
    return latest


def sync_geo_history(
    db_path: Path,
    *,
    run_id: str,
    source_id: str,
    work_dir: Path,
) -> None:
    latest = _latest_source_rows(work_dir, source_id)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        ensure_geo_history_schema(conn)
        for proxy_id, row in latest.items():
            found = conn.execute(
                "SELECT observation_id FROM proxy_observations WHERE run_id=? AND source_id=? AND proxy_id=?",
                (run_id, source_id, proxy_id),
            ).fetchone()
            if found is None:
                continue
            observation_id = int(found[0])
            geo = (row.get("tests") or {}).get("geo") or {}
            conn.execute(
                """
                UPDATE proxy_observations
                SET geo_provider=?, geo_fallback_used=?, geo_reason=?, geo_error=?
                WHERE observation_id=?
                """,
                (
                    geo.get("provider"),
                    None if geo.get("fallback_used") is None else (1 if geo.get("fallback_used") else 0),
                    geo.get("reason"),
                    geo.get("error"),
                    observation_id,
                ),
            )
            conn.execute("DELETE FROM geo_attempts WHERE observation_id=?", (observation_id,))
            for index, attempt in enumerate(geo.get("attempts") or []):
                conn.execute(
                    """
                    INSERT INTO geo_attempts(
                        observation_id, attempt_index, provider, url, ok, http_code, reason, error
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        observation_id,
                        index,
                        attempt.get("provider"),
                        attempt.get("url"),
                        None if attempt.get("ok") is None else (1 if attempt.get("ok") else 0),
                        attempt.get("http_code"),
                        attempt.get("reason"),
                        attempt.get("error"),
                    ),
                )
        conn.commit()
    finally:
        conn.close()
