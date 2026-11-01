from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sqlite3

from .history import _connect as history_connect
from .model import ProxyConfig


RESULT_PASS = "pass"
RESULT_FAIL = "fail"
DEFAULT_MIN_CONFIRMED_PASSES = 3
DEFAULT_MIN_CONSECUTIVE_PASSES = 2
RELIABLE_SCHEMA_VERSION = 1


def reliability_db_path(data_dir: Path, history_cfg: dict | None = None) -> Path:
    """Resolve the existing history database used by the rest of proxy-filter."""
    cfg = history_cfg or {}
    raw = cfg.get("database")
    if not raw:
        return data_dir / "history" / "proxy-history.sqlite3"
    path = Path(str(raw))
    return path if path.is_absolute() else data_dir / path


def _iso_now(now: datetime | None = None) -> str:
    value = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return value.isoformat(timespec="seconds")


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotently migrate the existing history DB with reliable-history tables.

    The core history schema remains owned by proxyfilter.history. This additive
    migration stores its own feature schema version so an existing history DB can
    be upgraded in place without rebuilding or losing per-source history.
    """
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS feature_schema_meta (
            feature TEXT PRIMARY KEY,
            version INTEGER NOT NULL
        );

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

        CREATE TABLE IF NOT EXISTS proxy_global_reliability_runs (
            run_key TEXT PRIMARY KEY,
            observed_at TEXT NOT NULL,
            passed_count INTEGER NOT NULL,
            failed_count INTEGER NOT NULL
        );
        """
    )
    row = conn.execute(
        "SELECT version FROM feature_schema_meta WHERE feature='global_reliability'"
    ).fetchone()
    version = int(row[0]) if row is not None else 0
    if version > RELIABLE_SCHEMA_VERSION:
        raise RuntimeError(
            f"global reliability schema v{version} is newer than supported "
            f"v{RELIABLE_SCHEMA_VERSION}"
        )
    conn.execute(
        """
        INSERT INTO feature_schema_meta(feature, version)
        VALUES('global_reliability', ?)
        ON CONFLICT(feature) DO UPDATE SET version=excluded.version
        """,
        (RELIABLE_SCHEMA_VERSION,),
    )
    conn.commit()


def _connect(path: Path) -> sqlite3.Connection:
    conn = history_connect(path)
    try:
        _ensure_schema(conn)
    except Exception:
        conn.close()
        raise
    return conn


def migrate_reliable_history(db_path: Path) -> None:
    """Apply the additive reliable-history migration to an existing history DB."""
    with _connect(db_path):
        pass


def _deduplicated_ids(proxies: list[ProxyConfig]) -> set[str]:
    return {proxy.ensure_id() for proxy in proxies}


def _read_proxy_jsonl(path: Path) -> list[ProxyConfig]:
    if not path.is_file():
        return []
    proxies: list[ProxyConfig] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON in {path}:{lineno}: {exc}") from exc
            if not isinstance(data, dict):
                raise ValueError(f"invalid record in {path}:{lineno}: expected JSON object")
            proxies.append(ProxyConfig.from_dict(data))
    return proxies


def terminal_outcomes_from_work(
    work_dir: Path,
    qualified: list[ProxyConfig],
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    """Derive one terminal PASS/FAIL outcome for every current-run candidate.

    ``02-unique.jsonl`` is the complete deduplicated candidate set for the current
    global run. A proxy that reaches ``12-qualified`` is a terminal PASS even if
    an earlier attempt was written to a rejected checkpoint and later recovered.
    Every remaining unique candidate is a terminal FAIL. This avoids treating
    stale rejected checkpoint files from previous runs as current failures.
    """
    unique_path = work_dir / "02-unique.jsonl"
    unique = _read_proxy_jsonl(unique_path)
    if not unique_path.is_file():
        raise FileNotFoundError(f"missing current-run unique snapshot: {unique_path}")

    unique_by_id = {proxy.ensure_id(): proxy for proxy in unique}
    qualified_by_id = {proxy.ensure_id(): proxy for proxy in qualified}
    missing = set(qualified_by_id) - set(unique_by_id)
    if missing:
        raise ValueError(
            "qualified proxy ids are missing from current-run unique snapshot: "
            + ", ".join(sorted(missing)[:10])
        )

    passed = [qualified_by_id[proxy_id] for proxy_id in sorted(qualified_by_id)]
    failed = [
        unique_by_id[proxy_id]
        for proxy_id in sorted(set(unique_by_id) - set(qualified_by_id))
    ]
    return passed, failed


def snapshot_run_key(
    work_dir: Path,
    passed: list[ProxyConfig],
    failed: list[ProxyConfig],
) -> str | None:
    """Identify one concrete global pipeline run for idempotent state updates.

    A fresh full run rewrites 01-parsed.jsonl. Resume-from-publish keeps the same
    snapshot, so its mtime plus the terminal outcome set is stable and prevents
    double-counting. If the parsed snapshot is unavailable, the caller should
    avoid an implicit reliability-state update.
    """
    parsed = work_dir / "01-parsed.jsonl"
    if not parsed.is_file():
        return None

    digest = hashlib.sha256()
    digest.update(str(parsed.stat().st_mtime_ns).encode("ascii"))
    digest.update(b"\0pass\0")
    for proxy_id in sorted(_deduplicated_ids(passed)):
        digest.update(proxy_id.encode("utf-8"))
        digest.update(b"\0")
    digest.update(b"fail\0")
    for proxy_id in sorted(_deduplicated_ids(failed)):
        digest.update(proxy_id.encode("utf-8"))
        digest.update(b"\0")
    return "global-" + digest.hexdigest()


def update_global_reliability(
    db_path: Path,
    passed: list[ProxyConfig],
    failed: list[ProxyConfig],
    *,
    now: datetime | None = None,
    run_key: str | None = None,
) -> dict[str, int]:
    """Record one complete global test outcome per proxy.

    A proxy is counted at most once per call even when it carries provenance
    from multiple sources. Only actually tested proxies should be supplied:
    source absence or fetch failure by itself is not a reliability failure.

    When ``run_key`` is supplied, replaying the same global snapshot is
    idempotent. This is required for resume-from-publish workflows.
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
        if run_key:
            exists = conn.execute(
                "SELECT 1 FROM proxy_global_reliability_runs WHERE run_key=?",
                (run_key,),
            ).fetchone()
            if exists is not None:
                return {"tested": 0, "passed": 0, "failed": 0, "skipped": 1}

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

        if run_key:
            conn.execute(
                """
                INSERT INTO proxy_global_reliability_runs(
                    run_key, observed_at, passed_count, failed_count
                ) VALUES(?,?,?,?)
                """,
                (run_key, observed_at, len(passed_ids), len(failed_ids)),
            )

    return {
        "tested": len(passed_ids) + len(failed_ids),
        "passed": len(passed_ids),
        "failed": len(failed_ids),
        "skipped": 0,
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
    min_confirmed_passes: int = DEFAULT_MIN_CONFIRMED_PASSES,
    min_consecutive_passes: int = DEFAULT_MIN_CONSECUTIVE_PASSES,
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
