from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import uuid
from typing import Any


SCHEMA_VERSION = 2

# Ordered snapshots. Later files contain more complete test state for survivors;
# rejected files are the terminal snapshot for proxies that fail that stage.
_STAGE_FILES = (
    "02-unique.jsonl",
    "03-safe.jsonl",
    "03-rejected-security.jsonl",
    "04-tcp-ok.jsonl",
    "04-rejected-tcp.jsonl",
    "05-core-ok.jsonl",
    "05-rejected-core.jsonl",
    "06-latency-ok.jsonl",
    "06-rejected-latency.jsonl",
    "07-download-ok.jsonl",
    "07-rejected-download.jsonl",
    "08-upload-ok.jsonl",
    "08-rejected-upload.jsonl",
    "09-exit-ip-ok.jsonl",
    "09-rejected-exit-ip.jsonl",
    "10-geo.jsonl",
    "11-render-ok.jsonl",
    "11-rejected-render.jsonl",
    "12-published.jsonl",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_run_id(source_id: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{source_id}-{uuid.uuid4().hex[:8]}"


def _existing_schema_version(conn: sqlite3.Connection) -> int | None:
    meta_exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'"
    ).fetchone()
    if not meta_exists:
        populated = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name IN ('runs','proxy_observations') LIMIT 1"
        ).fetchone()
        if populated:
            raise RuntimeError(
                "history database has an unknown legacy schema; move it to a backup path "
                "and create a fresh schema v2 database"
            )
        return None
    row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
    return int(row[0]) if row is not None else None


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    try:
        version = _existing_schema_version(conn)
        if version not in {None, SCHEMA_VERSION}:
            raise RuntimeError(
                f"history database schema v{version} is incompatible with schema v{SCHEMA_VERSION}; "
                "move the old database to a backup path and import the existing JSONL snapshot "
                "with --history-import"
            )
        _init_schema(conn)
    except Exception:
        conn.close()
        raise
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            source_id TEXT NOT NULL,
            source_name TEXT,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status TEXT NOT NULL,
            source_format TEXT,
            parsed_count INTEGER,
            unique_count INTEGER,
            security_pass_count INTEGER,
            tcp_pass_count INTEGER,
            core_pass_count INTEGER,
            latency_pass_count INTEGER,
            download_pass_count INTEGER,
            upload_pass_count INTEGER,
            published_count INTEGER,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_source_finished
            ON runs(source_id, finished_at);

        CREATE TABLE IF NOT EXISTS proxy_observations (
            observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            proxy_id TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            present INTEGER NOT NULL,
            availability_state TEXT NOT NULL,
            final_status TEXT,
            furthest_stage TEXT,

            protocol TEXT,
            server TEXT,
            port INTEGER,
            proxy_name TEXT,
            config_params_json TEXT,
            original_format TEXT,
            original_raw TEXT,

            security_status TEXT,
            tcp_status TEXT,
            tcp_latency_ms REAL,
            tcp_reason TEXT,
            tcp_error TEXT,
            core_status TEXT,
            core_error TEXT,

            latency_status TEXT,
            latency_ms REAL,
            latency_http_code INTEGER,
            latency_method TEXT,
            latency_error TEXT,

            download_status TEXT,
            download_mbps REAL,
            download_single_mbps REAL,
            download_aggregate_mbps REAL,
            download_best_partial_mbps REAL,
            download_best_partial_streams INTEGER,
            download_best_partial_backend TEXT,
            download_backend TEXT,
            download_bytes INTEGER,
            download_expected_bytes INTEGER,
            download_payload_valid INTEGER,
            download_time_seconds REAL,
            download_http_code INTEGER,
            download_url TEXT,
            download_method TEXT,
            stream_reliability TEXT,
            download_error TEXT,

            upload_status TEXT,
            upload_mbps REAL,
            upload_single_mbps REAL,
            upload_aggregate_mbps REAL,
            upload_best_partial_mbps REAL,
            upload_best_partial_streams INTEGER,
            upload_bytes INTEGER,
            upload_expected_bytes INTEGER,
            upload_payload_valid INTEGER,
            upload_time_seconds REAL,
            upload_http_code INTEGER,
            upload_url TEXT,
            upload_method TEXT,
            upload_error TEXT,

            exit_ip_status TEXT,
            exit_ip TEXT,
            exit_ip_http_code INTEGER,
            exit_ip_direct_wan_match INTEGER,
            exit_ip_method TEXT,
            exit_ip_error TEXT,

            geo_status TEXT,
            geo_provider TEXT,
            geo_ip TEXT,
            country TEXT,
            country_code TEXT,
            country_flag TEXT,
            isp TEXT,
            org TEXT,
            asn TEXT,
            geo_error TEXT,

            render_status TEXT,
            render_name TEXT,
            render_uri TEXT,
            render_stream_reliability TEXT,
            render_error TEXT,

            diversity_status TEXT,
            diversity_reason TEXT,
            diversity_cluster_type TEXT,
            diversity_cluster_key TEXT,
            diversity_cluster_size INTEGER,
            diversity_download_rank INTEGER,
            diversity_upload_rank INTEGER,
            diversity_latency_rank INTEGER,
            diversity_rank_sum INTEGER,
            diversity_overall_rank INTEGER,

            published INTEGER NOT NULL DEFAULT 0,
            failure_stage TEXT,
            failure_reason TEXT,

            UNIQUE(run_id, source_id, proxy_id),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_observations_source_proxy_time
            ON proxy_observations(source_id, proxy_id, observed_at);
        CREATE INDEX IF NOT EXISTS idx_observations_source_state_time
            ON proxy_observations(source_id, availability_state, observed_at);
        CREATE INDEX IF NOT EXISTS idx_observations_run
            ON proxy_observations(run_id);

        CREATE TABLE IF NOT EXISTS security_reasons (
            observation_id INTEGER NOT NULL,
            reason_index INTEGER NOT NULL,
            reason TEXT NOT NULL,
            PRIMARY KEY (observation_id, reason_index),
            FOREIGN KEY (observation_id) REFERENCES proxy_observations(observation_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS latency_attempts (
            observation_id INTEGER NOT NULL,
            attempt_index INTEGER NOT NULL,
            ok INTEGER,
            latency_ms REAL,
            http_code INTEGER,
            error TEXT,
            PRIMARY KEY (observation_id, attempt_index),
            FOREIGN KEY (observation_id) REFERENCES proxy_observations(observation_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS transfer_stages (
            stage_id INTEGER PRIMARY KEY AUTOINCREMENT,
            observation_id INTEGER NOT NULL,
            direction TEXT NOT NULL CHECK(direction IN ('download','upload')),
            stage_index INTEGER NOT NULL,
            backend TEXT,
            streams INTEGER,
            skipped INTEGER,
            ok INTEGER,
            classification TEXT,
            mbps REAL,
            bytes INTEGER,
            expected_bytes INTEGER,
            payload_valid INTEGER,
            time_seconds REAL,
            http_code INTEGER,
            error TEXT,
            UNIQUE(observation_id, direction, stage_index),
            FOREIGN KEY (observation_id) REFERENCES proxy_observations(observation_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_transfer_stages_observation
            ON transfer_stages(observation_id, direction, stage_index);

        CREATE TABLE IF NOT EXISTS transfer_attempts (
            attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
            stage_id INTEGER NOT NULL,
            attempt_index INTEGER NOT NULL,
            backend TEXT,
            url TEXT,
            ok INTEGER,
            mbps REAL,
            bytes INTEGER,
            expected_bytes INTEGER,
            payload_valid INTEGER,
            time_seconds REAL,
            http_code INTEGER,
            error_code INTEGER,
            error TEXT,
            expect_disabled INTEGER,
            UNIQUE(stage_id, attempt_index),
            FOREIGN KEY (stage_id) REFERENCES transfer_stages(stage_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_transfer_attempts_stage
            ON transfer_attempts(stage_id, attempt_index);
        CREATE INDEX IF NOT EXISTS idx_transfer_attempts_error_code
            ON transfer_attempts(error_code);

        CREATE TABLE IF NOT EXISTS proxy_source_state (
            source_id TEXT NOT NULL,
            proxy_id TEXT NOT NULL,
            first_seen_at TEXT,
            last_seen_at TEXT,
            first_seen_run_id TEXT,
            last_seen_run_id TEXT,
            seen_count INTEGER NOT NULL DEFAULT 0,
            available_count INTEGER NOT NULL DEFAULT 0,
            degraded_count INTEGER NOT NULL DEFAULT 0,
            unavailable_count INTEGER NOT NULL DEFAULT 0,
            below_threshold_count INTEGER NOT NULL DEFAULT 0,
            absent_count INTEGER NOT NULL DEFAULT 0,
            last_status TEXT,
            last_availability_state TEXT,
            last_available_at TEXT,
            last_unavailable_at TEXT,
            current_streak INTEGER NOT NULL DEFAULT 0,
            current_streak_state TEXT,
            PRIMARY KEY (source_id, proxy_id)
        );
        CREATE INDEX IF NOT EXISTS idx_proxy_source_last_seen
            ON proxy_source_state(source_id, last_seen_at);

        CREATE VIEW IF NOT EXISTS history AS
        SELECT
            run_id, source_id, proxy_id, observed_at, present,
            availability_state, final_status, furthest_stage,
            protocol, server, port,
            latency_ms, download_mbps, upload_mbps,
            stream_reliability, exit_ip, country_code, asn,
            published, failure_stage, failure_reason
        FROM proxy_observations;
        """
    )
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),),
    )
    conn.commit()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _latest_snapshots(work_dir: Path) -> tuple[dict[str, dict[str, Any]], set[str]]:
    latest: dict[str, dict[str, Any]] = {}
    present_ids: set[str] = set()
    for filename in _STAGE_FILES:
        for row in _read_jsonl(work_dir / filename):
            proxy_id = str(row.get("id") or "")
            if not proxy_id:
                continue
            if filename == "02-unique.jsonl":
                present_ids.add(proxy_id)
            latest[proxy_id] = row
    return latest, present_ids


def _count(path: Path) -> int:
    return len(_read_jsonl(path))


def _test_status(tests: dict[str, Any], name: str) -> str | None:
    value = tests.get(name)
    return value.get("status") if isinstance(value, dict) else None


def _bool_int(value: Any) -> int | None:
    if value is None:
        return None
    return 1 if bool(value) else 0


def _furthest_stage(tests: dict[str, Any], final_status: str | None) -> str | None:
    if final_status == "published":
        return "publish"
    ordered = (
        ("render", "render"),
        ("geo", "geo"),
        ("exit_ip_probe", "exit-ip"),
        ("upload", "upload"),
        ("download", "download"),
        ("latency", "latency"),
        ("core", "core"),
        ("tcp", "tcp"),
        ("security", "security"),
    )
    for key, label in ordered:
        status = _test_status(tests, key)
        if status and status != "pending":
            return label
    return None


def _failure_stage(final_status: str | None) -> str | None:
    if not final_status:
        return None
    if final_status.startswith("rejected_"):
        return final_status.removeprefix("rejected_").replace("_threshold", "").replace("_error", "")
    if final_status == "excluded_unreliable":
        return "render"
    return None


def _failure_reason(tests: dict[str, Any], final_status: str | None) -> str | None:
    stage = _failure_stage(final_status)
    key = "exit_ip_probe" if stage == "exit-ip" else stage
    if key and isinstance(tests.get(key), dict):
        data = tests[key]
        return data.get("error") or data.get("reason") or final_status
    return final_status if stage else None


def _availability_state(tests: dict[str, Any], final_status: str | None) -> str:
    reliability = str((tests.get("download") or {}).get("stream_reliability") or "stable")
    if final_status == "excluded_unreliable" or reliability == "degraded" and final_status in {"render_pass", "published"}:
        return "degraded"
    if final_status in {"render_pass", "published"}:
        return "available"
    if final_status in {"rejected_download_threshold", "rejected_upload_threshold"}:
        return "below_threshold"
    return "unavailable"


def _json_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _observation_record(
    *,
    run_id: str,
    source_id: str,
    observed_at: str,
    row: dict[str, Any],
) -> dict[str, Any]:
    tests = row.get("tests") or {}
    config = row.get("config") or {}
    original = row.get("original") or {}
    security = tests.get("security") or {}
    tcp = tests.get("tcp") or {}
    core = tests.get("core") or {}
    latency = tests.get("latency") or {}
    download = tests.get("download") or {}
    upload = tests.get("upload") or {}
    exit_probe = tests.get("exit_ip_probe") or {}
    geo = tests.get("geo") or {}
    render = tests.get("render") or {}
    diversity = tests.get("diversity") or {}
    final_status = tests.get("status")

    return {
        "run_id": run_id,
        "source_id": source_id,
        "proxy_id": str(row.get("id")),
        "observed_at": observed_at,
        "present": 1,
        "availability_state": _availability_state(tests, final_status),
        "final_status": final_status,
        "furthest_stage": _furthest_stage(tests, final_status),
        "protocol": config.get("protocol"),
        "server": config.get("server"),
        "port": config.get("port"),
        "proxy_name": config.get("name"),
        "config_params_json": _json_or_none(config.get("params")),
        "original_format": original.get("format"),
        "original_raw": original.get("raw"),
        "security_status": security.get("status"),
        "tcp_status": tcp.get("status"),
        "tcp_latency_ms": tcp.get("latency_ms"),
        "tcp_reason": tcp.get("reason"),
        "tcp_error": tcp.get("error"),
        "core_status": core.get("status"),
        "core_error": core.get("error"),
        "latency_status": latency.get("status"),
        "latency_ms": tests.get("latency_ms") if tests.get("latency_ms") is not None else latency.get("latency_ms"),
        "latency_http_code": latency.get("http_code"),
        "latency_method": latency.get("method"),
        "latency_error": latency.get("error"),
        "download_status": download.get("status"),
        "download_mbps": tests.get("download_mbps") if tests.get("download_mbps") is not None else download.get("mbps"),
        "download_single_mbps": download.get("single_mbps"),
        "download_aggregate_mbps": download.get("aggregate_mbps"),
        "download_best_partial_mbps": download.get("best_partial_mbps"),
        "download_best_partial_streams": download.get("best_partial_streams"),
        "download_best_partial_backend": download.get("best_partial_backend"),
        "download_backend": download.get("backend"),
        "download_bytes": download.get("bytes"),
        "download_expected_bytes": download.get("expected_bytes"),
        "download_payload_valid": _bool_int(download.get("payload_valid")),
        "download_time_seconds": download.get("time_seconds"),
        "download_http_code": download.get("http_code"),
        "download_url": download.get("url"),
        "download_method": download.get("method"),
        "stream_reliability": download.get("stream_reliability"),
        "download_error": download.get("error"),
        "upload_status": upload.get("status"),
        "upload_mbps": tests.get("upload_mbps") if tests.get("upload_mbps") is not None else upload.get("mbps"),
        "upload_single_mbps": upload.get("single_mbps"),
        "upload_aggregate_mbps": upload.get("aggregate_mbps"),
        "upload_best_partial_mbps": upload.get("best_partial_mbps"),
        "upload_best_partial_streams": upload.get("best_partial_streams"),
        "upload_bytes": upload.get("bytes"),
        "upload_expected_bytes": upload.get("expected_bytes"),
        "upload_payload_valid": _bool_int(upload.get("payload_valid")),
        "upload_time_seconds": upload.get("time_seconds"),
        "upload_http_code": upload.get("http_code"),
        "upload_url": upload.get("url"),
        "upload_method": upload.get("method"),
        "upload_error": upload.get("error"),
        "exit_ip_status": exit_probe.get("status"),
        "exit_ip": tests.get("exit_ip") or exit_probe.get("ip"),
        "exit_ip_http_code": exit_probe.get("http_code"),
        "exit_ip_direct_wan_match": _bool_int(exit_probe.get("direct_wan_match")),
        "exit_ip_method": exit_probe.get("method"),
        "exit_ip_error": exit_probe.get("error"),
        "geo_status": geo.get("status"),
        "geo_provider": geo.get("provider"),
        "geo_ip": geo.get("ip"),
        "country": geo.get("country") or tests.get("country"),
        "country_code": geo.get("country_code"),
        "country_flag": geo.get("flag"),
        "isp": geo.get("isp"),
        "org": geo.get("org"),
        "asn": None if geo.get("asn") is None else str(geo.get("asn")),
        "geo_error": geo.get("error"),
        "render_status": render.get("status"),
        "render_name": render.get("name"),
        "render_uri": render.get("uri"),
        "render_stream_reliability": render.get("stream_reliability"),
        "render_error": render.get("error"),
        "diversity_status": diversity.get("status"),
        "diversity_reason": diversity.get("reason"),
        "diversity_cluster_type": diversity.get("cluster_type"),
        "diversity_cluster_key": diversity.get("cluster_key"),
        "diversity_cluster_size": diversity.get("cluster_size"),
        "diversity_download_rank": diversity.get("download_rank"),
        "diversity_upload_rank": diversity.get("upload_rank"),
        "diversity_latency_rank": diversity.get("latency_rank"),
        "diversity_rank_sum": diversity.get("rank_sum"),
        "diversity_overall_rank": diversity.get("overall_rank"),
        "published": 1 if final_status == "published" else 0,
        "failure_stage": _failure_stage(final_status),
        "failure_reason": _failure_reason(tests, final_status),
    }


def _insert_record(conn: sqlite3.Connection, table: str, record: dict[str, Any]) -> int:
    columns = list(record)
    placeholders = ",".join("?" for _ in columns)
    cursor = conn.execute(
        f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})",
        tuple(record[column] for column in columns),
    )
    return int(cursor.lastrowid)


def _curl_error_code(error: Any) -> int | None:
    if not error:
        return None
    match = re.search(r"curl:\s*\((\d+)\)", str(error))
    return int(match.group(1)) if match else None


def _insert_security_reasons(conn: sqlite3.Connection, observation_id: int, tests: dict[str, Any]) -> None:
    reasons = (tests.get("security") or {}).get("reasons") or []
    for index, reason in enumerate(reasons):
        conn.execute(
            "INSERT INTO security_reasons(observation_id, reason_index, reason) VALUES(?,?,?)",
            (observation_id, index, str(reason)),
        )


def _insert_latency_attempts(conn: sqlite3.Connection, observation_id: int, tests: dict[str, Any]) -> None:
    attempts = (tests.get("latency") or {}).get("attempts") or []
    for index, attempt in enumerate(attempts):
        conn.execute(
            """
            INSERT INTO latency_attempts(
                observation_id, attempt_index, ok, latency_ms, http_code, error
            ) VALUES(?,?,?,?,?,?)
            """,
            (
                observation_id,
                index,
                _bool_int(attempt.get("ok")),
                attempt.get("latency_ms"),
                attempt.get("http_code"),
                attempt.get("error"),
            ),
        )


def _insert_transfer_data(
    conn: sqlite3.Connection,
    observation_id: int,
    tests: dict[str, Any],
    direction: str,
) -> None:
    result = tests.get(direction) or {}
    stages = result.get("stages") or []
    for stage_index, stage in enumerate(stages):
        stage_id = _insert_record(
            conn,
            "transfer_stages",
            {
                "observation_id": observation_id,
                "direction": direction,
                "stage_index": stage_index,
                "backend": stage.get("backend"),
                "streams": stage.get("streams"),
                "skipped": _bool_int(stage.get("skipped")),
                "ok": _bool_int(stage.get("ok")),
                "classification": stage.get("classification"),
                "mbps": stage.get("mbps"),
                "bytes": stage.get("bytes"),
                "expected_bytes": stage.get("expected_bytes"),
                "payload_valid": _bool_int(stage.get("payload_valid")),
                "time_seconds": stage.get("time_seconds"),
                "http_code": stage.get("http_code"),
                "error": stage.get("error"),
            },
        )
        for attempt_index, attempt in enumerate(stage.get("stream_results") or []):
            _insert_record(
                conn,
                "transfer_attempts",
                {
                    "stage_id": stage_id,
                    "attempt_index": attempt_index,
                    "backend": attempt.get("backend"),
                    "url": attempt.get("url"),
                    "ok": _bool_int(attempt.get("ok")),
                    "mbps": attempt.get("mbps"),
                    "bytes": attempt.get("bytes"),
                    "expected_bytes": attempt.get("expected_bytes"),
                    "payload_valid": _bool_int(attempt.get("payload_valid")),
                    "time_seconds": attempt.get("time_seconds"),
                    "http_code": attempt.get("http_code"),
                    "error_code": _curl_error_code(attempt.get("error")),
                    "error": attempt.get("error"),
                    "expect_disabled": _bool_int(attempt.get("expect_disabled")),
                },
            )


def _update_state(
    conn: sqlite3.Connection,
    source_id: str,
    proxy_id: str,
    run_id: str,
    observed_at: str,
    state: str,
    final_status: str | None,
    present: bool,
) -> None:
    current = conn.execute(
        "SELECT * FROM proxy_source_state WHERE source_id=? AND proxy_id=?",
        (source_id, proxy_id),
    ).fetchone()
    same_streak = current is not None and current["current_streak_state"] == state
    streak = (int(current["current_streak"]) + 1) if same_streak else 1
    available = state in {"available", "degraded"} and present
    degraded = state == "degraded" and present
    unavailable = state in {"unavailable", "below_threshold"} and present
    below_threshold = state == "below_threshold" and present

    if current is None:
        conn.execute(
            """
            INSERT INTO proxy_source_state(
                source_id, proxy_id, first_seen_at, last_seen_at, first_seen_run_id,
                last_seen_run_id, seen_count, available_count, degraded_count,
                unavailable_count, below_threshold_count, absent_count,
                last_status, last_availability_state, last_available_at,
                last_unavailable_at, current_streak, current_streak_state
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                source_id, proxy_id,
                observed_at if present else None, observed_at if present else None,
                run_id if present else None, run_id if present else None,
                1 if present else 0,
                1 if available else 0,
                1 if degraded else 0,
                1 if unavailable else 0,
                1 if below_threshold else 0,
                0 if present else 1,
                final_status, state,
                observed_at if available else None,
                observed_at if unavailable else None,
                streak, state,
            ),
        )
        return

    conn.execute(
        """
        UPDATE proxy_source_state SET
            last_seen_at = CASE WHEN ? THEN ? ELSE last_seen_at END,
            last_seen_run_id = CASE WHEN ? THEN ? ELSE last_seen_run_id END,
            seen_count = seen_count + ?,
            available_count = available_count + ?,
            degraded_count = degraded_count + ?,
            unavailable_count = unavailable_count + ?,
            below_threshold_count = below_threshold_count + ?,
            absent_count = absent_count + ?,
            last_status = ?,
            last_availability_state = ?,
            last_available_at = CASE WHEN ? THEN ? ELSE last_available_at END,
            last_unavailable_at = CASE WHEN ? THEN ? ELSE last_unavailable_at END,
            current_streak = ?,
            current_streak_state = ?
        WHERE source_id=? AND proxy_id=?
        """,
        (
            1 if present else 0, observed_at,
            1 if present else 0, run_id,
            1 if present else 0,
            1 if available else 0,
            1 if degraded else 0,
            1 if unavailable else 0,
            1 if below_threshold else 0,
            0 if present else 1,
            final_status, state,
            1 if available else 0, observed_at,
            1 if unavailable else 0, observed_at,
            streak, state, source_id, proxy_id,
        ),
    )


def record_source_run(
    db_path: Path,
    *,
    run_id: str,
    source_id: str,
    source_name: str,
    work_dir: Path,
    started_at: str,
    finished_at: str | None = None,
) -> None:
    finished_at = finished_at or utc_now()
    latest, present_ids = _latest_snapshots(work_dir)
    unique_rows = _read_jsonl(work_dir / "02-unique.jsonl")
    source_format = None
    if unique_rows:
        source_format = (unique_rows[0].get("source") or {}).get("format")

    counts = {
        "parsed_count": _count(work_dir / "01-parsed.jsonl"),
        "unique_count": len(present_ids),
        "security_pass_count": _count(work_dir / "03-safe.jsonl"),
        "tcp_pass_count": _count(work_dir / "04-tcp-ok.jsonl"),
        "core_pass_count": _count(work_dir / "05-core-ok.jsonl"),
        "latency_pass_count": _count(work_dir / "06-latency-ok.jsonl"),
        "download_pass_count": _count(work_dir / "07-download-ok.jsonl"),
        "upload_pass_count": _count(work_dir / "08-upload-ok.jsonl"),
        "published_count": _count(work_dir / "12-published.jsonl"),
    }

    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs(
                run_id, source_id, source_name, started_at, finished_at, status,
                source_format, parsed_count, unique_count, security_pass_count,
                tcp_pass_count, core_pass_count, latency_pass_count,
                download_pass_count, upload_pass_count, published_count, error
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)
            """,
            (
                run_id, source_id, source_name, started_at, finished_at, "ok", source_format,
                counts["parsed_count"], counts["unique_count"], counts["security_pass_count"],
                counts["tcp_pass_count"], counts["core_pass_count"], counts["latency_pass_count"],
                counts["download_pass_count"], counts["upload_pass_count"], counts["published_count"],
            ),
        )

        for proxy_id in sorted(present_ids):
            row = latest.get(proxy_id)
            if row is None:
                continue
            observation_id = _insert_record(
                conn,
                "proxy_observations",
                _observation_record(
                    run_id=run_id,
                    source_id=source_id,
                    observed_at=finished_at,
                    row=row,
                ),
            )
            tests = row.get("tests") or {}
            _insert_security_reasons(conn, observation_id, tests)
            _insert_latency_attempts(conn, observation_id, tests)
            _insert_transfer_data(conn, observation_id, tests, "download")
            _insert_transfer_data(conn, observation_id, tests, "upload")
            state = _availability_state(tests, tests.get("status"))
            _update_state(conn, source_id, proxy_id, run_id, finished_at, state, tests.get("status"), True)

        previous_ids = {
            str(row[0])
            for row in conn.execute(
                "SELECT proxy_id FROM proxy_source_state WHERE source_id=?",
                (source_id,),
            )
        }
        for proxy_id in sorted(previous_ids - present_ids):
            _insert_record(
                conn,
                "proxy_observations",
                {
                    "run_id": run_id,
                    "source_id": source_id,
                    "proxy_id": proxy_id,
                    "observed_at": finished_at,
                    "present": 0,
                    "availability_state": "absent",
                    "final_status": "absent",
                    "published": 0,
                },
            )
            _update_state(conn, source_id, proxy_id, run_id, finished_at, "absent", "absent", False)


def record_failed_run(
    db_path: Path,
    *,
    run_id: str,
    source_id: str,
    source_name: str,
    started_at: str,
    error: str,
    finished_at: str | None = None,
) -> None:
    finished_at = finished_at or utc_now()
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs(run_id, source_id, source_name, started_at, finished_at, status, error)
            VALUES(?,?,?,?,?,?,?)
            """,
            (run_id, source_id, source_name, started_at, finished_at, "error", error),
        )
