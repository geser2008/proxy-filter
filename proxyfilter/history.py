from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid
from typing import Any


SCHEMA_VERSION = 1

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


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    _init_schema(conn)
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
            tcp_ok INTEGER,
            tcp_latency_ms REAL,
            core_ok INTEGER,
            latency_ok INTEGER,
            latency_ms REAL,
            download_ok INTEGER,
            download_mbps REAL,
            download_backend TEXT,
            stream_reliability TEXT,
            upload_ok INTEGER,
            upload_mbps REAL,
            exit_ip_status TEXT,
            exit_ip TEXT,
            country_code TEXT,
            asn TEXT,
            published INTEGER NOT NULL DEFAULT 0,
            failure_stage TEXT,
            failure_reason TEXT,
            details_json TEXT,
            PRIMARY KEY (run_id, source_id, proxy_id),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_observations_source_proxy_time
            ON proxy_observations(source_id, proxy_id, observed_at);
        CREATE INDEX IF NOT EXISTS idx_observations_source_state_time
            ON proxy_observations(source_id, availability_state, observed_at);

        CREATE TABLE IF NOT EXISTS proxy_source_state (
            source_id TEXT NOT NULL,
            proxy_id TEXT NOT NULL,
            first_seen_at TEXT,
            last_seen_at TEXT,
            first_seen_run_id TEXT,
            last_seen_run_id TEXT,
            seen_count INTEGER NOT NULL DEFAULT 0,
            available_count INTEGER NOT NULL DEFAULT 0,
            unavailable_count INTEGER NOT NULL DEFAULT 0,
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


def _ok_status(status: str | None) -> int | None:
    if status is None or status == "pending":
        return None
    return 1 if status in {"pass", "ok"} else 0


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


def _details_json(row: dict[str, Any], store_details: str) -> str | None:
    mode = store_details.lower()
    if mode == "none":
        return None
    tests = row.get("tests") or {}
    final_status = tests.get("status")
    if mode == "failures" and final_status in {"published", "render_pass"}:
        return None
    if mode not in {"none", "failures", "all"}:
        raise ValueError("history.store_details must be one of: none, failures, all")
    payload = {
        "tests": tests,
        "config": row.get("config"),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _observation_values(
    *,
    run_id: str,
    source_id: str,
    observed_at: str,
    row: dict[str, Any],
    store_details: str,
) -> tuple[Any, ...]:
    tests = row.get("tests") or {}
    config = row.get("config") or {}
    tcp = tests.get("tcp") or {}
    core = tests.get("core") or {}
    latency = tests.get("latency") or {}
    download = tests.get("download") or {}
    upload = tests.get("upload") or {}
    exit_probe = tests.get("exit_ip_probe") or {}
    geo = tests.get("geo") or {}
    final_status = tests.get("status")
    availability = _availability_state(tests, final_status)
    published = 1 if final_status == "published" else 0
    return (
        run_id, source_id, str(row.get("id")), observed_at, 1, availability,
        final_status, _furthest_stage(tests, final_status), config.get("protocol"),
        config.get("server"), config.get("port"), _ok_status(tcp.get("status")),
        tcp.get("latency_ms"), _ok_status(core.get("status")),
        _ok_status(latency.get("status")), tests.get("latency_ms") or latency.get("latency_ms"),
        _ok_status(download.get("status")), tests.get("download_mbps") or download.get("mbps"),
        download.get("backend"), download.get("stream_reliability"),
        _ok_status(upload.get("status")), tests.get("upload_mbps") or upload.get("mbps"),
        exit_probe.get("status"), tests.get("exit_ip") or exit_probe.get("ip"),
        geo.get("country_code"), None if geo.get("asn") is None else str(geo.get("asn")),
        published, _failure_stage(final_status), _failure_reason(tests, final_status),
        _details_json(row, store_details),
    )


_OBS_COLUMNS = """
run_id, source_id, proxy_id, observed_at, present, availability_state,
final_status, furthest_stage, protocol, server, port, tcp_ok, tcp_latency_ms,
core_ok, latency_ok, latency_ms, download_ok, download_mbps, download_backend,
stream_reliability, upload_ok, upload_mbps, exit_ip_status, exit_ip,
country_code, asn, published, failure_stage, failure_reason, details_json
""".replace("\n", " ")


def _update_state(conn: sqlite3.Connection, source_id: str, proxy_id: str, run_id: str, observed_at: str, state: str, final_status: str | None, present: bool) -> None:
    current = conn.execute(
        "SELECT * FROM proxy_source_state WHERE source_id=? AND proxy_id=?",
        (source_id, proxy_id),
    ).fetchone()
    same_streak = current is not None and current["current_streak_state"] == state
    streak = (int(current["current_streak"]) + 1) if same_streak else 1

    if current is None:
        conn.execute(
            """
            INSERT INTO proxy_source_state(
                source_id, proxy_id, first_seen_at, last_seen_at, first_seen_run_id,
                last_seen_run_id, seen_count, available_count, unavailable_count,
                absent_count, last_status, last_availability_state, last_available_at,
                last_unavailable_at, current_streak, current_streak_state
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                source_id, proxy_id, observed_at if present else None, observed_at if present else None,
                run_id if present else None, run_id if present else None, 1 if present else 0,
                1 if state in {"available", "degraded"} and present else 0,
                1 if state in {"unavailable", "below_threshold"} and present else 0,
                0 if present else 1, final_status, state,
                observed_at if state in {"available", "degraded"} and present else None,
                observed_at if state in {"unavailable", "below_threshold"} and present else None,
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
            unavailable_count = unavailable_count + ?,
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
            1 if present else 0, observed_at, 1 if present else 0, run_id,
            1 if present else 0,
            1 if state in {"available", "degraded"} and present else 0,
            1 if state in {"unavailable", "below_threshold"} and present else 0,
            0 if present else 1, final_status, state,
            1 if state in {"available", "degraded"} and present else 0, observed_at,
            1 if state in {"unavailable", "below_threshold"} and present else 0, observed_at,
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
    store_details: str = "failures",
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

        placeholders = ",".join("?" for _ in range(30))
        insert_sql = f"INSERT INTO proxy_observations({_OBS_COLUMNS}) VALUES({placeholders})"
        for proxy_id in sorted(present_ids):
            row = latest.get(proxy_id)
            if row is None:
                continue
            values = _observation_values(
                run_id=run_id, source_id=source_id, observed_at=finished_at,
                row=row, store_details=store_details,
            )
            conn.execute(insert_sql, values)
            tests = row.get("tests") or {}
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
            conn.execute(
                f"INSERT INTO proxy_observations({_OBS_COLUMNS}) VALUES({placeholders})",
                (
                    run_id, source_id, proxy_id, finished_at, 0, "absent", "absent", None,
                    None, None, None, None, None, None, None, None, None, None, None,
                    None, None, None, None, None, None, None, 0, None, None, None,
                ),
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
