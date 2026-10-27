from __future__ import annotations

from pathlib import Path

from .history import (
    _STAGE_FILES,
    _availability_state,
    _connect,
    _insert_latency_attempts,
    _insert_record,
    _insert_security_reasons,
    _insert_transfer_data,
    _observation_record,
    _record_run,
    _update_state,
    _read_jsonl,
    utc_now,
)
from .history_geo import sync_geo_history


def _row_source_ids(row: dict) -> set[str]:
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


def _belongs_to_source(row: dict, source_id: str) -> bool:
    return source_id in _row_source_ids(row)


def _source_rows(path: Path, source_id: str) -> list[dict]:
    return [row for row in _read_jsonl(path) if _belongs_to_source(row, source_id)]


def _source_ids(path: Path, source_id: str) -> set[str]:
    return {
        str(row.get("id"))
        for row in _source_rows(path, source_id)
        if row.get("id")
    }


def _latest_source_snapshots(work_dir: Path, source_id: str) -> tuple[dict[str, dict], set[str]]:
    latest: dict[str, dict] = {}
    for filename in _STAGE_FILES:
        for row in _source_rows(work_dir / filename, source_id):
            proxy_id = str(row.get("id") or "")
            if proxy_id:
                latest[proxy_id] = row

    # A proxy is present only if it was fetched from this source in this run.
    # Retained known-working candidates can still be present in later work files
    # because they are re-tested, but they must not masquerade as source input.
    present_ids = _source_ids(work_dir / "01-parsed.jsonl", source_id)
    return latest, present_ids


def _count_source_present(path: Path, source_id: str, present_ids: set[str]) -> int:
    return len(_source_ids(path, source_id) & present_ids)


def _source_published_reliability_counts(
    path: Path,
    source_id: str,
    present_ids: set[str],
) -> tuple[int, int]:
    stable = 0
    unstable = 0
    for row in _source_rows(path, source_id):
        if str(row.get("id") or "") not in present_ids:
            continue
        tests = row.get("tests") or {}
        reliability = tests.get("reliability") or {}
        status = str(
            reliability.get("status")
            or (tests.get("download") or {}).get("stream_reliability")
            or "stable"
        )
        if status == "degraded":
            unstable += 1
        else:
            stable += 1
    return stable, unstable


def _ensure_run_warnings_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS run_warnings (
            warning_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            source_id TEXT NOT NULL,
            stage TEXT NOT NULL,
            reason TEXT NOT NULL,
            message TEXT,
            error TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(run_id, source_id, stage, reason),
            FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_run_warnings_source_time
            ON run_warnings(source_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_run_warnings_reason
            ON run_warnings(reason, created_at);
        """
    )


def record_global_source_run(
    db_path: Path,
    *,
    run_id: str,
    source_id: str,
    source_name: str,
    work_dir: Path,
    started_at: str,
    finished_at: str | None = None,
    source_available: bool = True,
    run_status: str = "ok",
    run_error: str | None = None,
    warning_stage: str | None = None,
    warning_reason: str | None = None,
    warning_message: str | None = None,
) -> None:
    """Record one source view from the global pipeline into history.

    Presence is derived from the current 01-parsed snapshot only when the source
    was actually fetched. If source_available is false, retained proxies can still
    contribute test observations, but proxy_source_state is left untouched so a
    fetch outage never becomes a false source-absence event.
    """
    finished_at = finished_at or utc_now()
    latest, present_ids = _latest_source_snapshots(work_dir, source_id)
    if not source_available:
        present_ids = set()

    parsed_rows = _source_rows(work_dir / "01-parsed.jsonl", source_id)
    source_format = None
    if parsed_rows:
        source_format = (parsed_rows[0].get("source") or {}).get("format")
        for item in parsed_rows[0].get("sources") or []:
            if isinstance(item, dict) and str(item.get("id") or "") == source_id:
                source_format = item.get("format") or source_format
                break

    stable_count, unstable_count = _source_published_reliability_counts(
        work_dir / "14-published.jsonl",
        source_id,
        present_ids,
    )
    counts = {
        "parsed_count": len(present_ids),
        "unique_count": _count_source_present(work_dir / "02-unique.jsonl", source_id, present_ids),
        "security_pass_count": _count_source_present(work_dir / "03-safe.jsonl", source_id, present_ids),
        "tcp_pass_count": _count_source_present(work_dir / "04-tcp-ok.jsonl", source_id, present_ids),
        "core_pass_count": _count_source_present(work_dir / "05-core-ok.jsonl", source_id, present_ids),
        "latency_pass_count": _count_source_present(work_dir / "06-latency-ok.jsonl", source_id, present_ids),
        "download_pass_count": _count_source_present(work_dir / "07-download-ok.jsonl", source_id, present_ids),
        "upload_pass_count": _count_source_present(work_dir / "08-upload-ok.jsonl", source_id, present_ids),
        "qualified_count": _count_source_present(work_dir / "12-qualified.jsonl", source_id, present_ids),
        "diversity_selected_count": _count_source_present(work_dir / "13-diversity-selected.jsonl", source_id, present_ids),
        "diversity_suppressed_count": _count_source_present(work_dir / "13-diversity-suppressed.jsonl", source_id, present_ids),
        "published_count": _count_source_present(work_dir / "14-published.jsonl", source_id, present_ids),
        "stable_published_count": stable_count,
        "unstable_published_count": unstable_count,
    }

    with _connect(db_path) as conn:
        _ensure_run_warnings_schema(conn)
        _record_run(
            conn,
            run_id=run_id,
            source_id=source_id,
            source_name=source_name,
            started_at=started_at,
            finished_at=finished_at,
            source_format=source_format,
            counts=counts,
        )
        if run_status != "ok" or run_error:
            conn.execute(
                "UPDATE runs SET status=?, error=? WHERE run_id=?",
                (run_status, run_error, run_id),
            )
        if warning_reason:
            conn.execute(
                """
                INSERT INTO run_warnings(
                    run_id, source_id, stage, reason, message, error, created_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(run_id, source_id, stage, reason) DO UPDATE SET
                    message=excluded.message,
                    error=excluded.error,
                    created_at=excluded.created_at
                """,
                (
                    run_id,
                    source_id,
                    warning_stage or "fetch",
                    warning_reason,
                    warning_message,
                    run_error,
                    finished_at,
                ),
            )

        candidate_ids = set(latest)
        for proxy_id in sorted(candidate_ids):
            row = latest[proxy_id]
            present = source_available and proxy_id in present_ids
            observation_id = _insert_record(
                conn,
                "proxy_observations",
                _observation_record(
                    run_id=run_id,
                    source_id=source_id,
                    observed_at=finished_at,
                    row=row,
                    present=present,
                ),
            )
            tests = row.get("tests") or {}
            _insert_security_reasons(conn, observation_id, tests)
            _insert_latency_attempts(conn, observation_id, tests)
            _insert_transfer_data(conn, observation_id, tests, "download")
            _insert_transfer_data(conn, observation_id, tests, "upload")
            if source_available:
                state = _availability_state(tests, tests.get("status"))
                _update_state(
                    conn,
                    source_id,
                    proxy_id,
                    run_id,
                    finished_at,
                    state,
                    tests.get("status"),
                    present,
                )

        if source_available:
            previous_ids = {
                str(row[0])
                for row in conn.execute(
                    "SELECT proxy_id FROM proxy_source_state WHERE source_id=?",
                    (source_id,),
                )
            }
            for proxy_id in sorted(previous_ids - candidate_ids):
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
                _update_state(
                    conn,
                    source_id,
                    proxy_id,
                    run_id,
                    finished_at,
                    "absent",
                    "absent",
                    False,
                )

    # GeoIP fallback metadata is an additive schema extension. Sync after the
    # canonical observation transaction so existing databases upgrade in place.
    sync_geo_history(
        db_path,
        run_id=run_id,
        source_id=source_id,
        work_dir=work_dir,
    )
