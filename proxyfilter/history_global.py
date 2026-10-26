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
    _read_jsonl,
    _update_state,
    utc_now,
)


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


def _latest_source_snapshots(work_dir: Path, source_id: str) -> tuple[dict[str, dict], set[str]]:
    latest: dict[str, dict] = {}
    present_ids: set[str] = set()
    for filename in _STAGE_FILES:
        for row in _source_rows(work_dir / filename, source_id):
            proxy_id = str(row.get("id") or "")
            if not proxy_id:
                continue
            if filename == "02-unique.jsonl":
                present_ids.add(proxy_id)
            latest[proxy_id] = row
    return latest, present_ids


def record_global_source_run(
    db_path: Path,
    *,
    run_id: str,
    source_id: str,
    source_name: str,
    work_dir: Path,
    started_at: str,
    finished_at: str | None = None,
) -> None:
    """Record one source view from a global pipeline snapshot into schema v2.

    The database schema remains unchanged. Global work JSONL files are filtered
    by each proxy's existing ``source``/``sources`` provenance before the same
    per-source run and observation rows are written.
    """
    finished_at = finished_at or utc_now()
    latest, present_ids = _latest_source_snapshots(work_dir, source_id)
    unique_rows = _source_rows(work_dir / "02-unique.jsonl", source_id)
    source_format = None
    if unique_rows:
        matching = [
            item
            for item in (unique_rows[0].get("sources") or [])
            if isinstance(item, dict) and str(item.get("id") or "") == source_id
        ]
        if matching:
            source_format = matching[0].get("format")
        else:
            source_format = (unique_rows[0].get("source") or {}).get("format")

    counts = {
        "parsed_count": len(_source_rows(work_dir / "01-parsed.jsonl", source_id)),
        "unique_count": len(present_ids),
        "security_pass_count": len(_source_rows(work_dir / "03-safe.jsonl", source_id)),
        "tcp_pass_count": len(_source_rows(work_dir / "04-tcp-ok.jsonl", source_id)),
        "core_pass_count": len(_source_rows(work_dir / "05-core-ok.jsonl", source_id)),
        "latency_pass_count": len(_source_rows(work_dir / "06-latency-ok.jsonl", source_id)),
        "download_pass_count": len(_source_rows(work_dir / "07-download-ok.jsonl", source_id)),
        "upload_pass_count": len(_source_rows(work_dir / "08-upload-ok.jsonl", source_id)),
        "published_count": len(_source_rows(work_dir / "12-published.jsonl", source_id)),
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
