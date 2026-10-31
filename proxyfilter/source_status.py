from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_source_status_rows(sources: list[dict], summary: dict) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    results = summary.get("sources") or {}
    observed_at = utc_now()
    for source in sources:
        source_id = str(source.get("id") or "")
        source_name = str(source.get("name") or source_id)
        result = dict(results.get(source_id) or {})
        ok = result.get("status") == "ok"
        rows.append(
            {
                "source_id": source_id,
                "source_name": source_name,
                "url": source.get("url"),
                "status": "ok" if ok else "warning",
                "stage": "fetch",
                "reason": None if ok else "source_unavailable",
                "error": None if ok else str(result.get("error") or "source unavailable"),
                "fetched": ok,
                "parsed_count": int(result.get("parsed") or 0),
                "parse_errors": int(result.get("parse_errors") or 0),
                "format": result.get("format"),
                "observed_at": observed_at,
            }
        )
    return rows


def write_source_status(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


def warning_source_ids(rows: list[dict[str, Any]]) -> set[str]:
    return {
        str(row.get("source_id") or "")
        for row in rows
        if row.get("status") == "warning" and row.get("source_id")
    }


def apply_warning_summary(summary: dict, rows: list[dict[str, Any]]) -> dict:
    warnings = [row for row in rows if row.get("status") == "warning"]
    for row in rows:
        source_id = str(row.get("source_id") or "")
        if not source_id:
            continue
        result = summary.setdefault("sources", {}).setdefault(source_id, {})
        if row.get("status") == "warning":
            result.update(
                {
                    "status": "warning",
                    "stage": "fetch",
                    "reason": "source_unavailable",
                    "error": row.get("error"),
                    "fetched": False,
                }
            )
        else:
            result["fetched"] = True

    if warnings:
        pipeline = summary.setdefault("pipeline", {})
        if pipeline.get("status") != "error":
            pipeline["status"] = "warning"
        pipeline["warning_count"] = len(warnings)
        pipeline["unavailable_sources"] = [str(row.get("source_id")) for row in warnings]
    return summary
