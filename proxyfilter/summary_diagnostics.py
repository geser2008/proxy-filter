from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Any


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    result: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            text = line.strip()
            if not text:
                continue
            try:
                item = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                result.append(item)
    return result


def _tests(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("tests")
    return value if isinstance(value, dict) else {}


def _counts(items: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(items).items()))


def _stage_reason(record: dict[str, Any], stage: str, default: str) -> str:
    details = _tests(record).get(stage)
    if isinstance(details, dict):
        reason = details.get("reason")
        if reason:
            return str(reason)
        reasons = details.get("reasons")
        if isinstance(reasons, list) and reasons:
            return str(reasons[0])
    return default


def build_diagnostics(data_dir: Path) -> dict[str, Any]:
    work = data_dir / "work"

    security_ok = _records(work / "03-safe.jsonl")
    security_rejected = _records(work / "03-rejected-security.jsonl")
    tcp_ok = _records(work / "04-tcp-ok.jsonl")
    tcp_rejected = _records(work / "04-rejected-tcp.jsonl")
    core_ok = _records(work / "05-core-ok.jsonl")
    core_rejected = _records(work / "05-rejected-core.jsonl")
    latency_ok = _records(work / "06-latency-ok.jsonl")
    latency_rejected = _records(work / "06-rejected-latency.jsonl")
    download_ok = _records(work / "07-download-ok.jsonl")
    download_rejected = _records(work / "07-rejected-download.jsonl")
    upload_ok = _records(work / "08-upload-ok.jsonl")
    upload_rejected = _records(work / "08-rejected-upload.jsonl")
    exit_ok = _records(work / "09-exit-ip-ok.jsonl")
    exit_rejected = _records(work / "09-rejected-exit-ip.jsonl")
    geo = _records(work / "10-geo.jsonl")
    render_ok = _records(work / "11-render-ok.jsonl")
    render_rejected = _records(work / "11-rejected-render.jsonl")
    qualified = _records(work / "12-qualified.jsonl")
    selected = _records(work / "13-diversity-selected.jsonl")
    suppressed = _records(work / "13-diversity-suppressed.jsonl")
    published = _records(work / "14-published.jsonl")

    exit_unknown = sum(
        1 for record in exit_ok
        if (_tests(record).get("exit_ip_probe") or {}).get("status") == "unknown"
    )
    exit_direct = sum(
        1 for record in exit_rejected
        if _tests(record).get("status") == "rejected_exit_ip_direct_wan"
    )
    geo_errors = [
        record for record in geo
        if (_tests(record).get("geo") or {}).get("status") in {"error", "unknown"}
    ]
    reliability = _counts([
        str((_tests(record).get("reliability") or {}).get("status") or "unknown")
        for record in qualified
    ])

    return {
        "security": {
            "input": len(security_ok) + len(security_rejected),
            "passed": len(security_ok),
            "rejected": len(security_rejected),
            "reasons": _counts([
                _stage_reason(item, "security", "security_policy")
                for item in security_rejected
            ]),
        },
        "tcp": {
            "input": len(tcp_ok) + len(tcp_rejected),
            "passed_or_skipped": len(tcp_ok),
            "rejected": len(tcp_rejected),
            "reasons": _counts([
                _stage_reason(item, "tcp", "tcp_connect_failed")
                for item in tcp_rejected
            ]),
        },
        "core": {
            "input": len(core_ok) + len(core_rejected),
            "passed": len(core_ok),
            "rejected": len(core_rejected),
            "reasons": _counts([
                _stage_reason(item, "core", "core_validation_failed")
                for item in core_rejected
            ]),
        },
        "latency": {
            "input": len(latency_ok) + len(latency_rejected),
            "passed": len(latency_ok),
            "rejected": len(latency_rejected),
            "reasons": _counts([
                _stage_reason(item, "latency", "latency_probe_failed")
                for item in latency_rejected
            ]),
        },
        "download": {
            "input": len(download_ok) + len(download_rejected),
            "passed": len(download_ok),
            "rejected": len(download_rejected),
            "reasons": _counts([
                _stage_reason(item, "download", "download_probe_failed")
                for item in download_rejected
            ]),
        },
        "upload": {
            "input": len(upload_ok) + len(upload_rejected),
            "passed": len(upload_ok),
            "rejected": len(upload_rejected),
            "reasons": _counts([
                _stage_reason(item, "upload", "upload_probe_failed")
                for item in upload_rejected
            ]),
        },
        "exit_ip": {
            "input": len(exit_ok) + len(exit_rejected),
            "passed_or_unknown": len(exit_ok),
            "unknown": exit_unknown,
            "rejected": len(exit_rejected),
            "direct_wan": exit_direct,
            "reasons": _counts([
                _stage_reason(item, "exit_ip_probe", "exit_ip_lookup_failed")
                for item in [*exit_rejected, *[
                    record for record in exit_ok
                    if (_tests(record).get("exit_ip_probe") or {}).get("status") == "unknown"
                ]]
            ]),
        },
        "geo": {
            "input": len(geo),
            "ok": len(geo) - len(geo_errors),
            "errors_or_unknown": len(geo_errors),
            "reasons": _counts([
                _stage_reason(item, "geo", "geo_lookup_failed")
                for item in geo_errors
            ]),
        },
        "render": {
            "input": len(render_ok) + len(render_rejected),
            "passed": len(render_ok),
            "rejected": len(render_rejected),
            "reasons": _counts([
                _stage_reason(item, "render", "render_error")
                for item in render_rejected
            ]),
        },
        "reliability": reliability,
        "qualified": len(qualified),
        "diversity": {
            "selected": len(selected),
            "suppressed": len(suppressed),
            "reasons": _counts([
                _stage_reason(item, "diversity", "diversity_limit")
                for item in suppressed
            ]),
        },
        "published": len(published),
    }


def enrich_summary(path: Path, data: Any) -> Any:
    if path.name != "summary.json" or not isinstance(data, dict):
        return data
    enriched = dict(data)
    enriched["diagnostics"] = build_diagnostics(path.parent.parent)
    return enriched
