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


def _is_timeout(error: Any) -> bool:
    text = str(error or "").lower()
    return "curl: (28)" in text or "timed out" in text or "timeout" in text


def _latency_reason(record: dict[str, Any]) -> str:
    tests = _tests(record)
    status = str(tests.get("status") or "")
    latency = tests.get("latency") if isinstance(tests.get("latency"), dict) else {}
    if status == "rejected_latency_threshold":
        return "below_threshold"
    code = latency.get("http_code")
    if code in {503, 504}:
        return f"http_{code}"
    error = latency.get("error")
    if _is_timeout(error):
        return "timeout"
    text = str(error or "").lower()
    if any(marker in text for marker in ("connection reset", "connection aborted", "network is unreachable", "temporary failure", "remote end closed")):
        return "network_error"
    return "other_error"


def _speed_reason(record: dict[str, Any], stage: str) -> str:
    tests = _tests(record)
    status = str(tests.get("status") or "")
    details = tests.get(stage) if isinstance(tests.get(stage), dict) else {}
    if status == f"rejected_{stage}_threshold":
        return "below_threshold"
    error = details.get("error")
    if _is_timeout(error):
        return "timeout"
    if details.get("payload_valid") is False or "invalid payload" in str(error or "").lower():
        return "invalid_payload"
    code = details.get("http_code")
    if code not in {None, 0}:
        return "provider_error"
    return "transport_error"


def _counts(items: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(items).items()))


def build_diagnostics(data_dir: Path) -> dict[str, Any]:
    work = data_dir / "work"

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
    qualified = _records(work / "12-qualified.jsonl")
    selected = _records(work / "13-diversity-selected.jsonl")
    suppressed = _records(work / "13-diversity-suppressed.jsonl")
    published = _records(work / "14-published.jsonl")

    core_categories = []
    for record in core_rejected:
        core = _tests(record).get("core")
        category = core.get("category") if isinstance(core, dict) else None
        core_categories.append(str(category or "runtime_error"))

    exit_unknown = sum(
        1 for record in exit_ok
        if (_tests(record).get("exit_ip_probe") or {}).get("status") == "unknown"
    )
    exit_direct = sum(
        1 for record in exit_rejected
        if _tests(record).get("status") == "rejected_exit_ip_direct_wan"
    )
    reliability = _counts([
        str((_tests(record).get("reliability") or {}).get("status") or "unknown")
        for record in qualified
    ])

    return {
        "core": {
            "input": len(core_ok) + len(core_rejected),
            "passed": len(core_ok),
            "rejected": len(core_rejected),
            "reasons": _counts(core_categories),
        },
        "latency": {
            "input": len(latency_ok) + len(latency_rejected),
            "passed": len(latency_ok),
            "rejected": len(latency_rejected),
            "reasons": _counts([_latency_reason(item) for item in latency_rejected]),
        },
        "download": {
            "input": len(download_ok) + len(download_rejected),
            "passed": len(download_ok),
            "rejected": len(download_rejected),
            "reasons": _counts([_speed_reason(item, "download") for item in download_rejected]),
        },
        "upload": {
            "input": len(upload_ok) + len(upload_rejected),
            "passed": len(upload_ok),
            "rejected": len(upload_rejected),
            "reasons": _counts([_speed_reason(item, "upload") for item in upload_rejected]),
        },
        "exit_ip": {
            "input": len(exit_ok) + len(exit_rejected),
            "passed_or_unknown": len(exit_ok),
            "unknown": exit_unknown,
            "rejected": len(exit_rejected),
            "direct_wan": exit_direct,
        },
        "reliability": reliability,
        "qualified": len(qualified),
        "diversity": {
            "selected": len(selected),
            "suppressed": len(suppressed),
        },
        "published": len(published),
    }


def enrich_summary(path: Path, data: Any) -> Any:
    if path.name != "summary.json" or not isinstance(data, dict):
        return data
    enriched = dict(data)
    enriched["diagnostics"] = build_diagnostics(path.parent.parent)
    return enriched