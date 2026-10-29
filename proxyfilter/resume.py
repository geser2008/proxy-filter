from __future__ import annotations

import json
from pathlib import Path

from .model import ProxyConfig


STAGE_ORDER = (
    "parse",
    "dedup",
    "security",
    "tcp",
    "core",
    "latency",
    "download",
    "upload",
    "exit-ip",
    "geo",
    "render",
    "publish",
    "history",
)

STAGE_FILES = {
    "parse": "01-parsed.jsonl",
    "dedup": "02-unique.jsonl",
    "security": "03-safe.jsonl",
    "tcp": "04-tcp-ok.jsonl",
    "core": "05-core-ok.jsonl",
    "latency": "06-latency-ok.jsonl",
    "download": "07-download-ok.jsonl",
    "upload": "08-upload-ok.jsonl",
    "exit-ip": "09-exit-ip-ok.jsonl",
    "geo": "10-geo.jsonl",
    "render": "11-render-ok.jsonl",
    "publish": "12-published.jsonl",
}

_DIAGNOSTIC_STAGES = {"tcp", "core"}
_ACTIVE_UNTIL: str | None = None


def stage_index(stage: str) -> int:
    try:
        return STAGE_ORDER.index(stage)
    except ValueError as exc:
        raise ValueError(f"unknown pipeline stage: {stage}") from exc


def stage_should_run(stage: str, resume_from: str | None) -> bool:
    # tcp/core are retained as explicit diagnostics, but are no longer part of
    # the normal production path. validate_resume_range() records the CLI target
    # before process_proxies() starts. Direct library callers that do not set a
    # target keep the historical stage-order behavior for compatibility.
    if _ACTIVE_UNTIL is not None and stage in _DIAGNOSTIC_STAGES and _ACTIVE_UNTIL != stage:
        return False
    return resume_from is None or stage_index(stage) > stage_index(resume_from)


def validate_resume_range(resume_from: str | None, until: str) -> None:
    global _ACTIVE_UNTIL
    _ACTIVE_UNTIL = until
    if resume_from is None:
        return
    if stage_index(until) < stage_index(resume_from):
        raise ValueError(f"--until {until} is before --resume-from {resume_from}")


def _read_stage(path: Path) -> list[ProxyConfig]:
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
            try:
                proxies.append(ProxyConfig.from_dict(data))
            except Exception as exc:
                raise ValueError(f"invalid proxy record in {path}:{lineno}: {exc}") from exc
    return proxies


def load_stage(
    data_dir: Path,
    source_or_stage: str,
    stage: str | None = None,
) -> tuple[list[ProxyConfig], Path]:
    """Load a pipeline checkpoint.

    New runs use one common work directory: ``data/work/<stage-file>``.
    The optional three-argument form is retained for compatibility with older
    callers and snapshots; if no common checkpoint exists, it falls back to
    ``data/work/<source>/<stage-file>``.
    """
    if stage is None:
        resolved_stage = source_or_stage
        legacy_source = None
    else:
        legacy_source = source_or_stage
        resolved_stage = stage

    filename = STAGE_FILES.get(resolved_stage)
    if filename is None:
        raise ValueError(f"stage {resolved_stage} cannot be resumed")

    common_path = data_dir / "work" / filename
    if common_path.is_file():
        return _read_stage(common_path), common_path

    if legacy_source is not None:
        legacy_path = data_dir / "work" / legacy_source / filename
        if legacy_path.is_file():
            return _read_stage(legacy_path), legacy_path

    raise FileNotFoundError(f"resume file not found: {common_path}")
