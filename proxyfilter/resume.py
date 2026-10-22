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


def stage_index(stage: str) -> int:
    try:
        return STAGE_ORDER.index(stage)
    except ValueError as exc:
        raise ValueError(f"unknown pipeline stage: {stage}") from exc


def stage_should_run(stage: str, resume_from: str | None) -> bool:
    return resume_from is None or stage_index(stage) > stage_index(resume_from)


def validate_resume_range(resume_from: str | None, until: str) -> None:
    if resume_from is None:
        return
    if stage_index(until) < stage_index(resume_from):
        raise ValueError(f"--until {until} is before --resume-from {resume_from}")


def load_stage(data_dir: Path, source_id: str, stage: str) -> tuple[list[ProxyConfig], Path]:
    filename = STAGE_FILES.get(stage)
    if filename is None:
        raise ValueError(f"stage {stage} cannot be resumed")

    path = data_dir / "work" / source_id / filename
    if not path.is_file():
        raise FileNotFoundError(f"resume file not found: {path}")

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

    return proxies, path
