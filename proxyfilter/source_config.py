from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"expected YAML mapping in {path}")
    return data


def load_sources_file(path: Path) -> list[dict[str, Any]]:
    data = load_yaml_mapping(path)
    sources = data.get("sources")
    if not isinstance(sources, list):
        raise ValueError(f"expected top-level 'sources' list in {path}")

    result: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(sources, 1):
        if not isinstance(item, dict):
            raise ValueError(f"invalid source #{index} in {path}: expected mapping")
        source_id = str(item.get("id", "")).strip()
        url = str(item.get("url", "")).strip()
        if not source_id:
            raise ValueError(f"invalid source #{index} in {path}: missing id")
        if source_id in seen_ids:
            raise ValueError(f"duplicate source id in {path}: {source_id}")
        if not url:
            raise ValueError(f"invalid source {source_id!r} in {path}: missing url")
        seen_ids.add(source_id)
        result.append(dict(item))
    return result


def merged_config(config_path: Path, sources_path: Path) -> dict[str, Any]:
    cfg = load_yaml_mapping(config_path)
    merged = dict(cfg)
    merged["sources"] = load_sources_file(sources_path)
    return merged
