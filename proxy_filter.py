#!/usr/bin/python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

import yaml

from proxyfilter import cli
from proxyfilter.history import new_run_id, record_failed_run, record_source_run, utc_now
from proxyfilter.output_policy import render_proxies as render_proxies_with_reliability
from proxyfilter.source_config import merged_config

# Backward-compatible public import used by existing tests and callers.
# The implementation now lives in proxyfilter.cli, but the old import path
# `from proxy_filter import deduplicate` remains valid.
deduplicate = cli.deduplicate


DEFAULT_CONFIG_PATH = "/srv/proxy-filter/config/config.yaml"
DEFAULT_SOURCES_PATH = "/srv/proxy-filter/config/sources.yaml"


def _option_values(args: list[str], option: str) -> list[str]:
    values: list[str] = []
    for index, item in enumerate(args):
        if item == option and index + 1 < len(args):
            values.append(args[index + 1])
        elif item.startswith(option + "="):
            values.append(item.split("=", 1)[1])
    return values


def _resolved_until(args: list[str]) -> str:
    values = _option_values(args, "--until")
    return values[-1] if values else "publish"


def _history_db_path(cfg: dict, data_dir: Path) -> Path:
    history_cfg = cfg.get("history", {}) or {}
    raw = history_cfg.get("database")
    if not raw:
        return data_dir / "history" / "proxy-history.sqlite3"
    path = Path(str(raw))
    return path if path.is_absolute() else data_dir / path


def _record_history(cfg: dict, remaining: list[str], started_at: str, run_ids: dict[str, str]) -> None:
    history_cfg = cfg.get("history", {}) or {}
    if not bool(history_cfg.get("enabled", True)):
        return
    if _resolved_until(remaining) != "publish" or _option_values(remaining, "--resume-from"):
        return

    data_dir = Path(cfg.get("paths", {}).get("data_dir", "/srv/proxy-filter/data"))
    summary_path = data_dir / "reports" / "summary.json"
    if not summary_path.exists():
        return
    with summary_path.open("r", encoding="utf-8") as fh:
        summary = json.load(fh)

    configured = {str(item.get("id")): item for item in cfg.get("sources", [])}
    selected = set(_option_values(remaining, "--source"))
    source_ids = selected if selected else set(configured)
    db_path = _history_db_path(cfg, data_dir)
    store_details = str(history_cfg.get("store_details", "failures"))

    for source_id in sorted(source_ids):
        source = configured.get(source_id) or {}
        source_name = str(source.get("name", source_id))
        run_id = run_ids[source_id]
        result = (summary.get("sources") or {}).get(source_id) or {}
        try:
            if result.get("status") == "ok":
                record_source_run(
                    db_path,
                    run_id=run_id,
                    source_id=source_id,
                    source_name=source_name,
                    work_dir=data_dir / "work" / source_id,
                    started_at=started_at,
                    finished_at=utc_now(),
                    store_details=store_details,
                )
            else:
                record_failed_run(
                    db_path,
                    run_id=run_id,
                    source_id=source_id,
                    source_name=source_name,
                    started_at=started_at,
                    finished_at=utc_now(),
                    error=str(result.get("error") or "source run failed"),
                )
        except Exception as exc:
            # History is analytical persistence, not part of filtering
            # correctness. Database problems must not suppress publication.
            print(f"[history] source={source_id} ERROR: {exc}", file=sys.stderr)


def main() -> int:
    # Launcher-owned options have independent defaults. Supplying one option
    # never changes the interpretation or default of another option.
    pre_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre_parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    pre_parser.add_argument("--sources", default=DEFAULT_SOURCES_PATH)
    known, remaining = pre_parser.parse_known_args()

    try:
        cfg = merged_config(Path(known.config), Path(known.sources))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        pre_parser.error(str(exc))

    tmp_path: str | None = None
    started_at = utc_now()
    selected = set(_option_values(remaining, "--source"))
    configured_ids = {str(source.get("id")) for source in cfg.get("sources", [])}
    source_ids = selected if selected else configured_ids
    run_ids = {source_id: new_run_id(source_id) for source_id in source_ids}

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".yaml",
            prefix="proxy-filter-",
            delete=False,
        ) as fh:
            yaml.safe_dump(cfg, fh, allow_unicode=True, sort_keys=False)
            tmp_path = fh.name

        # Keep cli.py as the pipeline implementation while applying the output
        # policy here, where the merged config is already available.
        cli._render_proxies = render_proxies_with_reliability

        # The package CLI remains the single implementation of the pipeline.
        # It receives a temporary merged config, while all other arguments are
        # passed through unchanged. Publication is the default final stage.
        if "--until" not in remaining and not any(item.startswith("--until=") for item in remaining):
            remaining = [*remaining, "--until", "publish"]

        sys.argv = [sys.argv[0], "--config", tmp_path, *remaining]
        result = cli.main()
        _record_history(cfg, remaining, started_at, run_ids)
        return result
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
