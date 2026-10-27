#!/usr/bin/python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

import yaml

from proxyfilter import cli
from proxyfilter.history import new_run_id, record_failed_run, record_source_run, utc_now
from proxyfilter.history_global import record_global_source_run
from proxyfilter.known_working import (
    load_known_working,
    load_rejected_candidates,
    load_seen_ids,
    update_known_working,
)
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


def _has_option(args: list[str], option: str) -> bool:
    return option in args or any(item.startswith(option + "=") for item in args)


def _resolved_until(args: list[str]) -> str:
    values = _option_values(args, "--until")
    return values[-1] if values else "publish"


def _replace_option(args: list[str], option: str, value: str) -> list[str]:
    result: list[str] = []
    replaced = False
    index = 0
    while index < len(args):
        item = args[index]
        if item == option:
            if index + 1 < len(args):
                index += 2
            else:
                index += 1
            if not replaced:
                result.extend([option, value])
                replaced = True
            continue
        if item.startswith(option + "="):
            if not replaced:
                result.extend([option, value])
                replaced = True
            index += 1
            continue
        result.append(item)
        index += 1
    if not replaced:
        result.extend([option, value])
    return result


def _history_db_path(cfg: dict, data_dir: Path) -> Path:
    history_cfg = cfg.get("history", {}) or {}
    raw = history_cfg.get("database")
    if not raw:
        return data_dir / "history" / "proxy-history.sqlite3"
    path = Path(str(raw))
    return path if path.is_absolute() else data_dir / path


def _validate_snapshot(work_dir: Path) -> None:
    required = ("02-unique.jsonl", "12-published.jsonl")
    missing = [name for name in required if not (work_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"history snapshot is incomplete in {work_dir}: missing {', '.join(missing)}"
        )


def _snapshot_run_id(source_id: str, work_dir: Path) -> str:
    """Return a deterministic id for the exact JSONL snapshot in work_dir."""
    _validate_snapshot(work_dir)
    digest = hashlib.sha256()
    files = sorted(path for path in work_dir.glob("*.jsonl") if path.is_file())
    for path in files:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return f"snapshot-{source_id}-{digest.hexdigest()[:24]}"


def _mtime_iso(path: Path, fallback: str) -> str:
    if not path.exists():
        return fallback
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")


def _selected_source_ids(cfg: dict, args: list[str]) -> tuple[dict[str, dict], set[str]]:
    configured = {str(item.get("id")): item for item in cfg.get("sources", [])}
    selected = set(_option_values(args, "--source"))
    unknown = sorted(selected - set(configured))
    if unknown:
        raise ValueError("unknown source id(s): " + ", ".join(unknown))
    return configured, selected if selected else set(configured)


def _import_history_snapshot(cfg: dict, args: list[str]) -> int:
    configured, source_ids = _selected_source_ids(cfg, args)
    data_dir = Path(cfg.get("paths", {}).get("data_dir", "/srv/proxy-filter/data"))
    db_path = _history_db_path(cfg, data_dir)
    imported = 0
    skipped = 0

    global_work = data_dir / "work"
    use_global = all((global_work / name).is_file() for name in ("02-unique.jsonl", "12-published.jsonl"))

    for source_id in sorted(source_ids):
        source = configured[source_id]
        work_dir = global_work if use_global else data_dir / "work" / source_id
        try:
            _validate_snapshot(work_dir)
            run_id = _snapshot_run_id(source_id, work_dir)
            now = utc_now()
            started_at = _mtime_iso(work_dir / "01-parsed.jsonl", now)
            finished_at = _mtime_iso(work_dir / "12-published.jsonl", now)
            recorder = record_global_source_run if use_global else record_source_run
            recorder(
                db_path,
                run_id=run_id,
                source_id=source_id,
                source_name=str(source.get("name", source_id)),
                work_dir=work_dir,
                started_at=started_at,
                finished_at=finished_at,
            )
            imported += 1
            print(f"[history] source={source_id} imported run_id={run_id}")
        except sqlite3.IntegrityError:
            skipped += 1
            print(f"[history] source={source_id} already_imported")
        except Exception as exc:
            print(f"[history] source={source_id} ERROR: {exc}", file=sys.stderr)
            return 1

    print(f"[history] imported={imported} already_present={skipped} db={db_path}")
    return 0


def _record_history(
    cfg: dict,
    remaining: list[str],
    started_at: str,
    run_ids: dict[str, str],
    *,
    force: bool = False,
) -> None:
    history_cfg = cfg.get("history", {}) or {}
    if not force and not bool(history_cfg.get("enabled", False)):
        return

    requested_until = _resolved_until(remaining)
    resume_from = _option_values(remaining, "--resume-from")
    if requested_until not in {"publish", "history"}:
        return
    if resume_from and not (requested_until == "history" and resume_from[-1] == "publish"):
        return

    data_dir = Path(cfg.get("paths", {}).get("data_dir", "/srv/proxy-filter/data"))
    summary_path = data_dir / "reports" / "summary.json"
    if not summary_path.exists():
        return
    with summary_path.open("r", encoding="utf-8") as fh:
        summary = json.load(fh)

    configured, source_ids = _selected_source_ids(cfg, remaining)
    db_path = _history_db_path(cfg, data_dir)
    work_dir = data_dir / "work"

    for source_id in sorted(source_ids):
        source = configured.get(source_id) or {}
        source_name = str(source.get("name", source_id))
        result = (summary.get("sources") or {}).get(source_id) or {}
        try:
            if requested_until == "history" and resume_from:
                # A history-only stage consumes the existing complete global work
                # snapshot and uses a deterministic id so rerunning is idempotent.
                _validate_snapshot(work_dir)
                run_id = _snapshot_run_id(source_id, work_dir)
                history_started = _mtime_iso(work_dir / "01-parsed.jsonl", started_at)
                history_finished = _mtime_iso(work_dir / "12-published.jsonl", utc_now())
            else:
                run_id = run_ids[source_id]
                history_started = started_at
                history_finished = utc_now()

            if result.get("status") == "ok":
                record_global_source_run(
                    db_path,
                    run_id=run_id,
                    source_id=source_id,
                    source_name=source_name,
                    work_dir=work_dir,
                    started_at=history_started,
                    finished_at=history_finished,
                )
                print(f"[history] source={source_id} recorded run_id={run_id}")
            else:
                record_failed_run(
                    db_path,
                    run_id=run_id,
                    source_id=source_id,
                    source_name=source_name,
                    started_at=history_started,
                    finished_at=history_finished,
                    error=str(result.get("error") or "source run failed"),
                )
        except sqlite3.IntegrityError:
            print(f"[history] source={source_id} already_recorded")
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
    pre_parser.add_argument("--history-import", action="store_true")
    known, remaining = pre_parser.parse_known_args()

    try:
        cfg = merged_config(Path(known.config), Path(known.sources))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        pre_parser.error(str(exc))

    if known.history_import:
        try:
            return _import_history_snapshot(cfg, remaining)
        except ValueError as exc:
            pre_parser.error(str(exc))

    tmp_path: str | None = None
    started_at = utc_now()
    selected = set(_option_values(remaining, "--source"))
    configured_ids = {str(source.get("id")) for source in cfg.get("sources", [])}
    source_ids = selected if selected else configured_ids
    run_ids = {source_id: new_run_id(source_id) for source_id in source_ids}

    requested_until = _resolved_until(remaining)
    resume_from = _option_values(remaining, "--resume-from")
    history_stage = requested_until == "history"
    if history_stage and resume_from and resume_from[-1] != "publish":
        pre_parser.error("--until history may resume only from --resume-from publish")

    original_render = cli._render_proxies
    original_load_previous = cli._load_previous_working
    original_publish_merged = cli.publish_merged
    state_context: dict[str, object] = {}

    def load_previous_with_retention(data_dir: Path, selected_sources: set[str]):
        proxies, path = load_known_working(data_dir, selected_sources)
        state_context["previous"] = list(proxies)
        state_context["path"] = path
        return proxies, path

    def publish_merged_with_retention(data_dir: Path, proxies, diversity_cfg=None):
        # Capture the complete qualified set before publish_merged mutates the
        # list down to the diversity-selected publication set.
        qualified = list(proxies)
        result = original_publish_merged(data_dir, proxies, diversity_cfg)

        # Retained state is updated only by a fresh full publish. Resume runs do
        # not rewrite availability history, and partial-source runs never call
        # publish_merged in cli.py.
        if not resume_from and "previous" in state_context:
            previous = list(state_context["previous"])
            retention_days = int((cfg.get("state", {}) or {}).get("working_retention_days", 30))
            counts = update_known_working(
                data_dir,
                previous,
                qualified,
                load_rejected_candidates(data_dir),
                seen_ids=load_seen_ids(data_dir),
                retention_days=retention_days,
            )
            print(
                "[state] known_working="
                f"{counts['retained']} working_now={counts['working_now']} "
                f"failing_retained={counts['failing_retained']} "
                f"new={counts['new_working']} recovered={counts['recovered']} "
                f"expired={counts['expired']} retention_days={retention_days}"
            )
        return result

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

        # Keep cli.py as the pipeline implementation while applying policy and
        # retained-state integration here, where merged config is available.
        cli._render_proxies = render_proxies_with_reliability
        cli._load_previous_working = load_previous_with_retention
        cli.publish_merged = publish_merged_with_retention

        # history is a launcher-owned non-filtering stage after publish. The
        # package CLI still executes through publish; then the snapshot is stored.
        cli_args = list(remaining)
        if history_stage:
            cli_args = _replace_option(cli_args, "--until", "publish")
        elif not _has_option(cli_args, "--until"):
            cli_args = [*cli_args, "--until", "publish"]

        sys.argv = [sys.argv[0], "--config", tmp_path, *cli_args]
        result = cli.main()

        # Use the original requested arguments so explicit history remains
        # distinguishable from a normal publish with automatic history enabled.
        _record_history(
            cfg,
            remaining if _has_option(remaining, "--until") else [*remaining, "--until", "publish"],
            started_at,
            run_ids,
            force=history_stage,
        )
        return result
    finally:
        cli._render_proxies = original_render
        cli._load_previous_working = original_load_previous
        cli.publish_merged = original_publish_merged
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
