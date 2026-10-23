#!/usr/bin/python3
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

import yaml

from proxyfilter import cli
from proxyfilter.source_config import merged_config

# Backward-compatible public import used by existing tests and callers.
# The implementation now lives in proxyfilter.cli, but the old import path
# `from proxy_filter import deduplicate` remains valid.
deduplicate = cli.deduplicate


DEFAULT_CONFIG_PATH = "/srv/proxy-filter/config/config.yaml"
DEFAULT_SOURCES_PATH = "/srv/proxy-filter/config/sources.yaml"


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

        # The package CLI remains the single implementation of the pipeline.
        # It receives a temporary merged config, while all other arguments are
        # passed through unchanged. Publication is the default final stage.
        if "--until" not in remaining:
            remaining = [*remaining, "--until", "publish"]

        sys.argv = [sys.argv[0], "--config", tmp_path, *remaining]
        return cli.main()
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
