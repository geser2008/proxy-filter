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


def main() -> int:
    # This parser only peels off launcher-owned options. Abbreviation must be
    # disabled so the pipeline option `--source` is not mistaken for
    # launcher-owned `--sources`.
    pre_parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    pre_parser.add_argument("--config")
    pre_parser.add_argument("--sources")
    known, remaining = pre_parser.parse_known_args()

    # Backward-compatible path: let the existing CLI handle everything exactly
    # as before when sources are still embedded in config.yaml.
    if not known.sources:
        return cli.main()

    if not known.config:
        pre_parser.error("--config is required when --sources is used")

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
        # passed through unchanged.
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
