#!/usr/bin/env python3
"""Offline A/B sing-box check on the SAME URI profiles.

A: original URI through sing-box-extended type=parser
B: experimental mapped native JSON.

Only read safe checkpoint input. Writes no raw URIs, credentials or JSON
outbounds to persistent reports. Network, latency and throughput NOT measured.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from proxyfilter.model import ProxyConfig
from proxyfilter.native_experiment import convert_uri_to_native
from proxyfilter.security import check_static_security
from proxyfilter.singbox_modes import SingBoxBackend


def _check(binary: str, config: dict[str, Any], timeout: float = 20.0) -> str:
    """Return a non-secret-bearing result classification."""
    with tempfile.TemporaryDirectory(prefix="proxyfilter-ab-") as tmp:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        path.chmod(0o600)
        try:
            proc = subprocess.run(
                [binary, "check", "-c", str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "timeout"
        except OSError:
            return "binary_error"
        return "pass" if proc.returncode == 0 else "check_failed"


def compare_one(proxy: ProxyConfig, extended_binary: str, native_binary: str,
                timeout: float = 20.0) -> dict[str, Any]:
    """A/B check without changing persistent ProxyConfig history or identity."""
    raw = str(proxy.original_raw or "")
    result: dict[str, Any] = {
        "uri_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "protocol": proxy.protocol,
        "extended": "not_run",
        "native": "not_run",
        "conversion": "not_run",
        "dropped_fields": [],
        "no_unclassified_loss": False,
    }
    if not raw or not str(proxy.original_format).endswith("-uri"):
        result["conversion"] = "not_uri"
        return result
    safe, reasons = check_static_security(proxy)
    if not safe:
        result["conversion"] = "security_rejected"
        result["security_reason_codes"] = sorted(set(reasons))
        return result

    # Both tests receive the same runtime configuration template (listen
    # address, DNS, routing). Only outbound differs.
    extended_backend = SingBoxBackend(backend_mode="extended")
    base = extended_backend.render_config(proxy, 0)
    result["extended"] = _check(extended_binary, base, timeout)

    try:
        converted = convert_uri_to_native(proxy)
    except Exception as exc:
        # Exception strings can include credentials or URI field values.
        # Intentionally retain only the exception class.
        result["conversion"] = "rejected"
        result["conversion_error_type"] = type(exc).__name__
        return result

    result["conversion"] = "mapped"
    result["dropped_fields"] = [
        {"name": item.name, "reason": item.reason}
        for item in converted.dropped_fields
    ]
    result["no_unclassified_loss"] = converted.no_unclassified_loss
    native_config = dict(base)
    native_config["outbounds"] = [converted.outbound]
    result["native"] = _check(native_binary, native_config, timeout)
    return result


def run(checkpoint: Path, output: Path, extended_binary: str, native_binary: str,
        limit: int, timeout: float) -> dict[str, int]:
    if checkpoint.name != "03-safe.jsonl":
        raise ValueError("A/B check accepts only the 03-safe.jsonl checkpoint")
    counts: Counter[str] = Counter()
    output.parent.mkdir(parents=True, exist_ok=True)
    with checkpoint.open(encoding="utf-8") as source, output.open("w", encoding="utf-8") as sink:
        for lineno, line in enumerate(source, 1):
            if limit and sum(counts.values()) >= limit:
                break
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                proxy = ProxyConfig.from_dict(row)
                report = compare_one(proxy, extended_binary, native_binary, timeout)
            except (ValueError, KeyError, TypeError):
                # No raw input or exception messages are written.
                report = {"line": lineno, "conversion": "invalid_checkpoint",
                          "extended": "not_run", "native": "not_run"}
            sink.write(json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n")
            counts[report["conversion"]] += 1
    return dict(sorted(counts.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=Path("data/work/03-safe.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-ab-core.jsonl"))
    parser.add_argument("--extended-bin", default="sing-box")
    parser.add_argument("--native-bin", default="sing-box")
    parser.add_argument("--limit", type=int, default=100, help="0 = all")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    if args.limit < 0 or args.timeout <= 0:
        parser.error("--limit must be nonnegative and --timeout positive")
    summary = run(args.checkpoint, args.output, args.extended_bin,
                  args.native_bin, args.limit, args.timeout)
    print(f"report: {args.output}")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
