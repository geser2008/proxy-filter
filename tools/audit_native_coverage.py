#!/usr/bin/env python3
"""Read-only coverage audit for the single experimental URI -> sing-box adapter.

Reads an existing JSONL checkpoint (default: data/work/03-safe.jsonl).
Never runs sing-box, probes the network, mutates records, or writes URI data.
Reports counts only; no endpoint, credential, URI or arbitrary field name.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys

# Support both 'python3 tools/audit_native_coverage.py' and module execution.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.native_experiment import NativeMappingError, convert_uri_to_native
from proxyfilter.engine import EngineError

DEFAULT_CHECKPOINT = ROOT.parent / "data" / "work" / "03-safe.jsonl"
DEFAULT_OUTPUT = Path("/tmp/proxyfilter-native-coverage.json")
PROTOCOLS = frozenset(("vless", "vmess", "trojan", "ss", "hysteria2", "tuic"))
# Values may originate in a parser, so only enumerate locally controlled codes.
REASON_CODES = frozenset((
    "not_uri", "unsupported_protocol", "invalid_params",
    "conflicting_aliases", "unsupported_connection_field",
    "unsupported_certificate_fingerprint", "empty_tls_cipher_suites",
    "unsupported_tls_cipher_suites", "unsupported_vless_encryption",
    "unsupported_tls_security", "reality_missing_fingerprint",
    "reality_missing_public_key", "unsupported_vmess_header",
    "conflicting_transport_aliases", "unsupported_transport",
    "unsupported_authority", "transport_fields_on_tcp",
    "unmapped_transport_headers", "unmapped_connection_field",
    "invalid_xhttp_extra_encoding", "invalid_xhttp_extra_json",
    "invalid_xhttp_extra_type", "unmapped_vmess_http_method",
    "invalid_vmess_http_field", "ambiguous_vmess_http_hosts",
    "vmess_http_disguise_tls_conflict",
))


def _new_counts() -> dict:
    return {
        "rows": 0, "native_ok": 0, "native_ok_no_unclassified_loss": 0,
        "native_ok_unclassified_loss": 0, "rejected": 0,
        "reasons": Counter(), "dropped_fields": Counter(),
    }


def _parse_record(raw: object) -> ProxyConfig:
    if not isinstance(raw, dict):
        raise ValueError("invalid row")
    config, original = raw["config"], raw["original"]
    if not isinstance(config, dict) or not isinstance(original, dict):
        raise ValueError("invalid config/original")
    protocol = config["protocol"]
    params = config["params"]
    if not isinstance(protocol, str) or not isinstance(params, dict):
        raise ValueError("invalid protocol/params")
    source = SourceInfo("audit", "audit", "plain")
    return ProxyConfig(
        source, protocol, str(config["server"]), int(config["port"]),
        "audit", params, str(original["format"]), str(original["raw"]),
    )


def coverage_audit(checkpoint: Path) -> dict:
    totals = _new_counts()
    by_protocol = defaultdict(_new_counts)
    summary = {
        "schema": "native-uri-coverage-v1",
        "checkpoint": checkpoint.name,
        "note": (
            "Conversion coverage only; no sing-box check, connectivity or "
            "semantic-equivalence claim. Successful rows with unclassified "
            "field loss are not counted as safe coverage."
        ),
        "invalid_rows": 0,
        "skipped_non_uri": 0,
        "protocols": {},
    }
    with checkpoint.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                item = _parse_record(json.loads(line))
            except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
                summary["invalid_rows"] += 1
                continue
            if not item.original_format.endswith("-uri"):
                summary["skipped_non_uri"] += 1
                continue
            protocol = item.protocol.lower()
            if protocol == "hy2":
                protocol = "hysteria2"
            if protocol not in PROTOCOLS:
                # Unknown protocol is counted without exposing source values.
                protocol = "other"
            for bucket in (totals, by_protocol[protocol]):
                bucket["rows"] += 1
            try:
                mapped = convert_uri_to_native(item)
            except NativeMappingError as exc:
                reason = exc.code if exc.code in REASON_CODES else "other_native_rejection"
                for bucket in (totals, by_protocol[protocol]):
                    bucket["rejected"] += 1
                    bucket["reasons"][reason] += 1
            except (EngineError, ValueError, TypeError, OverflowError):
                for bucket in (totals, by_protocol[protocol]):
                    bucket["rejected"] += 1
                    bucket["reasons"]["backend_rejected"] += 1
            else:
                for bucket in (totals, by_protocol[protocol]):
                    bucket["native_ok"] += 1
                    if mapped.no_unclassified_loss:
                        bucket["native_ok_no_unclassified_loss"] += 1
                    else:
                        bucket["native_ok_unclassified_loss"] += 1
                    for field in mapped.dropped_fields:
                        kind = "metadata" if field.reason == "metadata" else "unclassified"
                        bucket["dropped_fields"][kind] += 1

    def rendered(data: dict) -> dict:
        return {
            key: (dict(sorted(value.items())) if isinstance(value, Counter) else value)
            for key, value in data.items()
        }

    summary["total"] = rendered(totals)
    summary["protocols"] = {
        key: rendered(value) for key, value in sorted(by_protocol.items())
    }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = coverage_audit(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"URI rows={report['total']['rows']} safe_native={report['total']['native_ok_no_unclassified_loss']} "
          f"lossy_native={report['total']['native_ok_unclassified_loss']} "
          f"rejected={report['total']['rejected']} invalid={report['invalid_rows']}")
    for protocol, result in report["protocols"].items():
        print(f"{protocol}: rows={result['rows']} safe={result['native_ok_no_unclassified_loss']} "
              f"lossy={result['native_ok_unclassified_loss']} rejected={result['rejected']}")


if __name__ == "__main__":
    main()
