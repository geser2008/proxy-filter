#!/usr/bin/env python3
"""Read-only VMess PCS/TLS context audit; aggregate categorical decisions only.

This is diagnostic, not evidence that PCS may safely be ignored. Never emit
certificate hashes, TLS values, arbitrary names, endpoint data or share URIs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxyfilter.engine import EngineError
from proxyfilter.native_experiment import NativeMappingError, convert_uri_to_native
from tools.audit_native_coverage import DEFAULT_CHECKPOINT, _parse_record

# These are the *target sing-box-extended VMess link parser's* literal
# enabling values (parser/link/vmess.go), not Python truthiness.
_TLS_ON = frozenset(("1", "true", "tls"))
_TLS_OFF = frozenset(("", "0", "false", "none"))
_INSECURE_ON = frozenset(("1", "true"))
_INSECURE_OFF = frozenset(("", "0", "false", "none"))


def _tls_state(params: dict) -> str:
    if "tls" not in params:
        return "absent"
    marker = params["tls"]
    if not isinstance(marker, str):
        return "non_string"
    if marker in _TLS_ON:
        return "enabled_literal"
    if marker in _TLS_OFF:
        return "disabled_literal"
    return "other_literal"


def _insecure_state(params: dict) -> str:
    # The verified target VMess link parser recognizes these two keys only.
    keys = ("insecure", "skip-cert-verify")
    present = [(key, params[key]) for key in keys if key in params]
    if not present:
        return "absent"
    states = []
    for _, value in present:
        if not isinstance(value, str):
            states.append("non_string")
        elif value in _INSECURE_ON:
            states.append("on")
        elif value in _INSECURE_OFF:
            states.append("off")
        else:
            states.append("other")
    if len(set(states)) > 1:
        return "conflicting"
    return states[0]


def _pin_state(params: dict) -> str:
    value = params["pcs"]
    if isinstance(value, str):
        return "empty_string" if value == "" else "nonempty_string"
    if value is None:
        return "null"
    return "non_string"


def audit(checkpoint: Path) -> dict:
    contexts = Counter()
    tls = Counter()
    insecure = Counter()
    pin = Counter()
    accessory = Counter()
    rows = invalid = 0

    with checkpoint.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                item = _parse_record(json.loads(line))
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                invalid += 1
                continue
            if item.protocol.lower() != "vmess" or not item.original_format.endswith("-uri"):
                continue
            try:
                convert_uri_to_native(item)
            except NativeMappingError as exc:
                if exc.code != "unsupported_connection_field" or "pcs" not in item.params:
                    continue
            except (EngineError, ValueError, TypeError, OverflowError):
                continue
            else:
                continue

            params = item.params
            rows += 1
            tls_state = _tls_state(params)
            insecure_state = _insecure_state(params)
            pin_state = _pin_state(params)
            has_cert = "cert" in params
            tls[tls_state] += 1
            insecure[insecure_state] += 1
            pin[pin_state] += 1
            accessory["cert_present" if has_cert else "cert_absent"] += 1
            accessory["ech_present" if "ech" in params else "ech_absent"] += 1
            accessory["echConfigList_present" if "echConfigList" in params else "echConfigList_absent"] += 1
            accessory["security_present" if "security" in params else "security_absent"] += 1
            accessory["scy_present" if "scy" in params else "scy_absent"] += 1
            # Fixed vocabulary only: no stringification of source values.
            contexts[" | ".join((
                tls_state,
                insecure_state,
                "cert_present" if has_cert else "cert_absent",
                pin_state,
                "ech_present" if "ech" in params else "ech_absent",
            ))] += 1

    def ordered(counts):
        return dict(sorted(counts.items(), key=lambda row: (-row[1], row[0])))

    return {
        "schema": "vmess-pcs-context-v1",
        "checkpoint": checkpoint.name,
        "rows": rows,
        "invalid_checkpoint_rows": invalid,
        "note": (
            "Categorical census of VMess pcs first-rejections only; parser literals "
            "are not a statement about complete TLS semantics. No source values "
            "or unregistered names are written. No automatic bypass of pinning."
        ),
        "tls_state": ordered(tls),
        "insecure_state": ordered(insecure),
        "pin_state": ordered(pin),
        "other_fields": ordered(accessory),
        "contexts": ordered(contexts),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-vmess-pcs-context.json"))
    args = parser.parse_args()
    report = audit(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"VMess pcs first-rejections={report['rows']}")


if __name__ == "__main__":
    main()
