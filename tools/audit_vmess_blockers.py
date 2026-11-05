#!/usr/bin/env python3
"""Read-only tally of registered VMess blockers; never emit URI values."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.audit_native_coverage import DEFAULT_CHECKPOINT, _parse_record
from proxyfilter.native_experiment import NativeMappingError, _UNSUPPORTED, convert_uri_to_native
from proxyfilter.engine import EngineError

GROUPS = {
    "fm": "finalmask", "final_mask": "finalmask",
    "pcs": "certificate_pin", "pinnedPeerCertSha256": "certificate_pin",
    "peer_certificate_sha256": "certificate_pin", "pinSHA256": "certificate_pin",
    "pin_sha256": "certificate_pin",
    "ech": "ech", "echConfigList": "ech",
    "spx": "reality_spider", "spider_x": "reality_spider",
    "smux": "multiplex", "fastopen": "socket_option",
    "realm-opts": "realm", "token": "token",
}

def audit(checkpoint: Path) -> dict:
    if set(GROUPS) != _UNSUPPORTED:
        raise RuntimeError("Update registered blocker groups before running audit")
    fields, combinations, groups = Counter(), Counter(), Counter()
    count, invalid = 0, 0
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
                if exc.code != "unsupported_connection_field":
                    continue
            except (EngineError, ValueError, TypeError, OverflowError):
                continue
            else:
                continue
            names = tuple(sorted(_UNSUPPORTED.intersection(item.params)))
            if not names:
                raise RuntimeError("Registered blocker missing for reported rejection")
            count += 1
            fields.update(names)
            combinations[" + ".join(names)] += 1
            groups.update({GROUPS[name] for name in names})
    sort_counts = lambda counter: dict(sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])))
    return {
        "schema": "vmess-registered-blockers-v1",
        "checkpoint": checkpoint.name,
        "note": "Only pre-registered names; per-field and group counts can overlap. No URI data or values.",
        "rows": count, "invalid_checkpoint_rows": invalid,
        "by_field": sort_counts(fields), "by_group": sort_counts(groups),
        "by_combination": sort_counts(combinations),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-vmess-blockers.json"))
    args = parser.parse_args()
    report = audit(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"VMess registered blocker rows={report['rows']}")

if __name__ == "__main__":
    main()
