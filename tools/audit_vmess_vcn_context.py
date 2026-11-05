#!/usr/bin/env python3
"""Read-only aggregate VMess vcn presence/value class in the checkpoint.

Never writes the verification names, URIs, credentials or server addresses.
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

from tools.audit_native_coverage import DEFAULT_CHECKPOINT, _parse_record


def audit(checkpoint: Path) -> dict:
    types, tls, pairs = Counter(), Counter(), Counter()
    count = invalid = 0
    with checkpoint.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                item = _parse_record(json.loads(line))
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                invalid += 1
                continue
            if item.protocol.lower() != "vmess" or not item.original_format.endswith("-uri"):
                continue
            params = item.params
            if "vcn" not in params:
                continue
            val = params["vcn"]
            vtype = "empty_string" if type(val) is str and val == "" else (
                "nonempty_string" if type(val) is str else "non_string"
            )
            tval = params.get("tls")
            ttype = "tls_enabled_literal" if type(tval) is str and tval in ("1", "true", "tls") else (
                "tls_other" if "tls" in params else "tls_absent"
            )
            count += 1
            types[vtype] += 1
            tls[ttype] += 1
            pairs[f"{vtype} | {ttype} | " +
                  ("empty_pcs" if type(params.get("pcs")) is str and params["pcs"] == ""
                   else "other_pcs")] += 1
    def ordered(counter):
        return dict(sorted(counter.items(), key=lambda x: (-x[1], x[0])))
    return {
        "schema": "vmess-vcn-context-v1",
        "checkpoint": checkpoint.name,
        "rows_with_vcn": count,
        "invalid_checkpoint_rows": invalid,
        "by_value_class": ordered(types),
        "by_tls_class": ordered(tls),
        "contexts": ordered(pairs),
        "note": "Predefined categories only. No verification names, URI values or identifiers.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-vmess-vcn-context.json"))
    args = parser.parse_args()
    report = audit(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"VMess rows with vcn={report['rows_with_vcn']}")

if __name__ == "__main__":
    main()
