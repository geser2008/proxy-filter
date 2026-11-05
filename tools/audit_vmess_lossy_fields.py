#!/usr/bin/env python3
"""Read-only census of dropped VMess fields after empty-PCS exception.

Only explicit pre-approved names and the aggregate 'other_unregistered'
appear. No URI, field values, credentials, endpoint or arbitrary keys.
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

from proxyfilter.native_experiment import convert_uri_to_native, NativeMappingError
from proxyfilter.engine import EngineError
from tools.audit_native_coverage import DEFAULT_CHECKPOINT, _parse_record

# Verified as names in the existing protocol-matrix inventory; expand only
# after reviewing provenance. Never show arbitrary names from checkpoint.
REPORTABLE_NAMES = frozenset((
    "vcn", "note", "Telegram", "password", "allowinsecure", "security",
    "skip-cert-verify", "ech", "echConfigList", "pcs", "fm", "final_mask",
))

def audit(checkpoint: Path) -> dict:
    names, combinations = Counter(), Counter()
    rows = 0
    with_empty_pcs = 0
    other_only = 0
    invalid = 0
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
            try:
                mapped = convert_uri_to_native(item)
            except (NativeMappingError, EngineError, ValueError, TypeError, OverflowError):
                continue
            if mapped.no_unclassified_loss:
                continue
            rows += 1
            if type(item.params.get("pcs")) is str and item.params["pcs"] == "":
                with_empty_pcs += 1
            dropped_names = {
                field.name for field in mapped.dropped_fields
                if field.reason == "unclassified"
            }
            categories = {name if name in REPORTABLE_NAMES else "other_unregistered"
                          for name in dropped_names}
            names.update(categories)
            combinations[" + ".join(sorted(categories))] += 1
            if categories == {"other_unregistered"}:
                other_only += 1
    def sorted_counts(counter):
        return dict(sorted(counter.items(), key=lambda pair: (-pair[1], pair[0])))
    return {
        "schema": "vmess-lossy-field-census-v1",
        "checkpoint": checkpoint.name,
        "rows": rows,
        "with_empty_pcs": with_empty_pcs,
        "other_unregistered_only": other_only,
        "invalid_checkpoint_rows": invalid,
        "note": "Categories only; combinations count unique rows, names may overlap. Do not treat classification as evidence of neutral fields.",
        "by_field_category": sorted_counts(names),
        "by_combination": sorted_counts(combinations),
    }

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-vmess-lossy-fields.json"))
    args = parser.parse_args()
    report = audit(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"VMess lossy_native rows={report['rows']}; with empty pcs={report['with_empty_pcs']}")

if __name__ == "__main__":
    main()
