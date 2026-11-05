#!/usr/bin/env python3
"""Read-only URI-field provenance audit driven by the existing Markdown matrix.

No raw URI, endpoint, parameter value, credential, or unknown key is emitted.
This audits documented FIELD NAMES, not native JSON correctness or connectivity.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MATRIX = ROOT / "docs" / "protocol-uri-to-singbox-matrix.md"
DEFAULT_CHECKPOINT = ROOT.parent / "data" / "work" / "03-safe.jsonl"
HEADINGS = {
    "VLESS": "vless",
    "VMess": "vmess",
    "Trojan": "trojan",
    "Shadowsocks": "ss",
    "Hysteria2": "hysteria2",
    "TUIC": "tuic",
}
KNOWN_CLASSES = {"SPEC", "EXT", "LEGACY", "OBSERVED", "META"}
FIELD_PATTERN = re.compile(r"`([^`]+)`")
SOURCE_PATTERN = re.compile(r"\b(?:V[12]|M1|T1|S1|H1|U[12])\b")
FIELD_NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]*\Z")

def load_matrix(path: Path) -> dict[str, dict[str, dict[str, Any]]]:
    """Extract per-field records from the 'Поимённая инвентаризация' tables.

    Fail closed if this documentation layout changes: no fallback to KNOWN.
    Compound classifications such as EXT/OBSERVED are preserved as uncertain.
    """
    source = path.read_text(encoding="utf-8")
    start_marker = "### Поимённая инвентаризация URI-полей"
    end_marker = "### Ссылки классификации происхождения URI"
    if source.count(start_marker) != 1 or source.count(end_marker) != 1:
        raise ValueError("matrix field inventory markers missing or duplicated")
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    inventory = source[start:end]
    registry: dict[str, dict[str, dict[str, Any]]] = {
        protocol: {} for protocol in HEADINGS.values()
    }
    proto = None
    for line in inventory.splitlines():
        if line.startswith("#### "):
            heading = line[5:].strip()
            proto = next((value for prefix, value in HEADINGS.items()
                          if heading.startswith(prefix)), None)
            continue
        if proto is None or not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] == "Поле / алиасы":
            continue
        names, location, category_cell, details = cells
        classes = category_cell.split()[0].split("/")
        if not classes or any(name not in KNOWN_CLASSES for name in classes):
            raise ValueError(f"unsupported provenance class in {proto} matrix")
        for token in FIELD_PATTERN.findall(names):
            if "://" in token or not FIELD_NAME.fullmatch(token):
                continue
            if location.startswith(("URI authority", "authority", "fragment")):
                continue
            # For VMess the payload is itself JSON, not an RFC query.
            field = registry[proto].get(token)
            item = {
                "classes": sorted(set(classes)),
                "location": location,
                "source_refs": sorted(set(SOURCE_PATTERN.findall(category_cell + " " + details))),
            }
            if field is not None and field != item:
                # Matrix ambiguity must be represented, not silently resolved.
                merged = sorted(set(field["classes"] + item["classes"]))
                item["classes"] = merged
                item["source_refs"] = sorted(set(field["source_refs"] + item["source_refs"]))
                item["location"] = "multiple"
            registry[proto][token] = item
    if any(not registry[name] for name in HEADINGS.values()):
        raise ValueError("missing per-protocol field inventory in matrix")
    return registry


def _value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "other"


def audit(checkpoint: Path, registry: dict[str, dict[str, dict[str, Any]]]) -> dict:
    report: dict[str, Any] = {
        "schema": "uri-provenance-audit-v1",
        "checkpoint": checkpoint.name,
        "matrix": DEFAULT_MATRIX.name,
        "notice": ("Read-only field-name provenance, not a parser acceptance gate. "
                   "Unlisted names are SHA-256 identifiers, not raw strings; "
                   "no values or raw URIs are collected."),
        "valid_rows": 0,
        "invalid_rows": 0,
        "protocols": {},
    }
    by_proto: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "rows": 0, "class_counts": Counter(), "fields": {},
    })
    with checkpoint.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                config = row["config"]
                proto = config["protocol"].lower()
                if proto == "hy2":
                    proto = "hysteria2"
                params = config["params"]
                if not isinstance(params, dict) or proto not in registry:
                    raise ValueError("unsupported protocol or params")
            except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError):
                report["invalid_rows"] += 1
                continue
            report["valid_rows"] += 1
            p = by_proto[proto]
            p["rows"] += 1
            for key, value in params.items():
                if not isinstance(key, str):
                    # JSON object keys are always strings, but keep the invariant.
                    continue
                known = registry[proto].get(key)
                # Raw names are exposed ONLY if they appear verbatim in the
                # documentation registry. Unknown names may contain secrets.
                identifier = key if known is not None else "sha256:" + hashlib.sha256(
                    key.encode("utf-8")).hexdigest()
                classes = known["classes"] if known is not None else ["UNLISTED"]
                bucket = p["fields"].setdefault(identifier, {
                    "count": 0, "value_types": Counter(),
                    "classes": classes,
                    "source_refs": known["source_refs"] if known is not None else [],
                    "location": known["location"] if known is not None else "unknown",
                })
                bucket["count"] += 1
                bucket["value_types"][_value_type(value)] += 1
                p["class_counts"]["/".join(classes)] += 1
    for proto, item in sorted(by_proto.items()):
        fields = [
            {
                "field": key, "occurrences": rec["count"],
                "classes": rec["classes"], "source_refs": rec["source_refs"],
                "location": rec["location"],
                "value_types": dict(sorted(rec["value_types"].items())),
            }
            for key, rec in sorted(
                item["fields"].items(), key=lambda x: (-x[1]["count"], x[0])
            )
        ]
        report["protocols"][proto] = {
            "rows": item["rows"],
            "field_occurrences_by_class": dict(sorted(item["class_counts"].items())),
            "distinct_fields": len(fields),
            "fields": fields,
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-uri-provenance-audit.json"))
    args = parser.parse_args()
    registry = load_matrix(args.matrix)
    result = audit(args.checkpoint, registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"records: {result['valid_rows']} invalid: {result['invalid_rows']}")
    for proto, info in result["protocols"].items():
        print(f"{proto:10} rows={info['rows']:6} fields={info['distinct_fields']:3} "
              f"classes={info['field_occurrences_by_class']}")


if __name__ == "__main__":
    main()
