#!/usr/bin/env python3
"""Read-only VMess TCP-field first-rejection audit; fixed categories only.

No endpoints, share URIs, credentials, arbitrary field names, or field values.
Counts may overlap by field, but each context belongs to one rejected record.
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

FIELDS = ("host", "path", "headers", "serviceName", "service_name")


def _classify(value: object) -> str:
    if type(value) is str:
        return "empty" if value == "" else "nonempty"
    return "non_string"


def _network(params: dict) -> str:
    key = "network" if "network" in params else "net"
    if key not in params:
        return "absent"
    value = params[key]
    if type(value) is not str:
        return "non_string"
    return value if value in ("", "tcp", "raw") else "other"


def _header(params: dict) -> str:
    if "type" not in params:
        return "absent"
    value = params["type"]
    if type(value) is not str:
        return "non_string"
    return value if value in ("", "none", "http") else "other"


def _tls(params: dict) -> str:
    value = params.get("tls")
    if "tls" not in params:
        return "absent"
    if type(value) is not str:
        return "non_string"
    if value in ("tls", "1", "true"):
        return "enabled"
    if value in ("", "none", "0", "false"):
        return "disabled"
    return "other"


def audit(checkpoint: Path) -> dict:
    rows = invalid = 0
    network, header, tls, fields, shapes, contexts = (
        Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    )
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
                convert_uri_to_native(item)
            except NativeMappingError as exc:
                if exc.code != "transport_fields_on_tcp":
                    continue
            except (EngineError, ValueError, TypeError, OverflowError):
                continue
            else:
                continue
            params = item.params
            present = tuple(key for key in FIELDS if key in params)
            if not present:
                raise RuntimeError("TCP field rejection without registered field")
            rows += 1
            n, h, t = _network(params), _header(params), _tls(params)
            network[n] += 1
            header[h] += 1
            tls[t] += 1
            for key in present:
                fields[key] += 1
                shapes[f"{key}:{_classify(params[key])}"] += 1
            contexts[" | ".join((n, h, t, "+".join(present)))] += 1

    def ordered(counter: Counter) -> dict:
        return dict(sorted(counter.items(), key=lambda pair: (-pair[1], pair[0])))

    return {
        "schema": "vmess-tcp-field-rejections-v1",
        "checkpoint": checkpoint.name,
        "rows": rows,
        "invalid_checkpoint_rows": invalid,
        "note": "First-rejection census; field counts overlap; unknown values bucketed. Does not prove equivalence.",
        "by_network": ordered(network),
        "by_header": ordered(header),
        "by_tls": ordered(tls),
        "by_field": ordered(fields),
        "by_field_value_class": ordered(shapes),
        "contexts": ordered(contexts),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-vmess-tcp-fields.json"))
    args = parser.parse_args()
    report = audit(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"VMess transport_fields_on_tcp first-rejections={report['rows']}")


if __name__ == "__main__":
    main()
