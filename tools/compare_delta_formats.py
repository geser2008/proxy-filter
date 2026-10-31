#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys
from typing import Any

# Allow direct execution as `python3 tools/compare_delta_formats.py` without
# requiring PYTHONPATH=. or installing proxy-filter as a package.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proxyfilter.ingest import detect_and_parse_compat
from proxyfilter.io import fetch_url
from proxyfilter.render import render_uri, validate_round_trip


DEFAULT_URI_URL = (
    "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/"
    "config/all_configs.txt"
)
DEFAULT_CLASH_URL = (
    "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/"
    "config/clash.yaml"
)


def _protocol_counts(proxies) -> dict[str, int]:
    return dict(sorted(Counter(proxy.protocol for proxy in proxies).items()))


def _unique_by_id(proxies):
    unique = {}
    for proxy in proxies:
        proxy.ensure_id()
        unique.setdefault(proxy.id, proxy)
    return unique


def _endpoint_key(proxy) -> tuple[str, str, int]:
    return (proxy.protocol.lower(), proxy.server.strip().lower(), int(proxy.port))


def _group_by_endpoint(proxies):
    groups = defaultdict(list)
    for proxy in proxies:
        groups[_endpoint_key(proxy)].append(proxy)
    return groups


def _flatten_paths(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key in sorted(value):
            path = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten_paths(value[key], path))
        return out
    if isinstance(value, list):
        return {prefix: value}
    return {prefix: value}


def _diff_paths(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    lflat = _flatten_paths(left)
    rflat = _flatten_paths(right)
    keys = set(lflat) | set(rflat)
    return sorted(key for key in keys if lflat.get(key) != rflat.get(key))


def _render_stats(proxies):
    ok = 0
    errors = Counter()
    by_protocol = Counter()
    rejected_by_protocol = Counter()

    for proxy in proxies:
        by_protocol[proxy.protocol] += 1
        try:
            uri = render_uri(proxy, proxy.name)
            validate_round_trip(proxy, uri)
            ok += 1
        except Exception as exc:
            rejected_by_protocol[proxy.protocol] += 1
            errors[str(exc)] += 1

    return {
        "total": len(proxies),
        "ok": ok,
        "rejected": len(proxies) - ok,
        "ok_percent": round((ok / len(proxies) * 100), 2) if proxies else 0.0,
        "by_protocol": dict(sorted(by_protocol.items())),
        "rejected_by_protocol": dict(sorted(rejected_by_protocol.items())),
        "top_errors": [
            {"count": count, "error": error}
            for error, count in errors.most_common(30)
        ],
    }


def _compare(uri_proxies, clash_proxies):
    uri_unique = _unique_by_id(uri_proxies)
    clash_unique = _unique_by_id(clash_proxies)

    uri_ids = set(uri_unique)
    clash_ids = set(clash_unique)
    exact = uri_ids & clash_ids

    uri_endpoints = _group_by_endpoint(uri_unique.values())
    clash_endpoints = _group_by_endpoint(clash_unique.values())
    shared_endpoints = set(uri_endpoints) & set(clash_endpoints)

    diff_counter = Counter()
    one_to_one_mismatches = []
    ambiguous_shared_endpoints = 0

    for endpoint in shared_endpoints:
        left = uri_endpoints[endpoint]
        right = clash_endpoints[endpoint]
        if len(left) != 1 or len(right) != 1:
            ambiguous_shared_endpoints += 1
            continue
        if left[0].id == right[0].id:
            continue

        paths = _diff_paths(left[0].identity_payload(), right[0].identity_payload())
        diff_counter.update(paths)
        if len(one_to_one_mismatches) < 25:
            one_to_one_mismatches.append(
                {
                    "endpoint": {
                        "protocol": endpoint[0],
                        "server": endpoint[1],
                        "port": endpoint[2],
                    },
                    "uri_name": left[0].name,
                    "clash_name": right[0].name,
                    "different_paths": paths,
                    "uri_identity": left[0].identity_payload(),
                    "clash_identity": right[0].identity_payload(),
                }
            )

    return {
        "uri_unique": len(uri_unique),
        "clash_unique": len(clash_unique),
        "exact_identity_overlap": len(exact),
        "uri_only_identity": len(uri_ids - clash_ids),
        "clash_only_identity": len(clash_ids - uri_ids),
        "uri_unique_endpoints": len(uri_endpoints),
        "clash_unique_endpoints": len(clash_endpoints),
        "shared_endpoints": len(shared_endpoints),
        "uri_only_endpoints": len(set(uri_endpoints) - set(clash_endpoints)),
        "clash_only_endpoints": len(set(clash_endpoints) - set(uri_endpoints)),
        "ambiguous_shared_endpoints": ambiguous_shared_endpoints,
        "top_semantic_diff_paths": [
            {"count": count, "path": path}
            for path, count in diff_counter.most_common(40)
        ],
        "sample_one_to_one_semantic_mismatches": one_to_one_mismatches,
    }


def _load(url: str, source_id: str):
    raw = fetch_url(url)
    proxies, errors, detected = detect_and_parse_compat(raw, source_id, "Delta-Kronecker")
    return proxies, errors, detected


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare Delta-Kronecker URI and Clash feeds using proxy-filter semantics."
    )
    parser.add_argument("--uri-url", default=DEFAULT_URI_URL)
    parser.add_argument("--clash-url", default=DEFAULT_CLASH_URL)
    parser.add_argument("--json", dest="json_path", help="write full report to this JSON file")
    args = parser.parse_args()

    print(f"[uri] download {args.uri_url}")
    uri_proxies, uri_errors, uri_format = _load(args.uri_url, "delta-uri")
    print(f"[uri] format={uri_format} parsed={len(uri_proxies)} errors={len(uri_errors)}")

    print(f"[clash] download {args.clash_url}")
    clash_proxies, clash_errors, clash_format = _load(args.clash_url, "delta-clash")
    print(f"[clash] format={clash_format} parsed={len(clash_proxies)} errors={len(clash_errors)}")

    report = {
        "uri": {
            "url": args.uri_url,
            "format": uri_format,
            "parsed": len(uri_proxies),
            "parse_errors": len(uri_errors),
            "protocols": _protocol_counts(uri_proxies),
            "error_samples": uri_errors[:25],
            "uri_roundtrip": _render_stats(uri_proxies),
        },
        "clash": {
            "url": args.clash_url,
            "format": clash_format,
            "parsed": len(clash_proxies),
            "parse_errors": len(clash_errors),
            "protocols": _protocol_counts(clash_proxies),
            "error_samples": clash_errors[:25],
            "uri_roundtrip": _render_stats(clash_proxies),
        },
        "comparison": _compare(uri_proxies, clash_proxies),
    }

    cmp = report["comparison"]
    print("\n=== PARSE ===")
    print(f"URI   parsed={report['uri']['parsed']} errors={report['uri']['parse_errors']} protocols={report['uri']['protocols']}")
    print(f"Clash parsed={report['clash']['parsed']} errors={report['clash']['parse_errors']} protocols={report['clash']['protocols']}")

    print("\n=== UNIQUE / OVERLAP ===")
    print(f"URI unique identities:    {cmp['uri_unique']}")
    print(f"Clash unique identities:  {cmp['clash_unique']}")
    print(f"Exact identity overlap:   {cmp['exact_identity_overlap']}")
    print(f"URI-only identities:      {cmp['uri_only_identity']}")
    print(f"Clash-only identities:    {cmp['clash_only_identity']}")
    print(f"Shared endpoints:         {cmp['shared_endpoints']}")
    print(f"URI-only endpoints:       {cmp['uri_only_endpoints']}")
    print(f"Clash-only endpoints:     {cmp['clash_only_endpoints']}")

    print("\n=== URI ROUND-TRIP ===")
    for label in ("uri", "clash"):
        stats = report[label]["uri_roundtrip"]
        print(
            f"{label.upper():5} ok={stats['ok']}/{stats['total']} "
            f"({stats['ok_percent']}%) rejected={stats['rejected']} "
            f"rejected_by_protocol={stats['rejected_by_protocol']}"
        )

    print("\n=== TOP SEMANTIC DIFFERENCES ON SAME UNIQUE ENDPOINT ===")
    for item in cmp["top_semantic_diff_paths"][:20]:
        print(f"{item['count']:6}  {item['path']}")

    print("\n=== TOP CLASH -> URI REJECTIONS ===")
    for item in report["clash"]["uri_roundtrip"]["top_errors"][:20]:
        print(f"{item['count']:6}  {item['error']}")

    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(f"\nFull report: {args.json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
