#!/usr/bin/env python3
"""Read-only per-protocol URI field inventory for proxy-filter JSONL checkpoints.

Counts field names and Python value types, never records credential values or raw URI.
Supports the canonical checkpoint model: {"config": {"protocol": ..., "params": ...}}.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

STAGE_NAMES = (
    "01-parsed.jsonl",
    "03-safe.jsonl",
    "11-rejected-render.jsonl",
    "14-published.jsonl",
)

# Protocol-specific fields are collected to prioritize native JSON mapping.
# This is an audit vocabulary, NOT a normative protocol schema or acceptance gate.
KNOWN = {
    "vless": set("""
        uuid id flow packet_encoding packet-encoding packetEncoding encryption
        security tls sni server_name servername server-name alpn fp client-fingerprint
        fingerprint pbk public_key sid short_id spx spider_x reality-opts
        type net network transport host path serviceName service_name mode extra
        headerType header_type ed eh max_early_data early_data_header_name
        allowInsecure allow_insecure skip-cert-verify skip_cert_verify insecure
        cs cipher_suites pcs pinnedPeerCertSha256 peer_certificate_sha256
        ech echConfigList fm final_mask name tag ps udp
        ws-opts grpc-opts multiplex
    """.split()),
    "vmess": set("""
        v add port ps id uuid aid alterId alter_id scy security cipher
        tls sni server_name alpn fp client-fingerprint fingerprint
        net type network transport host path serviceName service_name
        headerType header_type mode extra ed eh packet_encoding
        packet-encoding packetEncoding global_padding authenticated_length
        insecure allowInsecure skip-cert-verify pcs vcn fm final_mask
        ws-opts grpc-opts multiplex name tag udp
    """.split()),
    "trojan": set("""
        password security tls sni server_name alpn fp client-fingerprint
        fingerprint type net network transport host path serviceName
        service_name headerType header_type mode extra ed eh
        insecure allowInsecure skip-cert-verify name tag ps udp
        ws-opts grpc-opts multiplex fm final_mask encryption
    """.split()),
    "ss": set("""
        method cipher password plugin plugin_opts plugin-opts network
        udp_over_tcp udp-over-tcp multiplex smux type headerType
        name tag ps udp
    """.split()),
    "hysteria2": set("""
        password auth sni server_name alpn tls insecure skip-cert-verify
        allowInsecure up down up_mbps down_mbps up-mbps down-mbps
        obfs obfs-password obfs_password server_ports ports mport
        hop_interval hop-interval hop_interval_max hop-interval-max
        network fingerprint fp client-fingerprint pinSHA256 pin_sha256
        fastopen realm realm-opts obfs_min_packet_size obfs_max_packet_size
        bbr_profile brutal_debug disable_chrome_parrot name tag ps
    """.split()),
    "tuic": set("""
        uuid password sni server_name alpn tls insecure skip-cert-verify
        allowInsecure allow_insecure congestion_control congestion-controller
        udp_relay_mode udp-relay-mode udp_over_stream udp-over-stream
        zero_rtt_handshake zero-rtt-handshake reduce_rtt heartbeat
        heartbeat_interval heartbeat-interval network token fp
        client-fingerprint fingerprint disable_sni disable-sni
        name tag ps
    """.split()),
}
KNOWN["hy2"] = KNOWN["hysteria2"]


def summarize(path: Path) -> dict:
    by_protocol = defaultdict(
        lambda: {"rows": 0, "field_counts": Counter(),
                 "types": defaultdict(Counter), "unclassified": Counter()}
    )
    total = 0
    invalid = 0
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                cfg = row["config"]
                protocol = str(cfg["protocol"]).lower()
                params = cfg["params"]
                if not isinstance(params, dict):
                    raise ValueError("config.params must be an object")
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                invalid += 1
                continue
            total += 1
            item = by_protocol[protocol]
            item["rows"] += 1
            known = KNOWN.get(protocol, set())
            for field, value in params.items():
                field = str(field)
                item["field_counts"][field] += 1
                item["types"][field][type(value).__name__] += 1
                if field not in known:
                    item["unclassified"][field] += 1

    return {
        "file": path.name, "valid_rows": total, "invalid_rows": invalid,
        "protocols": {
            proto: {
                "rows": item["rows"],
                "fields": [
                    {
                        "key": key, "count": count,
                        "value_types": dict(sorted(item["types"][key].items())),
                        "classification": (
                            "known-vocabulary" if key in KNOWN.get(proto, set())
                            else "requires-review"
                        ),
                    }
                    for key, count in sorted(
                        item["field_counts"].items(),
                        key=lambda t: (-t[1], t[0]),
                    )
                ],
                "requires_review": dict(sorted(
                    item["unclassified"].items(),
                    key=lambda t: (-t[1], t[0]),
                )),
            }
            for proto, item in sorted(by_protocol.items())
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, default=Path("../data/work"))
    parser.add_argument(
        "--output", type=Path,
        default=Path("/tmp/proxy-filter-uri-field-inventory.json"),
    )
    args = parser.parse_args()
    report = {
        "notice": (
            "Known vocabulary is only a review aid. Unknown names may be "
            "connection-relevant; do not drop them in production based on this report."
        ),
        "stages": {},
    }
    for name in STAGE_NAMES:
        path = args.work / name
        if path.exists():
            report["stages"][name] = summarize(path)
        else:
            report["stages"][name] = {"missing": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"report: {args.output}")
    for name, result in report["stages"].items():
        if result.get("missing"):
            print(f"{name}: MISSING")
            continue
        print(f"{name}: records={result['valid_rows']} invalid={result['invalid_rows']}")
        for protocol, item in result["protocols"].items():
            print(
                f"  {protocol:10} rows={item['rows']:6} "
                f"fields={len(item['fields']):3} "
                f"review={','.join(item['requires_review']) or '-'}"
            )


if __name__ == "__main__":
    main()
