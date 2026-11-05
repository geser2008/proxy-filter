#!/usr/bin/env python3
"""Read-only, privacy-preserving semantic audit of checkpoint config.params.

Aggregate only a bounded vocabulary of non-secret selectors and structural
properties. Never persist URI, endpoint, parameter values, UUIDs, keys,
passwords, hostnames, paths, cipher-suite names or nested JSON content.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

try:
    from tools.audit_uri_provenance import DEFAULT_CHECKPOINT, DEFAULT_MATRIX, load_matrix
except ModuleNotFoundError as exc:
    if exc.name != "tools":
        raise
    # Direct execution: python3 tools/audit_uri_semantics.py from app/.
    from audit_uri_provenance import DEFAULT_CHECKPOINT, DEFAULT_MATRIX, load_matrix

# Exact, finite, public selector vocabularies; all other values are redacted.
TRANSPORT_VALUES = frozenset({
    "tcp", "raw", "ws", "websocket", "grpc", "http", "h2", "httpupgrade",
    "xhttp", "splithttp", "kcp", "quic", "domainsocket", "none", "",
})
SECURITY_VALUES = frozenset({"", "none", "tls", "reality", "xtls"})
HEADER_VALUES = frozenset({"", "none", "http", "srtp", "utp", "wechat-video", "dtls", "wireguard"})
XHTTP_MODES = frozenset({"auto", "packet-up", "stream-up", "stream-one", ""})
CIPHER_METHODS = frozenset({"", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"})
BOOLEAN_VALUES = frozenset({"", "true", "false", "1", "0", "yes", "no"})
MAX_EXTRA_BYTES = 65536
TARGET_FIELDS = ("headerType", "cs", "extra", "mode", "type", "net", "security", "tls")
TLS_FIELDS = frozenset({"cs", "cipher_suites", "cipher-suites", "fp", "sni", "alpn", "pbk", "sid", "insecure", "allowInsecure", "tls"})
AUTH_FIELDS = frozenset({"uuid", "id", "password", "auth", "method"})
# Explicit key allow-list: never summarize generic unknown values.
SAFE_SELECTORS = {
    "headerType": HEADER_VALUES,
    "type": TRANSPORT_VALUES,
    "net": TRANSPORT_VALUES,
    "security": SECURITY_VALUES,
    "tls": SECURITY_VALUES,
    "mode": XHTTP_MODES,
}
SAFE_CIPHER_SUITE_RE = re.compile(r"^[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")


def selector_bucket(key: str, value: object) -> str:
    if value is None:
        return "<null>"
    if not isinstance(value, str):
        return "<non-string>"
    if value in SAFE_SELECTORS.get(key, ()):
        return "<empty>" if value == "" else value
    return "<other>"


def cipher_suites_bucket(value: object) -> str:
    if value is None:
        return "null"
    if not isinstance(value, str):
        return "non-string"
    if not value:
        return "empty"
    if len(value) > 4096:
        return "oversized"
    if not SAFE_CIPHER_SUITE_RE.fullmatch(value):
        return "invalid-character-or-format"
    parts = value.split(":")
    if len(parts) != len(set(parts)):
        return "duplicate-suite"
    # Do not output suite names; list length is enough for structural analysis.
    return "suite-count:" + ("5+" if len(parts) >= 5 else str(len(parts)))


def _shape(payload: object) -> str:
    if isinstance(payload, dict):
        return "object"
    if isinstance(payload, list):
        return "array"
    if payload is None:
        return "null"
    if isinstance(payload, str):
        return "string"
    if isinstance(payload, bool):
        return "boolean"
    if isinstance(payload, (int, float)):
        return "number"
    return "unknown"


def _parse_extra_json(raw: str) -> tuple[str, object | None]:
    if len(raw) > MAX_EXTRA_BYTES:
        return "oversized", None
    try:
        return "json-text", json.loads(raw)
    except (json.JSONDecodeError, ValueError, RecursionError):
        pass
    if not BASE64URL_RE.fullmatch(raw):
        return "invalid", None
    try:
        payload = base64.b64decode(raw + "=" * (-len(raw) % 4),
                                   altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        return "invalid", None
    if len(payload) > MAX_EXTRA_BYTES:
        return "oversized", None
    try:
        return "base64url-json", json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return "invalid", None


def extra_bucket(value: object) -> tuple[str, str]:
    if value is None:
        return "null", "none"
    if not isinstance(value, str):
        return "non-string", "none"
    if not value:
        return "empty", "none"
    encoding, parsed = _parse_extra_json(value)
    if encoding not in {"json-text", "base64url-json"}:
        return encoding, "none"
    return encoding, _shape(parsed)


def context(params: dict) -> tuple[str, str, str]:
    transport = params.get("net") if "net" in params else params.get("type")
    if transport is None:
        transport = ""
    transport_bucket = selector_bucket("net", transport)
    # Do NOT use the VMess 'type' as transport.
    security = params.get("security", params.get("tls", ""))
    security_bucket = selector_bucket("security", security)
    return transport_bucket, security_bucket, (
        "tls-marker-present" if any(k in params for k in TLS_FIELDS) else "no-tls-marker"
    )


def semantic_audit(checkpoint: Path, registry: dict) -> dict:
    result = {
        "schema": "uri-semantic-aggregation-v2",
        "checkpoint": checkpoint.name,
        "privacy": "Only fixed selector vocabulary and structural buckets; no actual URI or secret field values",
        "valid_rows": 0,
        "invalid_rows": 0,
        "protocols": {},
    }
    acc = defaultdict(lambda: {
        "rows": 0, "unlisted": Counter(), "selectors": defaultdict(Counter),
        "cs": defaultdict(Counter), "extra": defaultdict(Counter),
        "contexts": Counter(), "cooccurrences": defaultdict(Counter),
    })
    with checkpoint.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                cfg = row["config"]
                proto = cfg["protocol"].lower()
                proto = "hysteria2" if proto == "hy2" else proto
                params = cfg["params"]
                if proto not in registry or not isinstance(params, dict):
                    raise ValueError("invalid model")
            except (KeyError, TypeError, AttributeError, ValueError, json.JSONDecodeError):
                result["invalid_rows"] += 1
                continue
            result["valid_rows"] += 1
            a = acc[proto]
            a["rows"] += 1
            transport, tls, marker = context(params) if proto != "vmess" else (
                selector_bucket("net", params.get("net", "")),
                selector_bucket("tls", params.get("tls", "")),
                "tls-marker-present" if any(k in params for k in TLS_FIELDS) else "no-tls-marker",
            )
            for k in params:
                if k not in registry[proto]:
                    # Keep count only, never expose unknown key or hash in semantic report.
                    a["unlisted"]["occurrences"] += 1
            a["contexts"]["transport:" + transport] += 1
            a["contexts"]["security:" + tls] += 1
            for field in ("headerType", "type", "net", "security", "tls", "mode"):
                if field in params:
                    a["selectors"][field][selector_bucket(field, params[field])] += 1
            for key in ("cs", "cipher_suites", "cipher-suites"):
                if key in params:
                    a["cs"]["value_shape"][cipher_suites_bucket(params[key])] += 1
                    a["cs"]["transport_context"][transport] += 1
                    a["cs"]["security_context"][tls] += 1
                    # A cs field itself is in TLS_FIELDS, so checking for
                    # any TLS marker would be tautologically true.
                    a["cs"]["tls_activation"][tls] += 1
            if "extra" in params:
                encoding, shape = extra_bucket(params["extra"])
                a["extra"]["encoding"][encoding] += 1
                a["extra"]["top_level_shape"][shape] += 1
                a["extra"]["transport_context"][transport] += 1
                a["extra"]["security_context"][tls] += 1
                a["extra"]["encoding_by_transport"][transport + " / " + encoding] += 1
            if "headerType" in params:
                a["cooccurrences"]["headerType_by_transport"][transport] += 1
                header = selector_bucket("headerType", params["headerType"])
                # Cross-tab uses fixed selector vocabulary or <other>, never
                # an unbounded user-supplied value.
                a["cooccurrences"]["headerType_value_by_transport"][transport + " / " + header] += 1
    for proto, a in sorted(acc.items()):
        result["protocols"][proto] = {
            "rows": a["rows"],
            "unlisted_occurrences": a["unlisted"]["occurrences"],
            "selectors": {k: dict(sorted(v.items())) for k, v in sorted(a["selectors"].items())},
            "cs": {k: dict(sorted(v.items())) for k, v in sorted(a["cs"].items())},
            "extra": {k: dict(sorted(v.items())) for k, v in sorted(a["extra"].items())},
            "contexts": dict(sorted(a["contexts"].items())),
            "cooccurrences": {k: dict(sorted(v.items())) for k, v in sorted(a["cooccurrences"].items())},
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-uri-semantic-audit.json"))
    args = parser.parse_args()
    report = semantic_audit(args.checkpoint, load_matrix(args.matrix))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"report: {args.output}")
    print(f"valid={report['valid_rows']} invalid={report['invalid_rows']}")
    for proto, detail in report["protocols"].items():
        print(f"{proto}: rows={detail['rows']} unlisted={detail['unlisted_occurrences']}")


if __name__ == "__main__":
    main()
