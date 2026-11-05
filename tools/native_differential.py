#!/usr/bin/env python3
"""Offline differential harness for synthetic URI -> native sing-box JSON fixtures.

The target sing-box-extended URI oracle is represented by an externally
captured JSON result file; no unverified command interface is assumed.
An optional second oracle runs podkop-engine decode-link via stdin.
Only aggregate statuses and structural equality appear in reports.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

# Support direct invocation: python3 tools/native_differential.py from app/.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.native_experiment import NativeMappingError, convert_uri_to_native
from proxyfilter.engine import EngineError

FIXTURE_SOURCE = SourceInfo("differential-fixture", "Differential fixture", "plain")
ALLOWED_PROTOCOLS = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"}
STATUSES = {"ok", "rejected", "unavailable"}
MAX_BYTES = 1024 * 1024


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def load_fixtures(path: Path) -> list[dict]:
    items = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(items, list):
        raise ValueError("fixtures must be a JSON list")
    seen = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {
            "id", "protocol", "uri", "params", "expected_native"
        }:
            raise ValueError("fixture has invalid keys")
        if not isinstance(item["id"], str) or not item["id"].isascii() or not (
            item["id"].replace("-", "").replace("_", "").isalnum()
        ) or item["id"] in seen:
            raise ValueError("fixture id must be unique and ASCII alphanumeric")
        seen.add(item["id"])
        if item["protocol"] not in ALLOWED_PROTOCOLS:
            raise ValueError("unsupported fixture protocol")
        if not isinstance(item["uri"], str) or not item["uri"].startswith(
            item["protocol"] + "://"
        ) or not isinstance(item["params"], dict):
            raise ValueError("fixture URI or params invalid")
        expected = item["expected_native"]
        if not isinstance(expected, dict) or set(expected) != {"extended", "podkop-engine"} or any(
            value not in {"ok", "rejected"} for value in expected.values()
        ):
            raise ValueError("expected_native requires both profile outcomes")
    return items


def native_result(item: dict, *, profile: str = "extended") -> dict:
    # Fixtures intentionally use a known synthetic endpoint. Never fetch or
    # validate URI values by network and never mutate the fixture.
    p = ProxyConfig(
        FIXTURE_SOURCE, item["protocol"], "example.org", 443, "fixture",
        dict(item["params"]), item["protocol"] + "-uri", item["uri"],
    )
    try:
        output = convert_uri_to_native(p, profile=profile)
    except NativeMappingError as exc:
        return {"status": "rejected", "reason": exc.code}
    except (EngineError, ValueError, TypeError) as exc:
        # EngineError may include sensitive values, so do not expose its text.
        return {"status": "rejected", "reason": "backend_rejected"}
    return {
        "status": "ok", "outbound": output.outbound,
        "lossless_fields": output.no_unclassified_loss,
        "dropped_count": len(output.dropped_fields),
    }


def check_podkop_binary(binary: str) -> dict:
    """Reject an incompatible executable before sending any fixture URIs.

    The real podkop-engine has a 'tools decode-link' subcommand. Never accept
    the generic sing-box executable simply because it responds to 'version'.
    """
    try:
        result = subprocess.run(
            [binary, "tools", "decode-link", "--help"],
            input="", capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("podkop-engine binary unavailable or not executable") from exc
    if result.returncode != 0:
        # No stderr/stdout: a binary may echo an unsupported argument or path.
        raise ValueError("binary does not support tools decode-link --help")
    return {"decode_link_help": "ok"}


def outbound_top_level_difference(one: dict, two: dict) -> list[str]:
    """Only report static top-level field names, never values or arbitrary keys."""
    allowed = {
        "type", "tag", "server", "server_port", "domain_resolver",
        "uuid", "password", "security", "alter_id", "tls", "transport",
        "flow", "packet_encoding", "multiplex",
    }
    if one.get("status") != "ok" or two.get("status") != "ok":
        return []
    a, b = one["outbound"], two["outbound"]
    return sorted(
        k for k in allowed
        if (k in a) != (k in b) or (k in a and k in b and a[k] != b[k])
    )


def capture_podkop_engine(uri: str, binary: str, timeout: float = 10.0) -> dict:
    """Invoke known podkop-engine CLI with URI via stdin, never argv or shell."""
    try:
        completed = subprocess.run(
            [binary, "tools", "decode-link", "--compact"],
            input=uri + "\n", text=True, capture_output=True, timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "unavailable"}
    # Never expose stderr, which may contain arbitrary URI fragments.
    if completed.returncode == 2:
        return {"status": "rejected"}
    if completed.returncode != 0 or len(completed.stdout) > MAX_BYTES:
        return {"status": "unavailable"}
    try:
        output = json.loads(completed.stdout)
    except (json.JSONDecodeError, ValueError):
        return {"status": "unavailable"}
    if not isinstance(output, dict):
        return {"status": "unavailable"}
    return {"status": "ok", "outbound": output}


def load_oracle(path: Path | None, fixture_ids: set[str]) -> dict:
    if path is None:
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) - fixture_ids:
        raise ValueError("oracle result IDs must match known fixtures")
    for value in raw.values():
        if not isinstance(value, dict) or value.get("status") not in STATUSES:
            raise ValueError("invalid oracle status")
        if value["status"] == "ok" and not isinstance(value.get("outbound"), dict):
            raise ValueError("successful oracle result must include outbound object")
    return raw


def compare(one: dict, two: dict) -> str:
    if one["status"] == "unavailable" or two["status"] == "unavailable":
        return "unavailable"
    if one["status"] != two["status"]:
        return "status_mismatch"
    if one["status"] == "rejected":
        return "both_rejected"
    if one.get("lossless_fields") is False:
        return "unclassified_loss"
    # Exact structural equality is deliberately stricter than semantic
    # equivalence: defaults and aliases are NOT silently normalized.
    if _fingerprint(one["outbound"]) == _fingerprint(two["outbound"]):
        return "structural_equal_unverified"
    return "structural_difference"


def run(fixtures: list[dict], target: dict | None = None,
        podkop_binary: str | None = None,
        native_profile: str = "extended") -> dict:
    if native_profile not in {"extended", "podkop-engine"}:
        raise ValueError("unsupported native profile")
    if podkop_binary:
        check_podkop_binary(podkop_binary)
    target = target or {}
    entries = []
    for item in fixtures:
        native = native_result(item, profile=native_profile)
        oracle = target.get(item["id"], {"status": "unavailable"})
        podkop = (capture_podkop_engine(item["uri"], podkop_binary)
                  if podkop_binary else {"status": "unavailable"})
        entries.append({
            "id": item["id"],
            "native": native["status"],
            "native_reason": native.get("reason"),
            "expected_native_match": native["status"] == item["expected_native"][native_profile],
            "target": oracle["status"],
            "podkop": podkop["status"],
            "vs_target": compare(native, oracle),
            "vs_podkop": compare(native, podkop),
            "podkop_differing_fields": outbound_top_level_difference(native, podkop),
        })
    return {
        "schema": "native-differential-v1",
        "native_profile": native_profile,
        "notice": "Synthetic fixtures only. No network oracle and no semantic equivalence assertion.",
        "fixtures": len(entries),
        "expected_native_passed": sum(e["expected_native_match"] for e in entries),
        "target_comparisons": dict(sorted(Counter(e["vs_target"] for e in entries).items())),
        "podkop_comparisons": dict(sorted(Counter(e["vs_podkop"] for e in entries).items())),
        "podkop_oracle_checked": sum(e["podkop"] != "unavailable" for e in entries),
        "podkop_mismatch_ids": [
            e["id"] for e in entries if e["vs_podkop"] in {
                "status_mismatch", "structural_difference", "unclassified_loss"
            }
        ],
        "results": entries,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fixtures", type=Path, default=Path("tests/fixtures/native_differential.json"))
    p.add_argument("--target-oracle", type=Path,
                   help="Pre-captured target sing-box-extended URI parser outputs")
    p.add_argument("--podkop-binary", help="Local path to installed podkop-engine executable")
    p.add_argument("--native-profile", choices=("extended", "podkop-engine"),
                   default="extended", help="Opt-in XHTTP parsing reference profile")
    p.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-native-differential.json"))
    a = p.parse_args()
    fixtures = load_fixtures(a.fixtures)
    target = load_oracle(a.target_oracle, {item["id"] for item in fixtures})
    report = run(fixtures, target, a.podkop_binary, a.native_profile)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"report: {a.output}; fixtures={report['fixtures']} "
          f"expected_native_passed={report['expected_native_passed']}")
    print("target:", report["target_comparisons"])
    print("podkop:", report["podkop_comparisons"])
    print("podkop oracle checked:", report["podkop_oracle_checked"])
    print("podkop mismatch IDs:", ", ".join(report["podkop_mismatch_ids"]) or "(none)")


if __name__ == "__main__":
    main()
