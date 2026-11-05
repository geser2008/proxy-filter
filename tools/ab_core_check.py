#!/usr/bin/env python3
"""Offline A/B sing-box check on the SAME URI profiles.

A: original URI through sing-box-extended type=parser
B: experimental mapped native JSON.

Only read safe checkpoint input. Writes no raw URIs, credentials or JSON
outbounds to persistent reports. Network, latency and throughput NOT measured.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

# Allow both "python3 tools/ab_core_check.py" and "python3 -m tools.ab_core_check".
# The direct-script invocation otherwise places tools/ rather than the repo root
# on sys.path, so the sibling proxyfilter package cannot be imported.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig
from proxyfilter.native_experiment import NativeMappingError, convert_uri_to_native
from proxyfilter.security import check_static_security
from proxyfilter.singbox_modes import SingBoxBackend


def inspect_core_version(binary: str) -> str:
    """Read the core version without persisting the executable output verbatim."""
    try:
        proc = subprocess.run(
            [binary, "version"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot inspect core version: {type(exc).__name__}") from exc
    if proc.returncode:
        raise RuntimeError(f"core version command returned {proc.returncode}")
    # Reject unusual output instead of accidentally storing secrets or garbage.
    first_line = (proc.stdout or "").splitlines()
    line = first_line[0].strip() if first_line else ""
    if not re.fullmatch(r"sing-box version [A-Za-z0-9.+_-]+", line):
        raise RuntimeError("unexpected sing-box version output")
    return line.removeprefix("sing-box version ")


def inspect_pair(extended_binary: str, native_binary: str) -> dict[str, str]:
    """Fail early if A cannot parse URI or core revisions are not comparable."""
    extended = inspect_core_version(extended_binary)
    native = inspect_core_version(native_binary)
    if "extended" not in extended.lower():
        raise RuntimeError("extended binary does not identify as sing-box-extended")
    if extended != native:
        raise RuntimeError(
            "A/B requires identical core versions; pass the same extended binary "
            "for both --extended-bin and --native-bin"
        )
    return {"extended_version": extended, "native_version": native}


# Messages from the existing mapper are not trusted for reporting.
# These anchored, source-reviewed patterns emit ONLY fixed reason codes.
_MAPPER_PATTERNS = (
    ("backend_unsupported_tcp_header", r"^unsupported TCP transport header type:"),
    ("backend_unsupported_transport", r"^unsupported V2Ray transport:"),
    ("backend_invalid_boolean", r"^invalid boolean value"),
    ("backend_invalid_xhttp_json", r"^invalid XHTTP extra JSON:"),
    ("backend_unsupported_xhttp_field", r"^unsupported XHTTP extra field:"),
    ("backend_invalid_transport_headers", r"^(?:HTTP|HTTPUpgrade) transport headers must be an object$"),
    ("backend_invalid_multiplex", r"^multiplex must be an object$"),
    ("backend_unsupported_network", r"^unsupported (?:Shadowsocks|Hysteria2|TUIC) network:"),
)


_MAPPER_BOOLEAN_FIELDS = frozenset((
    "tls", "insecure", "disable_sni", "global_padding",
    "authenticated_length",
))


def classify_mapper_fields(exc: Exception) -> list[str]:
    """Source-reviewed strict-boolean field labels, never argument values."""
    if not isinstance(exc, EngineError):
        return []
    match = re.match(
        r"^invalid boolean value for ([a-z_]+):",
        str(exc),
    )
    if match and match.group(1) in _MAPPER_BOOLEAN_FIELDS:
        return [match.group(1)]
    return []


def diagnostic_value_shape(value: Any) -> str:
    """Diagnostic type/shape only, never the value itself."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        if not value:
            return "empty_string"
        if not value.strip():
            return "whitespace_string"
        return "nonempty_string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    return "other"


def classify_mapper_failure(exc: Exception) -> str:
    # Only known EngineError messages are inspected; arbitrary error text is
    # never emitted. A mismatch remains unclassified.
    if not isinstance(exc, EngineError):
        return "backend_mapping_error"
    message = str(exc)
    for code, pattern in _MAPPER_PATTERNS:
        if re.search(pattern, message):
            return code
    return "backend_mapping_error"


_CHECK_PATTERNS = (
    ("unknown_json_field", r"(?i)unknown field|unknown json field"),
    ("invalid_json_type", r"(?i)cannot unmarshal|expected (?:string|object|array|number|bool)|invalid character"),
    ("missing_required_field", r"(?i)missing (?:required )?field|missing (?:server|uuid|password)|required field"),
    ("invalid_field_value", r"(?i)invalid (?:value|type|argument|option)|unsupported (?:type|transport|protocol|cipher)"),
    ("unsupported_feature", r"(?i)not supported|unsupported|unknown (?:outbound|inbound) type"),
    ("invalid_configuration", r"(?i)decode configuration|parse configuration|invalid config"),
)


def classify_check_failure(stderr: str, stdout: str) -> str:
    """Fixed vocabulary only; never persist raw sing-box error text."""
    message = "\n".join((stderr or "", stdout or ""))
    for code, pattern in _CHECK_PATTERNS:
        if re.search(pattern, message):
            return code
    return "other_check_failure"


def _check_details(binary: str, config: dict[str, Any],
                   timeout: float = 20.0) -> tuple[str, str | None]:
    """Return result and safe error category without writing core diagnostics."""
    with tempfile.TemporaryDirectory(prefix="proxyfilter-ab-") as tmp:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        path.chmod(0o600)
        try:
            proc = subprocess.run(
                [binary, "check", "-c", str(path)],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return "timeout", "timeout"
        except OSError:
            return "binary_error", "binary_error"
        if proc.returncode == 0:
            return "pass", None
        return "check_failed", classify_check_failure(proc.stderr, proc.stdout)


def _safe_check(binary: str, config: dict[str, Any],
                timeout: float) -> tuple[str, str | None]:
    return _check_details(binary, config, timeout)


# URI parameter names may themselves contain arbitrary user text. This
# allowlist is diagnostic-only: unlisted names are never copied to reports.
_SAFE_FIELD_NAMES = frozenset((
    "fm", "final_mask", "pcs", "pinnedPeerCertSha256",
    "peer_certificate_sha256", "ech", "echConfigList", "spx",
    "spider_x", "smux", "pinSHA256", "pin_sha256", "fastopen",
    "realm-opts", "token", "authority", "headers", "host", "path",
    "serviceName", "service_name", "security", "allowinsecure",
    "peer", "type", "encryption", "fingerprint", "ws", "wspath", "headerType",
    "headertype", "pbk", "sid", "pool", "prefix", "udp", "v",
    "ps", "name", "tag", "note", "network",
))


def safe_field_name(name: str) -> str:
    return name if name in _SAFE_FIELD_NAMES else "<other_field>"


def compare_one(proxy: ProxyConfig, extended_binary: str, native_binary: str,
                timeout: float = 20.0) -> dict[str, Any]:
    """A/B check without changing persistent ProxyConfig history or identity."""
    raw = str(proxy.original_raw or "")
    result: dict[str, Any] = {
        "uri_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "protocol": proxy.protocol,
        "extended": "not_run",
        "native": "not_run",
        "conversion": "not_run",
        "dropped_fields": [],
        "no_unclassified_loss": False,
    }
    if not raw or not str(proxy.original_format).endswith("-uri"):
        result["conversion"] = "not_uri"
        return result
    safe, reasons = check_static_security(proxy)
    if not safe:
        result["conversion"] = "security_rejected"
        result["security_reason_codes"] = sorted(set(reasons))
        return result

    # Both tests receive the same runtime configuration template (listen
    # address, DNS, routing). Only outbound differs.
    extended_backend = SingBoxBackend(backend_mode="extended")
    base = extended_backend.render_config(proxy, 18080)
    result["extended"], extended_reason = _safe_check(extended_binary, base, timeout)
    if extended_reason:
        result["extended_reason"] = extended_reason

    try:
        converted = convert_uri_to_native(proxy)
    except NativeMappingError as exc:
        result["conversion"] = "rejected"
        result["conversion_reason"] = exc.code
        result["conversion_fields"] = [safe_field_name(name) for name in exc.fields]
        result["conversion_error_type"] = type(exc).__name__
        return result
    except Exception as exc:
        # Third-party mapper errors may contain secrets: classify only by
        # exception TYPE, never by message.
        result["conversion"] = "rejected"
        result["conversion_reason"] = classify_mapper_failure(exc)
        fields = classify_mapper_fields(exc)
        if fields:
            result["conversion_fields"] = fields
            if result["conversion_reason"] == "backend_invalid_boolean":
                result["conversion_value_shape"] = diagnostic_value_shape(proxy.params.get(fields[0]))
        result["conversion_error_type"] = type(exc).__name__
        return result

    result["conversion"] = "mapped"
    result["dropped_fields"] = [
        {"name": safe_field_name(item.name), "reason": item.reason}
        for item in converted.dropped_fields
    ]
    result["no_unclassified_loss"] = converted.no_unclassified_loss
    native_config = dict(base)
    native_config["outbounds"] = [converted.outbound]
    result["native"], native_reason = _safe_check(native_binary, native_config, timeout)
    if native_reason:
        result["native_reason"] = native_reason
    return result


def load_native_mismatch_hashes(report: Path) -> set[str]:
    """Select only A=pass/B=check_failed entries from a prior sanitized report."""
    hashes: set[str] = set()
    with report.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("invalid focus report row")
            if row.get("extended") != "pass" or row.get("native") != "check_failed":
                continue
            digest = row.get("uri_sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("focus report contains an invalid URI digest")
            hashes.add(digest)
    if not hashes:
        raise ValueError("focus report has no extended-pass/native-fail matches")
    return hashes


def run(checkpoint: Path, output: Path, extended_binary: str, native_binary: str,
        limit: int, timeout: float,
        focus_hashes: set[str] | None = None) -> dict[str, int]:
    if checkpoint.name != "03-safe.jsonl":
        raise ValueError("A/B check accepts only the 03-safe.jsonl checkpoint")
    if not checkpoint.is_file():
        raise FileNotFoundError(
            f"checkpoint not found: {checkpoint}. "
            "Use --checkpoint to specify an existing 03-safe.jsonl."
        )
    counts: Counter[str] = Counter()
    by_protocol: Counter[str] = Counter()
    by_protocol_outcome: Counter[str] = Counter()
    by_conversion_reason: Counter[str] = Counter()
    by_protocol_reason: Counter[str] = Counter()
    by_boolean_value_shape: Counter[str] = Counter()
    by_conversion_field: Counter[str] = Counter()
    by_protocol_conversion_field: Counter[str] = Counter()
    by_dropped_field: Counter[str] = Counter()
    by_native_check_reason: Counter[str] = Counter()
    output.parent.mkdir(parents=True, exist_ok=True)
    with checkpoint.open(encoding="utf-8") as source, output.open("w", encoding="utf-8") as sink:
        for lineno, line in enumerate(source, 1):
            if limit and sum(counts.values()) >= limit:
                break
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if focus_hashes is not None:
                    if not isinstance(row, dict):
                        continue
                    raw = row.get("original_raw")
                    if not isinstance(raw, str) or hashlib.sha256(raw.encode("utf-8")).hexdigest() not in focus_hashes:
                        continue
                proxy = ProxyConfig.from_dict(row)
                report = compare_one(proxy, extended_binary, native_binary, timeout)
            except (ValueError, KeyError, TypeError):
                # No raw input or exception messages are written.
                report = {"line": lineno, "conversion": "invalid_checkpoint",
                          "extended": "not_run", "native": "not_run"}
            sink.write(json.dumps(report, ensure_ascii=False, sort_keys=True) + "\n")
            counts[report["conversion"]] += 1
            protocol_name = str(report.get("protocol", "invalid"))
            by_protocol[protocol_name] += 1
            outcome = f"{protocol_name}:{report.get('conversion', 'unknown')}:{report.get('extended', 'not_run')}:{report.get('native', 'not_run')}"
            by_protocol_outcome[outcome] += 1
            if report.get("conversion_value_shape"):
                by_boolean_value_shape[f"{protocol_name}:{report['conversion_value_shape']}"] += 1
            if report.get("conversion_reason"):
                by_conversion_reason[str(report["conversion_reason"])] += 1
                by_protocol_reason[f"{protocol_name}:{report['conversion_reason']}"] += 1
            for field in report.get("conversion_fields", []):
                by_conversion_field[field] += 1
                by_protocol_conversion_field[f"{protocol_name}:{field}"] += 1
            for dropped in report.get("dropped_fields", []):
                by_dropped_field[dropped["name"]] += 1
            if report.get("native_reason"):
                by_native_check_reason[str(report["native_reason"])] += 1
    run.last_summary = {
        "conversion": dict(sorted(counts.items())),
        "by_protocol": dict(sorted(by_protocol.items())),
        "by_protocol_outcome": dict(sorted(by_protocol_outcome.items())),
        "conversion_reasons": dict(sorted(by_conversion_reason.items())),
        "by_protocol_reason": dict(sorted(by_protocol_reason.items())),
        "boolean_value_shapes": dict(sorted(by_boolean_value_shape.items())),
        "conversion_fields": dict(sorted(by_conversion_field.items())),
        "by_protocol_conversion_field": dict(sorted(by_protocol_conversion_field.items())),
        "dropped_fields": dict(sorted(by_dropped_field.items())),
        "native_check_reasons": dict(sorted(by_native_check_reason.items())),
    }
    return dict(sorted(counts.items()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", type=Path,
        default=Path(__file__).resolve().parents[2] / "data/work/03-safe.jsonl",
        help="Path to 03-safe.jsonl (default: sibling data/work of app/)",
    )
    parser.add_argument("--output", type=Path, default=Path("/tmp/proxyfilter-ab-core.jsonl"))
    parser.add_argument("--extended-bin", default="sing-box")
    parser.add_argument("--native-bin", default="sing-box")
    parser.add_argument(
        "--focus-report", type=Path,
        help="Recheck only extended-pass/native-fail URI hashes from a previous A/B JSONL report",
    )
    parser.add_argument("--limit", type=int, default=100, help="0 = all")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    if args.limit < 0 or args.timeout <= 0:
        parser.error("--limit must be nonnegative and --timeout positive")
    if not args.checkpoint.is_file():
        parser.error(f"checkpoint not found: {args.checkpoint}")
    try:
        versions = inspect_pair(args.extended_bin, args.native_bin)
    except RuntimeError as exc:
        parser.error(str(exc))
    print(f"sing-box extended: {versions['extended_version']}")
    print(f"sing-box native:   {versions['native_version']}")
    focus_hashes = None
    if args.focus_report is not None:
        try:
            focus_hashes = load_native_mismatch_hashes(args.focus_report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"invalid --focus-report: {type(exc).__name__}")
        print(f"focus: {len(focus_hashes)} native mismatch URI hashes")
    summary = run(args.checkpoint, args.output, args.extended_bin,
                  args.native_bin, args.limit, args.timeout, focus_hashes)
    print(f"report: {args.output}")
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    print(json.dumps(run.last_summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
