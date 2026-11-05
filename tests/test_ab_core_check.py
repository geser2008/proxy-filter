from __future__ import annotations

import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from tools.ab_core_check import compare_one, run, inspect_core_version, inspect_pair, classify_check_failure, classify_mapper_failure, classify_mapper_fields, load_native_mismatch_hashes, diagnostic_value_shape

UUID = "00000000-0000-0000-0000-000000000001"


def valid_proxy() -> ProxyConfig:
    return ProxyConfig(
        SourceInfo("ab", "AB", "plain"),
        "vless",
        "example.org",
        443,
        "test",
        {"uuid": UUID, "security": "tls", "sni": "example.org"},
        "vless-uri",
        f"vless://{UUID}@example.org:443?security=tls&sni=example.org",
    )


class ABCheckTests(unittest.TestCase):
    def test_version_check_accepts_same_extended_build(self):
        completed = subprocess.CompletedProcess(
            args=["sing-box", "version"], returncode=0,
            stdout="sing-box version 1.14.3-extended-2.7.3-lite\nEnvironment: linux/amd64\n",
            stderr="",
        )
        with patch("tools.ab_core_check.subprocess.run", return_value=completed) as call:
            versions = inspect_pair("sing-box", "sing-box")
        self.assertEqual(versions["extended_version"], "1.14.3-extended-2.7.3-lite")
        self.assertEqual(call.call_count, 2)

    def test_version_check_rejects_standard_core_for_baseline(self):
        with patch("tools.ab_core_check.inspect_core_version", return_value="1.14.3"):
            with self.assertRaisesRegex(RuntimeError, "sing-box-extended"):
                inspect_pair("sing-box", "sing-box")

    def test_version_check_rejects_mixed_revisions(self):
        with patch("tools.ab_core_check.inspect_core_version",
                   side_effect=["1.14.3-extended-2.7.3-lite", "1.14.4-extended-2.7.3-lite"]):
            with self.assertRaisesRegex(RuntimeError, "identical core versions"):
                inspect_pair("one", "two")

    def test_version_command_failure_rejected(self):
        completed = subprocess.CompletedProcess(
            args=["sing-box", "version"], returncode=1, stdout="", stderr="broken"
        )
        with patch("tools.ab_core_check.subprocess.run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "returned 1"):
                inspect_core_version("sing-box")

    def test_same_proxy_two_configurations_with_no_mutation(self):
        p = valid_proxy()
        initial_params = dict(p.params)
        seen: list[dict] = []

        def fake_check(binary, config, timeout):
            seen.append({"binary": binary, "outbound": config["outbounds"][0]})
            return "pass", None

        with patch("tools.ab_core_check._safe_check", side_effect=fake_check):
            row = compare_one(p, "extended-core", "native-core")

        self.assertEqual(row["extended"], "pass")
        self.assertEqual(row["native"], "pass")
        self.assertEqual(row["conversion"], "mapped")
        self.assertEqual(seen[0]["outbound"]["type"], "parser")
        self.assertEqual(seen[0]["outbound"]["link"], p.original_raw)
        self.assertEqual(seen[1]["outbound"]["type"], "vless")
        self.assertNotIn("link", seen[1]["outbound"])
        self.assertEqual([item["binary"] for item in seen], ["extended-core", "native-core"])
        self.assertEqual(p.params, initial_params)

    def test_failed_conversion_does_not_suppress_baseline(self):
        p = valid_proxy()
        p.params["fm"] = "{}"
        with patch("tools.ab_core_check._safe_check", return_value=("pass", None)) as check:
            row = compare_one(p, "extended-core", "native-core")
        self.assertEqual(row["extended"], "pass")
        self.assertEqual(row["native"], "not_run")
        self.assertEqual(row["conversion"], "rejected")
        self.assertEqual(check.call_count, 1)
        self.assertNotIn("fm", json.dumps(row.get("conversion_error_type", "")))

    def test_structured_mapping_refusal_reason_without_secret(self):
        p = valid_proxy()
        p.params["fm"] = "sensitive-content"
        with patch("tools.ab_core_check._safe_check", return_value=("pass", None)):
            report = compare_one(p, "extended", "native")
        self.assertEqual(report["conversion_reason"], "unsupported_connection_field")
        self.assertNotIn("sensitive-content", json.dumps(report))
        self.assertNotIn(p.original_raw, json.dumps(report))

    def test_unsupported_fields_are_reported_without_values(self):
        p = valid_proxy()
        p.params["fm"] = "redacted-sensitive-value"
        p.params["spx"] = "/potential-secret-path"
        with patch("tools.ab_core_check._safe_check", return_value=("pass", None)):
            row = compare_one(p, "extended", "native")
        self.assertEqual(row["conversion_fields"], ["fm", "spx"])
        self.assertEqual(row["conversion_reason"], "unsupported_connection_field")
        text = json.dumps(row)
        self.assertNotIn("redacted-sensitive-value", text)
        self.assertNotIn("/potential-secret-path", text)

    def test_transport_specific_field_names_are_reported(self):
        p = valid_proxy()
        p.params.update({"type": "tcp", "host": "private.example.org",
                         "path": "/sensitive"})
        with patch("tools.ab_core_check._safe_check", return_value=("pass", None)):
            row = compare_one(p, "extended", "native")
        self.assertEqual(row["conversion_fields"], ["host", "path"])
        self.assertEqual(row["conversion_reason"], "transport_fields_on_tcp")
        self.assertNotIn("private.example.org", json.dumps(row))
        self.assertNotIn("/sensitive", json.dumps(row))

    def test_arbitrary_unknown_field_name_cannot_leak_via_report(self):
        p = valid_proxy()
        p.params["secret-credential-as-key"] = "sensitive"
        with patch("tools.ab_core_check._safe_check", return_value=("pass", None)):
            row = compare_one(p, "extended", "native")
        self.assertEqual(row["conversion"], "mapped")
        self.assertEqual(row["dropped_fields"],
                         [{"name": "<other_field>", "reason": "unclassified"}])
        self.assertFalse(row["no_unclassified_loss"])
        text = json.dumps(row)
        self.assertNotIn("secret-credential-as-key", text)
        self.assertNotIn("sensitive", text)

    def test_known_legacy_mapper_error_has_safe_category(self):
        exc = EngineError("unsupported TCP transport header type: SECRET-SENTINEL")
        self.assertEqual(classify_mapper_failure(exc),
                         "backend_unsupported_tcp_header")
        self.assertNotIn("SECRET", classify_mapper_failure(exc))
        self.assertEqual(classify_mapper_failure(ValueError("SECRET-SENTINEL")),
                         "backend_mapping_error")

    def test_mapper_boolean_field_extracted_without_value(self):
        exc = EngineError("invalid boolean value for global_padding: 'PRIVATE-TOKEN'")
        self.assertEqual(classify_mapper_fields(exc), ["global_padding"])
        self.assertEqual(classify_mapper_failure(exc), "backend_invalid_boolean")
        self.assertNotIn("PRIVATE-TOKEN", str(classify_mapper_fields(exc)))
        self.assertEqual(classify_mapper_fields(
            EngineError("invalid boolean value for fake_private_field: 'SECRET'")
        ), [])
        self.assertEqual(classify_mapper_fields(
            EngineError("invalid boolean value: 'SECRET'")
        ), [])

    def test_core_failure_is_classified_without_echoing_sensitive_values(self):
        sensitive = "user:secret@example.org"
        self.assertEqual(
            classify_check_failure(
                f"decode configuration: unknown field 'foo' near {sensitive}", ""
            ), "unknown_json_field"
        )
        self.assertEqual(
            classify_check_failure(f"connection to {sensitive} failed", ""),
            "other_check_failure"
        )

    def test_native_reason_written_and_counted(self):
        p = valid_proxy()
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "03-safe.jsonl"
            output = Path(tmp) / "report.jsonl"
            checkpoint.write_text(json.dumps(p.to_dict()) + "\n", encoding="utf-8")
            with patch("tools.ab_core_check._safe_check",
                       side_effect=[("pass", None), ("check_failed", "unknown_json_field")]):
                counts = run(checkpoint, output, "extended", "native", 1, 3)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(counts["mapped"], 1)
            self.assertEqual(report["native_reason"], "unknown_json_field")
            self.assertEqual(run.last_summary["native_check_reasons"],
                             {"unknown_json_field": 1})
            self.assertEqual(run.last_summary["by_protocol_outcome"],
                             {"vless:mapped:pass:check_failed": 1})

    def test_opaque_core_error_has_safe_keyword_category(self):
        raw = "FATAL: REALITY handshake error for PRIVATE-TOKEN.example"
        category = classify_check_failure(raw, "")
        self.assertEqual(category, "reality_mentioned")
        self.assertNotIn("PRIVATE-TOKEN", category)
        self.assertEqual(
            classify_check_failure("FATAL: failed for PRIVATE-TOKEN.example", ""),
            "other_check_failure",
        )

    def test_focus_report_picks_only_native_mismatches(self):
        p = valid_proxy()
        first = p.original_raw
        focus = __import__("hashlib").sha256(first.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "prior.jsonl"
            report_path.write_text(
                json.dumps({"uri_sha256": focus, "extended": "pass",
                            "native": "check_failed"}) + "\n"
                + json.dumps({"uri_sha256": "0" * 64, "extended": "pass",
                              "native": "pass"}) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(load_native_mismatch_hashes(report_path), {focus})
            checkpoint = Path(tmp) / "03-safe.jsonl"
            other = valid_proxy()
            other.original_raw = "vless://different-private-credential"
            checkpoint.write_text(
                json.dumps(p.to_dict()) + "\n" + json.dumps(other.to_dict()) + "\n",
                encoding="utf-8",
            )
            output = Path(tmp) / "focused.jsonl"
            with patch("tools.ab_core_check._safe_check", return_value=("pass", None)) as check:
                count = run(checkpoint, output, "extended", "native", 0, 3, {focus})
            self.assertEqual(count, {"mapped": 1})
            self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 1)
            self.assertEqual(check.call_count, 2)

    def test_focus_report_rejects_invalid_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "prior.jsonl"
            report.write_text(
                json.dumps({"uri_sha256": "SECRET", "extended": "pass",
                            "native": "check_failed"}) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid URI digest"):
                load_native_mismatch_hashes(report)

    def test_boolean_value_shape_never_contains_content(self):
        self.assertEqual(diagnostic_value_shape(""), "empty_string")
        self.assertEqual(diagnostic_value_shape("   "), "whitespace_string")
        self.assertEqual(diagnostic_value_shape("PRIVATE-SECRET"), "nonempty_string")
        self.assertNotIn("PRIVATE-SECRET", diagnostic_value_shape("PRIVATE-SECRET"))

    def test_only_safe_checkpoint_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "01-parsed.jsonl"
            source.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "03-safe"):
                run(source, Path(tmp) / "report.jsonl", "extended", "native", 1, 3)

    def test_missing_checkpoint_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "03-safe.jsonl"
            output = Path(tmp) / "result.jsonl"
            with self.assertRaisesRegex(FileNotFoundError, "checkpoint not found"):
                run(checkpoint, output, "extended", "native", 1, 3)
            self.assertFalse(output.exists())

    def test_security_rejected_never_invokes_core(self):
        p = valid_proxy()
        p.params["insecure"] = "true"
        with patch("tools.ab_core_check._safe_check") as check:
            row = compare_one(p, "extended", "native")
        self.assertEqual(row["conversion"], "security_rejected")
        self.assertEqual(row["extended"], "not_run")
        check.assert_not_called()

    def test_checkpoint_does_not_write_uri_or_secret_to_report(self):
        p = valid_proxy()
        with tempfile.TemporaryDirectory() as tmp:
            checkpoint = Path(tmp) / "03-safe.jsonl"
            report = Path(tmp) / "comparison.jsonl"
            checkpoint.write_text(json.dumps(p.to_dict()) + "\n", encoding="utf-8")
            with patch("tools.ab_core_check._safe_check", return_value=("pass", None)):
                counts = run(checkpoint, report, "extended", "native", 1, 3)
            written = report.read_text(encoding="utf-8")
            self.assertEqual(counts, {"mapped": 1})
            self.assertNotIn(p.original_raw, written)
            self.assertNotIn(UUID, written)
            record = json.loads(written)
            self.assertEqual(record["extended"], "pass")
            self.assertEqual(record["native"], "pass")


if __name__ == "__main__":
    unittest.main()
