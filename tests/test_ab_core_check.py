from __future__ import annotations

import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from tools.ab_core_check import compare_one, run, inspect_core_version, inspect_pair, classify_check_failure

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
