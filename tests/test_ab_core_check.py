from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from tools.ab_core_check import compare_one, run

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
    def test_same_proxy_two_configurations_with_no_mutation(self):
        p = valid_proxy()
        initial_params = dict(p.params)
        seen: list[dict] = []

        def fake_check(binary, config, timeout):
            seen.append({"binary": binary, "outbound": config["outbounds"][0]})
            return "pass"

        with patch("tools.ab_core_check._check", side_effect=fake_check):
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
        with patch("tools.ab_core_check._check", return_value="pass") as check:
            row = compare_one(p, "extended-core", "native-core")
        self.assertEqual(row["extended"], "pass")
        self.assertEqual(row["native"], "not_run")
        self.assertEqual(row["conversion"], "rejected")
        self.assertEqual(check.call_count, 1)
        self.assertNotIn("fm", json.dumps(row.get("conversion_error_type", "")))

    def test_only_safe_checkpoint_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "01-parsed.jsonl"
            source.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "03-safe"):
                run(source, Path(tmp) / "report.jsonl", "extended", "native", 1, 3)

    def test_security_rejected_never_invokes_core(self):
        p = valid_proxy()
        p.params["insecure"] = "true"
        with patch("tools.ab_core_check._check") as check:
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
            with patch("tools.ab_core_check._check", return_value="pass"):
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
