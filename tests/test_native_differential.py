from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools.native_differential import (
    capture_podkop_engine, compare, load_fixtures, load_oracle,
    native_result, run,
)

FIXTURES = Path(__file__).parent / "fixtures" / "native_differential.json"


class NativeDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = load_fixtures(FIXTURES)

    def test_synthetic_fixtures_have_expected_native_results(self):
        self.assertGreaterEqual(len(self.fixtures), 12)
        result = run(self.fixtures)
        self.assertEqual(result["expected_native_passed"], len(self.fixtures))
        self.assertEqual(result["target_comparisons"], {"unavailable": len(self.fixtures)})
        self.assertEqual(result["podkop_comparisons"], {"unavailable": len(self.fixtures)})

    def test_report_has_no_uri_or_credential(self):
        result = json.dumps(run(self.fixtures))
        self.assertNotIn("vless://", result)
        self.assertNotIn("vmess://", result)
        self.assertNotIn("secret@example.org", result)
        self.assertNotIn("00000000-0000-0000-0000-000000000001", result)
        self.assertNotIn("xPaddingBytes", result)

    def test_comparison_is_structural_not_semantic(self):
        one = {"status": "ok", "outbound": {"type": "vless", "tls": {"enabled": True}}}
        self.assertEqual(compare(one, one), "structural_equal_unverified")
        self.assertEqual(compare(one, {"status": "ok", "outbound": {"type": "vless"}}),
                         "structural_difference")
        self.assertEqual(compare(one, {"status": "rejected"}), "status_mismatch")
        self.assertEqual(compare(one, {"status": "unavailable"}), "unavailable")
        self.assertEqual(compare({"status": "rejected"}, {"status": "rejected"}),
                         "both_rejected")
        self.assertEqual(compare({**one, "lossless_fields": False}, one),
                         "unclassified_loss")

    def test_oracle_file_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oracle.json"
            path.write_text(json.dumps({"unknown-id": {"status": "rejected"}}))
            with self.assertRaises(ValueError):
                load_oracle(path, {"fixture"})
            path.write_text(json.dumps({"fixture": {"status": "ok"}}))
            with self.assertRaises(ValueError):
                load_oracle(path, {"fixture"})
            path.write_text(json.dumps({"fixture": {"status": "ok", "outbound": {"type": "vless"}}}))
            self.assertEqual(load_oracle(path, {"fixture"})["fixture"]["status"], "ok")

    @patch("tools.native_differential.subprocess.run")
    def test_podkop_oracle_passes_uri_via_stdin_and_hides_stderr(self, mock_run):
        from subprocess import CompletedProcess
        mock_run.return_value = CompletedProcess(
            args=[], returncode=2, stdout="",
            stderr="secret password from arbitrary URI",
        )
        result = capture_podkop_engine("vless://secret@example.org:443", "/usr/bin/sing-box")
        self.assertEqual(result, {"status": "rejected"})
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["/usr/bin/sing-box", "tools", "decode-link", "--compact"])
        self.assertIn("secret", kwargs["input"])
        self.assertNotIn("secret", str(result))

    def test_target_oracle_structural_equality_is_not_certification(self):
        item = next(x for x in self.fixtures if x["id"] == "vless-ws-tls")
        n = native_result(item)
        self.assertEqual(n["status"], "ok")
        report = run([item], {item["id"]: {"status": "ok", "outbound": n["outbound"]}})
        self.assertEqual(report["results"][0]["vs_target"], "structural_equal_unverified")


if __name__ == "__main__":
    unittest.main()
