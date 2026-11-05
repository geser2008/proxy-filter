from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_native_coverage import coverage_audit, _parse_record

UUID = "00000000-0000-0000-0000-000000000001"


def row(protocol="vless", params=None, fmt="vless-uri", original="vless://SECRET"):
    return {
        "config": {
            "protocol": protocol, "server": "private.example", "port": 443,
            "params": {"uuid": UUID, "security": "tls", "type": "ws"} if params is None else params,
        },
        "original": {"format": fmt, "raw": original},
    }


class NativeCoverageAuditTests(unittest.TestCase):
    def make_audit(self, data):
        with tempfile.TemporaryDirectory() as temp:
            checkpoint = Path(temp) / "03-safe.jsonl"
            checkpoint.write_text(
                "\n".join(json.dumps(x) if not isinstance(x, str) else x for x in data) + "\n",
                encoding="utf-8",
            )
            return coverage_audit(checkpoint)

    def test_counts_success_rejection_and_loss_separately(self):
        report = self.make_audit([
            row(),
            row(params={"uuid": UUID, "type": "ws", "Telegram": "PRIVATE_CHANNEL"}),
            row(params={"uuid": UUID, "type": "unknown-transport"}),
            row(fmt="sing-box"),
            "{broken json",
        ])
        t = report["total"]
        self.assertEqual((t["rows"], t["native_ok"], t["rejected"]), (3, 2, 1))
        self.assertEqual(t["native_ok_no_unclassified_loss"], 1)
        self.assertEqual(t["native_ok_unclassified_loss"], 1)
        self.assertEqual(t["reasons"]["unsupported_transport"], 1)
        self.assertEqual(t["dropped_fields"]["unclassified"], 1)
        self.assertEqual(report["skipped_non_uri"], 1)
        self.assertEqual(report["invalid_rows"], 1)

    def test_hy2_alias_is_aggregated_under_hysteria2(self):
        report = self.make_audit([
            row("hy2", {"password": "SECRET"}, "hy2-uri", "hy2://SECRET@example.org"),
            row("hysteria2", {"password": "SECRET"}, "hysteria2-uri", "hysteria2://SECRET"),
        ])
        self.assertEqual(report["protocols"]["hysteria2"]["rows"], 2)
        self.assertNotIn("hy2", report["protocols"])

    def test_report_never_emits_endpoint_uri_secret_or_unknown_names(self):
        report = self.make_audit([
            row(params={"uuid": UUID, "type": "ws", "VendorPrivateName": "PrivateValue"}),
            row(params={"uuid": UUID, "type": "unknown-transport", "OpaquePassword": "SECRET"}),
        ])
        serialized = json.dumps(report)
        for private in ("private.example", "SECRET", UUID, "VendorPrivateName",
                        "PrivateValue", "OpaquePassword", "vless://"):
            self.assertNotIn(private, serialized)

    def test_corrupted_checkpoint_rows_are_invalid(self):
        report = self.make_audit(["null", "[]", "{}", row(params=[]), "not-json"])
        self.assertEqual(report["invalid_rows"], 5)
        self.assertEqual(report["total"]["rows"], 0)

    def test_input_record_is_not_modified_by_conversion(self):
        original = row()
        proxy = _parse_record(original)
        from proxyfilter.native_experiment import convert_uri_to_native
        convert_uri_to_native(proxy)
        self.assertEqual(proxy.params, original["config"]["params"])
        self.assertEqual(proxy.original_raw, original["original"]["raw"])


if __name__ == "__main__":
    unittest.main()
