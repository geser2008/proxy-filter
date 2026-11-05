from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_vmess_lossy_fields import audit

UUID = "00000000-0000-0000-0000-000000000001"


def row(params, protocol="vmess", fmt="vmess-uri"):
    return {
        "config": {
            "protocol": protocol, "server": "PRIVATE.example", "port": 443,
            "params": {"id": UUID, **params},
        },
        "original": {"format": fmt, "raw": "vmess://SECRET"},
    }


class VMessLossyFieldsTests(unittest.TestCase):
    def run_audit(self, rows):
        with tempfile.TemporaryDirectory() as root:
            checkpoint = Path(root) / "03-safe.jsonl"
            checkpoint.write_text(
                "\n".join(json.dumps(item) if isinstance(item, dict) else item for item in rows)
                + "\n", encoding="utf-8",
            )
            return audit(checkpoint)

    def test_approved_names_and_unknown_aggregate_only(self):
        report = self.run_audit([
            row({"pcs": "", "vcn": "PRIVATEVALUE"}),
            row({"pcs": "", "vcn": "MORE", "SecretNewField": "SECRET"}),
            row({"pcs": "", "SecretNewField": "SECRET"}),
            row({"pcs": "", "scy": "auto"}),
            row({"pcs": "", "vcn": "SECRET"}, protocol="vless"),
            "not-json",
        ])
        self.assertEqual(report["rows"], 3)
        self.assertEqual(report["with_empty_pcs"], 3)
        self.assertEqual(report["invalid_checkpoint_rows"], 1)
        self.assertEqual(report["by_field_category"], {
            "vcn": 2, "other_unregistered": 2,
        })
        self.assertEqual(report["other_unregistered_only"], 1)
        self.assertEqual(report["by_combination"], {
            "vcn": 1, "other_unregistered + vcn": 1, "other_unregistered": 1,
        })
        serialized = json.dumps(report)
        for secret in ("PRIVATEVALUE", "MORE", "PRIVATE.example", "SECRET",
                       "SecretNewField", UUID, "vmess://"):
            self.assertNotIn(secret, serialized)

    def test_does_not_count_rejected_nodes(self):
        report = self.run_audit([
            row({"pcs": "NONEMPTY", "HiddenField": "SECRET"}),
            row({"pcs": "", "ech": "ECHSECRET", "HiddenField": "SECRET"}),
        ])
        self.assertEqual(report["rows"], 0)


if __name__ == "__main__":
    unittest.main()
