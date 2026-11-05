from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from tools.audit_vmess_vcn_context import audit

UUID = "00000000-0000-0000-0000-000000000001"


def row(params, protocol="vmess"):
    return {
        "config": {
            "protocol": protocol, "server": "PRIVATE.example", "port": 443,
            "params": {"id": UUID, **params},
        },
        "original": {"format": protocol + "-uri", "raw": protocol + "://SECRET"},
    }


class VMessVCNContextTests(unittest.TestCase):
    def test_categories_preserve_no_private_values(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "03-safe.jsonl"
            checkpoint.write_text("\n".join([
                json.dumps(row({"vcn": "", "pcs": "", "tls": "tls"})),
                json.dumps(row({"vcn": "SECRET_HOST", "pcs": "", "tls": "none"})),
                json.dumps(row({"vcn": None})),
                json.dumps(row({"vcn": "SECRET_HOST"}, protocol="vless")),
                "invalid-json",
            ]) + "\n", encoding="utf-8")
            report = audit(checkpoint)
        self.assertEqual(report["rows_with_vcn"], 3)
        self.assertEqual(report["invalid_checkpoint_rows"], 1)
        self.assertEqual(report["by_value_class"], {
            "empty_string": 1, "nonempty_string": 1, "non_string": 1,
        })
        self.assertEqual(sum(report["contexts"].values()), 3)
        output = json.dumps(report)
        for private in ("SECRET", "PRIVATE.example", "SECRET_HOST", UUID, "vmess://"):
            self.assertNotIn(private, output)


if __name__ == "__main__":
    unittest.main()
