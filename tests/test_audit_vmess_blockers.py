from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_vmess_blockers import audit

UUID = "00000000-0000-0000-0000-000000000001"

def row(params, protocol="vmess", fmt="vmess-uri"):
    return {
        "config": {"protocol": protocol, "server": "PRIVATE.example", "port": 443,
                   "params": {"id": UUID, **params}},
        "original": {"format": fmt, "raw": "vmess://SECRET"},
    }

class VMessBlockerAuditTests(unittest.TestCase):
    def run_audit(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "03-safe.jsonl"
            path.write_text("\n".join(json.dumps(x) if isinstance(x, dict) else x for x in data)
                            + "\n", encoding="utf-8")
            return audit(path)

    def test_first_rejection_and_intersections(self):
        report = self.run_audit([
            row({"fm": "SECRET", "ech": "opaque"}),
            row({"fm": "OTHER"}),
            row({"net": "ws", "type": "none"}),
            row({"fm": "OUTSIDE"}, protocol="vless"),
            row({"fm": "OUTSIDE"}, fmt="sing-box"),
        ])
        self.assertEqual(report["rows"], 2)
        self.assertEqual(report["by_field"], {"fm": 2, "ech": 1})
        self.assertEqual(report["by_group"], {"finalmask": 2, "ech": 1})
        self.assertEqual(report["by_combination"], {"fm": 1, "ech + fm": 1})

    def test_aliases_and_no_secrets(self):
        report = self.run_audit([
            row({"spx": "PRIVATE", "spider_x": "SECRET"}),
            row({"token": "PASSWORD", "SecretCustomKey": "SECRET"}),
            "not-json",
        ])
        self.assertEqual(report["rows"], 2)
        self.assertEqual(report["by_group"]["reality_spider"], 1)
        self.assertEqual(report["invalid_checkpoint_rows"], 1)
        text = json.dumps(report)
        for secret in ("PRIVATE", "PASSWORD", "SECRET", "SecretCustomKey", UUID, "vmess://"):
            self.assertNotIn(secret, text)

if __name__ == "__main__":
    unittest.main()
