from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_vmess_tcp_fields import audit, _classify, _network, _header, _tls

UUID = "00000000-0000-0000-0000-000000000001"


def row(params, *, protocol="vmess", fmt="vmess-uri"):
    return {
        "config": {
            "protocol": protocol, "server": "private.example", "port": 443,
            "params": {"id": UUID, **params},
        },
        "original": {"format": fmt, "raw": "vmess://SECRET"},
    }


class VMessTCPFieldsAuditTests(unittest.TestCase):
    def run_audit(self, entries):
        with tempfile.TemporaryDirectory() as folder:
            checkpoint = Path(folder) / "03-safe.jsonl"
            checkpoint.write_text(
                "\n".join(json.dumps(entry) if isinstance(entry, dict) else entry
                          for entry in entries) + "\n", encoding="utf-8",
            )
            return audit(checkpoint)

    def test_first_rejections_and_overlap(self):
        result = self.run_audit([
            row({"net": "tcp", "type": "none", "host": "PRIVATEHOST", "path": "/PRIVATE"}),
            row({"net": "tcp", "type": "none", "host": ""}),
            row({"net": "raw", "type": "none", "serviceName": "SECRET"}),
            row({"net": "ws", "type": "none", "host": "not-a-rejection"}),
            row({"net": "tcp", "type": "http", "host": "valid", "tls": "none"}),
            row({"pcs": "PIN", "net": "tcp", "host": "SECRET"}),
            row({"net": "tcp", "type": "srtp", "host": "SECRET"}),
            row({"net": "tcp", "host": "SECRET"}, protocol="vless"),
            row({"net": "tcp", "host": "SECRET"}, fmt="sing-box"),
            "invalid-json",
        ])
        self.assertEqual(result["rows"], 3)
        self.assertEqual(result["invalid_checkpoint_rows"], 1)
        self.assertEqual(result["by_network"], {"tcp": 2, "raw": 1})
        self.assertEqual(result["by_header"], {"none": 3})
        self.assertEqual(result["by_field"], {"host": 2, "path": 1, "serviceName": 1})
        self.assertEqual(result["by_field_value_class"]["host:empty"], 1)
        self.assertEqual(sum(result["contexts"].values()), 3)

    def test_no_secrets_or_unregistered_names(self):
        result = self.run_audit([
            row({"net": "tcp", "host": "PRIVATEHOST", "path": "/PRIVATE",
                 "UnregisteredSecretField": "SECRET", "tls": "tls"}),
        ])
        serialized = json.dumps(result)
        for word in ("PRIVATEHOST", "/PRIVATE", "UnregisteredSecretField",
                     "SECRET", "private.example", UUID, "vmess://"):
            self.assertNotIn(word, serialized)

    def test_classifier_does_not_coerce_nonstring(self):
        self.assertEqual(_classify(None), "non_string")
        self.assertEqual(_classify(False), "non_string")
        self.assertEqual(_network({"net": None}), "non_string")
        self.assertEqual(_header({"type": "srtp"}), "other")
        self.assertEqual(_tls({"tls": "tls"}), "enabled")


if __name__ == "__main__":
    unittest.main()
