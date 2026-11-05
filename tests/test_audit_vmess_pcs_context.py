from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_vmess_pcs_context import audit, _tls_state, _insecure_state

UUID = "00000000-0000-0000-0000-000000000001"


def row(params, *, protocol="vmess", fmt="vmess-uri"):
    return {
        "config": {
            "protocol": protocol, "server": "PRIVATE.example", "port": 443,
            "params": {"id": UUID, **params},
        },
        "original": {"format": fmt, "raw": "vmess://SECRET"},
    }


class VMessPCSContextAuditTests(unittest.TestCase):
    def run_audit(self, entries):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "03-safe.jsonl"
            path.write_text(
                "\n".join(json.dumps(item) if isinstance(item, dict) else item for item in entries) + "\n",
                encoding="utf-8",
            )
            return audit(path)

    def test_tls_state_uses_target_parser_literals_and_types(self):
        self.assertEqual(_tls_state({}), "absent")
        self.assertEqual(_tls_state({"tls": "tls"}), "enabled_literal")
        self.assertEqual(_tls_state({"tls": "true"}), "enabled_literal")
        self.assertEqual(_tls_state({"tls": "none"}), "disabled_literal")
        self.assertEqual(_tls_state({"tls": "TLS"}), "other_literal")
        self.assertEqual(_tls_state({"tls": True}), "non_string")

    def test_insecure_state_handles_conflicts_and_types(self):
        self.assertEqual(_insecure_state({}), "absent")
        self.assertEqual(_insecure_state({"insecure": "true"}), "on")
        self.assertEqual(_insecure_state({"insecure": "false"}), "off")
        self.assertEqual(_insecure_state({"insecure": "true", "skip-cert-verify": "false"}), "conflicting")
        self.assertEqual(_insecure_state({"insecure": True}), "non_string")
        self.assertEqual(_insecure_state({"allowInsecure": "true"}), "absent")

    def test_context_counts_only_first_rejections_and_hides_values(self):
        report = self.run_audit([
            row({"pcs": "PRIVATE_HASH", "tls": "tls", "insecure": "false", "ech": "ECHSECRET"}),
            row({"pcs": "", "tls": "none", "cert": "PEMSECRET"}),
            row({"pcs": "PRIVATE_HASH", "tls": True, "skip-cert-verify": True}),
            row({"echConfigList": "SECRET"}),
            row({"pcs": "ANOTHER"}, protocol="vless"),
            row({"pcs": "ANOTHER"}, fmt="sing-box"),
            row({"net": "ws", "type": "none"}),
            "invalid-json",
        ])
        self.assertEqual(report["rows"], 3)
        self.assertEqual(report["invalid_checkpoint_rows"], 1)
        self.assertEqual(report["tls_state"], {
            "disabled_literal": 1, "enabled_literal": 1, "non_string": 1,
        })
        self.assertEqual(report["pin_state"], {"nonempty_string": 2, "empty_string": 1})
        self.assertEqual(report["other_fields"]["ech_present"], 1)
        self.assertEqual(report["other_fields"]["cert_present"], 1)
        self.assertEqual(sum(report["contexts"].values()), report["rows"])
        output = json.dumps(report)
        for secret in (
            "PRIVATE_HASH", "PRIVATE.example", "SECRET", "ECHSECRET",
            "PEMSECRET", "ANOTHER", UUID, "vmess://",
        ):
            self.assertNotIn(secret, output)


if __name__ == "__main__":
    unittest.main()
