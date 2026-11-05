from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_uri_provenance import DEFAULT_MATRIX, audit, load_matrix


class UriProvenanceAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = load_matrix(DEFAULT_MATRIX)

    def test_matrix_covers_all_production_protocols(self):
        self.assertEqual(set(self.registry), {
            "vless", "vmess", "trojan", "ss", "hysteria2", "tuic",
        })
        for name in self.registry:
            self.assertGreater(len(self.registry[name]), 0)

    def test_protocol_specific_classes_not_shared(self):
        self.assertEqual(self.registry["vless"]["type"]["classes"], ["EXT"])
        self.assertEqual(self.registry["vmess"]["type"]["classes"], ["LEGACY"])
        self.assertIn("SPEC", self.registry["hysteria2"]["pinSHA256"]["classes"])
        self.assertEqual(self.registry["ss"]["plugin"]["classes"], ["SPEC"])
        self.assertIn("OBSERVED", self.registry["tuic"]["congestion_control"]["classes"])

    def test_nonproduction_scheme_is_not_a_field(self):
        self.assertNotIn("hysteria2+realm", self.registry["hysteria2"])
        self.assertNotIn("hy2", self.registry["hysteria2"])
        self.assertIn("pinSHA256", self.registry["hysteria2"])

    def test_nonproduction_scheme_with_qualified_class_is_ignored(self):
        matrix = DEFAULT_MATRIX.read_text(encoding="utf-8")
        self.assertIn("SPEC, вне production", matrix)
        # The scheme-level row must not be fed to the field-class parser.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "matrix.md"
            path.write_text(matrix, encoding="utf-8")
            registry = load_matrix(path)
        self.assertEqual(registry["hysteria2"]["pinSHA256"]["classes"],
                         ["SPEC"])

    def test_audit_observed_post_ingest_fields_are_registered(self):
        expected = {
            "vless": ("note", "allowinsecure"),
            "vmess": ("name", "skip-cert-verify", "serviceName"),
            "trojan": ("insecure", "spx", "note"),
            "ss": ("note",),
            "hysteria2": ("password", "security", "fm"),
        }
        for protocol, keys in expected.items():
            for key in keys:
                with self.subTest(protocol=protocol, key=key):
                    self.assertIn(key, self.registry[protocol])
                    self.assertIn("OBSERVED",
                                  self.registry[protocol][key]["classes"])

    def test_credential_names_from_uri_are_classified(self):
        self.assertIn("uuid", self.registry["vless"])
        self.assertIn("uuid", self.registry["tuic"])
        self.assertIn("password", self.registry["tuic"])
        self.assertIn("auth", self.registry["hysteria2"])

    def test_audit_does_not_disclose_secret_values_or_unknown_field_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "03-safe.jsonl"
            records = [
                {"config": {"protocol": "vless", "params": {
                    "uuid": "secret-uuid", "type": "ws",
                    "UNTRUSTED-private@example.com": "secret-value",
                }}},
                {"config": {"protocol": "hy2", "params": {
                    "auth": "password", "pinSHA256": "secret-hash",
                }}},
                {"config": {"protocol": "vmess", "params": {
                    "type": "none", "net": "ws", "v": "2",
                }}},
                {"config": {"protocol": "tuic", "params": {
                    "uuid": "sensitive", "password": "password",
                }}},
            ]
            path.write_text("\n".join(map(json.dumps, records)) + "\n"
                            + '{"config":', encoding="utf-8")
            report = audit(path, self.registry)
            serialized = json.dumps(report)
            self.assertEqual(report["valid_rows"], 4)
            self.assertEqual(report["invalid_rows"], 1)
            self.assertEqual(report["protocols"]["hysteria2"]["rows"], 1)
            self.assertEqual(report["protocols"]["vless"]["rows"], 1)
            self.assertEqual(
                report["protocols"]["vmess"]["fields"][0]["classes"],
                ["LEGACY"],
            )  # equal counts are sorted by name; 'net' first
            self.assertIn("sha256:", serialized)
            for fragment in ("secret-uuid", "secret-value", "secret-hash",
                             "UNTRUSTED-private@example.com", "sensitive"):
                self.assertNotIn(fragment, serialized)

    def test_matrix_layout_change_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "changed.md"
            path.write_text("# undocumented layout\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "markers"):
                load_matrix(path)


if __name__ == "__main__":
    unittest.main()
