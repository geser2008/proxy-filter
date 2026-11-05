from __future__ import annotations

import base64
import json
from pathlib import Path
import tempfile
import unittest

from tools.audit_uri_provenance import DEFAULT_MATRIX, load_matrix
from tools.audit_uri_semantics import (
    cipher_suites_bucket, extra_bucket, semantic_audit, selector_bucket,
)


class UriSemanticAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = load_matrix(DEFAULT_MATRIX)

    def _audit(self, rows):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "03-safe.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in rows) + "\n",
                            encoding="utf-8")
            return semantic_audit(path, self.registry)

    def test_selector_uses_bounded_vocabulary(self):
        self.assertEqual(selector_bucket("headerType", "none"), "none")
        self.assertEqual(selector_bucket("headerType", "secret-host"), "<other>")
        self.assertEqual(selector_bucket("headerType", None), "<null>")

    def test_cipher_names_never_appear(self):
        self.assertEqual(cipher_suites_bucket("TLS_A:TLS_B"), "suite-count:2")
        self.assertEqual(cipher_suites_bucket("TLS_A:TLS_A"), "duplicate-suite")
        self.assertEqual(cipher_suites_bucket(""), "empty")
        self.assertEqual(cipher_suites_bucket("TLS_AES:example.com"),
                         "invalid-character-or-format")

    def test_xhttp_extra_shape_only(self):
        payload = {"downloadSettings": {"address": "private.example", "path": "/secret"}}
        raw = json.dumps(payload)
        b64 = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        self.assertEqual(extra_bucket(raw), ("json-text", "object"))
        self.assertEqual(extra_bucket(b64), ("base64url-json", "object"))
        self.assertEqual(extra_bucket("not-json!!"), ("invalid", "none"))
        self.assertEqual(extra_bucket('["secret"]'), ("json-text", "array"))
        self.assertEqual(extra_bucket("x" * 65537), ("oversized", "none"))

    def test_protocol_context_not_vmess_header_as_transport(self):
        report = self._audit([
            {"config": {"protocol": "vmess", "params": {
                "id": "private-uuid", "net": "ws", "type": "http",
                "cs": "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
                "tls": "tls",
            }}},
            {"config": {"protocol": "vless", "params": {
                "uuid": "private-uuid", "type": "xhttp", "security": "reality",
                "extra": base64.urlsafe_b64encode(
                    b'{"path":"/private","password":"hidden"}'
                ).decode().rstrip("="),
                "headerType": "secret-private-value",
            }}},
        ])
        vm = report["protocols"]["vmess"]
        self.assertEqual(vm["contexts"]["transport:ws"], 1)
        self.assertEqual(vm["selectors"]["type"]["http"], 1)
        self.assertEqual(vm["cs"]["value_shape"]["suite-count:2"], 1)
        vl = report["protocols"]["vless"]
        self.assertEqual(vl["extra"]["encoding"]["base64url-json"], 1)
        self.assertEqual(vl["cooccurrences"]["headerType_by_transport"]["xhttp"], 1)
        output = json.dumps(report)
        for value in ("private-uuid", "secret-private-value", "hidden",
                      "TLS_AES_128_GCM_SHA256", "/private", "password"):
            self.assertNotIn(value, output)

    def test_invalid_rows_counted_without_leaking(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "03-safe.jsonl"
            path.write_text('{"config":\n' + json.dumps({
                "config": {"protocol": "hy2", "params": {"sni": "secret.example"}}
            }) + "\n")
            report = semantic_audit(path, self.registry)
            self.assertEqual(report["valid_rows"], 1)
            self.assertEqual(report["invalid_rows"], 1)
            self.assertEqual(report["protocols"]["hysteria2"]["rows"], 1)
            self.assertNotIn("secret.example", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
