from __future__ import annotations

import unittest

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.native_experiment import convert_uri_to_native


SOURCE = SourceInfo("fixture", "Fixture", "plain")
UUID = "00000000-0000-0000-0000-000000000001"


def proxy(protocol: str, params: dict) -> ProxyConfig:
    return ProxyConfig(
        SOURCE, protocol, "example.org", 443, "fixture",
        dict(params), f"{protocol}-uri", f"{protocol}://redacted",
    )


class NativeExperimentTests(unittest.TestCase):
    def test_vless_json_unknown_field_reported_without_mutation(self):
        p = proxy("vless", {
            "uuid": UUID, "security": "tls", "sni": "example.org",
            "encryption": "none", "Telegram": "private-channel",
        })
        original = dict(p.params)
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "vless")
        self.assertEqual(result.outbound["tls"]["server_name"], "example.org")
        self.assertNotIn("Telegram", result.outbound)
        self.assertNotIn("encryption", result.outbound)
        self.assertEqual([(d.name, d.reason) for d in result.dropped_fields],
                         [("Telegram", "unclassified")])
        self.assertFalse(result.no_unclassified_loss)
        self.assertEqual(p.params, original)
        self.assertEqual(p.original_raw, "vless://redacted")
        self.assertEqual(p.id, "")

    def test_metadata_does_not_create_unknown_loss(self):
        p = proxy("ss", {"method": "aes-256-gcm", "password": "secret", "ps": "label"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "shadowsocks")
        self.assertEqual(result.dropped_fields[0].reason, "metadata")
        self.assertTrue(result.no_unclassified_loss)

    def test_conflicting_sni_aliases_fail(self):
        p = proxy("trojan", {
            "password": "secret", "sni": "one.example", "server_name": "two.example",
        })
        with self.assertRaisesRegex(EngineError, "conflicting URI aliases"):
            convert_uri_to_native(p)

    def test_equal_aliases_are_allowed(self):
        p = proxy("trojan", {
            "password": "secret", "sni": "same.example", "server_name": "same.example",
        })
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["tls"]["server_name"], "same.example")

    def test_known_unsupported_field_fails_instead_of_dropping(self):
        p = proxy("vless", {"uuid": UUID, "fm": '{"tcp":[]}'})
        with self.assertRaisesRegex(EngineError, "unsupported connection-relevant"):
            convert_uri_to_native(p)

    def test_invalid_vless_encryption_fails(self):
        p = proxy("vless", {"uuid": UUID, "encryption": "aes-128-gcm"})
        with self.assertRaisesRegex(EngineError, "unsupported VLESS encryption"):
            convert_uri_to_native(p)

    def test_extended_input_not_accepted(self):
        p = proxy("vless", {"uuid": UUID})
        p.original_format = "clash"
        with self.assertRaisesRegex(EngineError, "share URI"):
            convert_uri_to_native(p)

    def test_supported_hy2_alias(self):
        p = proxy("hy2", {"password": "secret", "sni": "example.org"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "hysteria2")
        self.assertTrue(result.outbound["tls"]["enabled"])

    def test_vmess_explicit_cipher_and_tls(self):
        p = proxy("vmess", {"id": UUID, "scy": "auto", "tls": "tls"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "vmess")
        self.assertEqual(result.outbound["security"], "auto")
        self.assertTrue(result.outbound["tls"]["enabled"])

    def test_tuic_native_outbound(self):
        p = proxy("tuic", {"uuid": UUID, "password": "secret"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "tuic")
        self.assertTrue(result.outbound["tls"]["enabled"])


if __name__ == "__main__":
    unittest.main()
