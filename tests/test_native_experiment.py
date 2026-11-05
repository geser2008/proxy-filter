from __future__ import annotations

import base64
import json
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
        with self.assertRaisesRegex(EngineError, "conflicting_aliases"):
            convert_uri_to_native(p)

    def test_equal_aliases_are_allowed(self):
        p = proxy("trojan", {
            "password": "secret", "sni": "same.example", "server_name": "same.example",
        })
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["tls"]["server_name"], "same.example")

    def test_known_unsupported_field_fails_instead_of_dropping(self):
        p = proxy("vless", {"uuid": UUID, "fm": '{"tcp":[]}'})
        with self.assertRaisesRegex(EngineError, "unsupported_connection_field"):
            convert_uri_to_native(p)

    def test_invalid_vless_encryption_fails(self):
        p = proxy("vless", {"uuid": UUID, "encryption": "aes-128-gcm"})
        with self.assertRaisesRegex(EngineError, "unsupported_vless_encryption"):
            convert_uri_to_native(p)

    def test_unknown_transport_never_falls_back_to_tcp(self):
        p = proxy("vless", {"uuid": UUID, "type": "future-transport"})
        with self.assertRaisesRegex(EngineError, "unsupported_transport"):
            convert_uri_to_native(p)

    def test_tcp_with_ws_path_does_not_silently_lose_path(self):
        p = proxy("vless", {"uuid": UUID, "type": "tcp", "path": "/hidden"})
        with self.assertRaisesRegex(EngineError, "transport_fields_on_tcp"):
            convert_uri_to_native(p)

    def test_reality_fingerprint_not_invented(self):
        p = proxy("vless", {
            "uuid": UUID, "security": "reality",
            "pbk": "public-key-placeholder",
        })
        with self.assertRaisesRegex(EngineError, "reality_missing_fingerprint"):
            convert_uri_to_native(p)

    def test_extended_input_not_accepted(self):
        p = proxy("vless", {"uuid": UUID})
        p.original_format = "clash"
        with self.assertRaisesRegex(EngineError, "not_uri"):
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

    def test_vmess_header_none_does_not_override_ws_transport(self):
        p = proxy("vmess", {"id": UUID, "scy": "auto", "tls": "tls",
                            "net": "ws", "type": "none", "path": "/socket"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["transport"]["type"], "ws")
        self.assertEqual(result.outbound["transport"]["path"], "/socket")
        self.assertEqual(p.params["type"], "none")

    def test_vmess_nontrivial_tcp_header_rejected(self):
        p = proxy("vmess", {"id": UUID, "net": "tcp", "type": "http"})
        with self.assertRaisesRegex(EngineError, "unsupported_vmess_header"):
            convert_uri_to_native(p)

    def test_vless_xhttp_base64url_extra_decoded_only_in_copy(self):
        extra = {"xPaddingBytes": "12-24", "mode": "stream-up"}
        encoded = base64.urlsafe_b64encode(json.dumps(extra).encode()).decode().rstrip("=")
        p = proxy("vless", {"uuid": UUID, "type": "xhttp",
                             "path": "/x", "extra": encoded})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["transport"]["type"], "xhttp")
        self.assertEqual(result.outbound["transport"]["x_padding_bytes"], "12-24")
        self.assertEqual(result.outbound["transport"]["mode"], "stream-up")
        self.assertEqual(p.params["extra"], encoded)

    def test_xhttp_plain_json_in_share_uri_is_not_base64url(self):
        p = proxy("vless", {"uuid": UUID, "type": "xhttp",
                             "extra": '{"mode":"auto"}'})
        with self.assertRaisesRegex(EngineError, "invalid_xhttp_extra_encoding"):
            convert_uri_to_native(p)

    def test_conflicting_transport_aliases_detected(self):
        p = proxy("vless", {"uuid": UUID, "type": "ws", "net": "grpc"})
        with self.assertRaisesRegex(EngineError, "conflicting_transport_aliases"):
            convert_uri_to_native(p)

    def test_tuic_native_outbound(self):
        p = proxy("tuic", {"uuid": UUID, "password": "secret"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "tuic")
        self.assertTrue(result.outbound["tls"]["enabled"])


if __name__ == "__main__":
    unittest.main()
