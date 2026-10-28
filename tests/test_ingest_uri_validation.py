from __future__ import annotations

import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo


class URIValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SourceInfo("test", "test", "plain")

    def test_rejects_bare_percent_in_query_value(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?encryption=none&type=ws&path=/%"
        )
        with self.assertRaisesRegex(ValueError, "invalid URI percent escape"):
            parse_uri(uri, self.source)

    def test_accepts_valid_percent_escape(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?encryption=none&type=ws&path=%2Fapi"
        )
        proxy = parse_uri(uri, self.source)
        self.assertEqual(proxy.params["path"], "/api")

    def test_rejects_duplicate_generic_query_parameter(self) -> None:
        uri = (
            "trojan://secret@example.com:443"
            "?security=tls&type=tcp&sni=one.example&sni=two.example"
        )
        with self.assertRaisesRegex(ValueError, "duplicate URI query parameter.*sni"):
            parse_uri(uri, self.source)

    def test_rejects_duplicate_shadowsocks_query_parameter(self) -> None:
        uri = (
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388"
            "?plugin=v2ray-plugin&plugin=obfs-local"
        )
        with self.assertRaisesRegex(ValueError, "duplicate URI query parameter.*plugin"):
            parse_uri(uri, self.source)

    def test_normalizes_lowercase_allowinsecure_alias(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?encryption=none&security=tls&type=tcp&allowinsecure=1"
        )
        proxy = parse_uri(uri, self.source)
        self.assertNotIn("allowinsecure", proxy.params)
        self.assertEqual(proxy.params["allowInsecure"], "1")
        self.assertTrue(proxy.identity_payload()["params"]["tls"]["insecure"])

    def test_rejects_duplicate_semantic_allowinsecure_alias(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?encryption=none&security=tls&type=tcp&allowinsecure=1&allowInsecure=0"
        )
        with self.assertRaisesRegex(ValueError, "duplicate semantic URI query parameter"):
            parse_uri(uri, self.source)

    def test_accepts_plain_sip002_shadowsocks_userinfo(self) -> None:
        uri = (
            "ss://chacha20-ietf-poly1305:oZIoA69Q8yhcQV8ka3Pa3A@"
            "193.29.139.202:8080#example"
        )
        proxy = parse_uri(uri, self.source)
        self.assertEqual(proxy.protocol, "ss")
        self.assertEqual(proxy.server, "193.29.139.202")
        self.assertEqual(proxy.port, 8080)
        self.assertEqual(proxy.params["method"], "chacha20-ietf-poly1305")
        self.assertEqual(proxy.params["password"], "oZIoA69Q8yhcQV8ka3Pa3A")
        self.assertEqual(proxy.name, "example")


if __name__ == "__main__":
    unittest.main()
