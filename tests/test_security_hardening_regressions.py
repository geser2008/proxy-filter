import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo
from proxyfilter.security import check_static_security


class SecurityHardeningRegressionTests(unittest.TestCase):
    def parse(self, uri):
        return parse_uri(uri, SourceInfo("test", "Test", "plain"))

    def test_case_insensitive_allow_insecure_is_rejected(self):
        for key in ("allowinsecure", "ALLOWINSECURE", "Allow_Insecure", "SKIP_CERT_VERIFY"):
            with self.subTest(key=key):
                proxy = self.parse(
                    f"vless://11111111-1111-1111-1111-111111111111@example.com:443"
                    f"?security=tls&{key}=1"
                )
                ok, reasons = check_static_security(proxy)
                self.assertFalse(ok)
                self.assertIn("certificate_verification_disabled", reasons)

    def test_malformed_certificate_verification_flag_fails_closed(self):
        proxy = self.parse(
            "trojan://secret@example.com:443?security=tls&allowInsecure=sometimes"
        )
        ok, reasons = check_static_security(proxy)
        self.assertFalse(ok)
        self.assertIn("invalid_certificate_verification_setting", reasons)

    def test_html_escaped_query_separators_are_decoded_for_parsing(self):
        uri = (
            "trojan://secret@example.com:443?security=tls&amp;"
            "allowInsecure=1&amp;type=tcp"
        )
        proxy = self.parse(uri)
        self.assertEqual(proxy.params["allowInsecure"], "1")
        self.assertEqual(proxy.params["type"], "tcp")
        self.assertEqual(proxy.original_raw, uri)
        ok, reasons = check_static_security(proxy)
        self.assertFalse(ok)
        self.assertIn("certificate_verification_disabled", reasons)

    def test_html_entity_prefix_in_opaque_query_key_is_not_decoded(self):
        uri = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=tls&note=%40FreeOnlineVPN&amp;allowInsecure=0"
        )
        proxy = self.parse(uri)
        self.assertEqual(proxy.params["note"], "@FreeOnlineVPN")
        self.assertEqual(proxy.params["allowInsecure"], "0")
        self.assertEqual(proxy.original_raw, uri)
        ok, reasons = check_static_security(proxy)
        self.assertTrue(ok, reasons)

    def test_html_escaped_reality_parameters_are_preserved(self):
        uri = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=reality&amp;pbk=public-key&amp;sid=1234&amp;sni=example.com"
        )
        proxy = self.parse(uri)
        self.assertEqual(proxy.params["pbk"], "public-key")
        self.assertEqual(proxy.params["sid"], "1234")
        ok, reasons = check_static_security(proxy)
        self.assertTrue(ok, reasons)

    def test_reality_requires_public_key(self):
        from proxyfilter.model import ProxyConfig
        base = {
            "uuid": "11111111-1111-1111-1111-111111111111",
            "security": "reality",
            "sni": "example.com",
        }
        for params in (base, {**base, "sid": "1234"}, {**base, "sid": ""}):
            with self.subTest(params=params):
                proxy = ProxyConfig(
                    SourceInfo("test", "Test"), "vless", "example.com", 443,
                    params=params,
                )
                ok, reasons = check_static_security(proxy)
                self.assertFalse(ok)
                self.assertIn("missing_reality_public_key", reasons)

    def test_reality_without_or_with_empty_short_id_passes(self):
        from proxyfilter.model import ProxyConfig
        base = {
            "uuid": "11111111-1111-1111-1111-111111111111",
            "security": "reality",
            "pbk": "public-key",
            "sni": "example.com",
        }
        for params in (base, {**base, "sid": ""}, {**base, "sid": "1234"}):
            with self.subTest(params=params):
                proxy = ProxyConfig(
                    SourceInfo("test", "Test"), "vless", "example.com", 443,
                    params=params,
                )
                ok, reasons = check_static_security(proxy)
                self.assertTrue(ok, reasons)

    def test_reality_uri_without_sid_preserves_absence(self):
        uri = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=reality&pbk=public-key&sni=example.com"
        )
        proxy = self.parse(uri)
        self.assertNotIn("sid", proxy.params)
        ok, reasons = check_static_security(proxy)
        self.assertTrue(ok, reasons)


if __name__ == "__main__":
    unittest.main()
