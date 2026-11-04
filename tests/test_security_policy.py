import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.security import check_static_security


class SecurityPolicyTests(unittest.TestCase):
    def _proxy(self, protocol: str, params: dict) -> ProxyConfig:
        return ProxyConfig(
            SourceInfo("test", "Test"),
            protocol,
            "example.com",
            443,
            params=params,
        )

    def assert_rejected(self, protocol: str, params: dict, reason: str) -> None:
        proxy = self._proxy(protocol, params)
        ok, reasons = check_static_security(proxy)
        self.assertFalse(ok)
        self.assertIn(reason, reasons)
        self.assertEqual(proxy.tests.security["status"], "reject")

    def assert_passes(self, protocol: str, params: dict) -> None:
        proxy = self._proxy(protocol, params)
        ok, reasons = check_static_security(proxy)
        self.assertTrue(ok, reasons)
        self.assertEqual(reasons, [])
        self.assertEqual(proxy.tests.security["status"], "pass")

    def test_vless_requires_uuid(self):
        self.assert_rejected(
            "vless",
            {"security": "reality", "pbk": "key"},
            "missing_uuid",
        )

    def test_vless_requires_tls_or_reality(self):
        self.assert_rejected(
            "vless",
            {"uuid": "11111111-1111-1111-1111-111111111111", "security": "none"},
            "vless_without_tls_or_reality",
        )

    def test_vmess_requires_uuid(self):
        self.assert_rejected(
            "vmess",
            {"security": "tls"},
            "missing_uuid",
        )

    def test_vmess_unspecified_cipher_without_tls_is_rejected(self):
        self.assert_rejected(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "tls": ""},
            "vmess_without_tls_or_safe_aead",
        )

    def test_vmess_none_cipher_without_tls_is_rejected(self):
        self.assert_rejected(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "scy": "none", "tls": ""},
            "vmess_without_tls_or_safe_aead",
        )

    def test_vmess_legacy_cipher_without_tls_is_rejected(self):
        self.assert_rejected(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "scy": "aes-128-ctr"},
            "vmess_without_tls_or_safe_aead",
        )

    def test_vmess_auto_without_tls_passes(self):
        self.assert_passes(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "scy": "auto", "tls": ""},
        )

    def test_vmess_aead_without_tls_passes(self):
        for cipher in ("aes-128-gcm", "chacha20-poly1305"):
            with self.subTest(cipher=cipher):
                self.assert_passes(
                    "vmess",
                    {"uuid": "11111111-1111-1111-1111-111111111111", "scy": cipher, "tls": ""},
                )

    def test_vmess_tls_passes_with_unspecified_cipher(self):
        self.assert_passes(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "tls": "tls"},
        )

    def test_vmess_cipher_security_field_does_not_enable_tls(self):
        self.assert_rejected(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "security": "none"},
            "vmess_without_tls_or_safe_aead",
        )

    def test_trojan_requires_password(self):
        self.assert_rejected("trojan", {"security": "tls"}, "missing_password")

    def test_tuic_requires_uuid(self):
        self.assert_rejected("tuic", {"password": "secret"}, "missing_uuid")

    def test_tuic_requires_password(self):
        self.assert_rejected(
            "tuic",
            {"uuid": "11111111-1111-1111-1111-111111111111"},
            "missing_tuic_password",
        )

    def test_tuic_with_credentials_passes(self):
        self.assert_passes(
            "tuic",
            {
                "uuid": "11111111-1111-1111-1111-111111111111",
                "password": "secret",
            },
        )

    def test_hysteria2_requires_auth(self):
        self.assert_rejected("hysteria2", {}, "missing_hysteria2_auth")

    def test_hy2_alias_requires_auth(self):
        self.assert_rejected("hy2", {}, "missing_hysteria2_auth")

    def test_hysteria2_password_passes(self):
        self.assert_passes("hysteria2", {"password": "secret"})

    def test_hysteria2_auth_alias_passes(self):
        self.assert_passes("hy2", {"auth": "secret"})

    def test_shadowsocks_rejects_aes_128_cfb(self):
        self.assert_rejected(
            "ss",
            {"method": "aes-128-cfb", "password": "secret"},
            "legacy_shadowsocks_cipher",
        )

    def test_shadowsocks_rejects_rc4_md5(self):
        self.assert_rejected(
            "ss",
            {"method": "rc4-md5", "password": "secret"},
            "legacy_shadowsocks_cipher",
        )

    def test_shadowsocks_aes_256_gcm_passes(self):
        self.assert_passes("ss", {"method": "aes-256-gcm", "password": "secret"})

    def test_shadowsocks_chacha20_poly1305_passes(self):
        self.assert_passes(
            "shadowsocks",
            {"method": "chacha20-ietf-poly1305", "password": "secret"},
        )

    def test_insecure_tls_is_rejected(self):
        self.assert_rejected(
            "trojan",
            {"password": "secret", "security": "tls", "insecure": "1"},
            "certificate_verification_disabled",
        )

    def test_explicit_false_insecure_is_allowed(self):
        self.assert_passes(
            "trojan",
            {
                "password": "secret",
                "security": "tls",
                "allowInsecure": "0",
                "insecure": "0",
            },
        )


if __name__ == "__main__":
    unittest.main()
