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

    def _vmess_params(self, **kwargs):
        return {"uuid": "11111111-1111-1111-1111-111111111111", "aid": 0, **kwargs}

    def test_vmess_requires_uuid(self):
        self.assert_rejected("vmess", {"security": "auto", "aid": 0}, "missing_uuid")

    def test_vmess_requires_explicit_alter_id(self):
        self.assert_rejected(
            "vmess",
            {"uuid": "11111111-1111-1111-1111-111111111111", "scy": "auto"},
            "missing_vmess_alter_id",
        )

    def test_vmess_rejects_legacy_alter_id(self):
        for value in (1, 16, "2"):
            with self.subTest(value=value):
                self.assert_rejected(
                    "vmess", self._vmess_params(aid=value, scy="auto"),
                    "legacy_vmess_alter_id",
                )

    def test_vmess_rejects_invalid_alter_id(self):
        for value in ("invalid", -1, True):
            with self.subTest(value=value):
                self.assert_rejected(
                    "vmess", self._vmess_params(aid=value, scy="auto"),
                    "invalid_vmess_alter_id",
                )

    def test_vmess_without_tls_requires_aead(self):
        for value in ("none", "zero", "aes-128-ctr", "unspecified"):
            with self.subTest(value=value):
                self.assert_rejected(
                    "vmess", self._vmess_params(scy=value, tls=""),
                    "vmess_without_tls_or_safe_aead",
                )

    def test_vmess_auto_and_aead_without_tls_pass(self):
        for cipher in ("auto", "aes-128-gcm", "chacha20-poly1305"):
            with self.subTest(cipher=cipher):
                self.assert_passes(
                    "vmess", self._vmess_params(scy=cipher, tls=""),
                )

    def test_vmess_with_tls_accepts_none_but_not_zero(self):
        self.assert_passes("vmess", self._vmess_params(scy="none", tls="tls"))
        self.assert_rejected(
            "vmess", self._vmess_params(scy="zero", tls="tls"),
            "unsafe_vmess_cipher",
        )

    def test_vmess_with_tls_rejects_unknown_cipher(self):
        for cipher in ("unknown", "aes-128-ctr"):
            with self.subTest(cipher=cipher):
                self.assert_rejected(
                    "vmess", self._vmess_params(scy=cipher, tls="tls"),
                    "unsafe_vmess_cipher",
                )
        self.assert_rejected(
            "vmess", self._vmess_params(tls="tls"), "unsafe_vmess_cipher"
        )

    def test_vmess_security_field_is_payload_cipher_not_transport(self):
        self.assert_rejected(
            "vmess", self._vmess_params(security="none"),
            "vmess_without_tls_or_safe_aead",
        )
        self.assert_passes(
            "vmess", self._vmess_params(security="auto", tls="tls"),
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

    def test_shadowsocks_unrecognized_method_rejected(self):
        self.assert_rejected(
            "ss", {"method": "future-unknown-cipher", "password": "secret"},
            "unknown_shadowsocks_cipher",
        )

    def test_shadowsocks_2022_aead_passes(self):
        for method in (
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ):
            with self.subTest(method=method):
                self.assert_passes(
                    "ss", {"method": method, "password": "secret"},
                )

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
