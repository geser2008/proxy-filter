from __future__ import annotations

import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.security import check_static_security
from proxyfilter.singbox_backend import SingBoxBackend


SOURCE = SourceInfo("test", "Test", "clash")
UUID = "00000000-0000-0000-0000-000000000001"


class SecurityBackendSemanticTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()

    def _vless(self, params: dict) -> ProxyConfig:
        return ProxyConfig(
            SOURCE,
            "vless",
            "example.com",
            443,
            params={"uuid": UUID, **params},
            original_format="clash",
        )

    def test_server_name_alone_does_not_enable_vless_tls(self) -> None:
        proxy = self._vless({"servername": "example.com"})

        ok, reasons = check_static_security(proxy)
        outbound = self.backend._render_outbound(proxy)

        self.assertFalse(ok)
        self.assertIn("vless_without_tls_or_reality", reasons)
        self.assertNotIn("tls", outbound)

    def test_tls_none_is_consistently_disabled(self) -> None:
        proxy = self._vless({"tls": "none"})

        ok, reasons = check_static_security(proxy)
        outbound = self.backend._render_outbound(proxy)

        self.assertFalse(ok)
        self.assertIn("vless_without_tls_or_reality", reasons)
        self.assertNotIn("tls", outbound)

    def test_native_tls_enabled_false_is_consistently_disabled(self) -> None:
        proxy = self._vless({"tls": {"enabled": False, "server_name": "example.com"}})

        ok, reasons = check_static_security(proxy)
        outbound = self.backend._render_outbound(proxy)

        self.assertFalse(ok)
        self.assertIn("vless_without_tls_or_reality", reasons)
        self.assertEqual(outbound.get("tls", {}).get("enabled"), False)

    def test_top_level_insecure_alias_is_rejected_when_tls_is_enabled(self) -> None:
        proxy = self._vless({"tls": True, "insecure": True})

        ok, reasons = check_static_security(proxy)
        outbound = self.backend._render_outbound(proxy)

        self.assertFalse(ok)
        self.assertIn("certificate_verification_disabled", reasons)
        self.assertTrue(outbound["tls"]["insecure"])


if __name__ == "__main__":
    unittest.main()
