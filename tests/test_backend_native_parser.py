from __future__ import annotations

import unittest

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.singbox_backend import SingBoxBackend


SOURCE = SourceInfo("test", "Test", "plain")


class BackendNativeParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()

    def _proxy(self, protocol: str, raw: str) -> ProxyConfig:
        return ProxyConfig(
            SOURCE,
            protocol,
            "example.com",
            443,
            params={"opaque": "value"},
            original_format=f"{protocol}-uri",
            original_raw=raw,
        )

    def test_uri_outbound_uses_native_parser_type(self) -> None:
        raw = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls"
        out = self.backend._render_outbound(self._proxy("vless", raw))
        self.assertEqual(out["type"], "parser")
        self.assertEqual(out["tag"], "proxy-out")

    def test_uri_is_forwarded_verbatim_to_native_parser(self) -> None:
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&futureParam=opaque%2Fvalue&empty=#Original%20Name"
        )
        out = self.backend._render_outbound(self._proxy("vless", raw))
        self.assertEqual(out["link"], raw)

    def test_unknown_uri_parameter_is_not_rejected_by_proxy_filter(self) -> None:
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&futureParam=opaque"
        )
        out = self.backend._render_outbound(self._proxy("vless", raw))
        self.assertEqual(out["link"], raw)

    def test_hy2_scheme_is_forwarded_without_rewrite(self) -> None:
        raw = "hy2://secret@example.com:443?sni=example.com&futureParam=opaque"
        out = self.backend._render_outbound(self._proxy("hy2", raw))
        self.assertEqual(out["type"], "parser")
        self.assertEqual(out["link"], raw)

    def test_all_production_uri_schemes_use_native_parser(self) -> None:
        samples = {
            "vless": "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls",
            "vmess": "vmess://eyJ2IjoiMiJ9",
            "trojan": "trojan://secret@example.com:443?sni=example.com",
            "ss": "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:443",
            "hysteria2": "hysteria2://secret@example.com:443?sni=example.com",
            "hy2": "hy2://secret@example.com:443?sni=example.com",
            "tuic": "tuic://00000000-0000-0000-0000-000000000001:secret@example.com:443",
        }
        for protocol, raw in samples.items():
            with self.subTest(protocol=protocol):
                out = self.backend._render_outbound(self._proxy(protocol, raw))
                self.assertEqual(out["type"], "parser")
                self.assertEqual(out["link"], raw)

    def test_uri_backend_does_not_emit_manually_mapped_connection_fields(self) -> None:
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=reality&pbk=opaque&sni=example.com&type=ws&path=%2Fws"
        )
        out = self.backend._render_outbound(self._proxy("vless", raw))
        self.assertEqual(set(out), {"type", "tag", "link", "domain_resolver"})

    def test_uri_backend_requires_original_raw_link(self) -> None:
        proxy = ProxyConfig(
            SOURCE,
            "vless",
            "example.com",
            443,
            params={"uuid": "00000000-0000-0000-0000-000000000001", "security": "tls"},
            original_format="vless-uri",
            original_raw="",
        )
        with self.assertRaisesRegex(EngineError, "original URI|original_raw|share link"):
            self.backend._render_outbound(proxy)


if __name__ == "__main__":
    unittest.main()
