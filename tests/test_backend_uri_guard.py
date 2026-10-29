from __future__ import annotations

import unittest

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.singbox_backend import SingBoxBackend


SOURCE = SourceInfo("test", "Test", "plain")
UUID = "00000000-0000-0000-0000-000000000001"


class BackendURIGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()

    def _uri_proxy(self, protocol: str, params: dict) -> ProxyConfig:
        return ProxyConfig(
            SOURCE,
            protocol,
            "example.com",
            443,
            params=params,
            original_format=f"{protocol}-uri",
        )

    def test_unknown_vless_uri_parameter_is_rejected_not_dropped(self) -> None:
        proxy = self._uri_proxy(
            "vless",
            {"uuid": UUID, "security": "tls", "future_param": "opaque"},
        )
        with self.assertRaisesRegex(EngineError, "unsupported vless URI parameter.*future_param"):
            self.backend._render_outbound(proxy)

    def test_unknown_vmess_uri_field_is_rejected_not_dropped(self) -> None:
        proxy = self._uri_proxy(
            "vmess",
            {"id": UUID, "net": "ws", "path": "/ws", "future_param": "opaque"},
        )
        with self.assertRaisesRegex(EngineError, "unsupported vmess URI parameter.*future_param"):
            self.backend._render_outbound(proxy)

    def test_vless_encryption_none_is_accepted_but_other_values_are_rejected(self) -> None:
        accepted = self._uri_proxy(
            "vless",
            {"uuid": UUID, "security": "tls", "encryption": "none"},
        )
        self.backend._render_outbound(accepted)

        rejected = self._uri_proxy(
            "vless",
            {"uuid": UUID, "security": "tls", "encryption": "aes-128-gcm"},
        )
        with self.assertRaisesRegex(EngineError, "unsupported VLESS encryption"):
            self.backend._render_outbound(rejected)

    def test_hy2_uri_is_rendered_as_hysteria2_outbound(self) -> None:
        proxy = self._uri_proxy(
            "hy2",
            {"password": "secret", "sni": "example.com"},
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["type"], "hysteria2")

    def test_explicitly_unsupported_uri_field_keeps_specific_error(self) -> None:
        proxy = self._uri_proxy(
            "vless",
            {"uuid": UUID, "security": "tls", "pcs": "deadbeef"},
        )
        with self.assertRaisesRegex(EngineError, "unsupported peer certificate SHA256 mapping"):
            self.backend._render_outbound(proxy)


if __name__ == "__main__":
    unittest.main()
