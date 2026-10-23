from __future__ import annotations

import unittest

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.singbox_backend import SingBoxBackend


SOURCE = SourceInfo("test", "Test", "clash")


class BackendMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()

    def _proxy(self, protocol: str, params: dict, *, port: int = 443) -> ProxyConfig:
        return ProxyConfig(
            SOURCE,
            protocol,
            "example.com",
            port,
            params=params,
            original_format="clash",
        )

    def test_vless_packet_encoding_is_preserved(self) -> None:
        proxy = self._proxy(
            "vless",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "tls",
                "packet-encoding": "xudp",
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["packet_encoding"], "xudp")

    def test_vmess_protocol_flags_are_preserved(self) -> None:
        proxy = self._proxy(
            "vmess",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "auto",
                "packet-encoding": "packetaddr",
                "global-padding": True,
                "authenticated-length": False,
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["packet_encoding"], "packetaddr")
        self.assertTrue(out["global_padding"])
        self.assertFalse(out["authenticated_length"])

    def test_vmess_optional_defaults_are_not_injected(self) -> None:
        proxy = self._proxy(
            "vmess",
            {"uuid": "00000000-0000-0000-0000-000000000001"},
        )
        out = self.backend._render_outbound(proxy)
        self.assertNotIn("security", out)
        self.assertNotIn("alter_id", out)

    def test_explicit_empty_vmess_values_are_not_replaced_by_defaults(self) -> None:
        proxy = self._proxy(
            "vmess",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "",
                "alterId": "",
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["security"], "")
        self.assertEqual(out["alter_id"], "")

    def test_vmess_empty_and_none_tls_mean_disabled(self) -> None:
        for tls_value in ("", "none"):
            with self.subTest(tls=tls_value):
                proxy = self._proxy(
                    "vmess",
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "scy": "auto",
                        "tls": tls_value,
                    },
                )
                out = self.backend._render_outbound(proxy)
                self.assertNotIn("tls", out)

    def test_reality_without_fp_enables_utls_without_inventing_fingerprint(self) -> None:
        proxy = self._proxy(
            "vless",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "reality",
                "pbk": "Svl81isn16RPAFnjtmYw7A6TPnsEPLHuYYaJht65Rzc",
                "sni": "www.cloudflare.com",
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["tls"]["utls"], {"enabled": True})
        self.assertNotIn("fingerprint", out["tls"]["utls"])

    def test_fp_unsafe_is_forwarded_not_reinterpreted(self) -> None:
        proxy = self._proxy(
            "vless",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "tls",
                "fp": "unsafe",
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["tls"]["utls"], {"enabled": True, "fingerprint": "unsafe"})

    def test_invalid_boolean_is_rejected_not_coerced_to_false(self) -> None:
        proxy = self._proxy(
            "vless",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "tls",
                "allowInsecure": "maybe",
            },
        )
        with self.assertRaisesRegex(EngineError, "invalid boolean value"):
            self.backend._render_outbound(proxy)

    def test_unsupported_v2ray_transport_is_rejected_not_dropped(self) -> None:
        proxy = self._proxy(
            "vless",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "tls",
                "network": "kcp",
            },
        )
        with self.assertRaisesRegex(EngineError, "unsupported V2Ray transport: kcp"):
            self.backend._render_outbound(proxy)

    def test_tcp_header_obfuscation_is_rejected_not_dropped(self) -> None:
        proxy = self._proxy(
            "vmess",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "network": "tcp",
                "headerType": "http",
            },
        )
        with self.assertRaisesRegex(EngineError, "unsupported TCP transport header type"):
            self.backend._render_outbound(proxy)

    def test_hysteria2_clash_fields_are_mapped(self) -> None:
        proxy = self._proxy(
            "hysteria2",
            {
                "password": "secret",
                "ports": "443,8443-8450",
                "hop-interval": 30,
                "up": "30 Mbps",
                "down": "200 Mbps",
                "obfs": "gecko",
                "obfs-password": "obfs-secret",
                "obfs-min-packet-size": 512,
                "obfs-max-packet-size": 1200,
                "bbr-profile": "aggressive",
                "network": "udp",
                "sni": "example.com",
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertNotIn("server_port", out)
        self.assertEqual(out["server_ports"], ["443", "8443:8450"])
        self.assertEqual(out["hop_interval"], "30s")
        self.assertEqual(out["up_mbps"], 30)
        self.assertEqual(out["down_mbps"], 200)
        self.assertEqual(out["network"], "udp")
        self.assertEqual(out["bbr_profile"], "aggressive")
        self.assertEqual(out["obfs"]["type"], "gecko")
        self.assertEqual(out["obfs"]["min_packet_size"], 512)
        self.assertEqual(out["obfs"]["max_packet_size"], 1200)

    def test_fractional_hysteria2_bandwidth_is_not_truncated(self) -> None:
        proxy = self._proxy(
            "hysteria2",
            {
                "password": "secret",
                "up": "30.5 Mbps",
            },
        )
        with self.assertRaisesRegex(EngineError, "cannot be represented losslessly"):
            self.backend._render_outbound(proxy)

    def test_hysteria2_clash_certificate_fingerprint_is_not_reinterpreted(self) -> None:
        proxy = self._proxy(
            "hysteria2",
            {
                "password": "secret",
                "fingerprint": "deadbeef",
            },
        )
        with self.assertRaisesRegex(EngineError, "certificate fingerprint mapping"):
            self.backend._render_outbound(proxy)

    def test_tuic_clash_fields_are_mapped(self) -> None:
        proxy = self._proxy(
            "tuic",
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "password": "secret",
                "congestion-controller": "bbr",
                "udp-relay-mode": "native",
                "reduce-rtt": True,
                "heartbeat-interval": 10000,
                "disable-sni": True,
                "network": "udp",
            },
        )
        out = self.backend._render_outbound(proxy)
        self.assertTrue(out["zero_rtt_handshake"])
        self.assertEqual(out["heartbeat"], "10000ms")
        self.assertEqual(out["network"], "udp")
        self.assertTrue(out["tls"]["disable_sni"])

    def test_tuic_v4_token_is_rejected(self) -> None:
        proxy = self._proxy("tuic", {"token": "legacy-token"})
        with self.assertRaisesRegex(EngineError, "TUIC v4"):
            self.backend._render_outbound(proxy)


if __name__ == "__main__":
    unittest.main()
