from __future__ import annotations

import json
import unittest
from urllib.parse import quote

from proxyfilter.engine import EngineError
from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo
from proxyfilter.render import render_uri, validate_round_trip
from proxyfilter.singbox_backend import SingBoxBackend


SOURCE = SourceInfo("test", "test", "plain")
UUID = "00000000-0000-0000-0000-000000000001"


class URIExtensionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()

    def _vless(self, query: str):
        return parse_uri(f"vless://{UUID}@example.com:443?{query}", SOURCE)

    def _round_trip(self, proxy):
        rendered = render_uri(proxy, "roundtrip")
        validate_round_trip(proxy, rendered)
        return rendered

    def test_camel_case_packet_encoding_maps_and_round_trips(self) -> None:
        proxy = self._vless("encryption=none&packetEncoding=xudp&type=tcp")
        self.assertEqual(proxy.semantic_payload()["params"]["packet_encoding"], "xudp")
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["packet_encoding"], "xudp")
        rendered = self._round_trip(proxy)
        self.assertIn("packetEncoding=xudp", rendered)

    def test_websocket_ed_eh_map_and_round_trip(self) -> None:
        proxy = self._vless(
            "encryption=none&security=tls&type=ws&path=%2Fws&host=cdn.example.com"
            "&ed=2048&eh=Sec-WebSocket-Protocol"
        )
        transport = proxy.semantic_payload()["params"]["transport"]
        self.assertEqual(transport["max_early_data"], 2048)
        self.assertEqual(transport["early_data_header_name"], "Sec-WebSocket-Protocol")
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["transport"]["max_early_data"], 2048)
        self.assertEqual(out["transport"]["early_data_header_name"], "Sec-WebSocket-Protocol")
        rendered = self._round_trip(proxy)
        self.assertIn("ed=2048", rendered)
        self.assertIn("eh=Sec-WebSocket-Protocol", rendered)

    def test_tls_cipher_suites_map_and_round_trip(self) -> None:
        proxy = self._vless(
            "encryption=none&security=tls&type=tcp"
            "&cs=TLS_AES_128_GCM_SHA256%3ATLS_AES_256_GCM_SHA384"
        )
        self.assertEqual(
            proxy.semantic_payload()["params"]["tls"]["cipher_suites"],
            ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        )
        out = self.backend._render_outbound(proxy)
        self.assertEqual(
            out["tls"]["cipher_suites"],
            ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
        )
        rendered = self._round_trip(proxy)
        self.assertIn("cs=TLS_AES_128_GCM_SHA256%3ATLS_AES_256_GCM_SHA384", rendered)

    def test_reality_spider_x_is_preserved_but_backend_rejects(self) -> None:
        proxy = self._vless(
            "encryption=none&security=reality&type=tcp&pbk=public-key&sid=01"
            "&sni=example.com&spx=%2Fcrawler%3Fx%3D1"
        )
        reality = proxy.semantic_payload()["params"]["tls"]["reality"]
        self.assertEqual(reality["spider_x"], "/crawler?x=1")
        rendered = self._round_trip(proxy)
        self.assertIn("spx=%2Fcrawler%3Fx%3D1", rendered)
        with self.assertRaisesRegex(EngineError, "spiderX"):
            self.backend._render_outbound(proxy)

    def test_peer_certificate_pin_is_preserved_but_backend_rejects(self) -> None:
        proxy = self._vless(
            "encryption=none&security=tls&type=tcp&pcs=abcdef0123456789"
        )
        self.assertEqual(
            proxy.semantic_payload()["params"]["tls"]["peer_certificate_sha256"],
            "abcdef0123456789",
        )
        rendered = self._round_trip(proxy)
        self.assertIn("pcs=abcdef0123456789", rendered)
        with self.assertRaisesRegex(EngineError, "certificate SHA256"):
            self.backend._render_outbound(proxy)

    def test_xray_ech_is_preserved_but_backend_rejects(self) -> None:
        ech = "cloudflare-ech.com+udp://1.1.1.1"
        proxy = self._vless(
            "encryption=none&security=tls&type=tcp&ech=" + quote(ech, safe="")
        )
        self.assertEqual(proxy.semantic_payload()["params"]["tls"]["ech"], ech)
        rendered = self._round_trip(proxy)
        self.assertIn("ech=", rendered)
        with self.assertRaisesRegex(EngineError, "ECH"):
            self.backend._render_outbound(proxy)

    def test_final_mask_is_preserved_but_backend_rejects(self) -> None:
        fm = {"tcp": [{"type": "fragment", "settings": {"packets": "tlshello"}}]}
        proxy = self._vless(
            "encryption=none&security=tls&type=tcp&fm="
            + quote(json.dumps(fm, separators=(",", ":")), safe="")
        )
        self.assertEqual(proxy.semantic_payload()["params"]["final_mask"], fm)
        rendered = self._round_trip(proxy)
        self.assertIn("fm=", rendered)
        with self.assertRaisesRegex(EngineError, "FinalMask"):
            self.backend._render_outbound(proxy)

    def test_shadowsocks_sip002_plugin_stays_lossless(self) -> None:
        proxy = parse_uri(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388"
            "?plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example.com",
            SOURCE,
        )
        self.assertEqual(proxy.params["plugin"], "v2ray-plugin")
        self.assertEqual(proxy.params["plugin_opts"], "tls;host=cdn.example.com")
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["plugin"], "v2ray-plugin")
        self.assertEqual(out["plugin_opts"], "tls;host=cdn.example.com")
        self._round_trip(proxy)

    def test_hysteria2_mport_and_bandwidth_aliases_map_and_round_trip(self) -> None:
        proxy = parse_uri(
            "hysteria2://secret@example.com:443?mport=20000-30000"
            "&upmbps=30&downmbps=200&sni=example.com",
            SOURCE,
        )
        identity = proxy.semantic_payload()["params"]
        self.assertEqual(identity["server_ports"], ["20000:30000"])
        self.assertEqual(identity["up_mbps"], "30")
        self.assertEqual(identity["down_mbps"], "200")
        out = self.backend._render_outbound(proxy)
        self.assertEqual(out["server_ports"], ["20000:30000"])
        self.assertEqual(out["up_mbps"], 30)
        self.assertEqual(out["down_mbps"], 200)
        rendered = self._round_trip(proxy)
        self.assertIn("ports=20000%3A30000", rendered)

    def test_hysteria2_pin_fastopen_and_fm_are_preserved_and_rejected_explicitly(self) -> None:
        cases = [
            ("pinSHA256=abcdef", "certificate SHA256"),
            ("fastopen=true", "fastopen"),
            ("fm=%7B%22tcp%22%3A%5B%5D%7D", "FinalMask"),
        ]
        for extra, error in cases:
            with self.subTest(extra=extra):
                proxy = parse_uri(
                    f"hysteria2://secret@example.com:443?sni=example.com&{extra}",
                    SOURCE,
                )
                self._round_trip(proxy)
                with self.assertRaisesRegex(EngineError, error):
                    self.backend._render_outbound(proxy)


if __name__ == "__main__":
    unittest.main()
