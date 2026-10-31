import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.render import format_output_name, render_proxy, render_uri, validate_round_trip


SOURCE = SourceInfo("test", "Test source", "plain")


class RenderTests(unittest.TestCase):
    def _round_trip(self, uri: str) -> str:
        proxy = parse_uri(uri, SOURCE)
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        reparsed = parse_uri(rendered, SOURCE)
        self.assertEqual(reparsed.name, "RENAMED")
        return rendered

    def test_vless_round_trip(self):
        rendered = self._round_trip(
            "vless://4054fdc2-ee80-4419-8a8e-d937df4719e2@203.0.113.10:443"
            "?security=reality&type=tcp&sni=example.com&fp=chrome&flow=xtls-rprx-vision#old"
        )
        self.assertTrue(rendered.startswith("vless://"))

    def test_structured_vless_clash_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "vless",
            "203.0.113.11",
            443,
            "old",
            {
                "uuid": "4054fdc2-ee80-4419-8a8e-d937df4719e2",
                "tls": True,
                "servername": "cdn.example.com",
                "client-fingerprint": "chrome",
                "network": "ws",
                "ws-opts": {
                    "path": "/ws",
                    "headers": {"Host": "cdn.example.com"},
                },
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertIn("security=tls", rendered)
        self.assertIn("type=ws", rendered)
        self.assertIn("path=%2Fws", rendered)

    def test_structured_vless_reality_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("singbox", "Sing-box", "sing-box"),
            "vless",
            "203.0.113.12",
            443,
            "old",
            {
                "uuid": "4054fdc2-ee80-4419-8a8e-d937df4719e2",
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": True,
                    "server_name": "example.com",
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": "public-key",
                        "short_id": "01",
                    },
                },
                "transport": {"type": "tcp"},
            },
            "sing-box",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertIn("security=reality", rendered)
        self.assertIn("pbk=public-key", rendered)
        self.assertIn("sid=01", rendered)

    def test_vmess_round_trip(self):
        proxy = ProxyConfig(
            SOURCE,
            "vmess",
            "203.0.113.20",
            443,
            "old",
            {
                "v": "2",
                "id": "1281acca-f21d-475c-bf04-eccbee7f8df2",
                "aid": "0",
                "scy": "auto",
                "net": "ws",
                "path": "/vmess-ws",
                "host": "example.com",
                "tls": "tls",
                "sni": "example.com",
            },
            "vmess-uri",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertTrue(rendered.startswith("vmess://"))

    def test_structured_vmess_clash_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "vmess",
            "203.0.113.22",
            443,
            "old",
            {
                "uuid": "1281acca-f21d-475c-bf04-eccbee7f8df2",
                "alterId": 0,
                "cipher": "auto",
                "tls": True,
                "servername": "cdn.example.com",
                "network": "ws",
                "ws-opts": {
                    "path": "/vmess-ws",
                    "headers": {"Host": "cdn.example.com"},
                },
                "udp": True,
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertTrue(rendered.startswith("vmess://"))

    def test_structured_vmess_false_tls_is_not_serialized_as_enabled(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "vmess",
            "203.0.113.23",
            80,
            "old",
            {
                "uuid": "1281acca-f21d-475c-bf04-eccbee7f8df2",
                "alterId": 0,
                "cipher": "auto",
                "tls": False,
                "network": "tcp",
                "servername": "ignored.example.com",
                "udp": True,
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertTrue(rendered.startswith("vmess://"))

    def test_trojan_round_trip(self):
        self._round_trip(
            "trojan://secret@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fws#old"
        )

    def test_structured_trojan_tls_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "trojan",
            "203.0.113.21",
            443,
            "old",
            {
                "password": "secret",
                "sni": "example.com",
                "network": "ws",
                "ws-opts": {"path": "/trojan", "headers": {"Host": "example.com"}},
                "udp": True,
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertIn("security=tls", rendered)
        self.assertIn("type=ws", rendered)

    def test_hysteria2_round_trip(self):
        self._round_trip(
            "hysteria2://secret@example.com:443?sni=example.com&insecure=0#old"
        )

    def test_structured_hysteria2_clash_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "hysteria2",
            "203.0.113.60",
            443,
            "old",
            {
                "auth": "secret",
                "sni": "example.com",
                "skip-cert-verify": False,
                "up": 50,
                "down": "100 Mbps",
                "obfs": "salamander",
                "obfs-password": "obfs-secret",
                "udp": True,
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertTrue(rendered.startswith("hysteria2://secret@"))
        self.assertIn("obfs=salamander", rendered)

    def test_hysteria2_certificate_and_utls_fingerprints_remain_distinct(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "hysteria2",
            "203.0.113.61",
            443,
            "old",
            {
                "password": "secret",
                "sni": "example.com",
                "fingerprint": "sha256:certificate-pin",
                "client-fingerprint": "chrome",
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertIn("fingerprint=sha256%3Acertificate-pin", rendered)
        self.assertIn("fp=chrome", rendered)

    def test_tuic_round_trip(self):
        self._round_trip(
            "tuic://550e8400-e29b-41d4-a716-446655440000:secret@example.com:443"
            "?congestion_control=bbr&alpn=h3#old"
        )

    def test_structured_tuic_clash_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "tuic",
            "203.0.113.62",
            443,
            "old",
            {
                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                "password": "secret",
                "congestion-controller": "bbr",
                "udp-relay-mode": "native",
                "reduce-rtt": True,
                "heartbeat-interval": 1000,
                "sni": "example.com",
                "skip-cert-verify": False,
                "udp": True,
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertTrue(rendered.startswith("tuic://"))
        self.assertIn("congestion_control=bbr", rendered)
        self.assertIn("zero_rtt_handshake=true", rendered)

    def test_shadowsocks_round_trip(self):
        self._round_trip(
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@203.0.113.30:8388"
            "?plugin=v2ray-plugin%3Btls%3Bhost%3Dexample.com#old"
        )

    def test_structured_shadowsocks_clash_semantics_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "ss",
            "203.0.113.31",
            8388,
            "old",
            {
                "cipher": "aes-256-gcm",
                "password": "secret",
                "udp": True,
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertTrue(rendered.startswith("ss://"))

    def test_structured_shadowsocks_plugin_aliases_render_losslessly(self):
        proxy = ProxyConfig(
            SourceInfo("clash", "Clash", "clash"),
            "ss",
            "203.0.113.32",
            8388,
            "old",
            {
                "cipher": "aes-256-gcm",
                "password": "secret",
                "plugin": "v2ray-plugin",
                "plugin-opts": "tls;host=cdn.example.com",
            },
            "clash",
            "",
        )
        rendered = render_uri(proxy, "RENAMED")
        validate_round_trip(proxy, rendered)
        self.assertIn("plugin=", rendered)

    def test_explicit_false_security_flag_can_be_normalized_away(self):
        proxy = ProxyConfig(
            SOURCE,
            "vless",
            "203.0.113.40",
            443,
            "old",
            {"uuid": "550e8400-e29b-41d4-a716-446655440000", "allowInsecure": False},
        )
        result = render_proxy(proxy, rename_template="{flag} {country_code}")
        self.assertTrue(result.ok, result.error)

    def test_unknown_typed_field_is_rejected_instead_of_silently_dropped(self):
        proxy = ProxyConfig(
            SOURCE,
            "vless",
            "203.0.113.41",
            443,
            "old",
            {"uuid": "550e8400-e29b-41d4-a716-446655440000", "future-option": True},
        )
        result = render_proxy(proxy, rename_template="{flag} {country_code}")
        self.assertFalse(result.ok)
        self.assertIn("unsupported source field", result.error or "")

    def test_output_name_uses_geo_and_metrics(self):
        proxy = ProxyConfig(SOURCE, "ss", "203.0.113.50", 8388, "old", {"method": "aes-256-gcm", "password": "secret"})
        proxy.tests.geo = {"flag": "🇳🇱", "country_code": "NL", "country": "Netherlands", "asn": 64500, "org": "Example", "isp": "Example"}
        proxy.tests.latency_ms = 172.6
        proxy.tests.download_mbps = 181.6
        proxy.tests.upload_mbps = 123.2
        name = format_output_name(
            proxy,
            template="{flag} {country_code} | {latency_ms}ms | ↓{download_mbps} ↑{upload_mbps} | {source}",
        )
        self.assertEqual(name, "🇳🇱 NL | 173ms | ↓182 ↑123 | test")


if __name__ == "__main__":
    unittest.main()
