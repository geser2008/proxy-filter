from __future__ import annotations

import json
import unittest

from proxyfilter.ingest import detect_and_parse, parse_uri
from proxyfilter.model import ProxyConfig, SourceInfo


UUID = "00000000-0000-0000-0000-000000000001"
SOURCE = SourceInfo("uri", "URI", "plain")


class IdentitySemanticTests(unittest.TestCase):
    def test_equivalent_vless_ws_tls_formats_share_identity(self) -> None:
        uri = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=ws"
            "&sni=cdn.example.com&host=cdn.example.com&path=%2Fws&headerType=none#URI",
            SOURCE,
        )

        clash_text = f"""
proxies:
  - name: Clash
    type: vless
    server: example.com
    port: 443
    uuid: {UUID}
    tls: true
    servername: cdn.example.com
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
"""
        clash, errors, fmt = detect_and_parse(clash_text, "clash", "Clash")
        self.assertEqual(errors, [])
        self.assertEqual(fmt, "clash")

        v2ray_obj = {
            "outbounds": [
                {
                    "tag": "V2Ray",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "example.com",
                                "port": 443,
                                "users": [{"id": UUID, "encryption": "none"}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "tls",
                        "tlsSettings": {"serverName": "cdn.example.com"},
                        "wsSettings": {
                            "path": "/ws",
                            "headers": {"Host": "cdn.example.com"},
                        },
                    },
                }
            ]
        }
        v2ray, errors, fmt = detect_and_parse(json.dumps(v2ray_obj), "v2ray", "V2Ray")
        self.assertEqual(errors, [])
        self.assertEqual(fmt, "v2ray-json")

        singbox_obj = {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "SingBox",
                    "server": "example.com",
                    "server_port": 443,
                    "uuid": UUID,
                    "tls": {"enabled": True, "server_name": "cdn.example.com"},
                    "transport": {
                        "type": "ws",
                        "path": "/ws",
                        "headers": {"Host": "cdn.example.com"},
                    },
                }
            ]
        }
        singbox, errors, fmt = detect_and_parse(json.dumps(singbox_obj), "singbox", "SingBox")
        self.assertEqual(errors, [])
        self.assertEqual(fmt, "sing-box")

        ids = {
            uri.ensure_id(),
            clash[0].ensure_id(),
            v2ray[0].ensure_id(),
            singbox[0].ensure_id(),
        }
        self.assertEqual(len(ids), 1)

    def test_default_tcp_and_explicit_tcp_none_header_share_identity(self) -> None:
        implicit = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&sni=example.com",
            SOURCE,
        )
        explicit = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&sni=example.com"
            "&type=tcp&headerType=none",
            SOURCE,
        )

        self.assertEqual(implicit.ensure_id(), explicit.ensure_id())

    def test_connection_relevant_vless_difference_changes_identity(self) -> None:
        first = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=ws&sni=example.com&path=%2Fa",
            SOURCE,
        )
        second = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=ws&sni=example.com&path=%2Fb",
            SOURCE,
        )

        self.assertNotEqual(first.ensure_id(), second.ensure_id())

    def test_equivalent_vmess_aliases_share_identity(self) -> None:
        first = ProxyConfig(
            SOURCE,
            "vmess",
            "example.com",
            443,
            params={
                "id": UUID,
                "scy": "auto",
                "aid": "0",
                "tls": "tls",
                "sni": "cdn.example.com",
                "net": "ws",
                "path": "/ws",
                "host": "cdn.example.com",
                "packet-encoding": "packetaddr",
                "global-padding": "true",
                "authenticated-length": False,
            },
        )
        second = ProxyConfig(
            SOURCE,
            "vmess",
            "example.com",
            443,
            params={
                "uuid": UUID,
                "security": "auto",
                "alter_id": 0,
                "tls": {"enabled": True, "server_name": "cdn.example.com"},
                "transport": {
                    "type": "ws",
                    "path": "/ws",
                    "headers": {"Host": "cdn.example.com"},
                },
                "packet_encoding": "packetaddr",
                "global_padding": True,
                "authenticated_length": False,
            },
        )

        self.assertEqual(first.ensure_id(), second.ensure_id())

    def test_vmess_cipher_difference_changes_identity(self) -> None:
        first = ProxyConfig(SOURCE, "vmess", "example.com", 443, params={"uuid": UUID, "security": "auto"})
        second = ProxyConfig(SOURCE, "vmess", "example.com", 443, params={"uuid": UUID, "security": "aes-128-gcm"})
        self.assertNotEqual(first.ensure_id(), second.ensure_id())

    def test_equivalent_trojan_tls_forms_share_identity(self) -> None:
        first = ProxyConfig(
            SOURCE,
            "trojan",
            "example.com",
            443,
            params={"password": "secret", "sni": "cdn.example.com", "type": "tcp", "headerType": "none"},
        )
        second = ProxyConfig(
            SOURCE,
            "trojan",
            "example.com",
            443,
            params={
                "password": "secret",
                "tls": {"enabled": True, "server_name": "cdn.example.com"},
                "transport": {"type": "tcp"},
            },
        )

        self.assertEqual(first.ensure_id(), second.ensure_id())

    def test_trojan_password_difference_changes_identity(self) -> None:
        first = ProxyConfig(SOURCE, "trojan", "example.com", 443, params={"password": "one"})
        second = ProxyConfig(SOURCE, "trojan", "example.com", 443, params={"password": "two"})
        self.assertNotEqual(first.ensure_id(), second.ensure_id())

    def test_equivalent_shadowsocks_aliases_share_identity(self) -> None:
        first = ProxyConfig(
            SOURCE,
            "ss",
            "example.com",
            8388,
            params={"method": "aes-256-gcm", "password": "secret", "plugin-opts": "tls;host=cdn.example.com"},
        )
        second = ProxyConfig(
            SOURCE,
            "ss",
            "example.com",
            8388,
            params={"cipher": "aes-256-gcm", "password": "secret", "plugin_opts": "tls;host=cdn.example.com"},
        )

        self.assertEqual(first.ensure_id(), second.ensure_id())

    def test_shadowsocks_plugin_difference_changes_identity(self) -> None:
        first = ProxyConfig(
            SOURCE,
            "ss",
            "example.com",
            8388,
            params={"method": "aes-256-gcm", "password": "secret", "plugin": "v2ray-plugin", "plugin_opts": "tls"},
        )
        second = ProxyConfig(
            SOURCE,
            "ss",
            "example.com",
            8388,
            params={"method": "aes-256-gcm", "password": "secret", "plugin": "obfs-local", "plugin_opts": "tls"},
        )
        self.assertNotEqual(first.ensure_id(), second.ensure_id())


if __name__ == "__main__":
    unittest.main()
