from __future__ import annotations

import json
import unittest

from proxyfilter.ingest import detect_and_parse, parse_uri
from proxyfilter.model import SourceInfo


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


if __name__ == "__main__":
    unittest.main()
