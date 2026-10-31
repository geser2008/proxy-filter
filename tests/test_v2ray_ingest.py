from __future__ import annotations

import json
import unittest

from proxyfilter.ingest import detect_and_parse_compat
from proxyfilter.security import check_static_security
from proxyfilter.singbox_backend import SingBoxBackend


UUID = "00000000-0000-0000-0000-000000000001"


class V2RayIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()

    def _parse(self, obj: dict):
        return detect_and_parse_compat(json.dumps(obj), "v2ray", "V2Ray")

    def test_vless_reality_websocket_is_flattened_losslessly(self) -> None:
        obj = {
            "outbounds": [
                {
                    "tag": "vless-reality",
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": "example.com",
                                "port": 443,
                                "users": [
                                    {
                                        "id": UUID,
                                        "encryption": "none",
                                        "flow": "xtls-rprx-vision",
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "www.cloudflare.com",
                            "publicKey": "public-key",
                            "shortId": "abcd",
                            "fingerprint": "chrome",
                        },
                        "wsSettings": {
                            "path": "/ws",
                            "headers": {"Host": "cdn.example.com"},
                        },
                    },
                }
            ]
        }

        proxies, errors, fmt = self._parse(obj)

        self.assertEqual(fmt, "v2ray-json")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)
        proxy = proxies[0]
        self.assertEqual(proxy.original_format, "v2ray-json")
        self.assertEqual(proxy.params["security"], "reality")
        self.assertEqual(proxy.params["pbk"], "public-key")
        self.assertEqual(proxy.params["sid"], "abcd")
        self.assertEqual(proxy.params["fp"], "chrome")
        self.assertEqual(proxy.params["path"], "/ws")
        self.assertEqual(proxy.params["ws-opts"]["headers"]["Host"], "cdn.example.com")

        ok, reasons = check_static_security(proxy)
        outbound = self.backend._render_outbound(proxy)
        self.assertTrue(ok, reasons)
        self.assertTrue(outbound["tls"]["reality"]["enabled"])
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertEqual(outbound["transport"]["headers"]["Host"], "cdn.example.com")

    def test_vmess_cipher_and_transport_tls_do_not_collide(self) -> None:
        obj = {
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": "vmess.example.com",
                                "port": 443,
                                "users": [{"id": UUID, "security": "auto", "alterId": 0}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "grpc",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "edge.example.com",
                            "allowInsecure": False,
                            "alpn": ["h2"],
                        },
                        "grpcSettings": {"serviceName": "svc"},
                    },
                }
            ]
        }

        proxies, errors, fmt = self._parse(obj)
        self.assertEqual(fmt, "v2ray-json")
        self.assertEqual(errors, [])
        proxy = proxies[0]
        self.assertEqual(proxy.params["security"], "auto")
        self.assertEqual(proxy.params["tls"], "tls")

        outbound = self.backend._render_outbound(proxy)
        self.assertEqual(outbound["security"], "auto")
        self.assertTrue(outbound["tls"]["enabled"])
        self.assertEqual(outbound["tls"]["server_name"], "edge.example.com")
        self.assertEqual(outbound["transport"]["type"], "grpc")
        self.assertEqual(outbound["transport"]["service_name"], "svc")

    def test_trojan_and_shadowsocks_server_lists_are_supported(self) -> None:
        obj = {
            "outbounds": [
                {
                    "tag": "trojan",
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {"address": "trojan.example.com", "port": 443, "password": "secret"}
                        ]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {"serverName": "trojan.example.com"},
                    },
                },
                {
                    "tag": "ss",
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": "ss.example.com",
                                "port": 8388,
                                "method": "aes-256-gcm",
                                "password": "secret",
                            }
                        ]
                    },
                },
            ]
        }

        proxies, errors, fmt = self._parse(obj)
        self.assertEqual(fmt, "v2ray-json")
        self.assertEqual(errors, [])
        self.assertEqual([proxy.protocol for proxy in proxies], ["trojan", "ss"])
        self.assertEqual(proxies[0].params["password"], "secret")
        self.assertEqual(proxies[1].params["method"], "aes-256-gcm")

    def test_unsupported_reality_spiderx_is_reported_not_dropped(self) -> None:
        obj = {
            "outbounds": [
                {
                    "tag": "bad-reality",
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
                        "security": "reality",
                        "realitySettings": {
                            "serverName": "example.com",
                            "publicKey": "key",
                            "shortId": "abcd",
                            "spiderX": "/",
                        },
                    },
                }
            ]
        }

        proxies, errors, fmt = self._parse(obj)
        self.assertEqual(fmt, "v2ray-json")
        self.assertEqual(proxies, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("spiderX", errors[0]["detail"])

    def test_singbox_outbounds_still_detect_as_singbox(self) -> None:
        obj = {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "node",
                    "server": "example.com",
                    "server_port": 443,
                    "uuid": UUID,
                }
            ]
        }

        proxies, errors, fmt = self._parse(obj)
        self.assertEqual(fmt, "sing-box")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)


if __name__ == "__main__":
    unittest.main()
