from __future__ import annotations

import base64
import json
import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.render import render_uri, validate_round_trip


SOURCE = SourceInfo("test", "test", "plain")
UUID = "00000000-0000-0000-0000-000000000001"


class RealURINormalizationTests(unittest.TestCase):
    def test_vless_raw_transport_normalizes_to_tcp_and_round_trips(self) -> None:
        uri = (
            "vless://b18d5990-96eb-4587-a386-7f8ef7591e6a@31.77.13.22:2063"
            "?security=reality&type=raw&sni=rusbid.de&fp=firefox"
            "&flow=xtls-rprx-vision&pbk=MMpt_jWc4J3oySBdf5sPDVRkiWlZmOObth6A1scM9BM"
        )
        proxy = parse_uri(uri, SOURCE)
        self.assertEqual(proxy.params["type"], "tcp")
        rendered = render_uri(proxy, "test")
        self.assertIn("type=tcp", rendered)
        validate_round_trip(proxy, rendered)

    def test_vless_raw_and_tcp_have_same_identity(self) -> None:
        raw = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=raw&future_param=one",
            SOURCE,
        )
        tcp = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=tcp&future_param=one",
            SOURCE,
        )
        self.assertEqual(raw.ensure_id(), tcp.ensure_id())

    def test_vmess_raw_transport_normalizes_to_tcp_and_round_trips(self) -> None:
        data = {
            "v": "2",
            "ps": "test",
            "add": "203.0.113.10",
            "port": "443",
            "id": "1281acca-f21d-475c-bf04-eccbee7f8df2",
            "aid": "0",
            "scy": "auto",
            "net": "raw",
            "type": "none",
            "tls": "tls",
        }
        token = base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
        proxy = parse_uri("vmess://" + token, SOURCE)
        self.assertEqual(proxy.params["net"], "tcp")
        rendered = render_uri(proxy, "test")
        validate_round_trip(proxy, rendered)

    def test_vmess_raw_and_tcp_have_same_identity(self) -> None:
        def build(net: str) -> str:
            data = {
                "v": "2",
                "ps": "test",
                "add": "203.0.113.10",
                "port": "443",
                "id": "1281acca-f21d-475c-bf04-eccbee7f8df2",
                "net": net,
                "future_param": "one",
            }
            return "vmess://" + base64.b64encode(
                json.dumps(data, separators=(",", ":")).encode()
            ).decode().rstrip("=")

        self.assertEqual(
            parse_uri(build("raw"), SOURCE).ensure_id(),
            parse_uri(build("tcp"), SOURCE).ensure_id(),
        )

    def test_unknown_query_fields_are_preserved(self) -> None:
        uri = (
            f"vless://{UUID}@example.com:443"
            "?security=tls&type=ws&path=%2Fws&note=%40FreeOnlineVPN&Telegram=%40channel"
        )
        proxy = parse_uri(uri, SOURCE)
        self.assertEqual(proxy.params["note"], "@FreeOnlineVPN")
        self.assertEqual(proxy.params["Telegram"], "@channel")

    def test_vmess_unknown_fields_are_preserved(self) -> None:
        data = {
            "v": "2",
            "ps": "test",
            "add": "203.0.113.11",
            "port": "443",
            "id": "1281acca-f21d-475c-bf04-eccbee7f8df2",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "path": "/ws",
            "tls": "tls",
            "test_name": "probe-label",
        }
        token = base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
        proxy = parse_uri("vmess://" + token, SOURCE)
        self.assertEqual(proxy.params["test_name"], "probe-label")

    def test_empty_optional_fields_are_preserved(self) -> None:
        data = {
            "v": "2",
            "ps": "test",
            "add": "203.0.113.12",
            "port": "443",
            "id": "1281acca-f21d-475c-bf04-eccbee7f8df2",
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "path": "/ws",
            "tls": "tls",
            "insecure": "",
            "pcs": "",
            "ech": "",
        }
        token = base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
        proxy = parse_uri("vmess://" + token, SOURCE)
        self.assertEqual(proxy.params["insecure"], "")
        self.assertEqual(proxy.params["pcs"], "")
        self.assertEqual(proxy.params["ech"], "")

    def test_unknown_query_fields_participate_in_uri_identity(self) -> None:
        first = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws&future_param=one",
            SOURCE,
        )
        second = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws&future_param=two",
            SOURCE,
        )
        self.assertNotEqual(first.ensure_id(), second.ensure_id())

    def test_query_order_does_not_change_uri_identity(self) -> None:
        first = parse_uri(
            f"vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws&future_param=one",
            SOURCE,
        )
        second = parse_uri(
            f"vless://{UUID}@example.com:443?future_param=one&path=%2Fws&type=ws&security=tls",
            SOURCE,
        )
        self.assertEqual(first.ensure_id(), second.ensure_id())

    def test_identity_is_conservative_independent_of_original_format(self) -> None:
        first = ProxyConfig(
            SOURCE,
            "vless",
            "example.com",
            443,
            params={"uuid": UUID, "security": "tls", "future_param": "one"},
            original_format="clash",
        )
        second = ProxyConfig(
            SOURCE,
            "vless",
            "example.com",
            443,
            params={"uuid": UUID, "security": "tls", "future_param": "two"},
            original_format="clash",
        )
        self.assertNotEqual(first.ensure_id(), second.ensure_id())


if __name__ == "__main__":
    unittest.main()
