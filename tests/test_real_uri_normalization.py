from __future__ import annotations

import base64
import json
import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo
from proxyfilter.render import render_uri, validate_round_trip
from proxyfilter.uri_normalize import normalize_uri


SOURCE = SourceInfo("test", "test", "plain")


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

    def test_unknown_query_fields_are_preserved(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
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
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&type=ws&path=%2Fws&future_param=one",
            SOURCE,
        )
        second = parse_uri(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&type=ws&path=%2Fws&future_param=two",
            SOURCE,
        )
        self.assertNotEqual(first.ensure_id(), second.ensure_id())

    def test_query_order_does_not_change_uri_identity(self) -> None:
        first = parse_uri(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&type=ws&path=%2Fws&future_param=one",
            SOURCE,
        )
        second = parse_uri(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?future_param=one&path=%2Fws&type=ws&security=tls",
            SOURCE,
        )
        self.assertEqual(first.ensure_id(), second.ensure_id())

    def test_normalized_generic_uri_preserves_opaque_and_empty_fields(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@Example.COM:443"
            "?z=&type=raw&future_param=one&security=tls#Name"
        )
        normalized = normalize_uri(uri, SOURCE)
        self.assertEqual(
            normalized,
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?future_param=one&security=tls&type=tcp&z=#Name",
        )
        self.assertEqual(normalize_uri(normalized, SOURCE), normalized)

    def test_normalized_vmess_preserves_unknown_fields_and_is_idempotent(self) -> None:
        data = {
            "v": "2",
            "ps": "Name",
            "add": "Example.COM",
            "port": "443",
            "id": "1281acca-f21d-475c-bf04-eccbee7f8df2",
            "net": "raw",
            "future_param": "opaque",
            "empty": "",
        }
        token = base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
        normalized = normalize_uri("vmess://" + token, SOURCE)
        reparsed = parse_uri(normalized, SOURCE)
        self.assertEqual(reparsed.server, "example.com")
        self.assertEqual(reparsed.params["net"], "tcp")
        self.assertEqual(reparsed.params["future_param"], "opaque")
        self.assertEqual(reparsed.params["empty"], "")
        self.assertEqual(normalize_uri(normalized, SOURCE), normalized)

    def test_normalized_shadowsocks_preserves_opaque_query_fields(self) -> None:
        uri = (
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@Example.COM:8388"
            "?future=x&empty=&plugin=v2ray-plugin%3Btls%3Bhost%3Dcdn.example.com#Name"
        )
        normalized = normalize_uri(uri, SOURCE)
        reparsed = parse_uri(normalized, SOURCE)
        self.assertEqual(reparsed.server, "example.com")
        self.assertEqual(reparsed.params["future"], "x")
        self.assertEqual(reparsed.params["empty"], "")
        self.assertEqual(reparsed.params["plugin"], "v2ray-plugin")
        self.assertEqual(reparsed.params["plugin_opts"], "tls;host=cdn.example.com")
        self.assertEqual(normalize_uri(normalized, SOURCE), normalized)


if __name__ == "__main__":
    unittest.main()
