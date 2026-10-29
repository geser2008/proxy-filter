from __future__ import annotations

import base64
import json
import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo
from proxyfilter.render import render_uri, validate_round_trip


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

    def test_known_metadata_query_fields_are_not_connection_semantics(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&type=ws&path=%2Fws&note=%40FreeOnlineVPN&Telegram=%40channel"
        )
        proxy = parse_uri(uri, SOURCE)
        self.assertNotIn("note", proxy.params)
        self.assertNotIn("Telegram", proxy.params)
        rendered = render_uri(proxy, "test")
        validate_round_trip(proxy, rendered)

    def test_vmess_test_name_is_metadata(self) -> None:
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
        self.assertNotIn("test_name", proxy.params)
        rendered = render_uri(proxy, "test")
        validate_round_trip(proxy, rendered)

    def test_empty_optional_tls_fields_are_ignored(self) -> None:
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
        self.assertNotIn("insecure", proxy.params)
        self.assertNotIn("pcs", proxy.params)
        self.assertNotIn("ech", proxy.params)
        rendered = render_uri(proxy, "test")
        validate_round_trip(proxy, rendered)


if __name__ == "__main__":
    unittest.main()
