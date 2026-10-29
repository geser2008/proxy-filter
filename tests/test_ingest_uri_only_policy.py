from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import patch

from proxyfilter.ingest import detect_and_parse, detect_and_parse_compat


UUID = "00000000-0000-0000-0000-000000000001"
URI = (
    f"vless://{UUID}@example.com:443"
    "?encryption=none&security=tls&type=ws&host=cdn.example.com&path=%2Fws#node"
)


class URIOnlyIngestPolicyTests(unittest.TestCase):
    def _assert_uri_only_reject(self, raw: str, expected_format: str = "unknown") -> None:
        proxies, errors, detected_format = detect_and_parse(raw, "test", "Test")
        self.assertEqual(detected_format, expected_format)
        self.assertEqual(proxies, [])
        self.assertEqual(errors, [{"reason": "unsupported_subscription_format"}])

    def test_plain_uri_subscription_is_accepted(self) -> None:
        proxies, errors, detected_format = detect_and_parse(URI + "\n", "test", "Test")

        self.assertEqual(detected_format, "plain")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].protocol, "vless")

    def test_base64_wrapped_uri_subscription_is_accepted(self) -> None:
        encoded = base64.b64encode((URI + "\n").encode()).decode()

        proxies, errors, detected_format = detect_and_parse(encoded, "test", "Test")

        self.assertEqual(detected_format, "base64/plain")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].source.format, "base64/plain")

    def test_production_plain_ingest_does_not_call_compat_parser(self) -> None:
        with patch("proxyfilter.ingest.detect_and_parse_compat", side_effect=AssertionError("compat called")):
            proxies, errors, detected_format = detect_and_parse(URI + "\n", "test", "Test")
        self.assertEqual(detected_format, "plain")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)

    def test_production_base64_ingest_does_not_call_compat_parser(self) -> None:
        encoded = base64.b64encode((URI + "\n").encode()).decode()
        with patch("proxyfilter.ingest.detect_and_parse_compat", side_effect=AssertionError("compat called")):
            proxies, errors, detected_format = detect_and_parse(encoded, "test", "Test")
        self.assertEqual(detected_format, "base64/plain")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)

    def test_clash_subscription_is_rejected_without_structured_parsing(self) -> None:
        clash = f"""proxies:\n  - name: node\n    type: vless\n    server: example.com\n    port: 443\n    uuid: {UUID}\n"""

        self._assert_uri_only_reject(clash)

        proxies, errors, detected_format = detect_and_parse_compat(clash, "test", "Test")
        self.assertEqual(detected_format, "clash")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)

    def test_v2ray_json_is_rejected_without_structured_parsing(self) -> None:
        config = {
            "outbounds": [
                {
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
                }
            ]
        }
        raw = json.dumps(config)

        self._assert_uri_only_reject(raw)

        proxies, errors, detected_format = detect_and_parse_compat(raw, "test", "Test")
        self.assertEqual(detected_format, "v2ray-json")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)

    def test_singbox_json_is_rejected_without_structured_parsing(self) -> None:
        config = {
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
        raw = json.dumps(config)

        self._assert_uri_only_reject(raw)

        proxies, errors, detected_format = detect_and_parse_compat(raw, "test", "Test")
        self.assertEqual(detected_format, "sing-box")
        self.assertEqual(errors, [])
        self.assertEqual(len(proxies), 1)

    def test_base64_wrapped_clash_is_rejected_without_structured_parsing(self) -> None:
        clash = f"""proxies:\n  - name: node\n    type: vless\n    server: example.com\n    port: 443\n    uuid: {UUID}\n"""
        encoded = base64.b64encode(clash.encode()).decode()

        self._assert_uri_only_reject(encoded, "base64/unknown")


if __name__ == "__main__":
    unittest.main()
