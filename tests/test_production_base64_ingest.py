from __future__ import annotations

import base64
import json
import unittest

from proxyfilter.ingest import detect_and_parse, detect_and_parse_compat


class ProductionBase64IngestTests(unittest.TestCase):
    @staticmethod
    def _b64(text: str) -> str:
        return base64.b64encode(text.encode("utf-8")).decode("ascii")

    def test_production_rejects_base64_clash_yaml(self) -> None:
        raw = self._b64(
            "proxies:\n"
            "  - name: test\n"
            "    type: vless\n"
            "    server: example.com\n"
            "    port: 443\n"
            "    uuid: 00000000-0000-0000-0000-000000000001\n"
        )
        proxies, errors, fmt = detect_and_parse(raw, "test", "Test")
        self.assertEqual(proxies, [])
        self.assertEqual(fmt, "base64/unknown")
        self.assertEqual(errors, [{"reason": "unsupported_subscription_format"}])

    def test_production_rejects_base64_singbox_json(self) -> None:
        raw = self._b64(
            json.dumps(
                {
                    "outbounds": [
                        {
                            "type": "vless",
                            "server": "example.com",
                            "server_port": 443,
                            "uuid": "00000000-0000-0000-0000-000000000001",
                        }
                    ]
                }
            )
        )
        proxies, errors, fmt = detect_and_parse(raw, "test", "Test")
        self.assertEqual(proxies, [])
        self.assertEqual(fmt, "base64/unknown")
        self.assertEqual(errors, [{"reason": "unsupported_subscription_format"}])

    def test_production_still_accepts_base64_uri_text(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&sni=example.com"
        )
        proxies, errors, fmt = detect_and_parse(self._b64(uri + "\n"), "test", "Test")
        self.assertEqual(errors, [])
        self.assertEqual(fmt, "base64/plain")
        self.assertEqual(len(proxies), 1)
        self.assertEqual(proxies[0].original_raw, uri)

    def test_compat_still_accepts_base64_structured_input(self) -> None:
        raw = self._b64(
            "proxies:\n"
            "  - name: test\n"
            "    type: vless\n"
            "    server: example.com\n"
            "    port: 443\n"
            "    uuid: 00000000-0000-0000-0000-000000000001\n"
        )
        proxies, errors, fmt = detect_and_parse_compat(raw, "test", "Test")
        self.assertEqual(errors, [])
        self.assertEqual(fmt, "base64/clash")
        self.assertEqual(len(proxies), 1)


if __name__ == "__main__":
    unittest.main()
