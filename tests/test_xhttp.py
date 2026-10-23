from __future__ import annotations

import json
import unittest
from urllib.parse import quote

from proxyfilter.engine import EngineError
from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo
from proxyfilter.singbox_backend import SingBoxBackend


class XHTTPTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = SingBoxBackend()
        self.source = SourceInfo("test", "test", "plain")

    def _render(self, query: str) -> dict:
        proxy = parse_uri(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?"
            + query,
            self.source,
        )
        return self.backend._render_outbound(proxy)["transport"]

    def test_basic_xhttp_fields(self) -> None:
        transport = self._render(
            "encryption=none&security=tls&type=xhttp&mode=stream-up"
            "&host=cdn.example.com&path=%2Fapi"
        )
        self.assertEqual(
            transport,
            {
                "type": "xhttp",
                "x_padding_bytes": "100-1000",
                "mode": "stream-up",
                "host": "cdn.example.com",
                "path": "/api",
            },
        )

    def test_extra_and_xmux_are_mapped_explicitly(self) -> None:
        extra = {
            "xPaddingBytes": "200-800",
            "scMinPostsIntervalMs": 30,
            "xmux": {
                "maxConcurrency": "16-32",
                "maxConnections": 0,
                "hMaxRequestTimes": "600-900",
            },
        }
        transport = self._render(
            "encryption=none&type=xhttp&extra="
            + quote(json.dumps(extra, separators=(",", ":")), safe="")
        )
        self.assertEqual(transport["x_padding_bytes"], "200-800")
        self.assertEqual(transport["sc_min_posts_interval_ms"], 30)
        self.assertEqual(
            transport["xmux"],
            {
                "max_concurrency": "16-32",
                "max_connections": 0,
                "h_max_request_times": "600-900",
            },
        )

    def test_barry_session_id_aliases_are_mapped(self) -> None:
        extra = {
            "mode": "packet-up",
            "sessionIDPlacement": "header",
            "sessionIDKey": "X-Session-ID",
        }
        transport = self._render(
            "encryption=none&type=xhttp&extra="
            + quote(json.dumps(extra, separators=(",", ":")), safe="")
        )
        self.assertEqual(transport["mode"], "packet-up")
        self.assertEqual(transport["session_placement"], "header")
        self.assertEqual(transport["session_key"], "X-Session-ID")

    def test_legacy_sc_max_concurrent_posts_is_intentionally_ignored(self) -> None:
        extra = {
            "scMaxConcurrentPosts": 4,
            "xPaddingBytes": "200-800",
        }
        transport = self._render(
            "encryption=none&type=xhttp&extra="
            + quote(json.dumps(extra, separators=(",", ":")), safe="")
        )
        self.assertEqual(transport["x_padding_bytes"], "200-800")
        self.assertNotIn("sc_max_concurrent_posts", transport)

    def test_unknown_extra_field_is_rejected(self) -> None:
        extra = quote('{"notARealXHTTPField":1}', safe="")
        with self.assertRaisesRegex(EngineError, "unsupported XHTTP extra field"):
            self._render("encryption=none&type=xhttp&extra=" + extra)

    def test_download_settings_are_not_silently_dropped(self) -> None:
        extra = quote('{"downloadSettings":{"address":"example.net"}}', safe="")
        with self.assertRaisesRegex(EngineError, "downloadSettings"):
            self._render("encryption=none&type=xhttp&extra=" + extra)


if __name__ == "__main__":
    unittest.main()
