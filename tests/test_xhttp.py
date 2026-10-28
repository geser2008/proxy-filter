from __future__ import annotations

import json
import unittest
from urllib.parse import quote

from proxyfilter.engine import EngineError
from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo
from proxyfilter.render import render_uri, validate_round_trip
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

    def test_basic_xhttp_fields_do_not_inject_padding_default(self) -> None:
        transport = self._render(
            "encryption=none&security=tls&type=xhttp&mode=stream-up"
            "&host=cdn.example.com&path=%2Fapi"
        )
        self.assertEqual(
            transport,
            {
                "type": "xhttp",
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

    def test_xhttp_uri_round_trip_preserves_extra_object_semantics(self) -> None:
        extra = {
            "xPaddingBytes": "200-800",
            "scMinPostsIntervalMs": 30,
            "xmux": {
                "maxConcurrency": "16-32",
                "maxConnections": 0,
            },
        }
        proxy = parse_uri(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?"
            "encryption=none&security=tls&type=xhttp&mode=stream-up"
            "&host=cdn.example.com&path=%2Fapi&extra="
            + quote(json.dumps(extra, separators=(",", ":")), safe=""),
            self.source,
        )
        self.assertIsInstance(proxy.identity_payload()["params"]["transport"]["extra"], dict)
        rendered = render_uri(proxy, "roundtrip")
        self.assertIn("type=xhttp", rendered)
        self.assertIn("extra=", rendered)
        validate_round_trip(proxy, rendered)

    def test_invalid_xhttp_extra_remains_rejected_at_render(self) -> None:
        proxy = parse_uri(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?"
            "encryption=none&type=xhttp&extra=not-json",
            self.source,
        )
        with self.assertRaisesRegex(ValueError, "XHTTP extra must be a JSON object"):
            render_uri(proxy, "bad")

    def test_invalid_but_present_xhttp_values_are_not_repaired(self) -> None:
        extra = {
            "xPaddingBytes": "0-0",
            "xmux": {
                "maxConcurrency": "",
                "maxConnections": 0,
            },
        }
        transport = self._render(
            "encryption=none&type=xhttp&extra="
            + quote(json.dumps(extra, separators=(",", ":")), safe="")
        )
        self.assertEqual(transport["x_padding_bytes"], "0-0")
        self.assertEqual(transport["xmux"]["max_concurrency"], "")
        self.assertEqual(transport["xmux"]["max_connections"], 0)

    def test_null_xhttp_value_is_not_repaired(self) -> None:
        extra = {
            "xPaddingBytes": None,
            "scMaxEachPostBytes": None,
        }
        transport = self._render(
            "encryption=none&type=xhttp&extra="
            + quote(json.dumps(extra, separators=(",", ":")), safe="")
        )
        self.assertIsNone(transport["x_padding_bytes"])
        self.assertIsNone(transport["sc_max_each_post_bytes"])

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

    def test_legacy_sc_max_concurrent_posts_is_rejected_not_dropped(self) -> None:
        extra = {
            "scMaxConcurrentPosts": 4,
            "xPaddingBytes": "200-800",
        }
        with self.assertRaisesRegex(EngineError, "scMaxConcurrentPosts"):
            self._render(
                "encryption=none&type=xhttp&extra="
                + quote(json.dumps(extra, separators=(",", ":")), safe="")
            )

    def test_explicit_empty_extra_is_rejected_not_treated_as_absent(self) -> None:
        with self.assertRaisesRegex(EngineError, "invalid XHTTP extra JSON"):
            self._render("encryption=none&type=xhttp&extra=")

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
