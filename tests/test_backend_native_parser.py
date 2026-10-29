from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.singbox_backend import SingBoxBackend
from proxyfilter.cli import process_proxies


SOURCE = SourceInfo("test", "Test", "plain")


class BackendModeTests(unittest.TestCase):
    def _uri_proxy(self, protocol: str, raw: str, params: dict | None = None) -> ProxyConfig:
        return ProxyConfig(
            SOURCE,
            protocol,
            "example.com",
            443,
            params=dict(params or {}),
            original_format=f"{protocol}-uri",
            original_raw=raw,
        )

    def test_standard_mode_keeps_manual_json_mapper(self) -> None:
        backend = SingBoxBackend(backend_mode="standard")
        raw = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&sni=example.com"
        proxy = self._uri_proxy(
            "vless",
            raw,
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "tls",
                "sni": "example.com",
            },
        )
        out = backend._render_outbound(proxy)
        self.assertEqual(out["type"], "vless")
        self.assertEqual(out["server"], "example.com")
        self.assertEqual(out["server_port"], 443)
        self.assertNotIn("link", out)

    def test_default_mode_is_standard_for_backward_compatibility(self) -> None:
        backend = SingBoxBackend()
        raw = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls"
        proxy = self._uri_proxy(
            "vless",
            raw,
            {"uuid": "00000000-0000-0000-0000-000000000001", "security": "tls"},
        )
        out = backend._render_outbound(proxy)
        self.assertEqual(out["type"], "vless")
        self.assertNotIn("link", out)

    def test_standard_mode_forwards_unmapped_uri_parameter_to_json(self) -> None:
        backend = SingBoxBackend(backend_mode="standard")
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&sni=example.com&futureParam=opaque"
        )
        proxy = self._uri_proxy(
            "vless",
            raw,
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "tls",
                "sni": "example.com",
                "futureParam": "opaque",
            },
        )
        out = backend._render_outbound(proxy)
        self.assertEqual(out["futureParam"], "opaque")
        self.assertNotIn("security", out)
        self.assertNotIn("sni", out)

    def test_standard_mode_moves_legacy_precheck_field_to_singbox_json(self) -> None:
        backend = SingBoxBackend(backend_mode="standard")
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=reality&sni=example.com&pbk=key&spx=%2F"
        )
        proxy = self._uri_proxy(
            "vless",
            raw,
            {
                "uuid": "00000000-0000-0000-0000-000000000001",
                "security": "reality",
                "sni": "example.com",
                "pbk": "key",
                "spx": "/",
            },
        )
        out = backend._render_outbound(proxy)
        self.assertEqual(out["spx"], "/")

    def test_extended_mode_uses_native_parser_type(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        raw = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls"
        out = backend._render_outbound(self._uri_proxy("vless", raw))
        self.assertEqual(out["type"], "parser")
        self.assertEqual(out["tag"], "proxy-out")
        self.assertEqual(out["link"], raw)

    def test_extended_mode_forwards_uri_verbatim(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&futureParam=opaque%2Fvalue&empty=#Original%20Name"
        )
        out = backend._render_outbound(self._uri_proxy("vless", raw))
        self.assertEqual(out["link"], raw)

    def test_extended_mode_does_not_reject_unknown_uri_parameter(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=tls&futureParam=opaque"
        )
        out = backend._render_outbound(self._uri_proxy("vless", raw))
        self.assertEqual(out["link"], raw)

    def test_extended_mode_forwards_hy2_scheme_without_rewrite(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        raw = "hy2://secret@example.com:443?sni=example.com&futureParam=opaque"
        out = backend._render_outbound(self._uri_proxy("hy2", raw))
        self.assertEqual(out["type"], "parser")
        self.assertEqual(out["link"], raw)

    def test_extended_mode_uses_native_parser_for_all_production_uri_schemes(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        samples = {
            "vless": "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls",
            "vmess": "vmess://eyJ2IjoiMiJ9",
            "trojan": "trojan://secret@example.com:443?sni=example.com",
            "ss": "ss://YWVzLTEyOC1nY206c2VjcmV0@example.com:443",
            "hysteria2": "hysteria2://secret@example.com:443?sni=example.com",
            "hy2": "hy2://secret@example.com:443?sni=example.com",
            "tuic": "tuic://00000000-0000-0000-0000-000000000001:secret@example.com:443",
        }
        for protocol, raw in samples.items():
            with self.subTest(protocol=protocol):
                out = backend._render_outbound(self._uri_proxy(protocol, raw))
                self.assertEqual(out["type"], "parser")
                self.assertEqual(out["link"], raw)

    def test_extended_mode_does_not_emit_manually_mapped_connection_fields(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        raw = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?security=reality&pbk=opaque&sni=example.com&type=ws&path=%2Fws"
        )
        out = backend._render_outbound(self._uri_proxy("vless", raw))
        self.assertEqual(set(out), {"type", "tag", "link", "domain_resolver"})

    def test_extended_mode_requires_original_raw_link(self) -> None:
        backend = SingBoxBackend(backend_mode="extended")
        proxy = ProxyConfig(
            SOURCE,
            "vless",
            "example.com",
            443,
            params={"uuid": "00000000-0000-0000-0000-000000000001", "security": "tls"},
            original_format="vless-uri",
            original_raw="",
        )
        with self.assertRaisesRegex(EngineError, "original_raw|share link"):
            backend._render_outbound(proxy)

    def test_unknown_backend_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex((EngineError, ValueError), "backend.*mode|mode.*backend|unsupported.*mode"):
            SingBoxBackend(backend_mode="invalid")


class CoreRejectionTests(unittest.TestCase):
    def test_core_rejection_keeps_singbox_error_in_jsonl(self) -> None:
        raw = "vless://00000000-0000-0000-0000-000000000001@example.com:443?futureParam=opaque"
        proxy = ProxyConfig(
            SOURCE,
            "vless",
            "example.com",
            443,
            params={
                "uuid": "00000000-0000-0000-0000-000000000001",
                "futureParam": "opaque",
            },
            original_format="vless-uri",
            original_raw=raw,
        )

        class RejectingEngine:
            def validate(self, _proxy):
                return False, 'json: unknown field "futureParam"'

        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            survivors = process_proxies(
                [proxy],
                {},
                data_dir,
                "core",
                RejectingEngine(),
                resume_from="tcp",
            )
            self.assertEqual(survivors, [])
            rejected_path = data_dir / "work" / "05-rejected-core.jsonl"
            record = json.loads(rejected_path.read_text(encoding="utf-8").strip())
            self.assertEqual(record["tests"]["status"], "rejected_core")
            self.assertEqual(record["tests"]["core"]["status"], "fail")
            self.assertEqual(record["tests"]["core"]["error"], 'json: unknown field "futureParam"')


if __name__ == "__main__":
    unittest.main()
