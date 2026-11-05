from __future__ import annotations

import base64
import json
import unittest

from proxyfilter.engine import EngineError
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.native_experiment import NativeMappingError, convert_uri_to_native


SOURCE = SourceInfo("fixture", "Fixture", "plain")
UUID = "00000000-0000-0000-0000-000000000001"


def proxy(protocol: str, params: dict) -> ProxyConfig:
    return ProxyConfig(
        SOURCE, protocol, "example.org", 443, "fixture",
        dict(params), f"{protocol}-uri", f"{protocol}://redacted",
    )


class NativeExperimentTests(unittest.TestCase):
    def test_vless_json_unknown_field_reported_without_mutation(self):
        p = proxy("vless", {
            "uuid": UUID, "security": "tls", "sni": "example.org",
            "encryption": "none", "Telegram": "private-channel",
        })
        original = dict(p.params)
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "vless")
        self.assertEqual(result.outbound["tls"]["server_name"], "example.org")
        self.assertNotIn("Telegram", result.outbound)
        self.assertNotIn("encryption", result.outbound)
        self.assertEqual([(d.name, d.reason) for d in result.dropped_fields],
                         [("Telegram", "unclassified")])
        self.assertFalse(result.no_unclassified_loss)
        self.assertEqual(p.params, original)
        self.assertEqual(p.original_raw, "vless://redacted")
        self.assertEqual(p.id, "")

    def test_metadata_does_not_create_unknown_loss(self):
        p = proxy("ss", {"method": "aes-256-gcm", "password": "secret", "ps": "label"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "shadowsocks")
        self.assertEqual(result.dropped_fields[0].reason, "metadata")
        self.assertTrue(result.no_unclassified_loss)

    def test_conflicting_sni_aliases_fail(self):
        p = proxy("trojan", {
            "password": "secret", "sni": "one.example", "server_name": "two.example",
        })
        with self.assertRaisesRegex(EngineError, "conflicting_aliases"):
            convert_uri_to_native(p)

    def test_equal_aliases_are_allowed(self):
        p = proxy("trojan", {
            "password": "secret", "sni": "same.example", "server_name": "same.example",
        })
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["tls"]["server_name"], "same.example")

    def test_known_unsupported_field_fails_instead_of_dropping(self):
        p = proxy("vless", {"uuid": UUID, "fm": '{"tcp":[]}'})
        with self.assertRaisesRegex(EngineError, "unsupported_connection_field"):
            convert_uri_to_native(p)

    def test_unsupported_fields_provide_stable_names_not_values(self):
        p = proxy("vless", {
            "uuid": UUID, "fm": "sensitive-one", "spx": "sensitive-two",
        })
        with self.assertRaises(NativeMappingError) as captured:
            convert_uri_to_native(p)
        self.assertEqual(captured.exception.code, "unsupported_connection_field")
        self.assertEqual(captured.exception.fields, ("fm", "spx"))
        self.assertNotIn("sensitive-one", str(captured.exception))
        self.assertNotIn("sensitive-two", str(captured.exception))

    def test_invalid_vless_encryption_fails(self):
        p = proxy("vless", {"uuid": UUID, "encryption": "aes-128-gcm"})
        with self.assertRaisesRegex(EngineError, "unsupported_vless_encryption"):
            convert_uri_to_native(p)

    def test_unknown_transport_never_falls_back_to_tcp(self):
        p = proxy("vless", {"uuid": UUID, "type": "future-transport"})
        with self.assertRaisesRegex(EngineError, "unsupported_transport"):
            convert_uri_to_native(p)

    def test_tcp_with_ws_path_does_not_silently_lose_path(self):
        p = proxy("vless", {"uuid": UUID, "type": "tcp", "path": "/hidden"})
        with self.assertRaisesRegex(EngineError, "transport_fields_on_tcp"):
            convert_uri_to_native(p)

    def test_reality_fingerprint_not_invented(self):
        p = proxy("vless", {
            "uuid": UUID, "security": "reality",
            "pbk": "public-key-placeholder",
        })
        with self.assertRaisesRegex(EngineError, "reality_missing_fingerprint"):
            convert_uri_to_native(p)

    def test_extended_input_not_accepted(self):
        p = proxy("vless", {"uuid": UUID})
        p.original_format = "clash"
        with self.assertRaisesRegex(EngineError, "not_uri"):
            convert_uri_to_native(p)

    def test_hysteria2_security_is_not_silently_discarded(self):
        p = proxy("hysteria2", {"password": "secret", "security": "tls"})
        with self.assertRaisesRegex(EngineError, "unmapped_connection_field"):
            convert_uri_to_native(p)

    def test_trojan_peer_is_not_silently_discarded(self):
        p = proxy("trojan", {"password": "secret", "peer": "example.org"})
        with self.assertRaises(NativeMappingError) as captured:
            convert_uri_to_native(p)
        self.assertEqual(captured.exception.code, "unmapped_connection_field")
        self.assertEqual(captured.exception.fields, ("peer",))

    def test_shadowsocks_transport_type_is_not_silently_discarded(self):
        p = proxy("ss", {"method": "aes-256-gcm", "password": "secret", "type": "ws"})
        with self.assertRaisesRegex(EngineError, "unmapped_connection_field"):
            convert_uri_to_native(p)

    def test_metadata_still_passes_without_connection_loss(self):
        p = proxy("ss", {"method": "aes-256-gcm", "password": "secret", "note": "free"})
        result = convert_uri_to_native(p)
        self.assertFalse(result.no_unclassified_loss)
        self.assertEqual(result.dropped_fields[0].name, "note")

    def test_supported_hy2_alias(self):
        p = proxy("hy2", {"password": "secret", "sni": "example.org"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "hysteria2")
        self.assertTrue(result.outbound["tls"]["enabled"])

    def test_vmess_explicit_cipher_and_tls(self):
        p = proxy("vmess", {"id": UUID, "scy": "auto", "tls": "tls"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "vmess")
        self.assertEqual(result.outbound["security"], "auto")
        self.assertTrue(result.outbound["tls"]["enabled"])

    def test_vmess_header_none_does_not_override_ws_transport(self):
        p = proxy("vmess", {"id": UUID, "scy": "auto", "tls": "tls",
                            "net": "ws", "type": "none", "path": "/socket"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["transport"]["type"], "ws")
        self.assertEqual(result.outbound["transport"]["path"], "/socket")
        self.assertEqual(p.params["type"], "none")

    def test_vmess_empty_insecure_preserves_verification(self):
        p = proxy("vmess", {
            "id": UUID, "scy": "auto", "tls": "tls", "insecure": "",
        })
        original = dict(p.params)
        result = convert_uri_to_native(p)
        self.assertTrue(result.outbound["tls"]["enabled"])
        self.assertFalse(result.outbound["tls"].get("insecure", False))
        self.assertEqual(p.params, original)
        self.assertEqual(p.original_raw, "vmess://redacted")

    def test_vmess_explicit_insecure_false_remains_false(self):
        p = proxy("vmess", {
            "id": UUID, "scy": "auto", "tls": "tls", "insecure": "false",
        })
        result = convert_uri_to_native(p)
        self.assertIs(result.outbound["tls"]["insecure"], False)

    def test_vmess_invalid_nonempty_insecure_is_not_repaired(self):
        p = proxy("vmess", {
            "id": UUID, "scy": "auto", "tls": "tls", "insecure": "invalid-value",
        })
        with self.assertRaisesRegex(EngineError, "invalid boolean value"):
            convert_uri_to_native(p)

    def test_vmess_empty_pcs_neutral_for_tls_enabled_and_disabled(self):
        for tls in ("none", "tls"):
            with self.subTest(tls=tls):
                p = proxy("vmess", {
                    "id": UUID, "scy": "auto", "pcs": "",
                    "tls": tls, "insecure": "false",
                })
                original = dict(p.params)
                result = convert_uri_to_native(p)
                self.assertTrue(result.no_unclassified_loss)
                self.assertEqual(result.dropped_fields, ())
                self.assertEqual(result.outbound.get("tls", {}).get("enabled", False),
                                 tls == "tls")
                self.assertEqual(p.params, original)
                self.assertEqual(p.original_raw, "vmess://redacted")

    def test_vmess_nonempty_or_nonstring_pcs_still_rejected(self):
        for pin in ("opaque-hash", None, 0, False, [], {}):
            with self.subTest(pin=pin):
                with self.assertRaises(NativeMappingError) as caught:
                    convert_uri_to_native(proxy("vmess", {"id": UUID, "pcs": pin}))
                self.assertEqual(caught.exception.code, "unsupported_connection_field")
                self.assertEqual(caught.exception.fields, ("pcs",))

    def test_vmess_empty_pcs_does_not_hide_ech(self):
        for field in ("ech", "echConfigList"):
            with self.subTest(field=field):
                with self.assertRaises(NativeMappingError) as caught:
                    convert_uri_to_native(proxy("vmess", {
                        "id": UUID, "pcs": "", field: "opaque",
                    }))
                self.assertEqual(caught.exception.code, "unsupported_connection_field")
                self.assertEqual(caught.exception.fields, (field,))

    def test_vmess_empty_pcs_does_not_bypass_other_blockers(self):
        p = proxy("vmess", {
            "id": UUID, "pcs": "", "fm": "opaque",
        })
        with self.assertRaises(NativeMappingError) as caught:
            convert_uri_to_native(p)
        self.assertEqual(caught.exception.fields, ("fm",))

    def test_empty_pcs_other_protocols_remain_rejected(self):
        for protocol, params in (
            ("vless", {"uuid": UUID, "pcs": ""}),
            ("trojan", {"password": "secret", "pcs": ""}),
        ):
            with self.subTest(protocol=protocol):
                with self.assertRaises(NativeMappingError) as caught:
                    convert_uri_to_native(proxy(protocol, params))
                self.assertEqual(caught.exception.code, "unsupported_connection_field")

    def test_vmess_empty_cs_is_parser_neutral_only_in_temporary_copy(self):
        params = {"id": UUID, "scy": "auto", "net": "ws", "tls": "tls",
                  "path": "/socket", "cs": ""}
        p = proxy("vmess", params)
        original = dict(p.params)
        result = convert_uri_to_native(p)
        baseline = convert_uri_to_native(proxy(
            "vmess", {key: value for key, value in params.items() if key != "cs"}
        ))
        self.assertEqual(result.outbound, baseline.outbound)
        self.assertTrue(result.no_unclassified_loss)
        self.assertNotIn("cipher_suites", result.outbound["tls"])
        self.assertEqual(result.dropped_fields, ())
        self.assertEqual(p.params, original)
        self.assertEqual(p.original_raw, "vmess://redacted")

    def test_empty_cs_other_cases_still_rejected_without_changing_source(self):
        fixtures = (
            ("vless", {"uuid": UUID, "security": "tls", "type": "ws", "cs": ""}),
            ("trojan", {"password": "secret", "cs": ""}),
            ("vmess", {"id": UUID, "tls": "tls", "cipher_suites": ""}),
            ("vmess", {"id": UUID, "tls": "tls", "cipher-suites": ""}),
        )
        for protocol, params in fixtures:
            with self.subTest(protocol=protocol, params=params):
                p = proxy(protocol, params)
                original = dict(p.params)
                with self.assertRaises(NativeMappingError) as captured:
                    convert_uri_to_native(p)
                self.assertEqual(captured.exception.code, "empty_tls_cipher_suites")
                self.assertEqual(captured.exception.fields, ())
                self.assertEqual(p.params, original)
                self.assertEqual(p.original_raw, f"{protocol}://redacted")

    def test_vmess_empty_cs_does_not_bypass_conflicting_aliases(self):
        p = proxy("vmess", {
            "id": UUID, "tls": "tls", "cs": "",
            "cipher_suites": "TLS_FAKE_VALUE",
        })
        with self.assertRaises(NativeMappingError) as caught:
            convert_uri_to_native(p)
        self.assertEqual(caught.exception.code, "unsupported_tls_cipher_suites")

    def test_nonempty_cs_is_not_mapped_to_native_tls_without_parser_equivalence(self):
        for protocol, identity in (
            ("vless", {"uuid": UUID, "type": "ws", "security": "tls"}),
            ("vmess", {"id": UUID, "net": "ws", "tls": "tls"}),
            ("trojan", {"password": "secret", "type": "ws"}),
        ):
            with self.subTest(protocol=protocol):
                p = proxy(protocol, {**identity, "cs": "TLS_A:TLS_B"})
                original = dict(p.params)
                with self.assertRaises(NativeMappingError) as captured:
                    convert_uri_to_native(p)
                self.assertEqual(captured.exception.code, "unsupported_tls_cipher_suites")
                self.assertEqual(p.params, original)

    def test_absent_cs_does_not_invent_cipher_suites(self):
        p = proxy("vmess", {"id": UUID, "scy": "auto", "net": "ws",
                            "tls": "tls", "path": "/socket"})
        output = convert_uri_to_native(p).outbound
        self.assertTrue(output["tls"]["enabled"])
        self.assertNotIn("cipher_suites", output["tls"])

    def test_vmess_tcp_http_disguise_maps_to_native_transport(self):
        p = proxy("vmess", {
            "id": UUID, "net": "tcp", "type": "http",
            "host": "cover.example", "path": "/cover", "method": "GET",
        })
        original = dict(p.params)
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["transport"], {
            "type": "http", "host": ["cover.example"],
            "path": "/cover", "method": "GET",
        })
        self.assertTrue(result.no_unclassified_loss)
        self.assertEqual(result.dropped_fields, ())
        self.assertEqual(p.params, original)
        self.assertEqual(p.original_raw, "vmess://redacted")

    def test_vmess_tcp_http_tls_mismatch_is_rejected(self):
        for tls in ("tls", "1", "true", "reality", "TLS", "unexpected"):
            with self.subTest(tls=tls):
                p = proxy("vmess", {
                    "id": UUID, "net": "tcp", "type": "http",
                    "tls": tls, "host": "cover.example",
                })
                before = dict(p.params)
                with self.assertRaises(NativeMappingError) as caught:
                    convert_uri_to_native(p)
                self.assertEqual(caught.exception.code, "vmess_http_disguise_tls_conflict")
                self.assertEqual(caught.exception.fields, ("tls",))
                self.assertEqual(p.params, before)
                self.assertEqual(p.original_raw, "vmess://redacted")

    def test_vmess_tcp_http_explicit_no_tls_is_allowed(self):
        for tls in ("", "none", "0", "false"):
            with self.subTest(tls=tls):
                result = convert_uri_to_native(proxy("vmess", {
                    "id": UUID, "net": "tcp", "type": "http",
                    "tls": tls, "host": "cover.example",
                }))
                self.assertEqual(result.outbound["transport"], {
                    "type": "http", "host": ["cover.example"],
                })
                self.assertNotIn("tls", result.outbound)

    def test_vmess_tcp_http_unknown_tls_type_fails_closed(self):
        for tls in (True, 1, None, ["tls"]):
            with self.subTest(tls=tls):
                with self.assertRaises(NativeMappingError) as caught:
                    convert_uri_to_native(proxy("vmess", {
                        "id": UUID, "net": "tcp", "type": "http",
                        "tls": tls,
                    }))
                self.assertEqual(caught.exception.code, "vmess_http_disguise_tls_conflict")

    def test_vmess_ws_tls_unaffected_by_http_disguise_gate(self):
        result = convert_uri_to_native(proxy("vmess", {
            "id": UUID, "net": "ws", "type": "none",
            "tls": "tls", "path": "/socket",
        }))
        self.assertEqual(result.outbound["transport"]["type"], "ws")
        self.assertTrue(result.outbound["tls"]["enabled"])

    def test_vmess_tcp_http_without_optional_fields(self):
        result = convert_uri_to_native(proxy("vmess", {
            "id": UUID, "net": "tcp", "type": "http",
        }))
        self.assertEqual(result.outbound["transport"], {"type": "http"})

    def test_vmess_tcp_http_ambiguous_hosts_are_not_guessed(self):
        p = proxy("vmess", {
            "id": UUID, "net": "tcp", "type": "http",
            "host": "one.example,two.example",
        })
        with self.assertRaises(NativeMappingError) as exc:
            convert_uri_to_native(p)
        self.assertEqual(exc.exception.code, "ambiguous_vmess_http_hosts")

    def test_vmess_tcp_http_headers_not_dropped(self):
        p = proxy("vmess", {
            "id": UUID, "net": "tcp", "type": "http",
            "headers": '{"X-Test":["opaque"]}',
        })
        with self.assertRaises(NativeMappingError) as exc:
            convert_uri_to_native(p)
        self.assertEqual(exc.exception.code, "unmapped_transport_headers")

    def test_vmess_tcp_http_requires_explicit_tcp(self):
        for net in (None, "ws", "grpc", "raw"):
            with self.subTest(net=net):
                params = {"id": UUID, "type": "http"}
                if net is not None:
                    params["net"] = net
                with self.assertRaises(NativeMappingError) as exc:
                    convert_uri_to_native(proxy("vmess", params))
                self.assertEqual(exc.exception.code, "unsupported_vmess_header")

    def test_vmess_http_method_not_silently_dropped_outside_disguise(self):
        p = proxy("vmess", {
            "id": UUID, "net": "tcp", "type": "none", "method": "GET",
        })
        with self.assertRaises(NativeMappingError) as exc:
            convert_uri_to_native(p)
        self.assertEqual(exc.exception.code, "unmapped_vmess_http_method")

    def test_vmess_tcp_http_rejects_non_string_fields(self):
        for field in ("host", "path", "method"):
            with self.subTest(field=field):
                with self.assertRaises(NativeMappingError) as exc:
                    convert_uri_to_native(proxy("vmess", {
                        "id": UUID, "net": "tcp", "type": "http", field: None,
                    }))
                self.assertEqual(exc.exception.code, "invalid_vmess_http_field")

    def test_vmess_nontrivial_unsupported_tcp_header_rejected(self):
        p = proxy("vmess", {"id": UUID, "net": "tcp", "type": "srtp"})
        with self.assertRaisesRegex(EngineError, "unsupported_vmess_header"):
            convert_uri_to_native(p)

    def test_vless_xhttp_base64url_extra_decoded_only_in_copy(self):
        extra = {"xPaddingBytes": "12-24", "mode": "stream-up"}
        encoded = base64.urlsafe_b64encode(json.dumps(extra).encode()).decode().rstrip("=")
        p = proxy("vless", {"uuid": UUID, "type": "xhttp",
                             "path": "/x", "extra": encoded})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["transport"]["type"], "xhttp")
        self.assertEqual(result.outbound["transport"]["x_padding_bytes"], "12-24")
        self.assertEqual(result.outbound["transport"]["mode"], "stream-up")
        self.assertEqual(p.params["extra"], encoded)

    def test_xhttp_absent_padding_uses_extended_runtime_default(self):
        for protocol, identity in (
            ("vless", {"uuid": UUID}),
            ("vmess", {"id": UUID, "scy": "auto", "net": "xhttp"}),
            ("trojan", {"password": "secret"}),
        ):
            with self.subTest(protocol=protocol):
                params = {**identity}
                if protocol != "vmess":
                    params["type"] = "xhttp"
                p = proxy(protocol, params)
                original = dict(p.params)
                result = convert_uri_to_native(p)
                transport = result.outbound["transport"]
                self.assertEqual(transport["type"], "xhttp")
                self.assertEqual(transport["x_padding_bytes"], "100-1000")
                self.assertEqual(p.params, original)

    def test_xhttp_explicit_padding_is_never_overwritten(self):
        for padding in ("12-24", "0-0", ""):
            with self.subTest(padding=padding):
                extra = {"xPaddingBytes": padding}
                encoded = base64.urlsafe_b64encode(
                    json.dumps(extra).encode()
                ).decode().rstrip("=")
                p = proxy("vless", {"uuid": UUID, "type": "xhttp",
                                    "extra": encoded})
                result = convert_uri_to_native(p)
                self.assertEqual(
                    result.outbound["transport"]["x_padding_bytes"], padding
                )
                self.assertEqual(p.params["extra"], encoded)

    def test_non_xhttp_does_not_receive_padding(self):
        p = proxy("vless", {"uuid": UUID, "type": "ws", "path": "/socket"})
        result = convert_uri_to_native(p)
        self.assertNotIn("x_padding_bytes", result.outbound["transport"])

    def test_xhttp_plain_json_in_share_uri_is_not_base64url(self):
        p = proxy("vless", {"uuid": UUID, "type": "xhttp",
                             "extra": '{"mode":"auto"}'})
        with self.assertRaisesRegex(EngineError, "invalid_xhttp_extra_encoding"):
            convert_uri_to_native(p)

    def test_conflicting_transport_aliases_detected(self):
        p = proxy("vless", {"uuid": UUID, "type": "ws", "net": "grpc"})
        with self.assertRaisesRegex(EngineError, "conflicting_transport_aliases"):
            convert_uri_to_native(p)

    def test_hy2_certificate_pin_is_not_lost_when_utls_fp_present(self):
        p = proxy("hy2", {
            "password": "secret", "fingerprint": "pin-secret",
            "fp": "chrome",
        })
        with self.assertRaises(NativeMappingError) as context:
            convert_uri_to_native(p)
        self.assertEqual(context.exception.code, "unsupported_certificate_fingerprint")
        self.assertEqual(context.exception.fields, ("fingerprint",))
        self.assertNotIn("pin-secret", str(context.exception))

    def test_tuic_certificate_pin_is_not_lost_when_utls_fp_present(self):
        p = proxy("tuic", {
            "uuid": UUID, "password": "secret",
            "fingerprint": "pin-secret", "fp": "chrome",
        })
        with self.assertRaisesRegex(EngineError, "unsupported_certificate_fingerprint"):
            convert_uri_to_native(p)

    def test_tuic_native_outbound(self):
        p = proxy("tuic", {"uuid": UUID, "password": "secret"})
        result = convert_uri_to_native(p)
        self.assertEqual(result.outbound["type"], "tuic")
        self.assertTrue(result.outbound["tls"]["enabled"])


if __name__ == "__main__":
    unittest.main()
