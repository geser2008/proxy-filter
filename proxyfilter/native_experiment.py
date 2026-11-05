from __future__ import annotations

"""Opt-in URI -> native sing-box outbound experiment.

This module is intentionally NOT wired into the production backend selector.
Unknown fields are removed only from a temporary mapping copy, and reported by
name. An outbound with removed fields is never asserted semantically equivalent.
"""
from dataclasses import dataclass
import base64
import binascii
import json
import re
from typing import Any

from .engine import EngineError
from .singbox_backend import SingBoxBackend as MappedBackend


# Registry entries are fields consumed by the existing mapper, NOT a claim of
# complete URI/protocol support. Extend only alongside mapping tests.
_TLS = set("""tls sni server_name servername server-name alpn fp client-fingerprint
 fingerprint allowInsecure allow_insecure skip-cert-verify insecure
 cs cipher_suites cipher-suites disable_sni disable-sni""".split())
_TRANSPORT = set("""type net network transport host path mode headerType header_type
 headers serviceName service_name authority ws-opts grpc-opts
 ed max_early_data max-early-data eh early_data_header_name
 early-data-header-name idle_timeout idle-timeout ping_timeout ping-timeout
 permit_without_stream permit-without-stream extra""".split())
_COMMON = set("multiplex".split())
_PROTOCOL_FIELDS: dict[str, set[str]] = {
    "vless": _TLS | _TRANSPORT | _COMMON | set("""uuid flow encryption security
        pbk public_key sid short_id reality-opts packet_encoding
        packet-encoding packetEncoding""".split()),
    "vmess": _TLS | _TRANSPORT | _COMMON | set("""id uuid aid alterId alter_id
        security scy cipher packet_encoding packet-encoding packetEncoding
        global_padding global-padding authenticated_length authenticated-length""".split()),
    "trojan": _TLS | _TRANSPORT | _COMMON | set("password security".split()),
    "ss": set("""method cipher password plugin plugin_opts plugin-opts network
        udp_over_tcp udp-over-tcp multiplex""".split()),
    "hysteria2": _TLS | set("""password auth up_mbps up-mbps up upmbps
        down_mbps down-mbps down downmbps obfs obfs-password obfs_password
        server_ports ports mport hop_interval hop-interval hop_interval_max
        hop-interval-max obfs_min_packet_size obfs-min-packet-size
        obfs_max_packet_size obfs-max-packet-size network bbr_profile
        bbr-profile brutal_debug brutal-debug disable_chrome_parrot
        disable-chrome-parrot realm""".split()),
    "tuic": _TLS | set("""uuid password congestion_control congestion-controller
        udp_relay_mode udp-relay-mode udp_over_stream udp-over-stream
        zero_rtt_handshake zero-rtt-handshake reduce-rtt heartbeat
        heartbeat-interval heartbeat_interval network""".split()),
}
# These cannot be treated as harmless unknown metadata.
_UNSUPPORTED = set("""fm final_mask pcs pinnedPeerCertSha256 peer_certificate_sha256
 ech echConfigList spx spider_x smux pinSHA256 pin_sha256 fastopen
 realm-opts token""".split())
_METADATA = {"ps", "name", "tag", "v"}
# Fields not represented by this protocol's native mapping are not
# necessarily harmless: even if an alternate URI parser ignores them,
# silently dropping them would make the A/B result misleading. This is a
# conservative registry, not an instruction to guess their meaning.
_UNMAPPED_CONNECTION_FIELDS = {
    "peer", "allowinsecure", "security", "encryption", "pbk", "sid",
    "ws", "wspath", "headertype", "headerType", "type", "pool",
    "udp", "prefix",
}

# Only alias groups whose values genuinely share one destination are checked.
_ALIASES = (
    ("sni", "server_name", "servername", "server-name"),
    ("fp", "client-fingerprint"),
    ("pbk", "public_key"),
    ("sid", "short_id"),
    # VMess legacy "type" is a TCP header selector, not a net alias.
    # Network alias conflict is verified separately per protocol.
    ("serviceName", "service_name"),
    ("ed", "max_early_data", "max-early-data"),
    ("eh", "early_data_header_name", "early-data-header-name"),
    ("allowInsecure", "allow_insecure", "skip-cert-verify", "insecure"),
    ("packet_encoding", "packet-encoding", "packetEncoding"),
    ("uuid", "id"),
    ("alter_id", "alterId", "aid"),
    ("method", "cipher"),
    ("password", "auth"),
    ("plugin_opts", "plugin-opts"),
    ("server_ports", "ports", "mport"),
    ("up_mbps", "up-mbps", "up", "upmbps"),
    ("down_mbps", "down-mbps", "down", "downmbps"),
    ("congestion_control", "congestion-controller"),
    ("udp_relay_mode", "udp-relay-mode"),
    ("zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt"),
)


class NativeMappingError(EngineError):
    """Safe diagnostic with a stable, non-secret reason code."""

    def __init__(self, code: str, fields: tuple[str, ...] = ()):
        self.code = code
        # Only explicit, statically registered names are included. Never
        # include arbitrary URI keys or values in diagnostic fields.
        self.fields = tuple(sorted(set(fields)))
        super().__init__(code)


@dataclass(frozen=True)
class DroppedField:
    name: str
    reason: str


@dataclass(frozen=True)
class NativeConversion:
    outbound: dict[str, Any]
    dropped_fields: tuple[DroppedField, ...]
    # True only when no unclassified source fields were removed. It is NOT
    # proof that both backend implementations behave identically on the wire.
    no_unclassified_loss: bool


def convert_uri_to_native(proxy: Any) -> NativeConversion:
    """Convert a URI proxy without changing identity or production configuration.

    Refuse recognized-but-unimplemented connection fields rather than silently
    dropping them. Unclassified fields are reported without leaking values.
    """
    if not str(getattr(proxy, "original_format", "")).endswith("-uri"):
        raise NativeMappingError("not_uri")
    protocol = str(proxy.protocol).lower()
    if protocol == "hy2":
        protocol = "hysteria2"
    if protocol not in _PROTOCOL_FIELDS:
        raise NativeMappingError("unsupported_protocol")
    params = proxy.params
    if not isinstance(params, dict):
        raise NativeMappingError("invalid_params")
    # URI-level aliases can otherwise be selected arbitrarily by first-match.
    for group in _ALIASES:
        present = [name for name in group if name in params and name in _PROTOCOL_FIELDS[protocol]]
        if len(present) > 1:
            values = [params[name] for name in present]
            if any(type(value) is not type(values[0]) or value != values[0] for value in values[1:]):
                raise NativeMappingError("conflicting_aliases")
    unsupported = sorted(set(params) & _UNSUPPORTED)
    if unsupported:
        raise NativeMappingError("unsupported_connection_field", tuple(unsupported))

    # HY2/TUIC "fingerprint" is a certificate pin, not the uTLS "fp".
    # The shared mapper can silently ignore the pin when both are present.
    if protocol in {"hysteria2", "tuic"} and "fingerprint" in params:
        raise NativeMappingError("unsupported_certificate_fingerprint", ("fingerprint",))

    if protocol == "vless" and "encryption" in params and params["encryption"] != "none":
        raise NativeMappingError("unsupported_vless_encryption")

    if protocol in {"vless", "trojan"} and "security" in params:
        if params["security"] not in {"", "none", "tls", "reality"}:
            raise NativeMappingError("unsupported_tls_security")
    if protocol == "vless" and params.get("security") == "reality":
        if not any(key in params for key in ("fp", "client-fingerprint", "fingerprint")):
            raise NativeMappingError("reality_missing_fingerprint")
        if not any(key in params for key in ("pbk", "public_key", "reality-opts")):
            raise NativeMappingError("reality_missing_public_key")

    # A VMess share JSON "type" denotes TCP header type; unlike VLESS URI
    # "type", it is not an alias for the transport network. Only the neutral
    # explicit value "none" is currently supported.
    if protocol == "vmess" and "type" in params:
        if params["type"] not in ("", "none"):
            raise NativeMappingError("unsupported_vmess_header")
    transport_keys = ("network", "net") if protocol == "vmess" else ("network", "net", "type")
    transport_aliases = [key for key in transport_keys if key in params]
    if len(transport_aliases) > 1 and any(
        params[key] != params[transport_aliases[0]] for key in transport_aliases[1:]
    ):
        raise NativeMappingError("conflicting_transport_aliases")
    # Do not turn an unknown transport into an unintentional TCP outbound.
    if protocol in {"vless", "vmess", "trojan"}:
        selector = next((params[key] for key in transport_keys if key in params), "")
        if selector not in {"", "tcp", "raw", "ws", "websocket", "grpc",
                            "http", "h2", "httpupgrade", "http-upgrade", "xhttp"}:
            raise NativeMappingError("unsupported_transport")
        if "authority" in params:
            raise NativeMappingError("unsupported_authority", ("authority",))
        tcp_fields = ("host", "path", "headers", "serviceName", "service_name")
        if selector in {"", "tcp", "raw"}:
            present_tcp_fields = tuple(key for key in tcp_fields if key in params)
            if present_tcp_fields:
                raise NativeMappingError("transport_fields_on_tcp", present_tcp_fields)
        if selector in {"ws", "websocket", "grpc", "xhttp"} and "headers" in params:
            raise NativeMappingError("unmapped_transport_headers", ("headers",))

    # The mapper currently does not consume security=none for VLESS, but the
    # explicit value is checked above for encryption, not inferred.
    known = _PROTOCOL_FIELDS[protocol]
    unmapped = tuple(sorted(
        key for key in params
        if key not in known and key in _UNMAPPED_CONNECTION_FIELDS
    ))
    if unmapped:
        raise NativeMappingError("unmapped_connection_field", unmapped)
    dropped = tuple(
        DroppedField(str(key), "metadata" if key in _METADATA else "unclassified")
        for key in sorted(params) if key not in known
    )
    mapped = {key: value for key, value in params.items() if key in known}
    if protocol == "vmess":
        # sing-box-extended parser/link/vmess.go enables insecure only for
        # literal "1" or "true"; an empty URI value leaves it false.
        # The native mapper rejects "", so omit it ONLY in the temporary
        # copy. This preserves TLS verification and the original URI.
        if mapped.get("insecure") == "":
            mapped.pop("insecure")
        # Marker "none" is a known explicit neutral VMess header setting.
        # Removing it prevents the shared mapper from interpreting it as a
        # different transport when "net" is absent.
        mapped.pop("type", None)
    if protocol in {"vless", "vmess", "trojan"} and selector == "xhttp":
        if "extra" in mapped:
            encoded = mapped["extra"]
            if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", encoded):
                raise NativeMappingError("invalid_xhttp_extra_encoding")
            try:
                raw = base64.b64decode(
                    encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
                )
                parsed = json.loads(raw.decode("utf-8"))
            except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
                raise NativeMappingError("invalid_xhttp_extra_json") from exc
            if not isinstance(parsed, dict):
                raise NativeMappingError("invalid_xhttp_extra_type")
            mapped["extra"] = parsed
    # Never invoke ensure_id(), alter original_raw, or mutate source params.
    from copy import copy
    temporary = copy(proxy)
    temporary.params = mapped
    outbound = MappedBackend()._render_outbound(temporary)
    # Evidence-based compatibility bridge for sing-box-extended XHTTP:
    # URI parser builds V2RayXHTTPOptions directly, where an absent
    # XPaddingBytes range is normalized to 100..1000 at runtime
    # (option/v2ray_transport.go:GetNormalizedXPaddingBytes).
    # Native JSON goes through UnmarshalJSON, which rejects a zero range.
    # Set that SAME range only when it is absent; never overwrite a
    # supplied xPaddingBytes option, even if the value is invalid.
    transport = outbound.get("transport")
    if (protocol in {"vless", "vmess", "trojan"} and selector == "xhttp"
            and isinstance(transport, dict)
            and transport.get("type") == "xhttp"
            and "x_padding_bytes" not in transport):
        transport["x_padding_bytes"] = "100-1000"
    return NativeConversion(
        outbound=outbound,
        dropped_fields=dropped,
        no_unclassified_loss=not any(item.reason == "unclassified" for item in dropped),
    )
