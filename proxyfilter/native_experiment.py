from __future__ import annotations

"""Opt-in URI -> native sing-box outbound experiment.

This module is intentionally NOT wired into the production backend selector.
Unknown fields are removed only from a temporary mapping copy, and reported by
name. An outbound with removed fields is never asserted semantically equivalent.
"""
from dataclasses import dataclass
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
# Only alias groups whose values genuinely share one destination are checked.
_ALIASES = (
    ("sni", "server_name", "servername", "server-name"),
    ("fp", "client-fingerprint"),
    ("pbk", "public_key"),
    ("sid", "short_id"),
    ("type", "net", "network"),
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
        raise EngineError("experimental native converter requires a share URI")
    protocol = str(proxy.protocol).lower()
    if protocol == "hy2":
        protocol = "hysteria2"
    if protocol not in _PROTOCOL_FIELDS:
        raise EngineError(f"unsupported native experiment protocol: {protocol}")
    params = proxy.params
    if not isinstance(params, dict):
        raise EngineError("URI params must be an object")
    # URI-level aliases can otherwise be selected arbitrarily by first-match.
    for group in _ALIASES:
        present = [name for name in group if name in params and name in _PROTOCOL_FIELDS[protocol]]
        if len(present) > 1:
            values = [params[name] for name in present]
            if any(type(value) is not type(values[0]) or value != values[0] for value in values[1:]):
                raise EngineError("conflicting URI aliases: " + ", ".join(present))
    unsupported = sorted(set(params) & _UNSUPPORTED)
    if unsupported:
        raise EngineError("unsupported connection-relevant URI field(s): " + ", ".join(unsupported))

    if protocol == "vless" and "encryption" in params and params["encryption"] != "none":
        raise EngineError("unsupported VLESS encryption (expected explicit 'none')")

    if protocol in {"vless", "trojan"} and "security" in params:
        if params["security"] not in {"", "none", "tls", "reality"}:
            raise EngineError("unsupported TLS security selector")
    # Do not turn an unknown transport into an unintentional TCP outbound.
    if protocol in {"vless", "vmess", "trojan"}:
        selector = next((params[key] for key in ("network", "net", "type")
                         if key in params), "")
        if selector not in {"", "tcp", "raw", "ws", "websocket", "grpc",
                            "http", "h2", "httpupgrade", "http-upgrade", "xhttp"}:
            raise EngineError(f"unsupported transport selector: {selector!r}")
        if "authority" in params:
            raise EngineError("unsupported connection-relevant URI field: authority")
        if selector in {"", "tcp", "raw"} and any(
            key in params for key in ("host", "path", "headers", "serviceName", "service_name")
        ):
            raise EngineError("transport-specific fields on TCP cannot be mapped losslessly")
        if selector in {"ws", "websocket", "grpc", "xhttp"} and "headers" in params:
            raise EngineError("unmapped generic headers on selected transport")

    # The mapper currently does not consume security=none for VLESS, but the
    # explicit value is checked above for encryption, not inferred.
    known = _PROTOCOL_FIELDS[protocol]
    dropped = tuple(
        DroppedField(str(key), "metadata" if key in _METADATA else "unclassified")
        for key in sorted(params) if key not in known
    )
    mapped = {key: value for key, value in params.items() if key in known}
    # Never invoke ensure_id(), alter original_raw, or mutate source params.
    from copy import copy
    temporary = copy(proxy)
    temporary.params = mapped
    outbound = MappedBackend()._render_outbound(temporary)
    return NativeConversion(
        outbound=outbound,
        dropped_fields=dropped,
        no_unclassified_loss=not any(item.reason == "unclassified" for item in dropped),
    )
