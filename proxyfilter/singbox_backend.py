from __future__ import annotations

"""Public sing-box backend with conservative guards for production URI inputs.

The conversion implementation lives in ``singbox_backend_impl``.  URI inputs
are checked here first so an unrecognised source parameter can never disappear
silently while a different sing-box configuration is tested.
"""

from typing import Any

from .engine import EngineError
from .singbox_backend_impl import SingBoxBackend as _MappedSingBoxBackend


_TLS_URI_PARAMS = {
    "tls", "security",
    "sni", "server_name", "servername", "server-name",
    "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure",
    "alpn", "cs", "cipher_suites", "cipher-suites",
    "fp", "client-fingerprint", "fingerprint",
    "reality-opts", "pbk", "public_key", "sid", "short_id",
    "disable_sni", "disable-sni",
    # Explicitly rejected by the mapper with a more specific error.
    "pcs", "pinnedPeerCertSha256", "peer_certificate_sha256",
    "ech", "echConfigList", "spx", "spider_x",
}

_V2RAY_URI_PARAMS = {
    "transport", "network", "net", "type",
    "ws-opts", "grpc-opts",
    "host", "path", "serviceName", "service_name",
    "headerType", "header_type",
    "ed", "max_early_data", "max-early-data",
    "eh", "early_data_header_name", "early-data-header-name",
    "idle_timeout", "idle-timeout", "ping_timeout", "ping-timeout",
    "permit_without_stream", "permit-without-stream",
    "method", "headers", "mode", "extra",
}

_URI_PARAMS_BY_PROTOCOL = {
    "vless": _TLS_URI_PARAMS | _V2RAY_URI_PARAMS | {
        "uuid", "flow", "encryption",
        "packet_encoding", "packet-encoding", "packetEncoding",
        "multiplex", "smux",
        "fm", "final_mask",
    },
    "vmess": _TLS_URI_PARAMS | _V2RAY_URI_PARAMS | {
        "v", "uuid", "id", "scy", "cipher",
        "alter_id", "alterId", "aid",
        "packet_encoding", "packet-encoding", "packetEncoding",
        "global_padding", "global-padding",
        "authenticated_length", "authenticated-length",
        "multiplex", "smux",
        "fm", "final_mask",
    },
    "trojan": _TLS_URI_PARAMS | _V2RAY_URI_PARAMS | {
        "password", "multiplex", "smux", "fm", "final_mask",
    },
    "ss": {
        "method", "cipher", "password", "plugin", "plugin_opts", "plugin-opts",
        "network", "udp_over_tcp", "udp-over-tcp", "multiplex", "smux",
        "fm", "final_mask",
    },
    "hysteria2": _TLS_URI_PARAMS | {
        "password", "auth",
        "server_ports", "ports", "mport",
        "hop_interval", "hop-interval", "hop_interval_max", "hop-interval-max",
        "up_mbps", "up-mbps", "up", "upmbps",
        "down_mbps", "down-mbps", "down", "downmbps",
        "obfs", "obfs-password", "obfs_password",
        "obfs_min_packet_size", "obfs-min-packet-size",
        "obfs_max_packet_size", "obfs-max-packet-size",
        "network", "bbr_profile", "bbr-profile",
        "brutal_debug", "brutal-debug",
        "disable_chrome_parrot", "disable-chrome-parrot",
        "realm", "realm-opts", "fastopen",
        "pinSHA256", "pin_sha256",
        "fm", "final_mask",
    },
    "tuic": _TLS_URI_PARAMS | {
        "uuid", "password", "token",
        "congestion_control", "congestion-controller",
        "udp_relay_mode", "udp-relay-mode",
        "udp_over_stream", "udp-over-stream",
        "zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt",
        "heartbeat", "heartbeat-interval", "heartbeat_interval",
        "network", "fm", "final_mask",
    },
}


def _canonical_protocol(protocol: str) -> str:
    value = protocol.strip().lower()
    return "hysteria2" if value == "hy2" else value


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


class SingBoxBackend(_MappedSingBoxBackend):
    def _guard_uri_params(self, proxy) -> None:
        if not proxy.original_format.endswith("-uri"):
            return

        protocol = _canonical_protocol(proxy.protocol)
        allowed = _URI_PARAMS_BY_PROTOCOL.get(protocol)
        if allowed is None:
            raise EngineError(f"unsupported URI protocol for sing-box backend: {proxy.protocol}")

        unknown = sorted(str(key) for key in proxy.params if key not in allowed)
        if unknown:
            noun = "parameter" if len(unknown) == 1 else "parameters"
            raise EngineError(
                f"unsupported {protocol} URI {noun}: {', '.join(unknown)}; refusing to drop source semantics"
            )

        if protocol == "vless" and "encryption" in proxy.params:
            encryption = _text(proxy.params["encryption"])
            if encryption not in {"", "none"}:
                raise EngineError(f"unsupported VLESS encryption: {proxy.params['encryption']!r}")

        if protocol == "vmess" and "v" in proxy.params:
            version = _text(proxy.params["v"])
            if version not in {"", "2"}:
                raise EngineError(f"unsupported VMess URI version: {proxy.params['v']!r}")

        if protocol in {"vless", "vmess", "trojan"}:
            header_key = "headerType" if "headerType" in proxy.params else "header_type"
            if header_key in proxy.params:
                header_type = _text(proxy.params[header_key])
                if header_type not in {"", "none"}:
                    raise EngineError(f"unsupported TCP transport header type: {header_type}")

    def _render_outbound(self, proxy):
        self._guard_uri_params(proxy)
        return super()._render_outbound(proxy)
