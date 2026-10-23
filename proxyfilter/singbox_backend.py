from __future__ import annotations

"""Compatibility layer for extended sing-box protocol and transport conversion.

The backend must test the same connection semantics that will later be published.
Known fields are mapped explicitly; unsupported connection-relevant fields are
rejected instead of being silently dropped.
"""

import json
import re
from typing import Any

from .engine import EngineError, SingBoxBackend as _BaseSingBoxBackend
from .engine import _first, _list_value, _truthy


_XHTTP_EXTRA_FIELDS = {
    "mode": "mode",
    "headers": "headers",
    "xPaddingBytes": "x_padding_bytes",
    "noGRPCHeader": "no_grpc_header",
    "noSSEHeader": "no_sse_header",
    "scMaxEachPostBytes": "sc_max_each_post_bytes",
    "scMinPostsIntervalMs": "sc_min_posts_interval_ms",
    "scMaxBufferedPosts": "sc_max_buffered_posts",
    "scStreamUpServerSecs": "sc_stream_up_server_secs",
    "serverMaxHeaderBytes": "server_max_header_bytes",
    "trustedXForwardedFor": "trusted_x_forwarded_for",
    "xPaddingObfsMode": "x_padding_obfs_mode",
    "xPaddingKey": "x_padding_key",
    "xPaddingHeader": "x_padding_header",
    "xPaddingPlacement": "x_padding_placement",
    "xPaddingMethod": "x_padding_method",
    "uplinkHTTPMethod": "uplink_http_method",
    "sessionPlacement": "session_placement",
    "sessionKey": "session_key",
    "sessionIDPlacement": "session_placement",
    "sessionIDKey": "session_key",
    "seqPlacement": "seq_placement",
    "seqKey": "seq_key",
    "uplinkDataPlacement": "uplink_data_placement",
    "uplinkDataKey": "uplink_data_key",
    "uplinkChunkSize": "uplink_chunk_size",
    "sessionIDTable": "session_id_table",
    "sessionIDLength": "session_id_length",
    "congestionController": "congestion_controller",
    "cwnd": "cwnd",
}

# Known legacy Xray setting that is no longer represented by current XHTTP.
# Ignoring it is intentional rather than accidental silent loss.
_XHTTP_IGNORED_LEGACY_FIELDS = {"scMaxConcurrentPosts"}

_XHTTP_XMUX_FIELDS = {
    "maxConcurrency": "max_concurrency",
    "maxConnections": "max_connections",
    "cMaxReuseTimes": "c_max_reuse_times",
    "hMaxRequestTimes": "h_max_request_times",
    "hMaxReusableSecs": "h_max_reusable_secs",
    "hKeepAlivePeriod": "h_keep_alive_period",
}

_UNSUPPORTED_V2RAY_TRANSPORTS = {
    "kcp",
    "mkcp",
    "quic",
    "domainsocket",
    "domain-socket",
    "ds",
    "splithttp",
    "split-http",
}


def _map_xhttp_object(value: Any, field_map: dict[str, str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EngineError(f"{context} must be a JSON object")

    result: dict[str, Any] = {}
    unknown = sorted(str(key) for key in value if key not in field_map)
    if unknown:
        raise EngineError(f"unsupported {context} field(s): {', '.join(unknown)}")

    for source_name, target_name in field_map.items():
        if source_name in value:
            result[target_name] = value[source_name]
    return result


def _duration(value: Any, unit: str) -> str:
    if isinstance(value, (int, float)):
        return f"{value:g}{unit}"
    text = str(value).strip()
    if not text:
        return text
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return f"{text}{unit}"
    return text


def _bandwidth_mbps(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(float(value))
    text = str(value).strip()
    try:
        return int(float(text))
    except ValueError:
        pass

    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B?bps)", text)
    if not match:
        raise EngineError(f"unsupported Hysteria2 bandwidth value: {value!r}")

    amount = float(match.group(1))
    unit = match.group(2)
    factors = {
        "bps": 1 / 1_000_000,
        "Bps": 8 / 1_000_000,
        "Kbps": 1 / 1_000,
        "KBps": 8 / 1_000,
        "Mbps": 1,
        "MBps": 8,
        "Gbps": 1_000,
        "GBps": 8_000,
        "Tbps": 1_000_000,
        "TBps": 8_000_000,
    }
    return int(amount * factors[unit])


def _server_ports(value: Any) -> list[str]:
    raw_items = value if isinstance(value, list) else str(value).split(",")
    result: list[str] = []
    for raw in raw_items:
        item = str(raw).strip()
        if not item:
            continue
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", item)
        result.append(f"{match.group(1)}:{match.group(2)}" if match else item)
    if not result:
        raise EngineError("Hysteria2 ports list is empty")
    return result


class SingBoxBackend(_BaseSingBoxBackend):
    def _apply_tls(
        self,
        out: dict[str, Any],
        p: dict[str, Any],
        protocol: str,
        default_enabled: bool = False,
    ) -> None:
        # In Clash Hysteria2/TUIC, `fingerprint` is certificate pinning, not an
        # uTLS ClientHello fingerprint. Do not reinterpret it as uTLS.
        if protocol in {"hysteria2", "hy2", "tuic"} and p.get("fingerprint") not in (None, ""):
            if p.get("fp") in (None, "") and p.get("client-fingerprint") in (None, ""):
                raise EngineError(
                    f"unsupported {protocol} certificate fingerprint mapping; refusing to treat it as uTLS"
                )

        native_tls = p.get("tls")
        if isinstance(native_tls, dict):
            tls = dict(native_tls)
            tls.setdefault("enabled", True)
            out["tls"] = tls
            return

        security = str(_first(p, "security", default="")).lower()
        native_tls_text = "" if native_tls is None else str(native_tls).strip().lower()
        is_reality = security == "reality" or native_tls_text == "reality"
        enabled = (
            default_enabled
            or security in {"tls", "reality"}
            or native_tls_text in {"tls", "reality"}
            or _truthy(native_tls)
        )
        if not enabled:
            return

        tls: dict[str, Any] = {"enabled": True}
        server_name = _first(p, "sni", "server_name", "servername", "server-name")
        if server_name:
            tls["server_name"] = str(server_name)

        insecure = _first(p, "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure")
        if insecure is not None:
            tls["insecure"] = _truthy(insecure)

        alpn = _list_value(_first(p, "alpn"))
        if alpn:
            tls["alpn"] = alpn

        reality_opts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
        is_reality = is_reality or bool(reality_opts)

        fp = _first(p, "fp", "client-fingerprint", "fingerprint")
        fp_text = "" if fp is None else str(fp).strip()
        fp_lower = fp_text.lower()

        if is_reality:
            if fp_lower == "unsafe":
                tls["utls"] = {"enabled": False}
            else:
                tls["utls"] = {"enabled": True, "fingerprint": fp_text}
        elif fp_text and fp_lower not in {"none", "unsafe"}:
            tls["utls"] = {"enabled": True, "fingerprint": fp_text}

        if is_reality:
            public_key = _first(p, "pbk", "public_key", default=reality_opts.get("public-key"))
            short_id = _first(p, "sid", "short_id", default=reality_opts.get("short-id"))
            reality: dict[str, Any] = {"enabled": True}
            if public_key:
                reality["public_key"] = str(public_key)
            if short_id is not None:
                reality["short_id"] = str(short_id)
            tls["reality"] = reality

        disable_sni = _first(p, "disable_sni", "disable-sni")
        if disable_sni is not None:
            tls["disable_sni"] = _truthy(disable_sni)

        out["tls"] = tls

    def _render_outbound(self, proxy):
        out = super()._render_outbound(proxy)
        if proxy.original_format == "sing-box":
            return out

        p = proxy.params
        protocol = proxy.protocol.lower()
        if protocol == "hy2":
            protocol = "hysteria2"

        if protocol in {"vless", "vmess"}:
            packet_encoding = _first(p, "packet_encoding", "packet-encoding")
            if packet_encoding not in (None, ""):
                out["packet_encoding"] = str(packet_encoding)

        if protocol == "vmess":
            global_padding = _first(p, "global_padding", "global-padding")
            if global_padding is not None:
                out["global_padding"] = _truthy(global_padding)
            authenticated_length = _first(p, "authenticated_length", "authenticated-length")
            if authenticated_length is not None:
                out["authenticated_length"] = _truthy(authenticated_length)

        if protocol in {"vless", "vmess", "trojan", "ss"}:
            multiplex = p.get("multiplex")
            if multiplex is not None:
                if not isinstance(multiplex, dict):
                    raise EngineError("multiplex must be an object")
                out["multiplex"] = dict(multiplex)
            if p.get("smux") is not None:
                raise EngineError("unsupported Clash smux mapping")

        if protocol == "ss":
            network = _first(p, "network")
            if network not in (None, ""):
                network_text = str(network).lower()
                if network_text not in {"tcp", "udp"}:
                    raise EngineError(f"unsupported Shadowsocks network: {network}")
                out["network"] = network_text
            udp_over_tcp = _first(p, "udp_over_tcp", "udp-over-tcp")
            if udp_over_tcp is not None:
                out["udp_over_tcp"] = udp_over_tcp

        if protocol == "hysteria2":
            self._apply_hysteria2_fields(out, p)

        if protocol == "tuic":
            self._apply_tuic_fields(out, p)

        return out

    def _apply_hysteria2_fields(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        ports = _first(p, "server_ports", "ports")
        if ports not in (None, ""):
            out["server_ports"] = _server_ports(ports)
            out.pop("server_port", None)

        hop_interval = _first(p, "hop_interval", "hop-interval")
        if hop_interval not in (None, ""):
            out["hop_interval"] = _duration(hop_interval, "s")
        hop_interval_max = _first(p, "hop_interval_max", "hop-interval-max")
        if hop_interval_max not in (None, ""):
            out["hop_interval_max"] = _duration(hop_interval_max, "s")

        for target, aliases in {
            "up_mbps": ("up_mbps", "up-mbps", "up"),
            "down_mbps": ("down_mbps", "down-mbps", "down"),
        }.items():
            value = _first(p, *aliases)
            if value not in (None, ""):
                out[target] = _bandwidth_mbps(value)

        min_packet = _first(p, "obfs_min_packet_size", "obfs-min-packet-size")
        max_packet = _first(p, "obfs_max_packet_size", "obfs-max-packet-size")
        if min_packet is not None or max_packet is not None:
            obfs = out.setdefault("obfs", {})
            if not isinstance(obfs, dict):
                raise EngineError("Hysteria2 obfs must be an object")
            if min_packet is not None:
                obfs["min_packet_size"] = int(min_packet)
            if max_packet is not None:
                obfs["max_packet_size"] = int(max_packet)

        network = _first(p, "network")
        if network not in (None, ""):
            network_text = str(network).lower()
            if network_text not in {"tcp", "udp"}:
                raise EngineError(f"unsupported Hysteria2 network: {network}")
            out["network"] = network_text

        bbr_profile = _first(p, "bbr_profile", "bbr-profile")
        if bbr_profile not in (None, ""):
            out["bbr_profile"] = str(bbr_profile)
        brutal_debug = _first(p, "brutal_debug", "brutal-debug")
        if brutal_debug is not None:
            out["brutal_debug"] = _truthy(brutal_debug)
        disable_chrome = _first(p, "disable_chrome_parrot", "disable-chrome-parrot")
        if disable_chrome is not None:
            out["disable_chrome_parrot"] = _truthy(disable_chrome)

        if p.get("realm-opts") is not None:
            raise EngineError("unsupported Hysteria2 realm-opts mapping")
        if isinstance(p.get("realm"), dict):
            out["realm"] = dict(p["realm"])

    def _apply_tuic_fields(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        if p.get("token") not in (None, ""):
            raise EngineError("unsupported TUIC v4 token authentication")

        udp_over_stream = _first(p, "udp_over_stream", "udp-over-stream")
        if udp_over_stream is not None:
            out["udp_over_stream"] = _truthy(udp_over_stream)

        zero_rtt = _first(p, "zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt")
        if zero_rtt is not None:
            out["zero_rtt_handshake"] = _truthy(zero_rtt)

        heartbeat = _first(p, "heartbeat")
        if heartbeat not in (None, ""):
            out["heartbeat"] = _duration(heartbeat, "s")
        heartbeat_ms = _first(p, "heartbeat-interval", "heartbeat_interval")
        if heartbeat_ms not in (None, ""):
            out["heartbeat"] = _duration(heartbeat_ms, "ms")

        network = _first(p, "network")
        if network not in (None, ""):
            network_text = str(network).lower()
            if network_text not in {"tcp", "udp"}:
                raise EngineError(f"unsupported TUIC network: {network}")
            out["network"] = network_text

    def _render_xhttp_transport(self, p: dict[str, Any]) -> dict[str, Any]:
        transport: dict[str, Any] = {"type": "xhttp", "x_padding_bytes": "100-1000"}

        for source_name in ("host", "path", "mode"):
            value = p.get(source_name)
            if value not in (None, ""):
                transport[source_name] = str(value)

        extra = p.get("extra")
        if extra in (None, ""):
            return transport
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except json.JSONDecodeError as exc:
                raise EngineError(f"invalid XHTTP extra JSON: {exc.msg}") from exc
        if not isinstance(extra, dict):
            raise EngineError("XHTTP extra must be a JSON object")

        if "downloadSettings" in extra:
            raise EngineError("unsupported XHTTP extra field: downloadSettings")

        xmux = extra.get("xmux")
        plain_extra = {
            key: value
            for key, value in extra.items()
            if key != "xmux" and key not in _XHTTP_IGNORED_LEGACY_FIELDS
        }
        transport.update(_map_xhttp_object(plain_extra, _XHTTP_EXTRA_FIELDS, "XHTTP extra"))

        if xmux is not None:
            transport["xmux"] = _map_xhttp_object(xmux, _XHTTP_XMUX_FIELDS, "XHTTP extra.xmux")

        return transport

    def _apply_transport(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        native = p.get("transport")
        if isinstance(native, dict):
            out["transport"] = native
            return

        network = str(_first(p, "network", "net", "type", default="")).strip().lower()
        if network == "xhttp":
            out["transport"] = self._render_xhttp_transport(p)
            return

        if network in _UNSUPPORTED_V2RAY_TRANSPORTS:
            raise EngineError(f"unsupported V2Ray transport: {network}")

        if network in {"tcp", ""}:
            header_type = str(_first(p, "headerType", "header_type", default="")).lower()
            if header_type not in {"", "none"}:
                raise EngineError(f"unsupported TCP transport header type: {header_type}")

        super()._apply_transport(out, p)
        transport = out.get("transport")
        if not isinstance(transport, dict):
            return

        if transport.get("type") == "ws":
            opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
            max_early_data = _first(
                p,
                "max_early_data",
                "max-early-data",
                default=opts.get("max-early-data"),
            )
            if max_early_data not in (None, ""):
                transport["max_early_data"] = int(max_early_data)
            early_header = _first(
                p,
                "early_data_header_name",
                "early-data-header-name",
                default=opts.get("early-data-header-name"),
            )
            if early_header not in (None, ""):
                transport["early_data_header_name"] = str(early_header)

        elif transport.get("type") == "grpc":
            for target, aliases in {
                "idle_timeout": ("idle_timeout", "idle-timeout"),
                "ping_timeout": ("ping_timeout", "ping-timeout"),
            }.items():
                value = _first(p, *aliases)
                if value not in (None, ""):
                    transport[target] = _duration(value, "s")
            permit = _first(p, "permit_without_stream", "permit-without-stream")
            if permit is not None:
                transport["permit_without_stream"] = _truthy(permit)

        elif transport.get("type") == "http":
            method = _first(p, "method")
            if method not in (None, ""):
                transport["method"] = str(method)
            headers = p.get("headers")
            if headers is not None:
                if not isinstance(headers, dict):
                    raise EngineError("HTTP transport headers must be an object")
                transport["headers"] = dict(headers)
            for target, aliases in {
                "idle_timeout": ("idle_timeout", "idle-timeout"),
                "ping_timeout": ("ping_timeout", "ping-timeout"),
            }.items():
                value = _first(p, *aliases)
                if value not in (None, ""):
                    transport[target] = _duration(value, "s")

        elif transport.get("type") == "httpupgrade":
            headers = p.get("headers")
            if headers is not None:
                if not isinstance(headers, dict):
                    raise EngineError("HTTPUpgrade transport headers must be an object")
                transport["headers"] = dict(headers)
