from __future__ import annotations

"""Compatibility layer for extended sing-box protocol and transport conversion.

The backend must test the same connection semantics that were supplied by the
source profile. Known fields are mapped structurally; source values are not
repaired, replaced with guessed defaults, or silently dropped. Unsupported
connection-relevant fields are rejected explicitly.
"""

import json
import re
from typing import Any

from .engine import EngineError, SingBoxBackend as _BaseSingBoxBackend


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

_MISSING = object()


def _first_present(params: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present alias without skipping explicit empty/null values."""
    for key in keys:
        if key in params:
            return params[key]
    return default


def _has_any(params: dict[str, Any], *keys: str) -> bool:
    return any(key in params for key in keys)


def _strict_bool(value: Any, field: str) -> bool:
    """Convert only unambiguous boolean representations; never guess invalid values."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise EngineError(f"invalid boolean value for {field}: {value!r}")


def _integer_or_original(value: Any) -> Any:
    """Translate an exact integer string to JSON integer; leave invalid input untouched."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value.strip())
    return value


def _list_value_exact(value: Any) -> list[Any]:
    """Translate comma-separated URI syntax to a list without deleting entries."""
    if isinstance(value, list):
        return list(value)
    return [item.strip() for item in str(value).split(",")]


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


def _duration(value: Any, unit: str) -> Any:
    """Perform only the syntax conversion required by the target duration type."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f"{value:g}{unit}"
    if not isinstance(value, str):
        return value
    text = value.strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return f"{text}{unit}"
    return value


def _bandwidth_mbps(value: Any) -> Any:
    """Convert bandwidth units exactly; never round or truncate source values."""
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        amount_mbps = float(value)
    else:
        text = str(value).strip()
        try:
            amount_mbps = float(text)
        except ValueError:
            match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B?bps)", text)
            if not match:
                return value
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
            amount_mbps = amount * factors[unit]

    if not amount_mbps.is_integer():
        raise EngineError(
            f"Hysteria2 bandwidth cannot be represented losslessly as integer Mbps: {value!r}"
        )
    return int(amount_mbps)


def _server_ports(value: Any) -> list[Any]:
    raw_items = value if isinstance(value, list) else str(value).split(",")
    result: list[Any] = []
    for raw in raw_items:
        if not isinstance(raw, str):
            result.append(raw)
            continue
        item = raw.strip()
        if not item:
            result.append(item)
            continue
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", item)
        result.append(f"{match.group(1)}:{match.group(2)}" if match else raw)
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
        # uTLS ClientHello fingerprint. There is no lossless mapping, so reject it.
        if protocol in {"hysteria2", "hy2", "tuic"} and "fingerprint" in p:
            if not _has_any(p, "fp", "client-fingerprint"):
                raise EngineError(
                    f"unsupported {protocol} certificate fingerprint mapping; refusing to reinterpret it as uTLS"
                )

        native_tls = p.get("tls", _MISSING)
        if isinstance(native_tls, dict):
            out["tls"] = dict(native_tls)
            return

        security_value = _first_present(p, "security", default="")
        security = "" if security_value is None else str(security_value).lower()
        native_tls_text = "" if native_tls in (_MISSING, None) else str(native_tls).strip().lower()
        is_reality = security == "reality" or native_tls_text == "reality"
        enabled = default_enabled or security in {"tls", "reality"} or native_tls_text in {"tls", "reality"}

        # VMess/Xray JSON uses string values for this field. Empty string and
        # "none" explicitly mean that TLS is not enabled; they are not malformed
        # boolean values. Other scalar forms still require an unambiguous mapping.
        if native_tls not in (_MISSING, None) and native_tls_text not in {"", "none", "tls", "reality"}:
            enabled = _strict_bool(native_tls, "tls") or enabled
        if not enabled:
            return

        tls: dict[str, Any] = {"enabled": True}

        if _has_any(p, "sni", "server_name", "servername", "server-name"):
            tls["server_name"] = _first_present(p, "sni", "server_name", "servername", "server-name")

        if _has_any(p, "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure"):
            insecure = _first_present(p, "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure")
            tls["insecure"] = _strict_bool(insecure, "insecure")

        if "alpn" in p:
            tls["alpn"] = _list_value_exact(p["alpn"])

        reality_opts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
        is_reality = is_reality or bool(reality_opts)

        if _has_any(p, "fp", "client-fingerprint"):
            fp = _first_present(p, "fp", "client-fingerprint")
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        elif protocol not in {"hysteria2", "hy2", "tuic"} and "fingerprint" in p:
            tls["utls"] = {"enabled": True, "fingerprint": p["fingerprint"]}
        elif is_reality:
            # Reality clients require uTLS. When the source omits `fp`, preserve
            # that omission and enable uTLS without inventing a fingerprint; the
            # core applies its own default fingerprint semantics.
            tls["utls"] = {"enabled": True}

        if is_reality:
            reality: dict[str, Any] = {"enabled": True}
            if _has_any(p, "pbk", "public_key"):
                reality["public_key"] = _first_present(p, "pbk", "public_key")
            elif "public-key" in reality_opts:
                reality["public_key"] = reality_opts["public-key"]

            if _has_any(p, "sid", "short_id"):
                reality["short_id"] = _first_present(p, "sid", "short_id")
            elif "short-id" in reality_opts:
                reality["short_id"] = reality_opts["short-id"]
            tls["reality"] = reality

        if _has_any(p, "disable_sni", "disable-sni"):
            disable_sni = _first_present(p, "disable_sni", "disable-sni")
            tls["disable_sni"] = _strict_bool(disable_sni, "disable_sni")

        out["tls"] = tls

    def _render_outbound(self, proxy):
        out = super()._render_outbound(proxy)
        if proxy.original_format == "sing-box":
            return out

        p = proxy.params
        protocol = proxy.protocol.lower()
        if protocol == "hy2":
            protocol = "hysteria2"

        # Remove values that the generic backend invents when the source did not
        # contain the corresponding parameter. Required fields are then validated
        # by sing-box itself rather than being filled with guessed defaults.
        if protocol == "vless":
            if "uuid" not in p:
                out.pop("uuid", None)
            else:
                out["uuid"] = p["uuid"]
            if "flow" in p:
                out["flow"] = p["flow"]

        elif protocol == "vmess":
            if not _has_any(p, "uuid", "id"):
                out.pop("uuid", None)
            else:
                out["uuid"] = _first_present(p, "uuid", "id")

            if not _has_any(p, "security", "scy", "cipher"):
                out.pop("security", None)
            else:
                out["security"] = _first_present(p, "security", "scy", "cipher")

            if not _has_any(p, "alter_id", "alterId", "aid"):
                out.pop("alter_id", None)
            else:
                out["alter_id"] = _integer_or_original(
                    _first_present(p, "alter_id", "alterId", "aid")
                )

        elif protocol == "trojan":
            if "password" not in p:
                out.pop("password", None)
            else:
                out["password"] = p["password"]

        elif protocol == "ss":
            if not _has_any(p, "method", "cipher"):
                out.pop("method", None)
            else:
                out["method"] = _first_present(p, "method", "cipher")
            if "password" not in p:
                out.pop("password", None)
            else:
                out["password"] = p["password"]

        elif protocol == "hysteria2":
            if not _has_any(p, "password", "auth"):
                out.pop("password", None)
            else:
                out["password"] = _first_present(p, "password", "auth")

        elif protocol == "tuic":
            if "uuid" not in p:
                out.pop("uuid", None)
            else:
                out["uuid"] = p["uuid"]
            if "password" not in p:
                out.pop("password", None)
            else:
                out["password"] = p["password"]

        if protocol in {"vless", "vmess"} and _has_any(p, "packet_encoding", "packet-encoding"):
            out["packet_encoding"] = _first_present(p, "packet_encoding", "packet-encoding")

        if protocol == "vmess":
            if _has_any(p, "global_padding", "global-padding"):
                global_padding = _first_present(p, "global_padding", "global-padding")
                out["global_padding"] = _strict_bool(global_padding, "global_padding")
            if _has_any(p, "authenticated_length", "authenticated-length"):
                authenticated_length = _first_present(p, "authenticated_length", "authenticated-length")
                out["authenticated_length"] = _strict_bool(authenticated_length, "authenticated_length")

        if protocol in {"vless", "vmess", "trojan", "ss"}:
            if "multiplex" in p:
                multiplex = p["multiplex"]
                if not isinstance(multiplex, dict):
                    raise EngineError("multiplex must be an object")
                out["multiplex"] = dict(multiplex)
            if "smux" in p:
                raise EngineError("unsupported Clash smux mapping")

        if protocol == "ss" and "network" in p:
            network = p["network"]
            network_text = str(network).lower()
            if network_text not in {"tcp", "udp"}:
                raise EngineError(f"unsupported Shadowsocks network: {network}")
            out["network"] = network_text
        if protocol == "ss" and _has_any(p, "udp_over_tcp", "udp-over-tcp"):
            out["udp_over_tcp"] = _first_present(p, "udp_over_tcp", "udp-over-tcp")

        if protocol == "hysteria2":
            self._apply_hysteria2_fields(out, p)

        if protocol == "tuic":
            self._apply_tuic_fields(out, p)

        return out

    def _apply_hysteria2_fields(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        if _has_any(p, "server_ports", "ports"):
            ports = _first_present(p, "server_ports", "ports")
            out["server_ports"] = _server_ports(ports)
            out.pop("server_port", None)

        if _has_any(p, "hop_interval", "hop-interval"):
            out["hop_interval"] = _duration(_first_present(p, "hop_interval", "hop-interval"), "s")
        if _has_any(p, "hop_interval_max", "hop-interval-max"):
            out["hop_interval_max"] = _duration(
                _first_present(p, "hop_interval_max", "hop-interval-max"), "s"
            )

        for target, aliases in {
            "up_mbps": ("up_mbps", "up-mbps", "up"),
            "down_mbps": ("down_mbps", "down-mbps", "down"),
        }.items():
            if _has_any(p, *aliases):
                out[target] = _bandwidth_mbps(_first_present(p, *aliases))

        if _has_any(p, "obfs_min_packet_size", "obfs-min-packet-size") or _has_any(
            p, "obfs_max_packet_size", "obfs-max-packet-size"
        ):
            obfs = out.setdefault("obfs", {})
            if not isinstance(obfs, dict):
                raise EngineError("Hysteria2 obfs must be an object")
            if _has_any(p, "obfs_min_packet_size", "obfs-min-packet-size"):
                obfs["min_packet_size"] = _integer_or_original(
                    _first_present(p, "obfs_min_packet_size", "obfs-min-packet-size")
                )
            if _has_any(p, "obfs_max_packet_size", "obfs-max-packet-size"):
                obfs["max_packet_size"] = _integer_or_original(
                    _first_present(p, "obfs_max_packet_size", "obfs-max-packet-size")
                )

        if "network" in p:
            network = p["network"]
            network_text = str(network).lower()
            if network_text not in {"tcp", "udp"}:
                raise EngineError(f"unsupported Hysteria2 network: {network}")
            out["network"] = network_text

        if _has_any(p, "bbr_profile", "bbr-profile"):
            out["bbr_profile"] = _first_present(p, "bbr_profile", "bbr-profile")
        if _has_any(p, "brutal_debug", "brutal-debug"):
            brutal_debug = _first_present(p, "brutal_debug", "brutal-debug")
            out["brutal_debug"] = _strict_bool(brutal_debug, "brutal_debug")
        if _has_any(p, "disable_chrome_parrot", "disable-chrome-parrot"):
            disable_chrome = _first_present(p, "disable_chrome_parrot", "disable-chrome-parrot")
            out["disable_chrome_parrot"] = _strict_bool(disable_chrome, "disable_chrome_parrot")

        if "realm-opts" in p:
            raise EngineError("unsupported Hysteria2 realm-opts mapping")
        if "realm" in p:
            if not isinstance(p["realm"], dict):
                raise EngineError("Hysteria2 realm must be an object")
            out["realm"] = dict(p["realm"])

    def _apply_tuic_fields(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        if "token" in p:
            raise EngineError("unsupported TUIC v4 token authentication")

        if _has_any(p, "udp_over_stream", "udp-over-stream"):
            udp_over_stream = _first_present(p, "udp_over_stream", "udp-over-stream")
            out["udp_over_stream"] = _strict_bool(udp_over_stream, "udp_over_stream")

        if _has_any(p, "zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt"):
            zero_rtt = _first_present(p, "zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt")
            out["zero_rtt_handshake"] = _strict_bool(zero_rtt, "zero_rtt_handshake")

        if "heartbeat" in p:
            out["heartbeat"] = _duration(p["heartbeat"], "s")
        if _has_any(p, "heartbeat-interval", "heartbeat_interval"):
            out["heartbeat"] = _duration(
                _first_present(p, "heartbeat-interval", "heartbeat_interval"), "ms"
            )

        if "network" in p:
            network = p["network"]
            network_text = str(network).lower()
            if network_text not in {"tcp", "udp"}:
                raise EngineError(f"unsupported TUIC network: {network}")
            out["network"] = network_text

    def _render_xhttp_transport(self, p: dict[str, Any]) -> dict[str, Any]:
        # Do not materialize Xray/sing-box defaults. Only fields present in the
        # source profile are mapped into the temporary sing-box outbound.
        transport: dict[str, Any] = {"type": "xhttp"}

        for source_name in ("host", "path", "mode"):
            if source_name in p:
                transport[source_name] = p[source_name]

        if "extra" not in p:
            return transport

        extra = p["extra"]
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except json.JSONDecodeError as exc:
                raise EngineError(f"invalid XHTTP extra JSON: {exc.msg}") from exc
        if not isinstance(extra, dict):
            raise EngineError("XHTTP extra must be a JSON object")

        if "downloadSettings" in extra:
            raise EngineError("unsupported XHTTP extra field: downloadSettings")

        xmux = extra.get("xmux", _MISSING)
        plain_extra = {key: value for key, value in extra.items() if key != "xmux"}
        transport.update(_map_xhttp_object(plain_extra, _XHTTP_EXTRA_FIELDS, "XHTTP extra"))

        if xmux is not _MISSING:
            transport["xmux"] = _map_xhttp_object(xmux, _XHTTP_XMUX_FIELDS, "XHTTP extra.xmux")

        return transport

    def _apply_transport(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        native = p.get("transport")
        if isinstance(native, dict):
            out["transport"] = native
            return

        network_value = _first_present(p, "network", "net", "type", default="")
        network = "" if network_value is None else str(network_value).strip().lower()
        if network == "xhttp":
            out["transport"] = self._render_xhttp_transport(p)
            return

        if network in _UNSUPPORTED_V2RAY_TRANSPORTS:
            raise EngineError(f"unsupported V2Ray transport: {network}")

        if network in {"tcp", ""}:
            header_value = _first_present(p, "headerType", "header_type", default="")
            header_type = "" if header_value is None else str(header_value).lower()
            if header_type not in {"", "none"}:
                raise EngineError(f"unsupported TCP transport header type: {header_type}")

        super()._apply_transport(out, p)
        transport = out.get("transport")
        if not isinstance(transport, dict):
            return

        if transport.get("type") == "ws":
            opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else {}
            if _has_any(p, "max_early_data", "max-early-data"):
                max_early_data = _first_present(p, "max_early_data", "max-early-data")
                transport["max_early_data"] = _integer_or_original(max_early_data)
            elif "max-early-data" in opts:
                transport["max_early_data"] = _integer_or_original(opts["max-early-data"])

            if _has_any(p, "early_data_header_name", "early-data-header-name"):
                transport["early_data_header_name"] = _first_present(
                    p, "early_data_header_name", "early-data-header-name"
                )
            elif "early-data-header-name" in opts:
                transport["early_data_header_name"] = opts["early-data-header-name"]

        elif transport.get("type") == "grpc":
            for target, aliases in {
                "idle_timeout": ("idle_timeout", "idle-timeout"),
                "ping_timeout": ("ping_timeout", "ping-timeout"),
            }.items():
                if _has_any(p, *aliases):
                    transport[target] = _duration(_first_present(p, *aliases), "s")
            if _has_any(p, "permit_without_stream", "permit-without-stream"):
                permit = _first_present(p, "permit_without_stream", "permit-without-stream")
                transport["permit_without_stream"] = _strict_bool(permit, "permit_without_stream")

        elif transport.get("type") == "http":
            if "method" in p:
                transport["method"] = p["method"]
            if "headers" in p:
                if not isinstance(p["headers"], dict):
                    raise EngineError("HTTP transport headers must be an object")
                transport["headers"] = dict(p["headers"])
            for target, aliases in {
                "idle_timeout": ("idle_timeout", "idle-timeout"),
                "ping_timeout": ("ping_timeout", "ping-timeout"),
            }.items():
                if _has_any(p, *aliases):
                    transport[target] = _duration(_first_present(p, *aliases), "s")

        elif transport.get("type") == "httpupgrade":
            if "headers" in p:
                if not isinstance(p["headers"], dict):
                    raise EngineError("HTTPUpgrade transport headers must be an object")
                transport["headers"] = dict(p["headers"])
