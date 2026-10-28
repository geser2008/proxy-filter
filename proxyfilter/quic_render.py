from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

from .identity_semantics import canonical_identity_params, canonical_identity_protocol
from .model import ProxyConfig


_HY2_SOURCE_FIELDS = {
    "password", "auth",
    "server_ports", "ports",
    "hop_interval", "hop-interval", "hop_interval_max", "hop-interval-max",
    "up_mbps", "up-mbps", "up", "down_mbps", "down-mbps", "down",
    "obfs", "obfs-password", "obfs_password",
    "obfs_min_packet_size", "obfs-min-packet-size",
    "obfs_max_packet_size", "obfs-max-packet-size",
    "network", "bbr_profile", "bbr-profile",
    "brutal_debug", "brutal-debug",
    "disable_chrome_parrot", "disable-chrome-parrot",
    "realm", "realm-opts",
    "tls", "security", "sni", "server_name", "servername", "server-name",
    "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify", "insecure",
    "alpn", "fp", "client-fingerprint", "fingerprint",
    "udp", "name", "tag", "ps",
}

_TUIC_SOURCE_FIELDS = {
    "uuid", "password", "token",
    "congestion_control", "congestion-controller",
    "udp_relay_mode", "udp-relay-mode",
    "udp_over_stream", "udp-over-stream",
    "zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt",
    "heartbeat", "heartbeat-interval", "heartbeat_interval",
    "network", "disable_sni", "disable-sni",
    "tls", "security", "sni", "server_name", "servername", "server-name",
    "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify", "insecure",
    "alpn", "fp", "client-fingerprint", "fingerprint",
    "udp", "name", "tag", "ps",
}


def _host_for_uri(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_source_fields(protocol: str, params: dict[str, Any]) -> None:
    allowed = _HY2_SOURCE_FIELDS if protocol == "hysteria2" else _TUIC_SOURCE_FIELDS
    unknown = sorted(str(key) for key in params if key not in allowed)
    if unknown:
        raise ValueError(
            f"unsupported source field(s) for {protocol} URI rendering: " + ", ".join(unknown)
        )


def _bool_text(value: Any, field: str) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, dict):
        raise ValueError(f"invalid {field} value cannot be represented losslessly")
    raise ValueError(f"{field} must be boolean")


def _tls_query(tls: Any) -> dict[str, str]:
    if not isinstance(tls, dict):
        raise ValueError("canonical TLS settings must be an object")
    mode = str(tls.get("mode") or "tls")
    if mode != "tls":
        raise ValueError(f"QUIC URI cannot represent TLS mode {mode!r} losslessly")

    query: dict[str, str] = {}
    if "server_name" in tls:
        query["sni"] = str(tls["server_name"])
    if tls.get("insecure") is True:
        query["insecure"] = "1"
    elif isinstance(tls.get("insecure"), dict):
        raise ValueError("invalid insecure value cannot be represented losslessly")

    if "alpn" in tls:
        alpn = tls["alpn"]
        if not isinstance(alpn, list) or not all(isinstance(item, str) for item in alpn):
            raise ValueError("ALPN must be a list of strings")
        query["alpn"] = ",".join(alpn)

    if "utls_fingerprint" in tls:
        query["fp"] = str(tls["utls_fingerprint"])
    if "utls_enabled" in tls:
        raise ValueError("invalid uTLS enabled value cannot be represented losslessly")

    extra = set(tls) - {"mode", "server_name", "insecure", "alpn", "utls_fingerprint", "utls_enabled"}
    if extra:
        raise ValueError("QUIC URI cannot represent TLS field(s): " + ", ".join(sorted(extra)))
    return query


def _scalar_query_value(value: Any, field: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    raise ValueError(f"{field} cannot be represented losslessly as URI text")


def _hysteria2_query(canonical: dict[str, Any]) -> dict[str, str]:
    query: dict[str, str] = {}

    if "server_ports" in canonical:
        ports = canonical["server_ports"]
        if not isinstance(ports, list) or not all(isinstance(item, str) for item in ports):
            raise ValueError("Hysteria2 server_ports must be a list of strings")
        query["ports"] = ",".join(ports)

    for key in ("hop_interval", "hop_interval_max", "up_mbps", "down_mbps", "network", "bbr_profile"):
        if key in canonical:
            query[key] = _scalar_query_value(canonical[key], key)

    for key in ("brutal_debug", "disable_chrome_parrot"):
        if key in canonical:
            query[key] = _bool_text(canonical[key], key)

    obfs = canonical.get("obfs")
    if obfs is not None:
        if not isinstance(obfs, dict):
            raise ValueError("Hysteria2 obfs settings must be an object")
        allowed = {"type", "password", "min_packet_size", "max_packet_size"}
        extra = set(obfs) - allowed
        if extra:
            raise ValueError("Hysteria2 URI cannot represent obfs field(s): " + ", ".join(sorted(extra)))
        if "type" in obfs:
            query["obfs"] = _scalar_query_value(obfs["type"], "obfs.type")
        if "password" in obfs:
            query["obfs-password"] = _scalar_query_value(obfs["password"], "obfs.password")
        if "min_packet_size" in obfs:
            query["obfs-min-packet-size"] = _scalar_query_value(obfs["min_packet_size"], "obfs.min_packet_size")
        if "max_packet_size" in obfs:
            query["obfs-max-packet-size"] = _scalar_query_value(obfs["max_packet_size"], "obfs.max_packet_size")

    if "realm" in canonical:
        query["realm"] = _scalar_query_value(canonical["realm"], "realm")
    if "realm_opts" in canonical:
        query["realm-opts"] = _scalar_query_value(canonical["realm_opts"], "realm_opts")

    if "tls" in canonical:
        query.update(_tls_query(canonical["tls"]))
    if "certificate_fingerprint" in canonical:
        query["fingerprint"] = _scalar_query_value(
            canonical["certificate_fingerprint"], "certificate_fingerprint"
        )
    return query


def _tuic_query(canonical: dict[str, Any]) -> dict[str, str]:
    if "token" in canonical:
        raise ValueError("TUIC token authentication cannot be represented by the supported URI form")

    query: dict[str, str] = {}
    for key in ("congestion_control", "udp_relay_mode", "heartbeat", "network"):
        if key in canonical:
            query[key] = _scalar_query_value(canonical[key], key)

    for key in ("udp_over_stream", "zero_rtt_handshake", "disable_sni"):
        if key in canonical:
            query[key] = _bool_text(canonical[key], key)

    if "tls" in canonical:
        query.update(_tls_query(canonical["tls"]))
    if "certificate_fingerprint" in canonical:
        query["fingerprint"] = _scalar_query_value(
            canonical["certificate_fingerprint"], "certificate_fingerprint"
        )
    return query


def render_quic_uri(proxy: ProxyConfig, name: str) -> str:
    protocol = canonical_identity_protocol(proxy.protocol)
    if protocol not in {"hysteria2", "tuic"}:
        raise ValueError(f"unsupported QUIC URI protocol: {proxy.protocol}")

    _validate_source_fields(protocol, proxy.params)
    canonical = canonical_identity_params(protocol, proxy.params)

    if protocol == "hysteria2":
        password = quote(_text(canonical.get("password"), "hysteria2 password"), safe="")
        userinfo = password
        query = _hysteria2_query(canonical)
        allowed = {
            "password", "server_ports", "hop_interval", "hop_interval_max",
            "up_mbps", "down_mbps", "obfs", "network", "bbr_profile",
            "brutal_debug", "disable_chrome_parrot", "realm", "realm_opts",
            "tls", "certificate_fingerprint",
        }
    else:
        uuid = quote(_text(canonical.get("uuid"), "tuic uuid"), safe="")
        password = canonical.get("password")
        if password is None:
            userinfo = uuid
        else:
            userinfo = f"{uuid}:{quote(_text(password, 'tuic password'), safe='')}"
        query = _tuic_query(canonical)
        allowed = {
            "uuid", "password", "token", "congestion_control", "udp_relay_mode",
            "udp_over_stream", "zero_rtt_handshake", "heartbeat", "network",
            "tls", "disable_sni", "certificate_fingerprint",
        }

    extra = set(canonical) - allowed
    if extra:
        raise ValueError(
            f"{protocol} URI cannot represent canonical field(s): " + ", ".join(sorted(extra))
        )

    uri = f"{protocol}://{userinfo}@{_host_for_uri(proxy.server)}:{int(proxy.port)}"
    if query:
        uri += "?" + urlencode(sorted(query.items()))
    if name:
        uri += "#" + quote(name, safe="")
    return uri
