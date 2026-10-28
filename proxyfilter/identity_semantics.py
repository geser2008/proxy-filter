from __future__ import annotations

from decimal import Decimal, InvalidOperation
import re
from typing import Any

from .semantics import (
    MISSING,
    _canonical_bool,
    _canonical_tls,
    _canonical_value,
    canonical_identity_params as _base_identity_params,
    first_present,
)


def canonical_identity_protocol(protocol: str) -> str:
    normalized = protocol.strip().lower()
    if normalized == "hy2":
        return "hysteria2"
    if normalized == "shadowsocks":
        return "ss"
    return normalized


def _duration_ms(value: Any, default_unit: str) -> Any:
    if isinstance(value, bool):
        return _canonical_value(value)
    if isinstance(value, (int, float)):
        amount = Decimal(str(value))
        unit = default_unit
    else:
        text = str(value).strip().lower()
        match = re.fullmatch(r"([+-]?\d+(?:\.\d+)?)\s*(ms|s)?", text)
        if not match:
            return _canonical_value(value)
        amount = Decimal(match.group(1))
        unit = match.group(2) or default_unit
    if unit == "s":
        amount *= Decimal(1000)
    normalized = amount.normalize()
    return format(normalized, "f") + "ms"


def _bandwidth_mbps(value: Any) -> Any:
    if isinstance(value, bool):
        return _canonical_value(value)
    if isinstance(value, (int, float)):
        amount = Decimal(str(value))
    else:
        text = str(value).strip()
        try:
            amount = Decimal(text)
        except InvalidOperation:
            match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?B?bps)", text)
            if not match:
                return _canonical_value(value)
            amount = Decimal(match.group(1))
            unit = match.group(2)
            factors = {
                "bps": Decimal(1) / Decimal(1_000_000),
                "Bps": Decimal(8) / Decimal(1_000_000),
                "Kbps": Decimal(1) / Decimal(1_000),
                "KBps": Decimal(8) / Decimal(1_000),
                "Mbps": Decimal(1),
                "MBps": Decimal(8),
                "Gbps": Decimal(1000),
                "GBps": Decimal(8000),
                "Tbps": Decimal(1_000_000),
                "TBps": Decimal(8_000_000),
            }
            amount *= factors[unit]
    return format(amount.normalize(), "f")


def _server_ports(value: Any) -> list[str]:
    items = value if isinstance(value, list) else str(value).split(",")
    result: list[str] = []
    for raw in items:
        text = str(raw).strip()
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", text)
        if match:
            text = f"{match.group(1)}:{match.group(2)}"
        result.append(text)
    return result


def _tls_without_certificate_pin(params: dict[str, Any]) -> dict[str, Any] | None:
    tls_params = dict(params)
    tls_params.pop("fingerprint", None)
    return _canonical_tls(tls_params, default_enabled=True)


def _canonical_hysteria2(params: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    password = first_present(params, "password", "auth", default=MISSING)
    if password is not MISSING:
        result["password"] = password

    ports = first_present(params, "server_ports", "ports", default=MISSING)
    if ports is not MISSING:
        result["server_ports"] = _server_ports(ports)

    for target, aliases in {
        "hop_interval": ("hop_interval", "hop-interval"),
        "hop_interval_max": ("hop_interval_max", "hop-interval-max"),
    }.items():
        value = first_present(params, *aliases, default=MISSING)
        if value is not MISSING:
            result[target] = _duration_ms(value, "s")

    for target, aliases in {
        "up_mbps": ("up_mbps", "up-mbps", "up"),
        "down_mbps": ("down_mbps", "down-mbps", "down"),
    }.items():
        value = first_present(params, *aliases, default=MISSING)
        if value is not MISSING:
            result[target] = _bandwidth_mbps(value)

    obfs_value = params.get("obfs", MISSING)
    obfs: dict[str, Any] = {}
    if isinstance(obfs_value, dict):
        obfs.update(_canonical_value(obfs_value))
    elif obfs_value is not MISSING:
        obfs["type"] = obfs_value
        password_value = first_present(params, "obfs-password", "obfs_password", default=MISSING)
        if password_value is not MISSING:
            obfs["password"] = password_value
    for target, aliases in {
        "min_packet_size": ("obfs_min_packet_size", "obfs-min-packet-size"),
        "max_packet_size": ("obfs_max_packet_size", "obfs-max-packet-size"),
    }.items():
        value = first_present(params, *aliases, default=MISSING)
        if value is not MISSING:
            obfs[target] = value
    if obfs:
        result["obfs"] = obfs

    if "network" in params:
        result["network"] = str(params["network"]).strip().lower()

    bbr = first_present(params, "bbr_profile", "bbr-profile", default=MISSING)
    if bbr is not MISSING:
        result["bbr_profile"] = bbr

    for target, aliases in {
        "brutal_debug": ("brutal_debug", "brutal-debug"),
        "disable_chrome_parrot": ("disable_chrome_parrot", "disable-chrome-parrot"),
    }.items():
        value = first_present(params, *aliases, default=MISSING)
        if value is not MISSING:
            result[target] = _canonical_bool(value, target)

    if "realm" in params:
        result["realm"] = _canonical_value(params["realm"])
    if "realm-opts" in params:
        result["realm_opts"] = _canonical_value(params["realm-opts"])

    tls = _tls_without_certificate_pin(params)
    if tls is not None:
        result["tls"] = tls

    if "fingerprint" in params:
        result["certificate_fingerprint"] = params["fingerprint"]

    return result


def _canonical_tuic(params: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key in ("uuid", "password", "token"):
        if key in params:
            result[key] = params[key]

    congestion = first_present(params, "congestion_control", "congestion-controller", default=MISSING)
    if congestion is not MISSING:
        result["congestion_control"] = congestion

    relay = first_present(params, "udp_relay_mode", "udp-relay-mode", default=MISSING)
    if relay is not MISSING:
        result["udp_relay_mode"] = relay

    udp_stream = first_present(params, "udp_over_stream", "udp-over-stream", default=MISSING)
    if udp_stream is not MISSING:
        result["udp_over_stream"] = _canonical_bool(udp_stream, "udp_over_stream")

    zero_rtt = first_present(
        params,
        "zero_rtt_handshake",
        "zero-rtt-handshake",
        "reduce-rtt",
        default=MISSING,
    )
    if zero_rtt is not MISSING:
        result["zero_rtt_handshake"] = _canonical_bool(zero_rtt, "zero_rtt_handshake")

    if "heartbeat" in params:
        result["heartbeat"] = _duration_ms(params["heartbeat"], "s")
    else:
        heartbeat = first_present(params, "heartbeat-interval", "heartbeat_interval", default=MISSING)
        if heartbeat is not MISSING:
            result["heartbeat"] = _duration_ms(heartbeat, "ms")

    if "network" in params:
        result["network"] = str(params["network"]).strip().lower()

    tls = _tls_without_certificate_pin(params)
    if tls is not None:
        result["tls"] = tls

    disable_sni = first_present(params, "disable_sni", "disable-sni", default=MISSING)
    if disable_sni is not MISSING:
        result["disable_sni"] = _canonical_bool(disable_sni, "disable_sni")

    if "fingerprint" in params:
        result["certificate_fingerprint"] = params["fingerprint"]

    return result


def canonical_identity_params(protocol: str, params: dict[str, Any]) -> dict[str, Any]:
    normalized = canonical_identity_protocol(protocol)
    if normalized == "hysteria2":
        return _canonical_hysteria2(params)
    if normalized == "tuic":
        return _canonical_tuic(params)
    return _base_identity_params(normalized, params)
