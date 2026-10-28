from __future__ import annotations

import json
from typing import Any

from .model import ProxyConfig, SourceInfo


SUPPORTED_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}


def is_v2ray_config(obj: object) -> bool:
    if not isinstance(obj, dict) or not isinstance(obj.get("outbounds"), list):
        return False
    return any(
        isinstance(item, dict) and "protocol" in item
        for item in obj["outbounds"]
    )


def _stream_params(stream: object, protocol: str) -> dict[str, Any]:
    if stream is None:
        return {}
    if not isinstance(stream, dict):
        raise ValueError("streamSettings must be an object")

    params: dict[str, Any] = {}
    network = str(stream.get("network") or "tcp").lower()
    security = str(stream.get("security") or "none").lower()

    if network:
        params["network"] = network

    if security not in {"", "none", "tls", "reality"}:
        raise ValueError(f"unsupported streamSettings.security: {security}")

    # VMess already uses `security` for its cipher. Keep transport security in
    # `tls` so the two independent V2Ray concepts cannot overwrite each other.
    if security in {"tls", "reality"}:
        if protocol == "vmess":
            params["tls"] = security
        else:
            params["security"] = security

    tls = stream.get("tlsSettings")
    if tls is not None:
        if not isinstance(tls, dict):
            raise ValueError("tlsSettings must be an object")
        if "serverName" in tls:
            params["sni"] = tls["serverName"]
        if "allowInsecure" in tls:
            params["allowInsecure"] = tls["allowInsecure"]
        if "alpn" in tls:
            params["alpn"] = tls["alpn"]
        if "fingerprint" in tls:
            params["fp"] = tls["fingerprint"]

    reality = stream.get("realitySettings")
    if reality is not None:
        if not isinstance(reality, dict):
            raise ValueError("realitySettings must be an object")
        if reality.get("spiderX") not in {None, ""}:
            raise ValueError("unsupported realitySettings.spiderX mapping")
        if "serverName" in reality:
            params["sni"] = reality["serverName"]
        if "publicKey" in reality:
            params["pbk"] = reality["publicKey"]
        if "shortId" in reality:
            params["sid"] = reality["shortId"]
        if "fingerprint" in reality:
            params["fp"] = reality["fingerprint"]

    if network in {"ws", "websocket"}:
        ws = stream.get("wsSettings") or {}
        if not isinstance(ws, dict):
            raise ValueError("wsSettings must be an object")
        if "path" in ws:
            params["path"] = ws["path"]
        headers = ws.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                raise ValueError("wsSettings.headers must be an object")
            params["ws-opts"] = {"headers": dict(headers)}
        if "maxEarlyData" in ws:
            params["max_early_data"] = ws["maxEarlyData"]
        if "earlyDataHeaderName" in ws:
            params["early_data_header_name"] = ws["earlyDataHeaderName"]

    elif network == "grpc":
        grpc = stream.get("grpcSettings") or {}
        if not isinstance(grpc, dict):
            raise ValueError("grpcSettings must be an object")
        if "serviceName" in grpc:
            params["serviceName"] = grpc["serviceName"]

    elif network in {"http", "h2"}:
        http = stream.get("httpSettings") or stream.get("http2Settings") or {}
        if not isinstance(http, dict):
            raise ValueError("httpSettings must be an object")
        if "path" in http:
            params["path"] = http["path"]
        if "host" in http:
            params["host"] = http["host"]

    elif network == "xhttp":
        xhttp = stream.get("xhttpSettings") or {}
        if not isinstance(xhttp, dict):
            raise ValueError("xhttpSettings must be an object")
        for key in ("host", "path", "mode", "extra"):
            if key in xhttp:
                params[key] = xhttp[key]

    elif network == "tcp":
        tcp = stream.get("tcpSettings") or {}
        if not isinstance(tcp, dict):
            raise ValueError("tcpSettings must be an object")
        header = tcp.get("header")
        if header is not None:
            if not isinstance(header, dict):
                raise ValueError("tcpSettings.header must be an object")
            if "type" in header:
                params["headerType"] = header["type"]

    return params


def _make_proxy(
    source: SourceInfo,
    protocol: str,
    server: object,
    port: object,
    name: str,
    params: dict[str, Any],
    raw: dict[str, Any],
) -> ProxyConfig:
    if not server or port is None:
        raise ValueError("missing server or port")
    proxy = ProxyConfig(
        source,
        protocol,
        str(server),
        int(port),
        name,
        params,
        "v2ray-json",
        json.dumps(raw, ensure_ascii=False, separators=(",", ":")),
    )
    proxy.ensure_id()
    return proxy


def _parse_vnext_outbound(
    item: dict[str, Any], source: SourceInfo, protocol: str, stream_params: dict[str, Any]
) -> list[ProxyConfig]:
    settings = item.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("settings must be an object")
    vnext = settings.get("vnext") or []
    if not isinstance(vnext, list):
        raise ValueError("settings.vnext must be an array")

    result: list[ProxyConfig] = []
    tag = str(item.get("tag") or "")
    for server_entry in vnext:
        if not isinstance(server_entry, dict):
            raise ValueError("settings.vnext entry must be an object")
        users = server_entry.get("users") or []
        if not isinstance(users, list) or not users:
            raise ValueError("settings.vnext.users must be a non-empty array")
        for user in users:
            if not isinstance(user, dict):
                raise ValueError("settings.vnext.users entry must be an object")
            params = dict(stream_params)
            user_id = user.get("id")
            if not user_id:
                raise ValueError(f"{protocol} user is missing id")
            params["uuid"] = user_id
            if "flow" in user:
                params["flow"] = user["flow"]
            if protocol == "vmess":
                if "security" in user:
                    params["security"] = user["security"]
                if "alterId" in user:
                    params["alterId"] = user["alterId"]
            elif user.get("encryption") not in {None, "", "none"}:
                raise ValueError(f"unsupported VLESS encryption: {user.get('encryption')}")
            result.append(
                _make_proxy(
                    source,
                    protocol,
                    server_entry.get("address"),
                    server_entry.get("port"),
                    str(user.get("email") or tag),
                    params,
                    item,
                )
            )
    return result


def _parse_server_outbound(
    item: dict[str, Any], source: SourceInfo, protocol: str, stream_params: dict[str, Any]
) -> list[ProxyConfig]:
    settings = item.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("settings must be an object")
    servers = settings.get("servers") or []
    if not isinstance(servers, list):
        raise ValueError("settings.servers must be an array")

    result: list[ProxyConfig] = []
    tag = str(item.get("tag") or "")
    for server_entry in servers:
        if not isinstance(server_entry, dict):
            raise ValueError("settings.servers entry must be an object")
        params = dict(stream_params)
        if protocol == "trojan":
            if not server_entry.get("password"):
                raise ValueError("trojan server is missing password")
            params["password"] = server_entry["password"]
            if "flow" in server_entry:
                params["flow"] = server_entry["flow"]
        else:
            method = server_entry.get("method")
            password = server_entry.get("password")
            if not method or not password:
                raise ValueError("shadowsocks server is missing method/password")
            params["method"] = method
            params["password"] = password
        result.append(
            _make_proxy(
                source,
                protocol,
                server_entry.get("address"),
                server_entry.get("port"),
                str(server_entry.get("email") or tag),
                params,
                item,
            )
        )
    return result


def parse_v2ray_config(
    obj: dict[str, Any], source_id: str, source_name: str
) -> tuple[list[ProxyConfig], list[dict[str, Any]]]:
    source = SourceInfo(source_id, source_name, "v2ray-json")
    proxies: list[ProxyConfig] = []
    errors: list[dict[str, Any]] = []

    for index, item in enumerate(obj.get("outbounds") or []):
        if not isinstance(item, dict):
            errors.append({"outbound": index, "reason": "invalid_outbound", "detail": "outbound must be an object"})
            continue
        raw_protocol = str(item.get("protocol") or "").lower()
        if raw_protocol not in SUPPORTED_PROTOCOLS:
            continue
        protocol = "ss" if raw_protocol == "shadowsocks" else raw_protocol
        try:
            stream_params = _stream_params(item.get("streamSettings"), protocol)
            if protocol in {"vless", "vmess"}:
                proxies.extend(_parse_vnext_outbound(item, source, protocol, stream_params))
            else:
                proxies.extend(_parse_server_outbound(item, source, protocol, stream_params))
        except (TypeError, ValueError) as exc:
            errors.append(
                {
                    "outbound": index,
                    "tag": item.get("tag"),
                    "protocol": raw_protocol,
                    "reason": type(exc).__name__,
                    "detail": str(exc),
                }
            )

    return proxies, errors
