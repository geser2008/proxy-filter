from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from .ingest import parse_uri
from .model import ProxyConfig, SourceInfo


class RenderError(ValueError):
    pass


@dataclass(slots=True)
class RenderResult:
    ok: bool
    uri: str | None = None
    name: str | None = None
    error: str | None = None


def _host_for_uri(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RenderError(f"{field} must be a non-empty string")
    return value


def _query_items(params: dict[str, Any], excluded: set[str]) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for key in sorted(params):
        if key in excluded:
            continue
        value = params[key]
        if isinstance(value, str):
            items.append((key, value))
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            items.extend((key, item) for item in value)
        else:
            raise RenderError(
                f"query parameter {key!r} cannot be represented losslessly as a URI string"
            )
    return items


def _generic_uri(proxy: ProxyConfig, name: str) -> str:
    protocol = proxy.protocol.lower()
    params = proxy.params

    if protocol == "vless":
        userinfo = quote(_require_text(params.get("uuid"), "vless uuid"), safe="")
        excluded = {"uuid"}
    elif protocol in {"trojan", "hysteria2", "hy2"}:
        userinfo = quote(_require_text(params.get("password"), f"{protocol} password"), safe="")
        excluded = {"password"}
        protocol = "hysteria2" if protocol == "hy2" else protocol
    elif protocol == "tuic":
        uuid = quote(_require_text(params.get("uuid"), "tuic uuid"), safe="")
        password = params.get("password")
        if password is None:
            userinfo = uuid
        else:
            userinfo = f"{uuid}:{quote(_require_text(password, 'tuic password'), safe='')}"
        excluded = {"uuid", "password"}
    else:
        raise RenderError(f"unsupported generic URI protocol: {protocol}")

    query = urlencode(_query_items(params, excluded), doseq=True)
    uri = f"{protocol}://{userinfo}@{_host_for_uri(proxy.server)}:{int(proxy.port)}"
    if query:
        uri += "?" + query
    if name:
        uri += "#" + quote(name, safe="")
    return uri


def _vmess_uri(proxy: ProxyConfig, name: str) -> str:
    data = dict(proxy.params)
    data["add"] = proxy.server
    data["port"] = str(int(proxy.port))
    data["ps"] = name
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = base64.b64encode(payload).decode("ascii").rstrip("=")
    return "vmess://" + token


def _ss_uri(proxy: ProxyConfig, name: str) -> str:
    params = proxy.params
    method = _require_text(params.get("method"), "shadowsocks method")
    password = _require_text(params.get("password"), "shadowsocks password")
    token = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")

    query_params = dict(params)
    query_params.pop("method", None)
    query_params.pop("password", None)
    plugin_opts = query_params.pop("plugin_opts", None)
    plugin = query_params.get("plugin")
    if plugin_opts is not None:
        plugin_name = _require_text(plugin, "shadowsocks plugin")
        if not isinstance(plugin_opts, str):
            raise RenderError("shadowsocks plugin_opts must be a string")
        query_params["plugin"] = f"{plugin_name};{plugin_opts}"

    query = urlencode(_query_items(query_params, set()), doseq=True)
    uri = f"ss://{token}@{_host_for_uri(proxy.server)}:{int(proxy.port)}"
    if query:
        uri += "?" + query
    if name:
        uri += "#" + quote(name, safe="")
    return uri


def render_uri(proxy: ProxyConfig, name: str | None = None) -> str:
    output_name = proxy.name if name is None else name
    protocol = proxy.protocol.lower()
    if protocol == "vmess":
        return _vmess_uri(proxy, output_name)
    if protocol == "ss":
        return _ss_uri(proxy, output_name)
    if protocol in {"vless", "trojan", "hysteria2", "hy2", "tuic"}:
        return _generic_uri(proxy, output_name)
    raise RenderError(f"unsupported protocol for URI output: {proxy.protocol}")


def validate_round_trip(proxy: ProxyConfig, uri: str) -> None:
    reparsed = parse_uri(uri, SourceInfo("render-check", "render-check", "plain"))
    if reparsed.identity_payload() != proxy.identity_payload():
        raise RenderError("rendered URI does not round-trip to the same connection identity")


def format_output_name(
    proxy: ProxyConfig,
    *,
    template: str,
    include_original_name: bool = True,
) -> str:
    geo = proxy.tests.geo or {}
    original_name = proxy.name if include_original_name else ""
    provenance = proxy.provenance_sources()
    source_ids = [source.id for source in provenance if source.id]

    def metric(value: float | None) -> str:
        return "?" if value is None else str(int(round(value)))

    values = {
        "flag": geo.get("flag") or "🌐",
        "country_code": geo.get("country_code") or "??",
        "country": geo.get("country") or "Unknown",
        "source": proxy.source.id,
        "source_name": proxy.source.name,
        "sources": "+".join(source_ids) or proxy.source.id,
        "source_count": len(source_ids),
        "protocol": proxy.protocol,
        "name": original_name,
        "original_name": original_name,
        "latency_ms": metric(proxy.tests.latency_ms),
        "download_mbps": metric(proxy.tests.download_mbps),
        "upload_mbps": metric(proxy.tests.upload_mbps),
        "exit_ip": proxy.tests.exit_ip or "unknown",
        "asn": geo.get("asn") if geo.get("asn") is not None else "?",
        "org": geo.get("org") or "Unknown",
        "isp": geo.get("isp") or "Unknown",
    }
    try:
        return template.format_map(values).strip()
    except KeyError as exc:
        raise RenderError(f"unknown rename_template field: {exc.args[0]}") from exc


def render_proxy(
    proxy: ProxyConfig,
    *,
    rename_template: str,
    include_original_name: bool = True,
) -> RenderResult:
    try:
        name = format_output_name(
            proxy,
            template=rename_template,
            include_original_name=include_original_name,
        )
        uri = render_uri(proxy, name)
        validate_round_trip(proxy, uri)
        return RenderResult(True, uri=uri, name=name)
    except (RenderError, ValueError, TypeError) as exc:
        return RenderResult(False, error=str(exc))
