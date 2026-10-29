from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlencode

from .ingest import parse_uri
from .model import ProxyConfig, SourceInfo


def _host_for_uri(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _normalized_query(params: dict[str, Any]) -> str:
    items: list[tuple[str, str]] = []
    for key in sorted(params):
        value = params[key]
        if not isinstance(value, str):
            raise ValueError(f"URI query parameter {key!r} is not a string")
        items.append((key, value))
    return urlencode(items)


def _normalize_generic_uri(proxy: ProxyConfig) -> str:
    protocol = proxy.protocol.lower()
    params = dict(proxy.params)
    if protocol in {"vless", "tuic"}:
        username = str(params.pop("uuid", ""))
    else:
        username = str(params.pop("password", ""))

    userinfo = quote(username, safe="")
    if protocol == "tuic":
        password = str(params.pop("password", ""))
        userinfo += ":" + quote(password, safe="")

    uri = f"{protocol}://{userinfo}@{_host_for_uri(proxy.server.lower())}:{int(proxy.port)}"
    query = _normalized_query(params)
    if query:
        uri += "?" + query
    if proxy.name:
        uri += "#" + quote(proxy.name, safe="")
    return uri


def _normalize_vmess_uri(proxy: ProxyConfig) -> str:
    data = dict(proxy.params)
    data["add"] = proxy.server.lower()
    data["port"] = str(int(proxy.port))
    data["ps"] = proxy.name
    payload = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "vmess://" + base64.b64encode(payload).decode("ascii").rstrip("=")


def _normalize_ss_uri(proxy: ProxyConfig) -> str:
    params = dict(proxy.params)
    method = str(params.pop("method"))
    password = str(params.pop("password"))
    plugin_opts = params.pop("plugin_opts", None)
    plugin = params.get("plugin")
    if plugin_opts is not None:
        if plugin is None:
            params["plugin_opts"] = str(plugin_opts)
        else:
            params["plugin"] = f"{plugin};{plugin_opts}"

    token = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")
    uri = f"ss://{token}@{_host_for_uri(proxy.server.lower())}:{int(proxy.port)}"
    query = _normalized_query(params)
    if query:
        uri += "?" + query
    if proxy.name:
        uri += "#" + quote(proxy.name, safe="")
    return uri


def normalize_uri(uri: str, source: SourceInfo | None = None) -> str:
    """Return a deterministic URI without interpreting opaque source fields.

    Parsing applies the project's documented URI equivalences (currently Xray
    RAW to TCP for VLESS and legacy VMess). Unknown and empty parameters are
    retained. This normalizer is intentionally independent of the publication
    renderer and backend capability checks.
    """
    proxy = parse_uri(uri, source or SourceInfo("normalize", "normalize", "plain"))
    protocol = proxy.protocol.lower()
    if protocol == "vmess":
        return _normalize_vmess_uri(proxy)
    if protocol == "ss":
        return _normalize_ss_uri(proxy)
    return _normalize_generic_uri(proxy)
