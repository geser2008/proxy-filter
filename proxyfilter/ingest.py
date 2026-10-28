from __future__ import annotations

import base64
import binascii
import json
import re
from urllib.parse import urlsplit, parse_qs, unquote

import yaml

from .model import ProxyConfig, SourceInfo
from .v2ray_ingest import is_v2ray_config, parse_v2ray_config

SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"}
URI_RE = re.compile(r"^(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://", re.I)
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _contains_proxy_uri(text: str) -> bool:
    """Return True when at least one non-empty line starts with a supported URI.

    Subscription containers often prepend metadata comments before proxy lines, so
    checking only the beginning of the whole decoded document is incorrect.
    """
    return any(URI_RE.match(line.strip()) for line in text.splitlines())


def _is_uri_subscription_format(fmt: str) -> bool:
    """Return True only for plain URI lists, optionally wrapped in Base64 layers."""
    parts = fmt.split("/")
    return bool(parts) and parts[-1] == "plain" and all(part == "base64" for part in parts[:-1])


def detect_and_parse(raw: bytes | str, source_id: str, source_name: str) -> tuple[list[ProxyConfig], list[dict], str]:
    """Production ingest entry point.

    The current service version is intentionally URI-only. Plain URI lists and
    Base64-wrapped URI lists are accepted. Structured Clash/Mihomo, Xray/V2Ray,
    and sing-box inputs remain implemented through ``detect_and_parse_compat``
    for tests and the future multi-format refactor, but are disabled here.
    """
    proxies, errors, detected_format = detect_and_parse_compat(raw, source_id, source_name)
    if detected_format == "unknown" or _is_uri_subscription_format(detected_format):
        return proxies, errors, detected_format
    return [], [
        {
            "reason": "unsupported_input_format_uri_only",
            "format": detected_format,
        }
    ], detected_format


def detect_and_parse_compat(raw: bytes | str, source_id: str, source_name: str) -> tuple[list[ProxyConfig], list[dict], str]:
    """Parse all currently implemented subscription formats.

    This compatibility API is retained for tests and future multi-format work.
    Production ingest should call ``detect_and_parse`` instead.
    """
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    text = text.lstrip("\ufeff").strip()

    try:
        obj = json.loads(text)
        if is_v2ray_config(obj):
            proxies, errors = parse_v2ray_config(obj, source_id, source_name)
            return proxies, errors, "v2ray-json"
        if isinstance(obj, dict) and isinstance(obj.get("outbounds"), list):
            return _parse_singbox(obj, source_id, source_name), [], "sing-box"
    except json.JSONDecodeError:
        pass

    try:
        obj = yaml.safe_load(text)
        if isinstance(obj, dict) and isinstance(obj.get("proxies"), list):
            return _parse_clash(obj, source_id, source_name), [], "clash"
    except yaml.YAMLError:
        pass

    if _contains_proxy_uri(text):
        proxies, errors = _parse_plain(text, source_id, source_name, "plain")
        return proxies, errors, "plain"

    decoded = _try_base64_text(text)
    if decoded is not None:
        proxies, errors, nested = detect_and_parse_compat(decoded, source_id, source_name)
        for proxy in proxies:
            proxy.source.format = f"base64/{nested}"
        return proxies, errors, f"base64/{nested}"

    return [], [{"reason": "unsupported_subscription_format"}], "unknown"


def _try_base64_text(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 16 or re.search(r"[^A-Za-z0-9+/=_-]", compact):
        return None
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    for altchars in (None, b"-_"):
        try:
            blob = base64.b64decode(padded, altchars=altchars, validate=False)
            decoded = blob.decode("utf-8")
            if _contains_proxy_uri(decoded) or "proxies:" in decoded or '"outbounds"' in decoded:
                return decoded
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return None


def _parse_plain(text: str, source_id: str, source_name: str, fmt: str) -> tuple[list[ProxyConfig], list[dict]]:
    proxies: list[ProxyConfig] = []
    errors: list[dict] = []
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not URI_RE.match(line):
            continue
        try:
            proxies.append(parse_uri(line, SourceInfo(source_id, source_name, fmt)))
        except Exception as exc:
            errors.append({"line": lineno, "reason": type(exc).__name__, "detail": str(exc), "raw": line})
    return proxies, errors


def _validate_percent_escapes(uri: str) -> None:
    """Reject malformed percent escapes instead of letting tolerant parsers guess.

    URI percent-encoding is syntactic: every literal percent sign must be followed
    by exactly two hexadecimal digits.  This check is protocol-independent and
    intentionally does not repair malformed input (for example ``%`` -> ``%25``).
    """
    match = _INVALID_PERCENT_ESCAPE_RE.search(uri)
    if match:
        raise ValueError(f"invalid URI percent escape at offset {match.start()}")


def parse_uri(uri: str, source: SourceInfo) -> ProxyConfig:
    scheme = uri.split(":", 1)[0].lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ValueError(f"unsupported protocol: {scheme}")
    _validate_percent_escapes(uri)
    if scheme == "vmess":
        return _parse_vmess_uri(uri, source)
    if scheme == "ss":
        return _parse_ss_uri(uri, source)

    parts = urlsplit(uri)
    if not parts.hostname or parts.port is None:
        raise ValueError("missing server or port")
    params = {k: v[-1] if len(v) == 1 else v for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    if parts.username:
        key = "uuid" if scheme in {"vless", "tuic"} else "password"
        params[key] = unquote(parts.username)
    if parts.password:
        params["password"] = unquote(parts.password)
    name = unquote(parts.fragment or "")
    proxy = ProxyConfig(source, scheme, parts.hostname, parts.port, name, params, f"{scheme}-uri", uri)
    proxy.ensure_id()
    return proxy


def _parse_vmess_uri(uri: str, source: SourceInfo) -> ProxyConfig:
    payload = uri[len("vmess://"):].split("#", 1)[0].strip()
    padded = payload + "=" * ((4 - len(payload) % 4) % 4)
    data = json.loads(base64.b64decode(padded).decode("utf-8"))
    server = data.get("add")
    port = int(data.get("port"))
    if not server or not port:
        raise ValueError("vmess missing add/port")
    name = str(data.get("ps") or "")
    params = {k: v for k, v in data.items() if k not in {"add", "port", "ps"}}
    proxy = ProxyConfig(source, "vmess", str(server), port, name, params, "vmess-uri", uri)
    proxy.ensure_id()
    return proxy


def _normalize_ss_query(query: str) -> dict[str, str]:
    """Parse SIP002 query parameters with exactly one URI-decoding pass.

    ``parse_qs`` performs the URI percent-decoding required for the query.  The
    decoded ``plugin`` value is then split according to SIP002's
    ``plugin;option=value`` syntax.  Extra percent-decoding layers are not
    guessed: a double-encoded feed remains double-encoded and is rejected later
    if the resulting plugin cannot be represented by the backend.
    """
    params = {k: v[-1] for k, v in parse_qs(query, keep_blank_values=True).items()}
    plugin = params.get("plugin")
    if plugin and ";" in plugin:
        name, opts = plugin.split(";", 1)
        params["plugin"] = name
        params["plugin_opts"] = opts
    return params


def _parse_ss_uri(uri: str, source: SourceInfo) -> ProxyConfig:
    # SIP002 supports both base64 userinfo and plain method:password userinfo.
    parts = urlsplit(uri)
    name = unquote(parts.fragment or "")
    if parts.hostname and parts.port is not None:
        if parts.username is None:
            raise ValueError("ss missing method/password")

        if parts.password is not None:
            method = unquote(parts.username)
            password = unquote(parts.password)
        else:
            decoded = _decode_b64_token(unquote(parts.username))
            if ":" not in decoded:
                raise ValueError("ss missing method/password")
            method, password = decoded.split(":", 1)

        if not method or not password:
            raise ValueError("ss missing method/password")
        if method.strip().lower() == "ss":
            raise ValueError("invalid shadowsocks method: ss")
        params = {"method": method, "password": password}
        params.update(_normalize_ss_query(parts.query))
        proxy = ProxyConfig(source, "ss", parts.hostname, parts.port, name, params, "ss-uri", uri)
        proxy.ensure_id()
        return proxy

    token = uri[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
    decoded = _decode_b64_token(token)
    reparsed = urlsplit("ss://" + decoded)
    if not reparsed.hostname or reparsed.port is None or not reparsed.username or reparsed.password is None:
        raise ValueError("invalid legacy ss URI")
    method = unquote(reparsed.username)
    if method.strip().lower() == "ss":
        raise ValueError("invalid shadowsocks method: ss")
    params = {"method": method, "password": unquote(reparsed.password)}
    # Query parameters belong to the original URI, not to the base64 token.
    original_query = urlsplit(uri).query
    if original_query:
        params.update(_normalize_ss_query(original_query))
    proxy = ProxyConfig(source, "ss", reparsed.hostname, reparsed.port, name, params, "ss-uri", uri)
    proxy.ensure_id()
    return proxy


def _decode_b64_token(token: str) -> str:
    padded = token + "=" * ((4 - len(token) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded).decode("utf-8")
    except Exception as exc:
        raise ValueError("invalid base64 token") from exc


def _parse_clash(obj: dict, source_id: str, source_name: str) -> list[ProxyConfig]:
    out: list[ProxyConfig] = []
    for item in obj.get("proxies", []):
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("type", "")).lower()
        if protocol == "hy2":
            protocol = "hysteria2"
        server, port = item.get("server"), item.get("port")
        if protocol not in SUPPORTED_SCHEMES or not server or port is None:
            continue
        params = {k: v for k, v in item.items() if k not in {"type", "server", "port", "name"}}
        proxy = ProxyConfig(SourceInfo(source_id, source_name, "clash"), protocol, str(server), int(port), str(item.get("name", "")), params, "clash", json.dumps(item, ensure_ascii=False, separators=(",", ":")))
        proxy.ensure_id()
        out.append(proxy)
    return out


def _parse_singbox(obj: dict, source_id: str, source_name: str) -> list[ProxyConfig]:
    out: list[ProxyConfig] = []
    for item in obj.get("outbounds", []):
        if not isinstance(item, dict):
            continue
        protocol = str(item.get("type", "")).lower()
        if protocol == "hy2":
            protocol = "hysteria2"
        server, port = item.get("server"), item.get("server_port")
        if protocol not in SUPPORTED_SCHEMES or not server or port is None:
            continue
        params = {k: v for k, v in item.items() if k not in {"type", "server", "server_port", "tag"}}
        proxy = ProxyConfig(SourceInfo(source_id, source_name, "sing-box"), protocol, str(server), int(port), str(item.get("tag", "")), params, "sing-box", json.dumps(item, ensure_ascii=False, separators=(",", ":")))
        proxy.ensure_id()
        out.append(proxy)
    return out
