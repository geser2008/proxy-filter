from __future__ import annotations

import json
from typing import Any


MISSING = object()
INSECURE_ALIASES = (
    "allowInsecure",
    "allow_insecure",
    "skip-cert-verify",
    "skip_cert_verify",
    "insecure",
)


def first_present(params: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in params:
            return params[key]
    return default


def parse_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"invalid boolean value for {field}: {value!r}")


def tls_enabled(params: dict[str, Any], *, default_enabled: bool = False) -> bool:
    """Return whether source semantics explicitly enable TLS/Reality.

    Server-name/SNI fields configure TLS when TLS exists; they never enable TLS
    by themselves. A native TLS object is considered enabled unless it contains
    an explicit false `enabled` value.
    """
    security_value = params.get("security")
    security = "" if security_value is None else str(security_value).strip().lower()
    if security in {"tls", "reality"}:
        return True

    native_tls = params.get("tls", MISSING)
    if native_tls is MISSING or native_tls is None:
        return default_enabled
    if isinstance(native_tls, dict):
        if "enabled" not in native_tls:
            return True
        return parse_bool(native_tls["enabled"], "tls.enabled")

    text = str(native_tls).strip().lower()
    if text in {"", "none"}:
        return default_enabled
    if text in {"tls", "reality"}:
        return True
    return parse_bool(native_tls, "tls") or default_enabled


def insecure_value(params: dict[str, Any]) -> tuple[bool, Any]:
    """Return the first explicit top-level certificate-verification setting."""
    for key in INSECURE_ALIASES:
        if key in params:
            return True, params[key]
    return False, None


def certificate_verification_disabled(params: dict[str, Any]) -> bool:
    present, value = insecure_value(params)
    if present and parse_bool(value, "insecure"):
        return True

    native_tls = params.get("tls")
    if isinstance(native_tls, dict) and "insecure" in native_tls:
        return parse_bool(native_tls["insecure"], "tls.insecure")
    return False


def _canonical_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _canonical_value(value[key])
            for key in sorted(value, key=lambda item: str(item))
            if key not in {"name", "tag", "ps"}
        }
    if isinstance(value, list):
        return [_canonical_value(item) for item in value]
    return value


def _canonical_json_object(value: Any) -> Any:
    if isinstance(value, dict):
        return _canonical_value(value)
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError:
            return value
        if isinstance(decoded, dict):
            return _canonical_value(decoded)
    return _canonical_value(value)


def _canonical_bool(value: Any, field: str) -> bool | dict[str, Any]:
    try:
        return parse_bool(value, field)
    except ValueError:
        return {"invalid": _canonical_value(value)}


def _canonical_integer(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("+-").isdigit():
            return int(text)
    return _canonical_value(value)


def _canonical_headers(value: Any) -> Any:
    if not isinstance(value, dict):
        return _canonical_value(value)
    return {
        str(key).strip().lower(): _canonical_value(value[key])
        for key in sorted(value, key=lambda item: str(item).strip().lower())
    }


def _canonical_tls(
    params: dict[str, Any],
    *,
    default_enabled: bool = False,
    use_security_field: bool = True,
) -> dict[str, Any] | None:
    tls_params = params if use_security_field else {key: value for key, value in params.items() if key != "security"}
    try:
        enabled = tls_enabled(tls_params, default_enabled=default_enabled)
    except ValueError:
        return {"enabled": {"invalid": _canonical_value(params.get("tls"))}}
    if not enabled:
        return None

    native_tls = params.get("tls") if isinstance(params.get("tls"), dict) else {}
    security = str(params.get("security") or "").strip().lower() if use_security_field else ""
    native_tls_text = "" if isinstance(params.get("tls"), dict) else str(params.get("tls") or "").strip().lower()
    reality_opts = params.get("reality-opts") if isinstance(params.get("reality-opts"), dict) else {}
    native_reality = native_tls.get("reality") if isinstance(native_tls.get("reality"), dict) else {}
    is_reality = (
        security == "reality"
        or native_tls_text == "reality"
        or bool(reality_opts)
        or bool(native_reality)
    )

    result: dict[str, Any] = {"mode": "reality" if is_reality else "tls"}

    server_name = first_present(
        params,
        "sni",
        "server_name",
        "servername",
        "server-name",
        default=MISSING,
    )
    if server_name is MISSING and "server_name" in native_tls:
        server_name = native_tls["server_name"]
    if server_name is not MISSING and server_name not in {None, ""}:
        result["server_name"] = server_name

    insecure_present, insecure = insecure_value(params)
    if not insecure_present and "insecure" in native_tls:
        insecure_present, insecure = True, native_tls["insecure"]
    if insecure_present:
        normalized = _canonical_bool(insecure, "insecure")
        if normalized is True or isinstance(normalized, dict):
            result["insecure"] = normalized

    alpn = params.get("alpn", MISSING)
    if alpn is MISSING:
        alpn = native_tls.get("alpn", MISSING)
    if alpn is not MISSING:
        if isinstance(alpn, list):
            result["alpn"] = [_canonical_value(item) for item in alpn]
        else:
            result["alpn"] = [item.strip() for item in str(alpn).split(",")]

    fingerprint = first_present(params, "fp", "client-fingerprint", "fingerprint", default=MISSING)
    native_utls = native_tls.get("utls") if isinstance(native_tls.get("utls"), dict) else {}
    if fingerprint is MISSING and "fingerprint" in native_utls:
        fingerprint = native_utls["fingerprint"]
    if fingerprint is not MISSING:
        utls_enabled = native_utls.get("enabled", True)
        normalized_enabled = _canonical_bool(utls_enabled, "tls.utls.enabled")
        if normalized_enabled is True:
            result["utls_fingerprint"] = fingerprint
        elif isinstance(normalized_enabled, dict):
            result["utls_enabled"] = normalized_enabled
            result["utls_fingerprint"] = fingerprint

    if is_reality:
        public_key = first_present(params, "pbk", "public_key", default=MISSING)
        if public_key is MISSING:
            public_key = reality_opts.get("public-key", native_reality.get("public_key", MISSING))
        short_id = first_present(params, "sid", "short_id", default=MISSING)
        if short_id is MISSING:
            short_id = reality_opts.get("short-id", native_reality.get("short_id", MISSING))
        reality: dict[str, Any] = {}
        if public_key is not MISSING:
            reality["public_key"] = public_key
        if short_id is not MISSING:
            reality["short_id"] = short_id
        result["reality"] = reality

    return result


def _canonical_transport(params: dict[str, Any]) -> dict[str, Any]:
    native = params.get("transport") if isinstance(params.get("transport"), dict) else None
    if native is not None:
        network = str(native.get("type") or "tcp").strip().lower()
    else:
        network = str(first_present(params, "network", "net", "type", default="tcp") or "tcp").strip().lower()

    aliases = {
        "": "tcp",
        "websocket": "ws",
        "h2": "http",
        "http-upgrade": "httpupgrade",
    }
    network = aliases.get(network, network)
    result: dict[str, Any] = {"type": network}

    if network == "tcp":
        header = ""
        if native is not None:
            native_header = native.get("header")
            if isinstance(native_header, dict):
                header = str(native_header.get("type") or "").strip().lower()
        else:
            header = str(first_present(params, "headerType", "header_type", default="") or "").strip().lower()
        if header not in {"", "none"}:
            result["header"] = header
        return result

    if network == "ws":
        opts = params.get("ws-opts") if isinstance(params.get("ws-opts"), dict) else {}
        path = native.get("path", MISSING) if native is not None else params.get("path", opts.get("path", MISSING))
        if path is not MISSING and path not in {None, ""}:
            result["path"] = path
        headers: dict[str, Any] = {}
        source_headers = native.get("headers") if native is not None else opts.get("headers")
        if isinstance(source_headers, dict):
            headers.update(source_headers)
        if native is None and "host" in params and not any(str(key).lower() == "host" for key in headers):
            headers["Host"] = params["host"]
        if headers:
            result["headers"] = _canonical_headers(headers)
        return result

    if network == "grpc":
        opts = params.get("grpc-opts") if isinstance(params.get("grpc-opts"), dict) else {}
        if native is not None:
            service = native.get("service_name", MISSING)
        else:
            service = first_present(params, "serviceName", "service_name", default=MISSING)
            if service is MISSING:
                service = opts.get("grpc-service-name", MISSING)
        if service is not MISSING and service not in {None, ""}:
            result["service_name"] = service
        return result

    if network == "http":
        source = native or params
        path = source.get("path", MISSING)
        if path is not MISSING and path not in {None, ""}:
            result["path"] = path
        host = source.get("host", MISSING)
        if host is not MISSING:
            result["host"] = list(host) if isinstance(host, list) else [str(host)]
        return result

    if network == "httpupgrade":
        source = native or params
        for key in ("path", "host"):
            if key in source and source[key] not in {None, ""}:
                result[key] = source[key]
        headers = source.get("headers")
        if headers is not None:
            result["headers"] = _canonical_headers(headers)
        return result

    if network == "xhttp":
        source = native or params
        for key in ("host", "path", "mode"):
            if key in source:
                result[key] = _canonical_value(source[key])
        if "extra" in source:
            result["extra"] = _canonical_json_object(source["extra"])
        return result

    result["raw"] = _canonical_value(native if native is not None else params)
    return result


def _canonical_vless(params: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    uuid = first_present(params, "uuid", "id", default=MISSING)
    if uuid is not MISSING:
        result["uuid"] = uuid

    flow = params.get("flow", MISSING)
    if flow is not MISSING and flow not in {None, ""}:
        result["flow"] = flow

    packet_encoding = first_present(params, "packet_encoding", "packet-encoding", default=MISSING)
    if packet_encoding is not MISSING and packet_encoding not in {None, ""}:
        result["packet_encoding"] = packet_encoding

    tls = _canonical_tls(params)
    if tls is not None:
        result["tls"] = tls

    result["transport"] = _canonical_transport(params)
    return result


def _canonical_vmess(params: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    uuid = first_present(params, "uuid", "id", default=MISSING)
    if uuid is not MISSING:
        result["uuid"] = uuid

    cipher = first_present(params, "security", "scy", "cipher", default=MISSING)
    if cipher is not MISSING:
        result["cipher"] = cipher

    alter_id = first_present(params, "alter_id", "alterId", "aid", default=MISSING)
    if alter_id is not MISSING:
        result["alter_id"] = _canonical_integer(alter_id)

    packet_encoding = first_present(params, "packet_encoding", "packet-encoding", default=MISSING)
    if packet_encoding is not MISSING and packet_encoding not in {None, ""}:
        result["packet_encoding"] = packet_encoding

    for target, aliases in {
        "global_padding": ("global_padding", "global-padding"),
        "authenticated_length": ("authenticated_length", "authenticated-length"),
    }.items():
        value = first_present(params, *aliases, default=MISSING)
        if value is not MISSING:
            result[target] = _canonical_bool(value, target)

    tls = _canonical_tls(params, use_security_field=False)
    if tls is not None:
        result["tls"] = tls

    result["transport"] = _canonical_transport(params)
    return result


def _canonical_trojan(params: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if "password" in params:
        result["password"] = params["password"]

    tls = _canonical_tls(params, default_enabled=True)
    if tls is not None:
        result["tls"] = tls

    result["transport"] = _canonical_transport(params)
    return result


def _canonical_shadowsocks(params: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    method = first_present(params, "method", "cipher", default=MISSING)
    if method is not MISSING:
        result["method"] = method
    if "password" in params:
        result["password"] = params["password"]

    plugin = params.get("plugin", MISSING)
    if plugin is not MISSING:
        result["plugin"] = plugin
    plugin_opts = first_present(params, "plugin_opts", "plugin-opts", default=MISSING)
    if plugin_opts is not MISSING:
        result["plugin_opts"] = plugin_opts

    if "network" in params:
        result["network"] = str(params["network"]).strip().lower()

    udp_over_tcp = first_present(params, "udp_over_tcp", "udp-over-tcp", default=MISSING)
    if udp_over_tcp is not MISSING:
        result["udp_over_tcp"] = _canonical_value(udp_over_tcp)

    if "multiplex" in params:
        result["multiplex"] = _canonical_value(params["multiplex"])
    if "smux" in params:
        result["smux"] = _canonical_value(params["smux"])
    return result


def canonical_identity_params(protocol: str, params: dict[str, Any]) -> dict[str, Any]:
    """Return connection-semantic params used for stable proxy identity.

    Only equivalences that are explicitly understood are collapsed. Unsupported
    protocols keep structural canonicalization so identity never guesses across
    representations.
    """
    normalized_protocol = protocol.strip().lower()
    if normalized_protocol == "vless":
        return _canonical_vless(params)
    if normalized_protocol == "vmess":
        return _canonical_vmess(params)
    if normalized_protocol == "trojan":
        return _canonical_trojan(params)
    if normalized_protocol in {"ss", "shadowsocks"}:
        return _canonical_shadowsocks(params)

    value = _canonical_value(params)
    return value if isinstance(value, dict) else {"value": value}
