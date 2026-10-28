from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from .identity_semantics import canonical_identity_params
from .ingest import parse_uri
from .model import ProxyConfig, SourceInfo
from .quic_render import render_quic_uri


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


def _validate_semantic_source_fields(protocol: str, params: dict[str, Any]) -> None:
    common_tls = {
        "security",
        "tls",
        "sni",
        "server_name",
        "servername",
        "server-name",
        "allowInsecure",
        "allow_insecure",
        "skip-cert-verify",
        "skip_cert_verify",
        "insecure",
        "alpn",
        "fp",
        "client-fingerprint",
        "fingerprint",
        "reality-opts",
        "pbk",
        "public_key",
        "sid",
        "short_id",
    }
    common_transport = {
        "transport",
        "network",
        "net",
        "type",
        "headerType",
        "header_type",
        "ws-opts",
        "grpc-opts",
        "path",
        "host",
        "serviceName",
        "service_name",
        "mode",
        "extra",
    }
    harmless = {"udp", "name", "tag", "ps"}

    if protocol == "vless":
        allowed = common_tls | common_transport | harmless | {
            "uuid",
            "id",
            "flow",
            "packet_encoding",
            "packet-encoding",
            "encryption",
        }
    elif protocol == "trojan":
        allowed = common_tls | common_transport | harmless | {"password"}
    elif protocol == "vmess":
        allowed = common_tls | common_transport | harmless | {
            "uuid",
            "id",
            "alter_id",
            "alterId",
            "aid",
            "scy",
            "cipher",
            "packet_encoding",
            "packet-encoding",
            "global_padding",
            "global-padding",
            "authenticated_length",
            "authenticated-length",
            "v",
            "pcs",
            "vcn",
        }
    elif protocol in {"ss", "shadowsocks"}:
        allowed = harmless | {
            "method",
            "cipher",
            "password",
            "plugin",
            "plugin_opts",
            "plugin-opts",
            "network",
            "udp_over_tcp",
            "udp-over-tcp",
            "multiplex",
            "smux",
        }
    else:
        return

    unknown = sorted(str(key) for key in params if key not in allowed)
    if unknown:
        raise RenderError(
            f"unsupported source field(s) for {protocol} URI rendering: " + ", ".join(unknown)
        )


def _canonical_transport_query(transport: dict[str, Any]) -> dict[str, str | list[str]]:
    transport_type = str(transport.get("type") or "tcp")
    query: dict[str, str | list[str]] = {"type": transport_type}

    if transport_type == "tcp":
        header = transport.get("header")
        if header not in {None, "", "none"}:
            query["headerType"] = str(header)
        return query

    if transport_type == "ws":
        if "path" in transport:
            query["path"] = str(transport["path"])
        headers = transport.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                raise RenderError("WebSocket headers cannot be represented losslessly")
            unknown = [key for key in headers if str(key).strip().lower() != "host"]
            if unknown:
                raise RenderError(
                    "WebSocket URI cannot represent header(s) losslessly: "
                    + ", ".join(sorted(map(str, unknown)))
                )
            for key, value in headers.items():
                if str(key).strip().lower() == "host":
                    query["host"] = str(value)
        return query

    if transport_type == "grpc":
        if "service_name" in transport:
            query["serviceName"] = str(transport["service_name"])
        extra = set(transport) - {"type", "service_name"}
        if extra:
            raise RenderError(
                "gRPC URI cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra))
            )
        return query

    if transport_type == "http":
        if "path" in transport:
            query["path"] = str(transport["path"])
        if "host" in transport:
            host = transport["host"]
            if isinstance(host, list):
                if not all(isinstance(item, str) for item in host):
                    raise RenderError("HTTP transport host list must contain strings")
                query["host"] = host
            else:
                query["host"] = str(host)
        extra = set(transport) - {"type", "path", "host"}
        if extra:
            raise RenderError(
                "HTTP URI cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra))
            )
        return query

    if transport_type == "httpupgrade":
        for key in ("path", "host"):
            if key in transport:
                query[key] = str(transport[key])
        extra = set(transport) - {"type", "path", "host"}
        if extra:
            raise RenderError(
                "HTTPUpgrade URI cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra))
            )
        return query

    if transport_type == "xhttp":
        for key in ("host", "path", "mode"):
            if key in transport:
                query[key] = str(transport[key])
        if "extra" in transport:
            extra_value = transport["extra"]
            if not isinstance(extra_value, dict):
                raise RenderError("XHTTP extra must be a JSON object for lossless URI rendering")
            query["extra"] = json.dumps(
                extra_value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        extra_fields = set(transport) - {"type", "host", "path", "mode", "extra"}
        if extra_fields:
            raise RenderError(
                "XHTTP URI cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra_fields))
            )
        return query

    raise RenderError(f"transport {transport_type!r} cannot be represented losslessly as URI")


def _canonical_tls_query(tls: dict[str, Any]) -> dict[str, str | list[str]]:
    query: dict[str, str | list[str]] = {}
    mode = str(tls.get("mode") or "tls")
    query["security"] = mode

    if "server_name" in tls:
        query["sni"] = str(tls["server_name"])
    if tls.get("insecure") is True:
        query["insecure"] = "1"
    elif isinstance(tls.get("insecure"), dict):
        raise RenderError("invalid insecure value cannot be represented losslessly")

    if "alpn" in tls:
        alpn = tls["alpn"]
        if not isinstance(alpn, list) or not all(isinstance(item, str) for item in alpn):
            raise RenderError("ALPN must be a list of strings")
        query["alpn"] = ",".join(alpn)

    if "utls_fingerprint" in tls:
        query["fp"] = str(tls["utls_fingerprint"])
    if "utls_enabled" in tls:
        raise RenderError("invalid uTLS enabled value cannot be represented losslessly")

    reality = tls.get("reality")
    if reality is not None:
        if not isinstance(reality, dict):
            raise RenderError("Reality settings must be an object")
        if "public_key" in reality:
            query["pbk"] = str(reality["public_key"])
        if "short_id" in reality:
            query["sid"] = str(reality["short_id"])

    allowed = {"mode", "server_name", "insecure", "alpn", "utls_fingerprint", "utls_enabled", "reality"}
    extra = set(tls) - allowed
    if extra:
        raise RenderError(
            "TLS URI cannot represent field(s) losslessly: " + ", ".join(sorted(extra))
        )
    return query


def _canonical_tls_vmess_fields(tls: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {"tls": str(tls.get("mode") or "tls")}
    if "server_name" in tls:
        fields["sni"] = str(tls["server_name"])
    if tls.get("insecure") is True:
        fields["insecure"] = True
    elif isinstance(tls.get("insecure"), dict):
        raise RenderError("invalid insecure value cannot be represented losslessly")

    if "alpn" in tls:
        alpn = tls["alpn"]
        if not isinstance(alpn, list) or not all(isinstance(item, str) for item in alpn):
            raise RenderError("ALPN must be a list of strings")
        fields["alpn"] = alpn

    if "utls_fingerprint" in tls:
        fields["fp"] = str(tls["utls_fingerprint"])
    if "utls_enabled" in tls:
        raise RenderError("invalid uTLS enabled value cannot be represented losslessly")

    reality = tls.get("reality")
    if reality is not None:
        if not isinstance(reality, dict):
            raise RenderError("Reality settings must be an object")
        if "public_key" in reality:
            fields["pbk"] = str(reality["public_key"])
        if "short_id" in reality:
            fields["sid"] = str(reality["short_id"])

    allowed = {"mode", "server_name", "insecure", "alpn", "utls_fingerprint", "utls_enabled", "reality"}
    extra = set(tls) - allowed
    if extra:
        raise RenderError(
            "VMess TLS cannot represent field(s) losslessly: " + ", ".join(sorted(extra))
        )
    return fields


def _canonical_vmess_transport_fields(transport: dict[str, Any]) -> dict[str, Any]:
    transport_type = str(transport.get("type") or "tcp")
    fields: dict[str, Any] = {"net": transport_type}

    if transport_type == "tcp":
        header = transport.get("header")
        if header not in {None, "", "none"}:
            fields["headerType"] = str(header)
        return fields

    if transport_type == "ws":
        if "path" in transport:
            fields["path"] = transport["path"]
        headers = transport.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                raise RenderError("VMess WebSocket headers must be an object")
            unknown = [key for key in headers if str(key).strip().lower() != "host"]
            if unknown:
                raise RenderError(
                    "VMess URI cannot represent WebSocket header(s) losslessly: "
                    + ", ".join(sorted(map(str, unknown)))
                )
            for key, value in headers.items():
                if str(key).strip().lower() == "host":
                    fields["host"] = value
        return fields

    if transport_type == "grpc":
        if "service_name" in transport:
            fields["serviceName"] = transport["service_name"]
        extra = set(transport) - {"type", "service_name"}
        if extra:
            raise RenderError(
                "VMess gRPC cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra))
            )
        return fields

    if transport_type == "http":
        if "path" in transport:
            fields["path"] = transport["path"]
        if "host" in transport:
            host = transport["host"]
            if isinstance(host, list) and len(host) == 1:
                fields["host"] = host[0]
            elif isinstance(host, str):
                fields["host"] = host
            else:
                raise RenderError("VMess URI cannot represent multiple HTTP hosts losslessly")
        extra = set(transport) - {"type", "path", "host"}
        if extra:
            raise RenderError(
                "VMess HTTP cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra))
            )
        return fields

    if transport_type == "httpupgrade":
        for key in ("path", "host"):
            if key in transport:
                fields[key] = transport[key]
        extra = set(transport) - {"type", "path", "host"}
        if extra:
            raise RenderError(
                "VMess HTTPUpgrade cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(extra))
            )
        return fields

    if transport_type == "xhttp":
        for key in ("path", "host", "mode"):
            if key in transport:
                fields[key] = transport[key]
        if "extra" in transport:
            extra_value = transport["extra"]
            if not isinstance(extra_value, dict):
                raise RenderError("VMess XHTTP extra must be a JSON object")
            fields["extra"] = extra_value
        unknown = set(transport) - {"type", "path", "host", "mode", "extra"}
        if unknown:
            raise RenderError(
                "VMess XHTTP cannot represent transport field(s) losslessly: "
                + ", ".join(sorted(unknown))
            )
        return fields

    raise RenderError(f"VMess transport {transport_type!r} cannot be represented losslessly")


def _semantic_generic_uri(proxy: ProxyConfig, name: str) -> str:
    protocol = proxy.protocol.lower()
    _validate_semantic_source_fields(protocol, proxy.params)
    canonical = canonical_identity_params(protocol, proxy.params)

    if protocol == "vless":
        userinfo = quote(_require_text(canonical.get("uuid"), "vless uuid"), safe="")
        allowed = {"uuid", "flow", "packet_encoding", "tls", "transport"}
    elif protocol == "trojan":
        userinfo = quote(_require_text(canonical.get("password"), "trojan password"), safe="")
        allowed = {"password", "tls", "transport"}
    else:
        raise RenderError(f"unsupported semantic URI protocol: {protocol}")

    extra = set(canonical) - allowed
    if extra:
        raise RenderError(
            f"{protocol} URI cannot represent canonical field(s): " + ", ".join(sorted(extra))
        )

    query: dict[str, str | list[str]] = {}
    if "flow" in canonical:
        query["flow"] = str(canonical["flow"])
    if "packet_encoding" in canonical:
        query["packet-encoding"] = str(canonical["packet_encoding"])
    if "tls" in canonical:
        tls = canonical["tls"]
        if not isinstance(tls, dict):
            raise RenderError("canonical TLS settings must be an object")
        query.update(_canonical_tls_query(tls))
    elif protocol == "trojan":
        query["security"] = "tls"

    transport = canonical.get("transport", {"type": "tcp"})
    if not isinstance(transport, dict):
        raise RenderError("canonical transport must be an object")
    query.update(_canonical_transport_query(transport))

    items: list[tuple[str, str]] = []
    for key in sorted(query):
        value = query[key]
        if isinstance(value, list):
            items.extend((key, item) for item in value)
        else:
            items.append((key, value))

    uri = f"{protocol}://{userinfo}@{_host_for_uri(proxy.server)}:{int(proxy.port)}"
    if items:
        uri += "?" + urlencode(items, doseq=True)
    if name:
        uri += "#" + quote(name, safe="")
    return uri


def _generic_uri(proxy: ProxyConfig, name: str) -> str:
    protocol = proxy.protocol.lower()
    if protocol in {"vless", "trojan"}:
        return _semantic_generic_uri(proxy, name)
    if protocol in {"hysteria2", "hy2", "tuic"}:
        return render_quic_uri(proxy, name)
    raise RenderError(f"unsupported generic URI protocol: {protocol}")


def _vmess_uri(proxy: ProxyConfig, name: str) -> str:
    _validate_semantic_source_fields("vmess", proxy.params)
    canonical = canonical_identity_params("vmess", proxy.params)
    allowed = {
        "uuid",
        "cipher",
        "alter_id",
        "packet_encoding",
        "global_padding",
        "authenticated_length",
        "tls",
        "transport",
    }
    extra = set(canonical) - allowed
    if extra:
        raise RenderError(
            "VMess URI cannot represent canonical field(s): " + ", ".join(sorted(extra))
        )

    data: dict[str, Any] = {
        "v": "2",
        "add": proxy.server,
        "port": str(int(proxy.port)),
        "ps": name,
    }
    if "uuid" in canonical:
        data["id"] = _require_text(canonical["uuid"], "vmess uuid")
    if "cipher" in canonical:
        data["scy"] = canonical["cipher"]
    if "alter_id" in canonical:
        data["aid"] = canonical["alter_id"]
    if "packet_encoding" in canonical:
        data["packet_encoding"] = canonical["packet_encoding"]

    for key in ("global_padding", "authenticated_length"):
        if key in canonical:
            value = canonical[key]
            if isinstance(value, dict):
                raise RenderError(f"invalid VMess {key} value cannot be represented losslessly")
            data[key] = value

    tls = canonical.get("tls")
    if tls is not None:
        if not isinstance(tls, dict):
            raise RenderError("canonical VMess TLS settings must be an object")
        data.update(_canonical_tls_vmess_fields(tls))

    transport = canonical.get("transport", {"type": "tcp"})
    if not isinstance(transport, dict):
        raise RenderError("canonical VMess transport must be an object")
    data.update(_canonical_vmess_transport_fields(transport))

    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = base64.b64encode(payload).decode("ascii").rstrip("=")
    return "vmess://" + token


def _ss_uri(proxy: ProxyConfig, name: str) -> str:
    _validate_semantic_source_fields("ss", proxy.params)
    canonical = canonical_identity_params("ss", proxy.params)
    allowed = {"method", "password", "plugin", "plugin_opts"}
    extra = set(canonical) - allowed
    if extra:
        raise RenderError(
            "Shadowsocks SIP002 cannot represent canonical field(s) losslessly: "
            + ", ".join(sorted(extra))
        )

    method = _require_text(canonical.get("method"), "shadowsocks method")
    password = _require_text(canonical.get("password"), "shadowsocks password")
    token = base64.urlsafe_b64encode(f"{method}:{password}".encode("utf-8")).decode("ascii").rstrip("=")

    query_params: dict[str, str] = {}
    plugin = canonical.get("plugin")
    plugin_opts = canonical.get("plugin_opts")
    if plugin_opts is not None:
        plugin_name = _require_text(plugin, "shadowsocks plugin")
        if not isinstance(plugin_opts, str):
            raise RenderError("shadowsocks plugin_opts must be a string")
        query_params["plugin"] = f"{plugin_name};{plugin_opts}"
    elif plugin is not None:
        query_params["plugin"] = _require_text(plugin, "shadowsocks plugin")

    query = urlencode(query_params)
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


def _source_label(source_ids: list[str]) -> str:
    if not source_ids:
        return "unknown"
    if len(source_ids) <= 3:
        return "+".join(source_ids)
    return f"{len(source_ids)}src"


def format_output_name(
    proxy: ProxyConfig,
    *,
    template: str,
    include_original_name: bool = True,
) -> str:
    geo = proxy.tests.geo or {}
    download = proxy.tests.download or {}
    original_name = proxy.name if include_original_name else ""
    provenance = proxy.provenance_sources()
    source_ids = [source.id for source in provenance if source.id]
    if not source_ids and proxy.source.id:
        source_ids = [proxy.source.id]

    def metric(value: float | None) -> str:
        return "?" if value is None else str(int(round(value)))

    stream_reliability = str(download.get("stream_reliability") or "unknown")
    values = {
        "flag": geo.get("flag") or "🌐",
        "country_code": geo.get("country_code") or "??",
        "country": geo.get("country") or "Unknown",
        "source": proxy.source.id,
        "source_name": proxy.source.name,
        "sources": _source_label(source_ids),
        "source_count": len(source_ids),
        "protocol": proxy.protocol,
        "name": original_name,
        "original_name": original_name,
        "latency_ms": metric(proxy.tests.latency_ms),
        "download_mbps": metric(proxy.tests.download_mbps),
        "upload_mbps": metric(proxy.tests.upload_mbps),
        "stream_reliability": stream_reliability,
        "reliability": stream_reliability,
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
