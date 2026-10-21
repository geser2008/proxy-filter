from __future__ import annotations

"""Compatibility layer for extended sing-box TLS/REALITY and XHTTP conversion.

URI ecosystems such as Xray use ``fp=unsafe`` to mean native Go TLS (uTLS
disabled) for ordinary TLS. sing-box does not accept ``unsafe`` as a uTLS
fingerprint, so it must not be copied into ``tls.utls.fingerprint``.

REALITY is different: both Xray and sing-box require uTLS there. For REALITY
profiles that omit ``fp`` we enable uTLS with an empty fingerprint; sing-box
1.14 documents that an empty uTLS fingerprint falls back to Chrome. A REALITY
profile that explicitly asks for ``fp=unsafe`` remains invalid rather than being
silently rewritten to a different semantic mode.

XHTTP share links follow the Xray VLESS URI proposal: ``host``, ``path`` and
``mode`` are top-level query parameters, while ``extra`` is one URI-decoded JSON
object containing the remaining XHTTP settings.  The extended sing-box core
uses snake_case names for the same settings, so conversion below is an explicit
field mapping. Unknown fields are rejected instead of being guessed or silently
lost.
"""

import json
from typing import Any

from .engine import EngineError, SingBoxBackend as _BaseSingBoxBackend
from .engine import _first, _list_value, _truthy


_XHTTP_EXTRA_FIELDS = {
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


class SingBoxBackend(_BaseSingBoxBackend):
    def _apply_tls(
        self,
        out: dict[str, Any],
        p: dict[str, Any],
        protocol: str,
        default_enabled: bool = False,
    ) -> None:
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
            # Xray explicitly does not support fp=unsafe for REALITY. Preserve
            # that incompatibility instead of silently changing the profile.
            if fp_lower == "unsafe":
                tls["utls"] = {"enabled": False}
            else:
                # Empty fingerprint is valid in sing-box and falls back to Chrome.
                tls["utls"] = {"enabled": True, "fingerprint": fp_text}
        elif fp_text and fp_lower not in {"none", "unsafe"}:
            # Ordinary TLS: fp=unsafe means do not use uTLS.
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

        out["tls"] = tls

    def _render_xhttp_transport(self, p: dict[str, Any]) -> dict[str, Any]:
        transport: dict[str, Any] = {"type": "xhttp"}

        # These are the XHTTP share-link fields defined by Xray. parse_qs in
        # ingest.py has already performed the one required URI decoding pass.
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

        # downloadSettings is a complete second Xray streamSettings tree. It is
        # intentionally rejected until it can be converted losslessly; silently
        # dropping it would route the download leg to the wrong endpoint.
        if "downloadSettings" in extra:
            raise EngineError("unsupported XHTTP extra field: downloadSettings")

        xmux = extra.get("xmux")
        plain_extra = {key: value for key, value in extra.items() if key != "xmux"}
        transport.update(_map_xhttp_object(plain_extra, _XHTTP_EXTRA_FIELDS, "XHTTP extra"))

        if xmux is not None:
            transport["xmux"] = _map_xhttp_object(xmux, _XHTTP_XMUX_FIELDS, "XHTTP extra.xmux")

        return transport

    def _apply_transport(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        native = p.get("transport")
        if isinstance(native, dict):
            # Native sing-box configuration is already in the core's schema.
            out["transport"] = native
            return

        network = str(_first(p, "network", "net", "type", default="")).strip().lower()
        if network == "xhttp":
            out["transport"] = self._render_xhttp_transport(p)
            return

        # Historical SplitHTTP spellings are not aliases in the VLESS share-link
        # specification. Do not guess that they mean XHTTP.
        if network in {"splithttp", "split-http"}:
            raise EngineError(f"unsupported V2Ray transport: {network}")

        super()._apply_transport(out, p)
