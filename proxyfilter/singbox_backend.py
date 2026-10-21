from __future__ import annotations

"""Compatibility layer for sing-box 1.14 TLS/REALITY conversion.

URI ecosystems such as Xray use ``fp=unsafe`` to mean native Go TLS (uTLS
disabled) for ordinary TLS. sing-box does not accept ``unsafe`` as a uTLS
fingerprint, so it must not be copied into ``tls.utls.fingerprint``.

REALITY is different: both Xray and sing-box require uTLS there. For REALITY
profiles that omit ``fp`` we enable uTLS with an empty fingerprint; sing-box
1.14 documents that an empty uTLS fingerprint falls back to Chrome. A REALITY
profile that explicitly asks for ``fp=unsafe`` remains invalid rather than being
silently rewritten to a different semantic mode.
"""

from typing import Any

from .engine import EngineError, SingBoxBackend as _BaseSingBoxBackend
from .engine import _first, _list_value, _truthy


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

    def _apply_transport(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        network = str(_first(p, "network", "net", "type", default="")).strip().lower()
        if network in {"xhttp", "splithttp", "split-http"}:
            raise EngineError(f"unsupported V2Ray transport in sing-box 1.14: {network}")
        super()._apply_transport(out, p)
