from __future__ import annotations

"""Backend mode adapter for standard sing-box and sing-box-extended.

Production input is URI-only. ``standard`` converts the parsed URI into normal
sing-box JSON and deliberately forwards URI parameters that the mapper did not
consume. ``sing-box check`` is therefore the final compatibility authority for
unknown JSON fields. ``extended`` forwards the original share URI through the
sing-box-extended ``parser`` outbound.
"""

from copy import copy
import os
from typing import Any

from .engine import EngineError
from .singbox_backend import SingBoxBackend as _MappedSingBoxBackend


# URI fields consumed by the current mapper or used only to derive a nested
# standard sing-box field. They must not be emitted a second time as top-level
# JSON keys. Anything else is deliberately retained so ``sing-box check`` can
# accept or reject it instead of proxy-filter silently dropping it.
_CONSUMED_URI_FIELDS = {
    "uuid", "id", "password", "auth", "method", "cipher", "security", "scy",
    "alter_id", "alterId", "aid", "flow",
    "type", "net", "network", "transport",
    "host", "path", "mode", "headerType", "header_type", "headers",
    "serviceName", "service_name", "authority",
    "sni", "server_name", "servername", "server-name",
    "tls", "allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify", "insecure",
    "alpn", "cs", "cipher_suites", "cipher-suites",
    "fp", "client-fingerprint", "fingerprint",
    "pbk", "public_key", "public-key", "sid", "short_id", "short-id", "reality-opts",
    "disable_sni", "disable-sni",
    "packet_encoding", "packet-encoding", "packetEncoding",
    "global_padding", "global-padding", "authenticated_length", "authenticated-length",
    "multiplex",
    "udp_over_tcp", "udp-over-tcp", "udp_over_stream", "udp-over-stream",
    "zero_rtt_handshake", "zero-rtt-handshake", "reduce-rtt",
    "heartbeat", "heartbeat-interval", "heartbeat_interval",
    "server_ports", "ports", "mport", "hop_interval", "hop-interval",
    "hop_interval_max", "hop-interval-max",
    "up_mbps", "up-mbps", "up", "upmbps", "down_mbps", "down-mbps", "down", "downmbps",
    "obfs_min_packet_size", "obfs-min-packet-size", "obfs_max_packet_size", "obfs-max-packet-size",
    "bbr_profile", "bbr-profile", "brutal_debug", "brutal-debug",
    "disable_chrome_parrot", "disable-chrome-parrot", "realm",
    "ed", "max_early_data", "max-early-data", "eh", "early_data_header_name", "early-data-header-name",
    "ws-opts", "idle_timeout", "idle-timeout", "ping_timeout", "ping-timeout",
    "permit_without_stream", "permit-without-stream", "method",
    "extra",
}

# Fields for which the legacy mapper currently fails before a sing-box config is
# produced. For URI input we instead withhold them from the legacy conversion,
# then put them back into the generated JSON unchanged. This moves the decision
# to ``sing-box check`` as intended.
_PRECHECK_ONLY_FIELDS = {
    "fm", "final_mask",
    "pcs", "pinnedPeerCertSha256", "peer_certificate_sha256",
    "ech", "echConfigList",
    "spx", "spider_x",
    "smux",
    "pinSHA256", "pin_sha256",
    "fastopen",
    "realm-opts",
    "token",
}


class SingBoxBackend(_MappedSingBoxBackend):
    """Dual-mode production backend.

    ``standard`` is the default. The optional environment variable
    ``PROXYFILTER_SINGBOX_MODE`` lets real-data runs switch between ``standard``
    and ``extended`` without changing the existing config schema yet.
    """

    def __init__(self, *args: Any, backend_mode: str | None = None, **kwargs: Any) -> None:
        mode = str(backend_mode or os.environ.get("PROXYFILTER_SINGBOX_MODE", "standard")).strip().lower()
        if mode not in {"standard", "extended"}:
            raise EngineError(f"unsupported sing-box backend mode: {mode}")
        self.backend_mode = mode
        super().__init__(*args, **kwargs)

    @staticmethod
    def _is_uri(proxy: Any) -> bool:
        return str(getattr(proxy, "original_format", "")).endswith("-uri")

    def _render_outbound(self, proxy: Any) -> dict[str, Any]:
        if self.backend_mode == "extended":
            if not self._is_uri(proxy):
                raise EngineError("extended sing-box backend requires a share URI input")
            raw = str(getattr(proxy, "original_raw", "") or "")
            if not raw:
                raise EngineError("extended sing-box backend requires original_raw share link")
            return {
                "type": "parser",
                "tag": "proxy-out",
                "link": raw,
                "domain_resolver": "dns-direct",
            }

        if not self._is_uri(proxy):
            return super()._render_outbound(proxy)

        original_params = dict(proxy.params)
        mapped_proxy = copy(proxy)
        mapped_proxy.params = {
            key: value for key, value in original_params.items() if key not in _PRECHECK_ONLY_FIELDS
        }
        out = super()._render_outbound(mapped_proxy)

        # Do not repair Reality share links by enabling uTLS when the source URI
        # did not request a fingerprint.  The generated standard JSON must keep
        # the source semantics and let ``sing-box check`` reject an incomplete
        # Reality configuration. Explicit fp/client-fingerprint/fingerprint
        # values are still mapped by the underlying mapper.
        security = str(original_params.get("security") or "").strip().lower()
        tls_value = original_params.get("tls")
        tls_text = "" if tls_value is None or isinstance(tls_value, dict) else str(tls_value).strip().lower()
        reality_opts = original_params.get("reality-opts")
        is_reality = (
            security == "reality"
            or tls_text == "reality"
            or (isinstance(reality_opts, dict) and bool(reality_opts))
        )
        has_explicit_fingerprint = any(
            key in original_params for key in ("fp", "client-fingerprint", "fingerprint")
        )
        if is_reality and not has_explicit_fingerprint:
            tls = out.get("tls")
            if isinstance(tls, dict):
                tls.pop("utls", None)

        for key, value in original_params.items():
            if key in _CONSUMED_URI_FIELDS:
                continue
            if key not in out:
                out[key] = value
        return out
