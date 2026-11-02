from __future__ import annotations

from .model import ProxyConfig
from .semantics import INSECURE_ALIASES, tls_enabled


LEGACY_SHADOWSOCKS_METHODS = {
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "salsa20",
    "chacha20",
    "chacha20-ietf",
    "none",
    "plain",
}


def check_static_security(proxy: ProxyConfig, reject_allow_insecure: bool = True) -> tuple[bool, list[str]]:
    p = proxy.protocol.strip().lower()
    if p == "shadowsocks":
        p = "ss"
    elif p == "hy2":
        p = "hysteria2"

    params = proxy.params
    reasons: list[str] = []

    def truthy(value) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    if reject_allow_insecure:
        for key in INSECURE_ALIASES:
            if truthy(params.get(key)):
                reasons.append("certificate_verification_disabled")
                break

        tls = params.get("tls")
        if isinstance(tls, dict) and truthy(tls.get("insecure")):
            reasons.append("certificate_verification_disabled")

        # SIP002 plugin options may carry their own TLS policy, e.g.
        # v2ray-plugin;tls;skip-cert-verify=true. Treat this exactly like the
        # top-level insecure flags instead of letting it bypass static policy.
        plugin_opts = str(params.get("plugin_opts") or params.get("plugin-opts") or "").lower()
        if re_search_insecure_plugin_option(plugin_opts):
            reasons.append("certificate_verification_disabled")

    if p in {"vless", "vmess", "tuic"} and not (params.get("uuid") or params.get("id")):
        reasons.append("missing_uuid")

    if p == "trojan" and not params.get("password"):
        reasons.append("missing_password")

    if p == "tuic" and not params.get("password"):
        reasons.append("missing_tuic_password")

    if p == "hysteria2" and not (params.get("password") or params.get("auth")):
        reasons.append("missing_hysteria2_auth")

    if p == "ss":
        method = str(params.get("method") or params.get("cipher") or "").strip().lower()
        password = params.get("password")
        if not method or not password:
            reasons.append("missing_shadowsocks_credentials")
        elif method in LEGACY_SHADOWSOCKS_METHODS:
            reasons.append("legacy_shadowsocks_cipher")

    if p in {"vless", "vmess"}:
        try:
            enabled = tls_enabled(params)
        except ValueError:
            enabled = False
        if not enabled:
            reasons.append(
                "vless_without_tls_or_reality"
                if p == "vless"
                else "vmess_without_tls_or_reality"
            )

    ok = not reasons
    proxy.tests.security = {"status": "pass" if ok else "reject", "reasons": reasons}
    proxy.tests.status = "security_pass" if ok else "rejected_security"
    return ok, reasons


def re_search_insecure_plugin_option(value: str) -> bool:
    """Recognize common plugin spellings for disabled certificate checks."""
    compact = value.replace("_", "-").replace(" ", "")
    return (
        "skip-cert-verify=true" in compact
        or "skip-cert-verify=1" in compact
        or "allow-insecure=true" in compact
        or "allow-insecure=1" in compact
    )
