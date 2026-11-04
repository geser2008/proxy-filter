from __future__ import annotations

from .model import ProxyConfig
from .semantics import INSECURE_ALIASES, tls_enabled


VMESS_AEAD_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305"}
VMESS_TLS_CIPHERS = VMESS_AEAD_CIPHERS | {"none"}

# Explicitly classified modern methods. New methods require security review.
SHADOWSOCKS_AEAD_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}


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
        elif method not in SHADOWSOCKS_AEAD_METHODS:
            reasons.append("unknown_shadowsocks_cipher")

    if p == "vless":
        try:
            enabled = tls_enabled(params)
        except ValueError:
            enabled = False
        if not enabled:
            reasons.append("vless_without_tls_or_reality")

    if p == "vmess":
        # VMess payload cipher is independent of transport TLS.
        transport_params = {key: value for key, value in params.items() if key != "security"}
        try:
            transport_protected = tls_enabled(transport_params)
        except ValueError:
            transport_protected = False
        cipher = next(
            (str(params[key]).strip().lower()
             for key in ("security", "scy", "cipher")
             if key in params and params[key] is not None),
            "",
        )
        accepted = VMESS_TLS_CIPHERS if transport_protected else VMESS_AEAD_CIPHERS
        if cipher not in accepted:
            reasons.append(
                "unsafe_vmess_cipher" if transport_protected
                else "vmess_without_tls_or_safe_aead"
            )

        # Explicit modern VMess header AEAD; never silently fill absent alterId.
        alter_id = next(
            (params[key] for key in ("alter_id", "alterId", "aid") if key in params),
            None,
        )
        if alter_id is None or str(alter_id).strip() == "":
            reasons.append("missing_vmess_alter_id")
        else:
            raw_id = str(alter_id).strip()
            if isinstance(alter_id, bool) or not raw_id.isdecimal():
                reasons.append("invalid_vmess_alter_id")
            elif int(raw_id) != 0:
                reasons.append("legacy_vmess_alter_id")

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
