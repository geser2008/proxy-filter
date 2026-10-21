from __future__ import annotations

from .model import ProxyConfig


def check_static_security(proxy: ProxyConfig, reject_allow_insecure: bool = True) -> tuple[bool, list[str]]:
    p = proxy.protocol.lower()
    params = proxy.params
    reasons: list[str] = []

    def truthy(value) -> bool:
        if isinstance(value, bool):
            return value
        if value is None:
            return False
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    # Look in common URI-style keys.
    if reject_allow_insecure:
        for key in ("allowInsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify"):
            if truthy(params.get(key)):
                reasons.append("certificate_verification_disabled")
                break

        # Clash / sing-box nested TLS forms.
        tls = params.get("tls")
        if isinstance(tls, dict) and truthy(tls.get("insecure")):
            reasons.append("certificate_verification_disabled")

    # Reject clearly malformed auth rather than letting later stages spend time on it.
    if p in {"vless", "vmess", "tuic"} and not (params.get("uuid") or params.get("id")):
        if p != "vmess":
            reasons.append("missing_uuid")
    if p == "trojan" and not params.get("password"):
        reasons.append("missing_password")
    if p == "ss" and (not params.get("method") or not params.get("password")):
        reasons.append("missing_shadowsocks_credentials")

    # VLESS has no confidentiality by itself. Require an explicitly protected mode.
    if p == "vless":
        security = str(params.get("security") or "").lower()
        # Clash/sing-box may represent TLS as bool/object rather than security=.
        has_tls = bool(params.get("tls")) or bool(params.get("servername")) or bool(params.get("server_name"))
        if security not in {"tls", "reality"} and not has_tls:
            reasons.append("vless_without_tls_or_reality")

    ok = not reasons
    proxy.tests.security = {"status": "pass" if ok else "reject", "reasons": reasons}
    proxy.tests.status = "security_pass" if ok else "rejected_security"
    return ok, reasons
