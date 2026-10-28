from __future__ import annotations

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
