from __future__ import annotations


BACKEND_UNSUPPORTED_MARKERS = (
    "unsupported ",
    "not supported",
    "cannot be represented losslessly",
    "refusing to reinterpret",
    "cannot be disabled",
    "unknown utls fingerprint",
    "unknown uTLS fingerprint",
)

INVALID_CONFIG_MARKERS = (
    "invalid ",
    "missing ",
    "must be ",
    "must contain ",
    "expected ",
    "malformed",
    "unknown field",
)


def classify_core_error(error: str | None) -> str | None:
    """Classify a failed core validation without changing rejection semantics.

    Categories are intentionally broad and diagnostic only:
    - invalid_config: malformed or internally invalid proxy configuration;
    - backend_unsupported: source option cannot be represented/tested by our
      sing-box backend;
    - runtime_error: everything else, including local execution failures.
    """
    if not error:
        return None
    text = error.lower()
    if any(marker.lower() in text for marker in BACKEND_UNSUPPORTED_MARKERS):
        return "backend_unsupported"
    if any(marker.lower() in text for marker in INVALID_CONFIG_MARKERS):
        return "invalid_config"
    return "runtime_error"


def annotate_core_category(proxy) -> None:
    core = proxy.tests.core or {}
    if core.get("status") != "fail":
        return
    if core.get("category"):
        return
    core["category"] = classify_core_error(core.get("error"))
    proxy.tests.core = core