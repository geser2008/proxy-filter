from __future__ import annotations

from .model import ProxyConfig


def classify_error(error: object, *, http_code: object = None, payload_valid: object = None) -> str | None:
    """Return a stable machine-readable reason for a technical failure."""
    if payload_valid is False:
        return "invalid_payload"

    try:
        code = int(http_code) if http_code not in {None, ""} else None
    except (TypeError, ValueError):
        code = None
    if code and code >= 400:
        return f"http_{code}"

    text = str(error or "").strip().lower()
    if not text:
        return None
    if "curl: (28)" in text or "timed out" in text or "timeout" in text:
        return "timeout"
    if any(marker in text for marker in ("name or service not known", "temporary failure in name resolution", "no address associated with hostname", "could not resolve")):
        return "dns_error"
    if "connection refused" in text:
        return "connection_refused"
    if "network is unreachable" in text:
        return "network_unreachable"
    if "no route to host" in text:
        return "no_route_to_host"
    if "socks" in text:
        return "socks_error"
    if any(marker in text for marker in ("tls", "ssl", "certificate")):
        return "tls_error"
    if any(marker in text for marker in ("connection reset", "connection aborted", "remote end closed", "eof")):
        return "connection_error"
    return "transport_error"


def annotate_failure_reasons(proxy: ProxyConfig) -> None:
    """Ensure every tested stage records a stable reason when it did not pass.

    The raw ``error`` field remains untouched for human diagnostics; ``reason``
    is a compact code suitable for reports/history and comparisons between runs.
    """
    tests = proxy.tests
    final_status = str(tests.status or "")

    security = tests.security or {}
    if security.get("status") in {"reject", "fail"} and not security.get("reason"):
        reasons = security.get("reasons") or []
        security["reason"] = str(reasons[0]) if reasons else "security_policy"
    tests.security = security

    tcp = tests.tcp or {}
    if tcp.get("status") in {"reject", "fail"} and not tcp.get("reason"):
        tcp["reason"] = classify_error(tcp.get("error")) or "tcp_connect_failed"
    tests.tcp = tcp

    core = tests.core or {}
    if core.get("status") == "fail" and not core.get("reason"):
        core["reason"] = core.get("category") or classify_error(core.get("error")) or "core_validation_failed"
    tests.core = core

    latency = tests.latency or {}
    if latency.get("status") == "fail" and not latency.get("reason"):
        if final_status == "rejected_latency_threshold":
            latency["reason"] = "above_max_latency"
        else:
            latency["reason"] = classify_error(
                latency.get("error"), http_code=latency.get("http_code")
            ) or "latency_probe_failed"
    tests.latency = latency

    download = tests.download or {}
    if download.get("status") == "fail" and not download.get("reason"):
        if final_status == "rejected_download_threshold":
            download["reason"] = "below_min_download_mbps"
        else:
            download["reason"] = classify_error(
                download.get("error"),
                http_code=download.get("http_code"),
                payload_valid=download.get("payload_valid"),
            ) or "download_probe_failed"
    tests.download = download

    upload = tests.upload or {}
    if upload.get("status") == "fail" and not upload.get("reason"):
        if final_status == "rejected_upload_threshold":
            upload["reason"] = "below_min_upload_mbps"
        else:
            upload["reason"] = classify_error(
                upload.get("error"), http_code=upload.get("http_code")
            ) or "upload_probe_failed"
    tests.upload = upload

    exit_ip = tests.exit_ip_probe or {}
    if exit_ip.get("status") in {"fail", "unknown"} and not exit_ip.get("reason"):
        if final_status == "rejected_exit_ip_direct_wan" or exit_ip.get("direct_wan_match"):
            exit_ip["reason"] = "direct_wan_match"
        else:
            exit_ip["reason"] = classify_error(
                exit_ip.get("error"), http_code=exit_ip.get("http_code")
            ) or "exit_ip_lookup_failed"
    tests.exit_ip_probe = exit_ip

    geo = tests.geo or {}
    if geo.get("status") in {"error", "unknown"} and not geo.get("reason"):
        if not tests.exit_ip:
            geo["reason"] = "exit_ip_unknown"
        else:
            geo["reason"] = classify_error(geo.get("error")) or "geo_lookup_failed"
    tests.geo = geo

    render = tests.render or {}
    if render.get("status") == "fail" and not render.get("reason"):
        render["reason"] = "render_error"
    tests.render = render

    reliability = tests.reliability or {}
    if reliability.get("status") == "degraded" and not reliability.get("reason"):
        reliability["reason"] = "stream_instability"
    tests.reliability = reliability

    diversity = tests.diversity or {}
    if diversity.get("status") == "suppressed" and not diversity.get("reason"):
        diversity["reason"] = "diversity_limit"
    tests.diversity = diversity
