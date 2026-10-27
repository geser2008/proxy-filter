from __future__ import annotations

from pathlib import Path

from .diversity import select_diverse
from .io import write_json, write_jsonl, write_text
from .model import ProxyConfig


def _rendered_uri(proxy: ProxyConfig) -> str:
    render = proxy.tests.render or {}
    if render.get("status") != "pass":
        raise ValueError(f"proxy {proxy.id or '<unknown>'} is not render-pass")
    uri = render.get("uri")
    if not isinstance(uri, str) or not uri.strip():
        raise ValueError(f"proxy {proxy.id or '<unknown>'} has no rendered URI")
    return uri.strip()


def subscription_text(proxies: list[ProxyConfig]) -> str:
    if not proxies:
        return ""
    return "\n".join(_rendered_uri(proxy) for proxy in proxies) + "\n"


def publish_subscription(
    proxies: list[ProxyConfig],
    *,
    txt_path: Path,
    jsonl_path: Path,
) -> None:
    """Atomically publish a rendered subscription and its canonical JSONL snapshot."""
    text = subscription_text(proxies)
    write_text(txt_path, text)
    write_jsonl(jsonl_path, proxies)


def publish_source(data_dir: Path, source_id: str, proxies: list[ProxyConfig]) -> tuple[Path, Path]:
    output_dir = data_dir / "output"
    txt_path = output_dir / f"{source_id}.txt"
    jsonl_path = output_dir / f"{source_id}.jsonl"
    publish_subscription(proxies, txt_path=txt_path, jsonl_path=jsonl_path)
    return txt_path, jsonl_path


def publish_merged(
    data_dir: Path,
    proxies: list[ProxyConfig],
    diversity_cfg: dict | None = None,
) -> tuple[Path, Path]:
    """Publish the merged subscription after infrastructure diversity selection.

    The input set is the qualified working set: every proxy here has already
    passed the functional/speed pipeline and rendering. Diversity never turns a
    working proxy into a failure; it only selects which working proxies appear
    in the merged subscription.
    """
    diversity_cfg = diversity_cfg or {}
    enabled = bool(diversity_cfg.get("enabled", True))
    work_dir = data_dir / "work"
    reports_dir = data_dir / "reports"

    # Snapshot the complete working set before diversity. This is also the set
    # that should be carried into the next full run for re-testing.
    for proxy in proxies:
        proxy.tests.status = "qualified"
    write_jsonl(work_dir / "12-qualified.jsonl", proxies)

    if enabled:
        selected, suppressed, report = select_diverse(
            proxies,
            max_same_exit_ip=int(diversity_cfg.get("max_same_exit_ip", 1)),
            max_same_exit_subnet_asn=int(diversity_cfg.get("max_same_exit_subnet_asn", 2)),
            ipv4_prefix=int(diversity_cfg.get("ipv4_prefix", 24)),
            ipv6_prefix=int(diversity_cfg.get("ipv6_prefix", 48)),
        )
    else:
        selected, suppressed, report = list(proxies), [], []
        for proxy in selected:
            proxy.tests.diversity = {"status": "selected", "reason": None, "stages": {}}

    for proxy in selected:
        proxy.tests.diversity["status"] = "selected"
        proxy.tests.status = "diversity_selected"
    for proxy in suppressed:
        proxy.tests.diversity["status"] = "suppressed"
        proxy.tests.status = "diversity_suppressed"

    # New explicit stage files. Keep the legacy unnumbered names as compatibility
    # aliases for existing tooling/tests.
    write_jsonl(work_dir / "13-diversity-selected.jsonl", selected)
    write_jsonl(work_dir / "13-diversity-suppressed.jsonl", suppressed)
    write_jsonl(work_dir / "diversity-selected.jsonl", selected)
    write_jsonl(work_dir / "diversity-suppressed.jsonl", suppressed)
    write_json(reports_dir / "diversity.json", {
        "enabled": enabled,
        "input": len(proxies),
        "selected": len(selected),
        "suppressed": len(suppressed),
        "settings": {
            "max_same_exit_ip": int(diversity_cfg.get("max_same_exit_ip", 1)),
            "max_same_exit_subnet_asn": int(diversity_cfg.get("max_same_exit_subnet_asn", 2)),
            "ipv4_prefix": int(diversity_cfg.get("ipv4_prefix", 24)),
            "ipv6_prefix": int(diversity_cfg.get("ipv6_prefix", 48)),
        },
        "clusters": report,
    })

    proxies[:] = selected
    for proxy in proxies:
        proxy.tests.status = "published"
    write_jsonl(work_dir / "14-published.jsonl", proxies)

    output_dir = data_dir / "output"
    txt_path = output_dir / "all.txt"
    jsonl_path = output_dir / "all.jsonl"
    publish_subscription(proxies, txt_path=txt_path, jsonl_path=jsonl_path)
    return txt_path, jsonl_path