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


def publish_merged(data_dir: Path, proxies: list[ProxyConfig]) -> tuple[Path, Path]:
    """Publish the merged subscription after infrastructure diversity selection.

    Per-source subscriptions stay complete. Only the merged all.txt/all.jsonl are
    reduced to at most two representatives per measured infrastructure cluster.
    The input list is updated in-place so caller summary counts match publication.
    """
    selected, suppressed, report = select_diverse(
        proxies,
        max_per_cluster=2,
        ipv4_prefix=24,
        ipv6_prefix=48,
    )

    work_dir = data_dir / "work" / "all"
    reports_dir = data_dir / "reports"
    write_jsonl(work_dir / "diversity-selected.jsonl", selected)
    write_jsonl(work_dir / "diversity-suppressed.jsonl", suppressed)
    write_json(reports_dir / "diversity.json", {
        "input": len(proxies),
        "selected": len(selected),
        "suppressed": len(suppressed),
        "clusters": report,
    })

    proxies[:] = selected

    output_dir = data_dir / "output"
    txt_path = output_dir / "all.txt"
    jsonl_path = output_dir / "all.jsonl"
    publish_subscription(proxies, txt_path=txt_path, jsonl_path=jsonl_path)
    return txt_path, jsonl_path
