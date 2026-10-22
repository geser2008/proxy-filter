from __future__ import annotations

from pathlib import Path

from .io import write_jsonl, write_text
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
    output_dir = data_dir / "output"
    txt_path = output_dir / "all.txt"
    jsonl_path = output_dir / "all.jsonl"
    publish_subscription(proxies, txt_path=txt_path, jsonl_path=jsonl_path)
    return txt_path, jsonl_path
