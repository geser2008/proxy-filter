from __future__ import annotations

from pathlib import Path

from .diversity import select_diverse
from .io import write_json, write_jsonl, write_text
from .model import ProxyConfig
from .reliability import DEGRADED, STABLE


FINAL_SUBSCRIPTION_NAMES = ("all.txt", "stable.txt", "unstable.txt")


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


def publish_subscription(proxies: list[ProxyConfig], *, txt_path: Path) -> None:
    """Atomically publish one rendered TXT subscription."""
    write_text(txt_path, subscription_text(proxies))


def publish_source(
    data_dir: Path,
    source_id: str,
    proxies: list[ProxyConfig],
) -> tuple[None, None]:
    """Compatibility no-op: per-source final subscriptions are disabled.

    Source provenance remains available in work/state/history JSONL records, but
    final publication is intentionally global only: all/stable/unstable.
    """
    return None, None


def _reliability_status(proxy: ProxyConfig) -> str:
    return str((proxy.tests.reliability or {}).get("status") or "unknown")


def _clean_output_dir(output_dir: Path) -> None:
    """Remove stale publication files before writing the canonical final set."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for path in output_dir.iterdir():
        if path.is_file():
            path.unlink()


def _publish_reliability_views(data_dir: Path, proxies: list[ProxyConfig]) -> tuple[Path, Path, dict[str, int]]:
    """Publish stable/degraded views of the already diversity-selected set.

    Diversity is intentionally applied before this split so infrastructure limits
    are global rather than independently refilled by each reliability class.
    """
    output_dir = data_dir / "output"
    stable = [proxy for proxy in proxies if _reliability_status(proxy) == STABLE]
    unstable = [proxy for proxy in proxies if _reliability_status(proxy) == DEGRADED]

    stable_path = output_dir / "stable.txt"
    unstable_path = output_dir / "unstable.txt"
    publish_subscription(stable, txt_path=stable_path)
    publish_subscription(unstable, txt_path=unstable_path)
    return stable_path, unstable_path, {
        "all": len(proxies),
        "stable": len(stable),
        "unstable": len(unstable),
        "unclassified": len(proxies) - len(stable) - len(unstable),
    }


def publish_merged(
    data_dir: Path,
    proxies: list[ProxyConfig],
    diversity_cfg: dict | None = None,
) -> tuple[Path, Path, Path]:
    """Publish exactly all.txt, stable.txt and unstable.txt after diversity.

    Canonical JSONL snapshots remain in data/work and data/state. The public
    output directory contains only the three subscription TXT files.
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

    # Internal diagnostic/checkpoint files remain JSONL under work/.
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
    _clean_output_dir(output_dir)

    all_path = output_dir / "all.txt"
    publish_subscription(proxies, txt_path=all_path)
    stable_path, unstable_path, split_counts = _publish_reliability_views(data_dir, proxies)
    write_json(reports_dir / "subscriptions.json", split_counts)

    return all_path, stable_path, unstable_path
