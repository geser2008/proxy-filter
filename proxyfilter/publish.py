from __future__ import annotations

import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory

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


def _subscription_generation(proxies: list[ProxyConfig]) -> tuple[dict[str, str], dict[str, int]]:
    """Render the complete publication generation before touching live files."""
    stable = [proxy for proxy in proxies if _reliability_status(proxy) == STABLE]
    unstable = [proxy for proxy in proxies if _reliability_status(proxy) == DEGRADED]
    texts = {
        "all.txt": subscription_text(proxies),
        "stable.txt": subscription_text(stable),
        "unstable.txt": subscription_text(unstable),
    }
    counts = {
        "all": len(proxies),
        "stable": len(stable),
        "unstable": len(unstable),
        "unclassified": len(proxies) - len(stable) - len(unstable),
    }
    return texts, counts


def _publish_subscription_generation(output_dir: Path, texts: dict[str, str]) -> None:
    """Transactionally replace only proxy-filter managed subscription files.

    The complete next generation is prepared first. Existing managed files are
    copied into a rollback area, then each prepared file is moved into place with
    os.replace(). If any commit step raises, the previous managed generation is
    restored. Unmanaged files in output_dir are never removed or modified.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    unexpected = set(texts) - set(FINAL_SUBSCRIPTION_NAMES)
    missing = set(FINAL_SUBSCRIPTION_NAMES) - set(texts)
    if unexpected or missing:
        raise ValueError(
            "invalid subscription generation: "
            f"missing={sorted(missing)} unexpected={sorted(unexpected)}"
        )

    with TemporaryDirectory(prefix=".publish-", dir=output_dir) as tmp:
        transaction_dir = Path(tmp)
        new_dir = transaction_dir / "new"
        backup_dir = transaction_dir / "backup"
        new_dir.mkdir()
        backup_dir.mkdir()

        existed: set[str] = set()
        for name in FINAL_SUBSCRIPTION_NAMES:
            target = output_dir / name
            if target.exists():
                if not target.is_file():
                    raise ValueError(f"publication target is not a regular file: {target}")
                shutil.copy2(target, backup_dir / name)
                existed.add(name)
            (new_dir / name).write_text(texts[name], encoding="utf-8")

        try:
            for name in FINAL_SUBSCRIPTION_NAMES:
                os.replace(new_dir / name, output_dir / name)
        except Exception:
            rollback_errors: list[Exception] = []
            for name in FINAL_SUBSCRIPTION_NAMES:
                target = output_dir / name
                try:
                    if name in existed:
                        backup = backup_dir / name
                        if backup.exists():
                            os.replace(backup, target)
                    elif target.exists():
                        target.unlink()
                except Exception as rollback_exc:  # pragma: no cover - catastrophic filesystem failure
                    rollback_errors.append(rollback_exc)
            if rollback_errors:
                raise RuntimeError(
                    "subscription publication failed and rollback was incomplete"
                ) from rollback_errors[0]
            raise


def publish_merged(
    data_dir: Path,
    proxies: list[ProxyConfig],
    diversity_cfg: dict | None = None,
) -> tuple[Path, None]:
    """Publish all.txt, stable.txt and unstable.txt after diversity.

    Canonical JSONL snapshots remain in data/work and data/state. Only the three
    managed subscription files are replaced in data/output; unrelated files are
    preserved.

    The second return value is kept as None for compatibility with the existing
    caller that previously expected an output JSONL path.
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

    # Render/validate the whole next generation before changing any live
    # subscription file. This prevents one bad view from leaving a partial set.
    texts, split_counts = _subscription_generation(proxies)
    output_dir = data_dir / "output"
    _publish_subscription_generation(output_dir, texts)
    write_json(reports_dir / "subscriptions.json", split_counts)

    return output_dir / "all.txt", None
