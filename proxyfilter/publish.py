from __future__ import annotations

import os
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory

from .diversity import select_diverse
from .io import write_json, write_jsonl, write_text
from .model import ProxyConfig
from .reliability import DEGRADED, STABLE
from .reliable_history import (
    DEFAULT_MIN_CONFIRMED_PASSES,
    DEFAULT_MIN_CONSECUTIVE_PASSES,
    reliability_db_path,
    reliable_ids as load_reliable_ids,
    reliable_name_metrics,
    snapshot_run_key,
    terminal_outcomes_from_work,
    update_global_reliability,
)
from .render import render_uri, validate_round_trip


FINAL_SUBSCRIPTION_NAMES = ("all.txt", "stable.txt", "unstable.txt", "reliable.txt")


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
    """Compatibility no-op: per-source final subscriptions are disabled."""
    return None, None


def _reliability_status(proxy: ProxyConfig) -> str:
    return str((proxy.tests.reliability or {}).get("status") or "unknown")


def _subscription_generation(
    proxies: list[ProxyConfig],
    reliable_ids: set[str] | None = None,
) -> tuple[dict[str, str], dict[str, int], list[ProxyConfig]]:
    """Render the complete publication generation before touching live files."""
    reliable_ids = reliable_ids or set()
    stable = [proxy for proxy in proxies if _reliability_status(proxy) == STABLE]
    unstable = [proxy for proxy in proxies if _reliability_status(proxy) == DEGRADED]
    reliable = [proxy for proxy in proxies if proxy.ensure_id() in reliable_ids]
    texts = {
        "all.txt": subscription_text(proxies),
        "stable.txt": subscription_text(stable),
        "unstable.txt": subscription_text(unstable),
        "reliable.txt": subscription_text(reliable),
    }
    counts = {
        "all": len(proxies),
        "stable": len(stable),
        "unstable": len(unstable),
        "reliable": len(reliable),
        "unclassified": len(proxies) - len(stable) - len(unstable),
    }
    return texts, counts, reliable


def _publish_subscription_generation(output_dir: Path, texts: dict[str, str]) -> None:
    """Transactionally replace only proxy-filter managed subscription files."""
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
                except Exception as rollback_exc:  # pragma: no cover
                    rollback_errors.append(rollback_exc)
            if rollback_errors:
                raise RuntimeError(
                    "subscription publication failed and rollback was incomplete"
                ) from rollback_errors[0]
            raise


def _historical_reliable_ids(
    data_dir: Path,
    qualified: list[ProxyConfig],
    reliable_cfg: dict | None,
    history_cfg: dict | None,
) -> tuple[set[str], dict]:
    cfg = reliable_cfg or {}
    enabled = bool(cfg.get("enabled", True))
    min_confirmed = int(cfg.get("min_confirmed_passes", DEFAULT_MIN_CONFIRMED_PASSES))
    min_consecutive = int(cfg.get("min_consecutive_passes", DEFAULT_MIN_CONSECUTIVE_PASSES))
    name_metric = str(cfg.get("name_metric", "raw")).lower()
    name_show_counts = bool(cfg.get("name_show_counts", True))
    db_path = reliability_db_path(data_dir, history_cfg)

    report = {
        "enabled": enabled,
        "database": str(db_path),
        "min_confirmed_passes": min_confirmed,
        "min_consecutive_passes": min_consecutive,
        "name_metric": name_metric,
        "name_show_counts": name_show_counts,
        "update": {"tested": 0, "passed": 0, "failed": 0, "skipped": 1},
        "eligible": 0,
    }
    if not enabled:
        return set(), report

    work_dir = data_dir / "work"
    parsed = work_dir / "01-parsed.jsonl"
    if parsed.is_file():
        passed, failed = terminal_outcomes_from_work(work_dir, qualified)
        run_key = snapshot_run_key(work_dir, passed, failed)
        if run_key is not None:
            report["update"] = update_global_reliability(
                db_path,
                passed,
                failed,
                run_key=run_key,
            )
            report["run_key"] = run_key

    ids = load_reliable_ids(
        db_path,
        min_confirmed_passes=min_confirmed,
        min_consecutive_passes=min_consecutive,
    )
    report["eligible"] = len(ids)
    return ids, report


def _apply_reliable_name_metrics(
    data_dir: Path,
    proxies: list[ProxyConfig],
    reliable_cfg: dict | None,
    history_cfg: dict | None,
) -> int:
    """Re-render only eligible reliable proxies with a derived history marker."""
    cfg = reliable_cfg or {}
    if not bool(cfg.get("enabled", True)):
        return 0

    metric = str(cfg.get("name_metric", "raw")).lower()
    if metric == "none":
        return 0

    min_confirmed = int(cfg.get("min_confirmed_passes", DEFAULT_MIN_CONFIRMED_PASSES))
    min_consecutive = int(cfg.get("min_consecutive_passes", DEFAULT_MIN_CONSECUTIVE_PASSES))
    show_counts = bool(cfg.get("name_show_counts", True))
    db_path = reliability_db_path(data_dir, history_cfg)
    markers = reliable_name_metrics(
        db_path,
        min_confirmed_passes=min_confirmed,
        min_consecutive_passes=min_consecutive,
        metric=metric,
        show_counts=show_counts,
    )

    changed = 0
    for proxy in proxies:
        marker = markers.get(proxy.ensure_id())
        if not marker:
            continue
        render = dict(proxy.tests.render or {})
        if render.get("status") != "pass":
            continue
        base_name = str(render.get("base_name") or render.get("name") or proxy.name or "").strip()
        name = f"{base_name} | {marker}" if base_name else marker
        uri = render_uri(proxy, name)
        validate_round_trip(proxy, uri)
        render["base_name"] = base_name
        render["name"] = name
        render["uri"] = uri
        render["historical_reliability"] = marker
        proxy.tests.render = render
        changed += 1
    return changed


def publish_merged(
    data_dir: Path,
    proxies: list[ProxyConfig],
    diversity_cfg: dict | None = None,
    reliable_ids: set[str] | None = None,
    reliable_cfg: dict | None = None,
    history_cfg: dict | None = None,
) -> tuple[Path, None]:
    """Publish all/stable/unstable/reliable subscriptions after diversity."""
    diversity_cfg = diversity_cfg or {}
    enabled = bool(diversity_cfg.get("enabled", True))
    work_dir = data_dir / "work"
    reports_dir = data_dir / "reports"

    for proxy in proxies:
        proxy.tests.status = "qualified"
    write_jsonl(work_dir / "12-qualified.jsonl", proxies)

    auto_reliable = reliable_ids is None
    if auto_reliable:
        reliable_ids, reliable_report = _historical_reliable_ids(
            data_dir,
            proxies,
            reliable_cfg,
            history_cfg,
        )
        reliable_report["name_annotated"] = _apply_reliable_name_metrics(
            data_dir,
            proxies,
            reliable_cfg,
            history_cfg,
        )
        write_json(reports_dir / "reliable.json", reliable_report)

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

    texts, split_counts, reliable = _subscription_generation(proxies, reliable_ids)
    write_jsonl(work_dir / "reliable.jsonl", reliable)
    output_dir = data_dir / "output"
    _publish_subscription_generation(output_dir, texts)
    write_json(reports_dir / "subscriptions.json", split_counts)

    return output_dir / "all.txt", None
