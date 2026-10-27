from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from .io import write_jsonl
from .model import ProxyConfig


REJECTED_STAGE_FILES = (
    "03-rejected-security.jsonl",
    "04-rejected-tcp.jsonl",
    "05-rejected-core.jsonl",
    "06-rejected-latency.jsonl",
    "07-rejected-download.jsonl",
    "08-rejected-upload.jsonl",
    "09-rejected-exit-ip.jsonl",
    "11-rejected-render.jsonl",
)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _read_jsonl(path: Path) -> list[ProxyConfig]:
    if not path.is_file():
        return []
    import json

    proxies: list[ProxyConfig] = []
    with path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            text = line.strip()
            if not text:
                continue
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON in {path}:{lineno}: {exc}") from exc
            if not isinstance(data, dict):
                raise ValueError(f"invalid record in {path}:{lineno}: expected JSON object")
            proxies.append(ProxyConfig.from_dict(data))
    return proxies


def load_known_working(
    data_dir: Path,
    selected_sources: set[str] | None = None,
) -> tuple[list[ProxyConfig], Path]:
    """Load retained working proxies, migrating transparently from working.jsonl."""
    state_dir = data_dir / "state"
    primary = state_dir / "known-working.jsonl"
    legacy = state_dir / "working.jsonl"
    path = primary if primary.is_file() else legacy
    proxies = _read_jsonl(path)

    legacy_time = None
    if path.is_file():
        legacy_time = _iso(datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc))

    for proxy in proxies:
        if not proxy.lifecycle:
            # Legacy working.jsonl contained only proxies that had just passed a
            # full run, so its mtime is a safe migration baseline.
            proxy.lifecycle = {
                "first_seen": legacy_time,
                "last_seen": legacy_time,
                "last_working": legacy_time,
                "last_tested": legacy_time,
                "consecutive_failures": 0,
            }

    selected = selected_sources or set()
    if selected:
        proxies = [
            proxy
            for proxy in proxies
            if {source.id for source in proxy.provenance_sources()} & selected
        ]
    return proxies, path


def load_rejected_candidates(data_dir: Path) -> list[ProxyConfig]:
    rejected: dict[str, ProxyConfig] = {}
    work_dir = data_dir / "work"
    for filename in REJECTED_STAGE_FILES:
        for proxy in _read_jsonl(work_dir / filename):
            rejected[proxy.ensure_id()] = proxy
    return list(rejected.values())


def update_known_working(
    data_dir: Path,
    previous: list[ProxyConfig],
    passed: list[ProxyConfig],
    rejected: list[ProxyConfig],
    *,
    seen_ids: set[str],
    retention_days: int = 30,
    now: datetime | None = None,
) -> dict[str, int]:
    """Update retained state after one successful full fresh run.

    New proxies enter the state only after passing the complete qualifying
    pipeline. Previously working proxies that fail remain eligible for re-test
    until their last successful run is older than retention_days.
    """
    if retention_days < 0:
        raise ValueError("state.working_retention_days must be non-negative")

    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    now_text = _iso(now)
    cutoff = now - timedelta(days=retention_days)

    previous_by_id = {proxy.ensure_id(): proxy for proxy in previous}
    rejected_by_id = {proxy.ensure_id(): proxy for proxy in rejected}
    passed_by_id = {proxy.ensure_id(): proxy for proxy in passed}

    retained: dict[str, ProxyConfig] = {}
    expired = 0
    new_working = 0
    recovered = 0
    failing_retained = 0

    for proxy_id, proxy in passed_by_id.items():
        old = previous_by_id.get(proxy_id)
        old_lifecycle = dict(old.lifecycle) if old else {}
        was_failing = int(old_lifecycle.get("consecutive_failures") or 0) > 0
        first_seen = old_lifecycle.get("first_seen") or now_text
        last_seen = now_text if proxy_id in seen_ids else old_lifecycle.get("last_seen")
        proxy.lifecycle = {
            "first_seen": first_seen,
            "last_seen": last_seen,
            "last_working": now_text,
            "last_tested": now_text,
            "consecutive_failures": 0,
        }
        retained[proxy_id] = proxy
        if old is None:
            new_working += 1
        elif was_failing:
            recovered += 1

    for proxy_id, old in previous_by_id.items():
        if proxy_id in passed_by_id:
            continue

        failed = rejected_by_id.get(proxy_id)
        if failed is None:
            # A full publish run should have an outcome for every retained proxy.
            # Preserve it rather than deleting state on an unexpected gap.
            retained[proxy_id] = old
            continue

        lifecycle = dict(old.lifecycle)
        last_working = _parse_iso(lifecycle.get("last_working"))
        if last_working is None:
            # Unknown age is treated conservatively: give the proxy one fresh
            # retention window instead of expiring migrated/corrupt state.
            last_working = now
            lifecycle["last_working"] = now_text

        lifecycle["last_tested"] = now_text
        if proxy_id in seen_ids:
            lifecycle["last_seen"] = now_text
        lifecycle["consecutive_failures"] = int(lifecycle.get("consecutive_failures") or 0) + 1
        failed.lifecycle = lifecycle

        if last_working < cutoff:
            expired += 1
            continue

        retained[proxy_id] = failed
        failing_retained += 1

    result = sorted(
        retained.values(),
        key=lambda proxy: (
            str(proxy.lifecycle.get("last_working") or ""),
            proxy.ensure_id(),
        ),
        reverse=True,
    )
    write_jsonl(data_dir / "state" / "known-working.jsonl", result)

    return {
        "retained": len(result),
        "working_now": len(passed_by_id),
        "failing_retained": failing_retained,
        "new_working": new_working,
        "recovered": recovered,
        "expired": expired,
    }
