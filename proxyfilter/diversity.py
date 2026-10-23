from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address, ip_network
from typing import Any

from .model import ProxyConfig


def _asn(proxy: ProxyConfig) -> str | None:
    value = (proxy.tests.geo or {}).get("asn")
    if value is None or value == "":
        return None
    return str(value)


def _subnet(ip_text: str, ipv4_prefix: int, ipv6_prefix: int) -> str | None:
    try:
        addr = ip_address(ip_text)
    except ValueError:
        return None
    prefix = ipv4_prefix if addr.version == 4 else ipv6_prefix
    return str(ip_network(f"{addr}/{prefix}", strict=False))


def infrastructure_key(
    proxy: ProxyConfig,
    *,
    ipv4_prefix: int = 24,
    ipv6_prefix: int = 48,
) -> tuple[str, str]:
    """Return a conservative failure-domain key for diversity selection.

    Prefer the measured exit network plus ASN. If that evidence is unavailable,
    fall back only to exact measured exit IP, then exact server endpoint. We do
    not infer shared infrastructure merely from adjacent server addresses.
    """
    exit_ip = proxy.tests.exit_ip
    asn = _asn(proxy)
    if exit_ip:
        subnet = _subnet(exit_ip, ipv4_prefix, ipv6_prefix)
        if subnet and asn:
            return "exit-subnet-asn", f"{subnet}|AS{asn}"
        return "exit-ip", exit_ip
    return "endpoint", f"{proxy.server.strip().lower()}:{int(proxy.port)}"


def _metric_ranks(
    group: list[ProxyConfig],
    getter,
    *,
    reverse: bool,
) -> dict[str, int]:
    ordered = sorted(
        group,
        key=lambda proxy: (
            getter(proxy) is None,
            -(getter(proxy) or 0) if reverse else (getter(proxy) if getter(proxy) is not None else float("inf")),
            proxy.id,
        ),
    )
    ranks: dict[str, int] = {}
    previous: float | None = None
    previous_rank = 0
    for position, proxy in enumerate(ordered, 1):
        value = getter(proxy)
        if value is None:
            rank = position
        elif previous is not None and value == previous:
            rank = previous_rank
        else:
            rank = position
        ranks[proxy.id] = rank
        previous = value
        previous_rank = rank
    return ranks


def select_diverse(
    proxies: list[ProxyConfig],
    *,
    max_per_cluster: int = 2,
    ipv4_prefix: int = 24,
    ipv6_prefix: int = 48,
) -> tuple[list[ProxyConfig], list[ProxyConfig], list[dict[str, Any]]]:
    if max_per_cluster < 1:
        raise ValueError("diversity.max_per_cluster must be >= 1")
    if not 0 <= ipv4_prefix <= 32:
        raise ValueError("diversity.ipv4_prefix must be between 0 and 32")
    if not 0 <= ipv6_prefix <= 128:
        raise ValueError("diversity.ipv6_prefix must be between 0 and 128")

    groups: dict[tuple[str, str], list[ProxyConfig]] = defaultdict(list)
    for proxy in proxies:
        proxy.ensure_id()
        groups[infrastructure_key(proxy, ipv4_prefix=ipv4_prefix, ipv6_prefix=ipv6_prefix)].append(proxy)

    selected: list[ProxyConfig] = []
    suppressed: list[ProxyConfig] = []
    report: list[dict[str, Any]] = []

    for (key_type, key_value), group in sorted(groups.items(), key=lambda item: item[0]):
        latency_ranks = _metric_ranks(group, lambda p: p.tests.latency_ms, reverse=False)
        download_ranks = _metric_ranks(group, lambda p: p.tests.download_mbps, reverse=True)
        upload_ranks = _metric_ranks(group, lambda p: p.tests.upload_mbps, reverse=True)

        ranked: list[tuple[int, float, float, float, str, ProxyConfig]] = []
        for proxy in group:
            latency_rank = latency_ranks[proxy.id]
            download_rank = download_ranks[proxy.id]
            upload_rank = upload_ranks[proxy.id]
            rank_sum = latency_rank + download_rank + upload_rank
            ranked.append((
                rank_sum,
                proxy.tests.latency_ms if proxy.tests.latency_ms is not None else float("inf"),
                -(proxy.tests.download_mbps or 0),
                -(proxy.tests.upload_mbps or 0),
                proxy.id,
                proxy,
            ))
            proxy.tests.diversity = {
                "status": "pending",
                "cluster_type": key_type,
                "cluster_key": key_value,
                "cluster_size": len(group),
                "latency_rank": latency_rank,
                "download_rank": download_rank,
                "upload_rank": upload_rank,
                "rank_sum": rank_sum,
                "overall_rank": None,
                "reason": None,
            }

        ranked.sort(key=lambda row: row[:-1])
        members: list[dict[str, Any]] = []
        for overall_rank, row in enumerate(ranked, 1):
            proxy = row[-1]
            keep = overall_rank <= max_per_cluster
            proxy.tests.diversity["overall_rank"] = overall_rank
            proxy.tests.diversity["status"] = "selected" if keep else "suppressed"
            proxy.tests.diversity["reason"] = None if keep else "cluster_limit"
            if keep:
                selected.append(proxy)
            else:
                proxy.tests.status = "diversity_suppressed"
                suppressed.append(proxy)
            members.append({
                "id": proxy.id,
                "selected": keep,
                "latency_ms": proxy.tests.latency_ms,
                "download_mbps": proxy.tests.download_mbps,
                "upload_mbps": proxy.tests.upload_mbps,
                "latency_rank": proxy.tests.diversity["latency_rank"],
                "download_rank": proxy.tests.diversity["download_rank"],
                "upload_rank": proxy.tests.diversity["upload_rank"],
                "rank_sum": proxy.tests.diversity["rank_sum"],
                "overall_rank": overall_rank,
            })

        report.append({
            "cluster_type": key_type,
            "cluster_key": key_value,
            "members": len(group),
            "selected": min(len(group), max_per_cluster),
            "suppressed": max(0, len(group) - max_per_cluster),
            "proxies": members,
        })

    return selected, suppressed, report
