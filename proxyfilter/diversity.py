from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address, ip_network
from typing import Any

from .model import ProxyConfig


def _asn(proxy: ProxyConfig) -> str | None:
    value = (proxy.tests.geo or {}).get("asn")
    if value is None or value == "":
        return None
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    return text or None


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


def _rank_group(group: list[ProxyConfig]) -> list[tuple[int, float, float, float, str, ProxyConfig]]:
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
    ranked.sort(key=lambda row: row[:-1])
    return ranked


def _rank_data(group: list[ProxyConfig], ranked) -> dict[str, dict[str, int]]:
    latency_ranks = _metric_ranks(group, lambda p: p.tests.latency_ms, reverse=False)
    download_ranks = _metric_ranks(group, lambda p: p.tests.download_mbps, reverse=True)
    upload_ranks = _metric_ranks(group, lambda p: p.tests.upload_mbps, reverse=True)
    overall = {row[-1].id: position for position, row in enumerate(ranked, 1)}
    return {
        proxy.id: {
            "latency_rank": latency_ranks[proxy.id],
            "download_rank": download_ranks[proxy.id],
            "upload_rank": upload_ranks[proxy.id],
            "rank_sum": latency_ranks[proxy.id] + download_ranks[proxy.id] + upload_ranks[proxy.id],
            "overall_rank": overall[proxy.id],
        }
        for proxy in group
    }


def select_diverse(
    proxies: list[ProxyConfig],
    *,
    max_same_exit_ip: int = 1,
    max_same_exit_subnet_asn: int = 2,
    ipv4_prefix: int = 24,
    ipv6_prefix: int = 48,
    max_per_cluster: int | None = None,
) -> tuple[list[ProxyConfig], list[ProxyConfig], list[dict[str, Any]]]:
    """Select representatives in two stages.

    Stage 1 keeps at most ``max_same_exit_ip`` proxies sharing the exact measured
    exit IP. Stage 2 then keeps at most ``max_same_exit_subnet_asn`` proxies per
    measured exit subnet + ASN infrastructure cluster. Both stages use the same
    equal-weight rank sum over latency, download and upload.

    ``max_per_cluster`` is retained as a compatibility alias for callers of the
    first diversity implementation and maps to ``max_same_exit_subnet_asn``.
    """
    if max_per_cluster is not None:
        max_same_exit_subnet_asn = max_per_cluster
    if max_same_exit_ip < 1:
        raise ValueError("diversity.max_same_exit_ip must be >= 1")
    if max_same_exit_subnet_asn < 1:
        raise ValueError("diversity.max_same_exit_subnet_asn must be >= 1")
    if not 0 <= ipv4_prefix <= 32:
        raise ValueError("diversity.ipv4_prefix must be between 0 and 32")
    if not 0 <= ipv6_prefix <= 128:
        raise ValueError("diversity.ipv6_prefix must be between 0 and 128")

    for proxy in proxies:
        proxy.ensure_id()
        proxy.tests.diversity = {
            "status": "pending",
            "reason": None,
            "stages": {},
        }

    suppressed: list[ProxyConfig] = []
    report: list[dict[str, Any]] = []

    # Stage 1: collapse multiple otherwise-distinct configs that actually leave
    # through the same measured public IP. Unknown exits are deliberately not
    # grouped here because there is no evidence that they share a failure domain.
    exact_groups: dict[str, list[ProxyConfig]] = defaultdict(list)
    no_exit: list[ProxyConfig] = []
    for proxy in proxies:
        if proxy.tests.exit_ip:
            exact_groups[proxy.tests.exit_ip].append(proxy)
        else:
            no_exit.append(proxy)

    stage1_candidates: list[ProxyConfig] = list(no_exit)
    for exit_ip, group in sorted(exact_groups.items()):
        ranked = _rank_group(group)
        ranks = _rank_data(group, ranked)
        members: list[dict[str, Any]] = []
        for position, row in enumerate(ranked, 1):
            proxy = row[-1]
            keep = position <= max_same_exit_ip
            stage_data = {
                "cluster_type": "exact-exit-ip",
                "cluster_key": exit_ip,
                "cluster_size": len(group),
                **ranks[proxy.id],
                "selected": keep,
            }
            proxy.tests.diversity["stages"]["exit_ip"] = stage_data
            if keep:
                stage1_candidates.append(proxy)
            else:
                proxy.tests.diversity["status"] = "suppressed"
                proxy.tests.diversity["reason"] = "same_exit_ip_limit"
                proxy.tests.status = "diversity_suppressed"
                suppressed.append(proxy)
            members.append({
                "id": proxy.id,
                "selected": keep,
                "latency_ms": proxy.tests.latency_ms,
                "download_mbps": proxy.tests.download_mbps,
                "upload_mbps": proxy.tests.upload_mbps,
                **ranks[proxy.id],
            })

        report.append({
            "stage": "exact-exit-ip",
            "cluster_type": "exact-exit-ip",
            "cluster_key": exit_ip,
            "members": len(group),
            "selected": min(len(group), max_same_exit_ip),
            "suppressed": max(0, len(group) - max_same_exit_ip),
            "proxies": members,
        })

    # Stage 2: apply the broader infrastructure cap only after exact exit-IP
    # duplicates have been reduced to their best representative(s).
    groups: dict[tuple[str, str], list[ProxyConfig]] = defaultdict(list)
    for proxy in stage1_candidates:
        groups[infrastructure_key(proxy, ipv4_prefix=ipv4_prefix, ipv6_prefix=ipv6_prefix)].append(proxy)

    selected: list[ProxyConfig] = []
    for (key_type, key_value), group in sorted(groups.items(), key=lambda item: item[0]):
        ranked = _rank_group(group)
        ranks = _rank_data(group, ranked)
        members: list[dict[str, Any]] = []
        for position, row in enumerate(ranked, 1):
            proxy = row[-1]
            keep = position <= max_same_exit_subnet_asn
            rank_data = ranks[proxy.id]
            stage_data = {
                "cluster_type": key_type,
                "cluster_key": key_value,
                "cluster_size": len(group),
                **rank_data,
                "selected": keep,
            }
            proxy.tests.diversity["stages"]["infrastructure"] = stage_data
            proxy.tests.diversity.update({
                "cluster_type": key_type,
                "cluster_key": key_value,
                "cluster_size": len(group),
                **rank_data,
            })
            if keep:
                proxy.tests.diversity["status"] = "selected"
                proxy.tests.diversity["reason"] = None
                selected.append(proxy)
            else:
                proxy.tests.diversity["status"] = "suppressed"
                proxy.tests.diversity["reason"] = (
                    "same_exit_subnet_asn_limit" if key_type == "exit-subnet-asn" else "cluster_limit"
                )
                proxy.tests.status = "diversity_suppressed"
                suppressed.append(proxy)
            members.append({
                "id": proxy.id,
                "selected": keep,
                "latency_ms": proxy.tests.latency_ms,
                "download_mbps": proxy.tests.download_mbps,
                "upload_mbps": proxy.tests.upload_mbps,
                **rank_data,
            })

        report.append({
            "stage": "infrastructure",
            "cluster_type": key_type,
            "cluster_key": key_value,
            "members": len(group),
            "selected": min(len(group), max_same_exit_subnet_asn),
            "suppressed": max(0, len(group) - max_same_exit_subnet_asn),
            "proxies": members,
        })

    return selected, suppressed, report
