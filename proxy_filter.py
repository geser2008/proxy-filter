#!/usr/bin/python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import yaml

from proxyfilter.batch_latency import check_latency_batched
from proxyfilter.debug_latency import debug_latency_proxy, find_proxy_in_work
from proxyfilter.exit_ip import check_exit_ip_many, discover_direct_ip
from proxyfilter.singbox_backend import SingBoxBackend
from proxyfilter.ingest import detect_and_parse
from proxyfilter.io import fetch_url, write_json, write_jsonl
from proxyfilter.probes import check_latency_many
from proxyfilter.security import check_static_security
from proxyfilter.speed import check_download_many, check_upload_many
from proxyfilter.tcpcheck import check_many


def deduplicate(proxies):
    unique = {}
    duplicates = []
    for proxy in proxies:
        proxy.ensure_id()
        if proxy.id in unique:
            proxy.tests.status = "rejected_duplicate"
            duplicates.append(proxy)
        else:
            unique[proxy.id] = proxy
    return list(unique.values()), duplicates


def build_engine(cfg, data_dir: Path):
    engine_cfg = cfg.get("engine", {})
    backend = str(engine_cfg.get("backend", "sing-box")).lower()
    if backend != "sing-box":
        raise ValueError(f"unsupported engine backend: {backend}")
    return SingBoxBackend(
        command=str(engine_cfg.get("command", "sing-box")),
        runtime_dir=str(engine_cfg.get("runtime_dir", data_dir / "runtime")),
        listen_host=str(engine_cfg.get("listen_host", "127.0.0.1")),
        startup_timeout=float(engine_cfg.get("startup_timeout_seconds", 5)),
        shutdown_timeout=float(engine_cfg.get("shutdown_timeout_seconds", 3)),
    )


def _as_string_list(value):
    if isinstance(value, str):
        return [value] if value else []
    return [str(item) for item in (value or []) if str(item)]


def _as_int_set(value, default):
    raw = default if value is None else value
    if isinstance(raw, (int, str)):
        raw = [raw]
    return {int(item) for item in (raw or [])}


def process_source(source, cfg, data_dir: Path, until: str, engine):
    source_id = source["id"]
    source_name = source.get("name", source_id)
    work = data_dir / "work" / source_id
    raw_dir = data_dir / "raw"
    reports = data_dir / "reports"
    work.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)

    print(f"[{source_id}] download {source['url']}")
    raw = fetch_url(source["url"])
    (raw_dir / f"{source_id}.raw").write_bytes(raw)

    proxies, parse_errors, detected_format = detect_and_parse(raw, source_id, source_name)
    for proxy in proxies:
        proxy.source.format = detected_format
    write_jsonl(work / "01-parsed.jsonl", proxies)
    write_json(reports / f"{source_id}-parse-errors.json", parse_errors)
    print(f"[{source_id}] parsed={len(proxies)} errors={len(parse_errors)} format={detected_format}")
    if until == "parse":
        return proxies

    proxies, duplicates = deduplicate(proxies)
    write_jsonl(work / "02-unique.jsonl", proxies)
    write_jsonl(work / "02-duplicates.jsonl", duplicates)
    print(f"[{source_id}] unique={len(proxies)} duplicates={len(duplicates)}")
    if until == "dedup":
        return proxies

    sec_cfg = cfg.get("filters", {}).get("security", {})
    safe, rejected = [], []
    for proxy in proxies:
        ok, _ = check_static_security(proxy, reject_allow_insecure=sec_cfg.get("reject_allow_insecure", True))
        (safe if ok else rejected).append(proxy)
    write_jsonl(work / "03-safe.jsonl", safe)
    write_jsonl(work / "03-rejected-security.jsonl", rejected)
    print(f"[{source_id}] security_pass={len(safe)} rejected={len(rejected)}")
    if until == "security":
        return safe

    tcp_cfg = cfg.get("filters", {}).get("tcp", {})
    if tcp_cfg.get("enabled", True):
        passed, tcp_rejected = check_many(
            safe,
            timeout=float(tcp_cfg.get("timeout_seconds", 3)),
            workers=int(tcp_cfg.get("workers", 64)),
        )
    else:
        passed, tcp_rejected = safe, []
    write_jsonl(work / "04-tcp-ok.jsonl", passed)
    write_jsonl(work / "04-rejected-tcp.jsonl", tcp_rejected)
    print(f"[{source_id}] tcp_pass={len(passed)} rejected={len(tcp_rejected)}")
    if until == "tcp":
        return passed

    core_ok, core_rejected = [], []
    for idx, proxy in enumerate(passed, 1):
        ok, error = engine.validate(proxy)
        proxy.tests.core = {"status": "pass" if ok else "fail", "error": error}
        proxy.tests.status = "core_valid" if ok else "rejected_core"
        (core_ok if ok else core_rejected).append(proxy)
        if idx % 100 == 0:
            print(f"[{source_id}] core_checked={idx}/{len(passed)}")
    write_jsonl(work / "05-core-ok.jsonl", core_ok)
    write_jsonl(work / "05-rejected-core.jsonl", core_rejected)
    print(f"[{source_id}] core_pass={len(core_ok)} rejected={len(core_rejected)}")
    if until == "core":
        return core_ok

    latency_cfg = cfg.get("filters", {}).get("latency", {})
    latency_mode = str(latency_cfg.get("mode", "singbox-api")).lower()
    common_latency_args = {
        "url": str(latency_cfg.get("test_url", "https://www.gstatic.com/generate_204")),
        "timeout": float(latency_cfg.get("timeout_seconds", 8)),
        "max_ms": float(latency_cfg.get("max_ms", 800)),
        "workers": int(latency_cfg.get("workers", 32)),
    }

    print(f"[{source_id}] latency_mode={latency_mode}")
    if latency_mode in {"singbox-api", "api", "batch"}:
        latency_ok, latency_rejected = check_latency_batched(
            core_ok,
            engine,
            **common_latency_args,
            batch_size=int(latency_cfg.get("batch_size", 128)),
        )
    elif latency_mode == "curl":
        latency_ok, latency_rejected = check_latency_many(
            core_ok,
            engine,
            **common_latency_args,
            curl_command=str(latency_cfg.get("command", "curl")),
        )
    else:
        raise ValueError(f"unsupported latency mode: {latency_mode}")

    latency_ok.sort(key=lambda proxy: proxy.tests.latency_ms if proxy.tests.latency_ms is not None else float("inf"))
    write_jsonl(work / "06-latency-ok.jsonl", latency_ok)
    write_jsonl(work / "06-rejected-latency.jsonl", latency_rejected)
    print(f"[{source_id}] latency_pass={len(latency_ok)} rejected={len(latency_rejected)}")
    if until == "latency":
        return latency_ok

    speed_cfg = cfg.get("filters", {}).get("speed", {})
    speed_timeout = float(speed_cfg.get("timeout_seconds", 30))
    speed_workers = int(speed_cfg.get("workers", 1))
    speed_curl = str(speed_cfg.get("command", "curl"))

    download_fallback_urls = _as_string_list(speed_cfg.get("download_fallback_urls", []))
    download_fallback_http_codes = _as_int_set(speed_cfg.get("download_fallback_http_codes"), [429])

    download_ok, download_rejected = check_download_many(
        latency_ok,
        engine,
        url=str(speed_cfg.get("download_url", "")),
        timeout=speed_timeout,
        min_mbps=float(speed_cfg.get("min_download_mbps", 30)),
        workers=speed_workers,
        curl_command=speed_curl,
        fallback_urls=download_fallback_urls,
        fallback_http_codes=download_fallback_http_codes,
    )
    write_jsonl(work / "07-download-ok.jsonl", download_ok)
    write_jsonl(work / "07-rejected-download.jsonl", download_rejected)
    print(f"[{source_id}] download_pass={len(download_ok)} rejected={len(download_rejected)}")
    if until == "download":
        return download_ok

    upload_fallback_urls = _as_string_list(speed_cfg.get("upload_fallback_urls", []))
    upload_fallback_http_codes = _as_int_set(
        speed_cfg.get("upload_fallback_http_codes"),
        [429, 500, 502, 503, 504],
    )

    upload_ok, upload_rejected = check_upload_many(
        download_ok,
        engine,
        url=str(speed_cfg.get("upload_url", "")),
        upload_bytes=int(speed_cfg.get("upload_bytes", 10_000_000)),
        timeout=speed_timeout,
        min_mbps=float(speed_cfg.get("min_upload_mbps", 10)),
        workers=speed_workers,
        curl_command=speed_curl,
        fallback_urls=upload_fallback_urls,
        fallback_http_codes=upload_fallback_http_codes,
    )
    write_jsonl(work / "08-upload-ok.jsonl", upload_ok)
    write_jsonl(work / "08-rejected-upload.jsonl", upload_rejected)
    print(f"[{source_id}] upload_pass={len(upload_ok)} rejected={len(upload_rejected)}")
    if until == "upload":
        return upload_ok

    exit_cfg = cfg.get("filters", {}).get("exit_ip", {})
    exit_url = str(exit_cfg.get("url", "https://api.ipify.org"))
    exit_timeout = float(exit_cfg.get("timeout_seconds", 8))
    exit_workers = int(exit_cfg.get("workers", 4))
    exit_curl = str(exit_cfg.get("command", "curl"))
    reject_direct = bool(exit_cfg.get("reject_direct_wan_ip", True))
    reject_unknown = bool(exit_cfg.get("reject_unknown_exit_ip", False))
    direct_ips = set(_as_string_list(exit_cfg.get("direct_ips", [])))

    if reject_direct and bool(exit_cfg.get("auto_discover_direct_ip", True)):
        direct_ip = discover_direct_ip(url=exit_url, timeout=exit_timeout, curl_command=exit_curl)
        direct_ips.add(direct_ip)
        print(f"[{source_id}] direct_wan_ip={direct_ip}")
    elif reject_direct and not direct_ips:
        raise ValueError("exit_ip.direct_ips is required when auto_discover_direct_ip is false")

    exit_ok, exit_rejected = check_exit_ip_many(
        upload_ok,
        engine,
        url=exit_url,
        timeout=exit_timeout,
        reject_direct_wan_ip=reject_direct,
        reject_unknown_exit_ip=reject_unknown,
        direct_ips=direct_ips,
        workers=exit_workers,
        curl_command=exit_curl,
    )
    write_jsonl(work / "09-exit-ip-ok.jsonl", exit_ok)
    write_jsonl(work / "09-rejected-exit-ip.jsonl", exit_rejected)
    unknown_count = sum(1 for proxy in exit_ok if proxy.tests.exit_ip is None)
    print(
        f"[{source_id}] exit_ip_pass={len(exit_ok) - unknown_count} "
        f"unknown={unknown_count} rejected={len(exit_rejected)}"
    )
    return exit_ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter public proxy subscriptions")
    parser.add_argument(
        "--until",
        choices=("parse", "dedup", "security", "tcp", "core", "latency", "download", "upload", "exit-ip"),
        default="core",
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--source", action="append", help="Process only the given source id; may be repeated")
    parser.add_argument("--debug-proxy", help="Re-run latency diagnostics for one existing proxy id or unique id prefix")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    with cfg_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    data_dir = Path(cfg.get("paths", {}).get("data_dir", "/srv/proxy-filter/data"))
    configured_sources = cfg.get("sources", [])
    selected = set(args.source or [])
    if selected:
        configured_ids = {source.get("id") for source in configured_sources}
        missing = sorted(selected - configured_ids)
        if missing:
            parser.error("unknown source id(s): " + ", ".join(missing))

    if args.debug_proxy:
        engine = build_engine(cfg, data_dir)
        print("[engine] " + engine.version().splitlines()[0])
        try:
            proxy, source_path = find_proxy_in_work(data_dir, args.debug_proxy, sorted(selected) if selected else None)
        except ValueError as exc:
            parser.error(str(exc))

        latency_cfg = cfg.get("filters", {}).get("latency", {})
        test_url = str(latency_cfg.get("test_url", "https://www.gstatic.com/generate_204"))
        timeout = float(latency_cfg.get("timeout_seconds", 8))
        result, runtime = debug_latency_proxy(
            proxy,
            engine,
            url=test_url,
            timeout=timeout,
            source_path=source_path,
        )
        print(f"[debug] proxy={proxy.id}")
        print(f"[debug] source_work_file={source_path}")
        print(f"[debug] runtime={runtime}")
        if result.get("ok"):
            print(f"[debug] latency_ms={result.get('latency_ms')}")
        else:
            print(f"[debug] error={result.get('error')}")
        return 0

    engine = build_engine(cfg, data_dir) if args.until in {"core", "latency", "download", "upload", "exit-ip"} else None
    if engine is not None:
        print("[engine] " + engine.version().splitlines()[0])

    sources = [source for source in configured_sources if not selected or source.get("id") in selected]

    all_survivors = []
    summary = {"sources": {}}

    for source in sources:
        try:
            survivors = process_source(source, cfg, data_dir, args.until, engine)
            all_survivors.extend(survivors)
            summary["sources"][source["id"]] = {"status": "ok", "survivors": len(survivors)}
        except Exception as exc:
            summary["sources"][source.get("id", "unknown")] = {"status": "error", "error": str(exc)}
            print(f"[{source.get('id', 'unknown')}] ERROR: {exc}", file=sys.stderr)

    merged, duplicates = deduplicate(all_survivors)
    if args.until == "latency":
        merged.sort(key=lambda proxy: proxy.tests.latency_ms if proxy.tests.latency_ms is not None else float("inf"))
    elif args.until == "download":
        merged.sort(key=lambda proxy: proxy.tests.download_mbps if proxy.tests.download_mbps is not None else -1, reverse=True)
    elif args.until == "upload":
        merged.sort(key=lambda proxy: proxy.tests.upload_mbps if proxy.tests.upload_mbps is not None else -1, reverse=True)
    elif args.until == "exit-ip":
        merged.sort(key=lambda proxy: (proxy.tests.exit_ip is None, proxy.tests.exit_ip or "", -(proxy.tests.download_mbps or 0)))
    write_jsonl(data_dir / "work" / "all" / f"{args.until}.jsonl", merged)
    write_json(data_dir / "reports" / "summary.json", summary)
    print(f"[all] survivors={len(merged)} cross_source_duplicates={len(duplicates)}")
    return 0 if all(v["status"] == "ok" for v in summary["sources"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
