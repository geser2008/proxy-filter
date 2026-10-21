#!/usr/bin/python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import yaml

from proxyfilter.engine import SingBoxBackend
from proxyfilter.ingest import detect_and_parse
from proxyfilter.io import fetch_url, write_json, write_jsonl
from proxyfilter.security import check_static_security
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
    return core_ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter public proxy subscriptions")
    parser.add_argument("--config", required=True)
    parser.add_argument("--until", choices=("parse", "dedup", "security", "tcp", "core"), default="core")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    with cfg_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    data_dir = Path(cfg.get("paths", {}).get("data_dir", "/srv/proxy-filter/data"))
    engine = build_engine(cfg, data_dir) if args.until == "core" else None
    if engine is not None:
        print("[engine] " + engine.version().splitlines()[0])

    all_survivors = []
    summary = {"sources": {}}

    for source in cfg.get("sources", []):
        try:
            survivors = process_source(source, cfg, data_dir, args.until, engine)
            all_survivors.extend(survivors)
            summary["sources"][source["id"]] = {"status": "ok", "survivors": len(survivors)}
        except Exception as exc:
            summary["sources"][source.get("id", "unknown")] = {"status": "error", "error": str(exc)}
            print(f"[{source.get('id', 'unknown')}] ERROR: {exc}", file=sys.stderr)

    merged, duplicates = deduplicate(all_survivors)
    write_jsonl(data_dir / "work" / "all" / f"{args.until}.jsonl", merged)
    write_json(data_dir / "reports" / "summary.json", summary)
    print(f"[all] survivors={len(merged)} cross_source_duplicates={len(duplicates)}")
    return 0 if all(v["status"] == "ok" for v in summary["sources"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
