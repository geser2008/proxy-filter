from __future__ import annotations

import argparse
from pathlib import Path
import sys

import yaml

from . import cli
from .batch_latency import check_latency_batched
from .debug_latency import debug_latency_proxy, find_proxy_in_work
from .exit_ip import check_exit_ip_many, discover_direct_ip
from .geoip import enrich_geo_many
from .io import write_json, write_jsonl
from .model import ProxyConfig
from .probes import check_latency_many
from .publish import publish_merged, publish_source
from .resume import STAGE_ORDER, load_stage, stage_index, validate_resume_range
from .speed import check_download_many, check_upload_many
from .tcpcheck import check_many


ENGINE_STAGES = {"core", "latency", "download", "upload", "exit-ip"}


def _source_ids(proxy: ProxyConfig) -> set[str]:
    return {source.id for source in proxy.provenance_sources()}


def _filter_for_source(proxies: list[ProxyConfig], source_id: str) -> list[ProxyConfig]:
    return [proxy for proxy in proxies if source_id in _source_ids(proxy)]


def _project_jsonl(data_dir: Path, sources: list[dict], filename: str, proxies: list[ProxyConfig]) -> None:
    for source in sources:
        source_id = str(source["id"])
        work = data_dir / "work" / source_id
        work.mkdir(parents=True, exist_ok=True)
        write_jsonl(work / filename, _filter_for_source(proxies, source_id))


def _run_global_stages(
    current: list[ProxyConfig],
    cfg: dict,
    data_dir: Path,
    sources: list[dict],
    *,
    start_after: str,
    until: str,
    engine,
) -> list[ProxyConfig]:
    def should_run(stage: str) -> bool:
        return stage_index(stage) > stage_index(start_after) and stage_index(stage) <= stage_index(until)

    if should_run("tcp"):
        tcp_cfg = cfg.get("filters", {}).get("tcp", {})
        if tcp_cfg.get("enabled", True):
            current, rejected = check_many(
                current,
                timeout=float(tcp_cfg.get("timeout_seconds", 3)),
                workers=int(tcp_cfg.get("workers", 64)),
            )
        else:
            rejected = []
        _project_jsonl(data_dir, sources, "04-tcp-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "04-rejected-tcp.jsonl", rejected)
        print(f"[all] tcp_pass={len(current)} rejected={len(rejected)}")
        if until == "tcp":
            return current

    if should_run("core"):
        core_ok: list[ProxyConfig] = []
        rejected: list[ProxyConfig] = []
        for idx, proxy in enumerate(current, 1):
            ok, error = engine.validate(proxy)
            proxy.tests.core = {"status": "pass" if ok else "fail", "error": error}
            proxy.tests.status = "core_valid" if ok else "rejected_core"
            (core_ok if ok else rejected).append(proxy)
            if idx % 100 == 0:
                print(f"[all] core_checked={idx}/{len(current)}")
        current = core_ok
        _project_jsonl(data_dir, sources, "05-core-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "05-rejected-core.jsonl", rejected)
        print(f"[all] core_pass={len(current)} rejected={len(rejected)}")
        if until == "core":
            return current

    if should_run("latency"):
        latency_cfg = cfg.get("filters", {}).get("latency", {})
        latency_mode = str(latency_cfg.get("mode", "singbox-api")).lower()
        common = {
            "url": str(latency_cfg.get("test_url", "https://www.gstatic.com/generate_204")),
            "timeout": float(latency_cfg.get("timeout_seconds", 8)),
            "max_ms": float(latency_cfg.get("max_ms", -1)),
            "workers": int(latency_cfg.get("workers", 32)),
        }
        print(f"[all] latency_mode={latency_mode}")
        if latency_mode in {"singbox-api", "api", "batch"}:
            current, rejected = check_latency_batched(
                current,
                engine,
                **common,
                batch_size=int(latency_cfg.get("batch_size", 128)),
                retry_batch_size=int(latency_cfg.get("retry_batch_size", 16)),
            )
        elif latency_mode == "curl":
            current, rejected = check_latency_many(
                current,
                engine,
                **common,
                curl_command=str(latency_cfg.get("command", "curl")),
            )
        else:
            raise ValueError(f"unsupported latency mode: {latency_mode}")
        current.sort(key=lambda proxy: proxy.tests.latency_ms if proxy.tests.latency_ms is not None else float("inf"))
        _project_jsonl(data_dir, sources, "06-latency-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "06-rejected-latency.jsonl", rejected)
        print(f"[all] latency_pass={len(current)} rejected={len(rejected)}")
        if until == "latency":
            return current

    if should_run("download"):
        speed_cfg = cfg.get("filters", {}).get("speed", {})
        transfer_timeout = float(speed_cfg.get("transfer_timeout_seconds", speed_cfg.get("timeout_seconds", 30)))
        connect_timeout = float(speed_cfg.get("connect_timeout_seconds", 10))
        min_mbps = float(speed_cfg.get("min_download_mbps", 30))
        current, rejected = check_download_many(
            current,
            engine,
            url=str(speed_cfg.get("download_url", "")),
            timeout=transfer_timeout,
            connect_timeout=connect_timeout,
            min_mbps=min_mbps,
            workers=int(speed_cfg.get("workers", 1)),
            curl_command=str(speed_cfg.get("command", "curl")),
            fallback_urls=cli._as_string_list(speed_cfg.get("download_fallback_urls", [])),
            stream_stages=speed_cfg.get("download_streams"),
            min_stream_bytes=int(speed_cfg.get("download_min_stream_bytes", 5_000_000)),
        )
        _project_jsonl(data_dir, sources, "07-download-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "07-rejected-download.jsonl", rejected)
        print(f"[all] download_pass={len(current)} rejected={len(rejected)}")
        if until == "download":
            return current

    if should_run("upload"):
        speed_cfg = cfg.get("filters", {}).get("speed", {})
        transfer_timeout = float(speed_cfg.get("transfer_timeout_seconds", speed_cfg.get("timeout_seconds", 30)))
        connect_timeout = float(speed_cfg.get("connect_timeout_seconds", 10))
        min_mbps = float(speed_cfg.get("min_upload_mbps", 10))
        fallback_codes = cli._as_int_set(
            speed_cfg.get("upload_fallback_http_codes"), [429, 500, 502, 503, 504]
        )
        current, rejected = check_upload_many(
            current,
            engine,
            url=str(speed_cfg.get("upload_url", "")),
            upload_bytes=int(speed_cfg.get("upload_bytes", 10_000_000)),
            timeout=transfer_timeout,
            connect_timeout=connect_timeout,
            min_mbps=min_mbps,
            workers=int(speed_cfg.get("workers", 1)),
            curl_command=str(speed_cfg.get("command", "curl")),
            fallback_urls=cli._as_string_list(speed_cfg.get("upload_fallback_urls", [])),
            fallback_http_codes=fallback_codes,
        )
        _project_jsonl(data_dir, sources, "08-upload-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "08-rejected-upload.jsonl", rejected)
        print(f"[all] upload_pass={len(current)} rejected={len(rejected)}")
        if until == "upload":
            return current

    if should_run("exit-ip"):
        exit_cfg = cfg.get("filters", {}).get("exit_ip", {})
        exit_url = str(exit_cfg.get("url", "https://api.ipify.org"))
        exit_timeout = float(exit_cfg.get("timeout_seconds", 8))
        exit_curl = str(exit_cfg.get("command", "curl"))
        reject_direct = bool(exit_cfg.get("reject_direct_wan_ip", True))
        reject_unknown = bool(exit_cfg.get("reject_unknown_exit_ip", False))
        direct_ips = set(cli._as_string_list(exit_cfg.get("direct_ips", [])))
        if reject_direct and bool(exit_cfg.get("auto_discover_direct_ip", True)):
            direct_ip = discover_direct_ip(url=exit_url, timeout=exit_timeout, curl_command=exit_curl)
            direct_ips.add(direct_ip)
            print(f"[all] direct_wan_ip={direct_ip}")
        elif reject_direct and not direct_ips:
            raise ValueError("exit_ip.direct_ips is required when auto_discover_direct_ip is false")
        current, rejected = check_exit_ip_many(
            current,
            engine,
            url=exit_url,
            timeout=exit_timeout,
            reject_direct_wan_ip=reject_direct,
            reject_unknown_exit_ip=reject_unknown,
            direct_ips=direct_ips,
            workers=int(exit_cfg.get("workers", 4)),
            curl_command=exit_curl,
        )
        _project_jsonl(data_dir, sources, "09-exit-ip-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "09-rejected-exit-ip.jsonl", rejected)
        unknown = sum(1 for proxy in current if proxy.tests.exit_ip is None)
        print(f"[all] exit_ip_pass={len(current) - unknown} unknown={unknown} rejected={len(rejected)}")
        if until == "exit-ip":
            return current

    if should_run("geo"):
        geo_cfg = cfg.get("filters", {}).get("geo", {})
        current = enrich_geo_many(
            current,
            provider=str(geo_cfg.get("provider", "ipwhois")),
            url_template=str(geo_cfg.get("url_template", "https://ipwho.is/{ip}")),
            timeout=float(geo_cfg.get("timeout_seconds", 8)),
            workers=int(geo_cfg.get("workers", 4)),
            curl_command=str(geo_cfg.get("command", "curl")),
        )
        _project_jsonl(data_dir, sources, "10-geo.jsonl", current)
        print(f"[all] geo_done={len(current)}")
        if until == "geo":
            return current

    if should_run("render"):
        current, rejected = cli._render_proxies(current, cfg)
        _project_jsonl(data_dir, sources, "11-render-ok.jsonl", current)
        _project_jsonl(data_dir, sources, "11-rejected-render.jsonl", rejected)
        print(f"[all] render_pass={len(current)} rejected={len(rejected)}")
        if until == "render":
            return current

    if should_run("publish"):
        for proxy in current:
            proxy.tests.status = "published"
        _project_jsonl(data_dir, sources, "12-published.jsonl", current)
        for source in sources:
            source_id = str(source["id"])
            source_current = _filter_for_source(current, source_id)
            txt_path, jsonl_path = publish_source(data_dir, source_id, source_current)
            print(f"[{source_id}] published={len(source_current)} txt={txt_path} jsonl={jsonl_path}")

    return current


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter public proxy subscriptions")
    parser.add_argument("--until", choices=STAGE_ORDER, default="core")
    parser.add_argument("--resume-from", choices=STAGE_ORDER, help="Resume from an existing successful stage JSONL")
    parser.add_argument("--config", required=True)
    parser.add_argument("--source", action="append", help="Process only the given source id; may be repeated")
    parser.add_argument("--debug-proxy", help="Re-run latency diagnostics for one existing proxy id or unique id prefix")
    args = parser.parse_args()

    try:
        validate_resume_range(args.resume_from, args.until)
    except ValueError as exc:
        parser.error(str(exc))

    cfg_path = Path(args.config)
    with cfg_path.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    data_dir = Path(cfg.get("paths", {}).get("data_dir", "/srv/proxy-filter/data"))
    configured_sources = cfg.get("sources", [])
    configured_ids = {source.get("id") for source in configured_sources}
    selected = set(args.source or [])
    if selected:
        missing = sorted(selected - configured_ids)
        if missing:
            parser.error("unknown source id(s): " + ", ".join(missing))
    sources = [source for source in configured_sources if not selected or source.get("id") in selected]

    if args.debug_proxy:
        engine = cli.build_engine(cfg, data_dir)
        print("[engine] " + engine.version().splitlines()[0])
        try:
            proxy, source_path = find_proxy_in_work(data_dir, args.debug_proxy, sorted(selected) if selected else None)
        except ValueError as exc:
            parser.error(str(exc))
        latency_cfg = cfg.get("filters", {}).get("latency", {})
        result, runtime = debug_latency_proxy(
            proxy,
            engine,
            url=str(latency_cfg.get("test_url", "https://www.gstatic.com/generate_204")),
            timeout=float(latency_cfg.get("timeout_seconds", 8)),
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

    start_index = stage_index(args.resume_from) + 1 if args.resume_from else 0
    end_index = stage_index(args.until)
    stages_to_run = STAGE_ORDER[start_index : end_index + 1]
    needs_engine = any(stage in ENGINE_STAGES for stage in stages_to_run)
    engine = cli.build_engine(cfg, data_dir) if needs_engine else None
    if engine is not None:
        print("[engine] " + engine.version().splitlines()[0])

    summary = {"sources": {}}
    early_duplicates: list[ProxyConfig] = []

    try:
        if stage_index(args.until) <= stage_index("security"):
            survivors: list[ProxyConfig] = []
            for source in sources:
                current = cli.process_source(source, cfg, data_dir, args.until, engine, resume_from=args.resume_from)
                survivors.extend(current)
                summary["sources"][source["id"]] = {
                    "status": "ok",
                    "survivors": len(current),
                    "resume_from": args.resume_from,
                }
            merged, early_duplicates = cli.deduplicate(survivors)
        else:
            if args.resume_from and stage_index(args.resume_from) >= stage_index("security"):
                boundary = args.resume_from
                boundary_records: list[ProxyConfig] = []
                for source in sources:
                    current, path = load_stage(data_dir, str(source["id"]), boundary)
                    print(f"[{source['id']}] resume_from={boundary} records={len(current)} file={path}")
                    boundary_records.extend(current)
            else:
                boundary = "security"
                boundary_records = []
                for source in sources:
                    current = cli.process_source(
                        source,
                        cfg,
                        data_dir,
                        boundary,
                        engine,
                        resume_from=args.resume_from,
                    )
                    boundary_records.extend(current)

            merged_boundary, early_duplicates = cli.deduplicate(boundary_records)
            print(
                f"[all] pre_network_unique={len(merged_boundary)} "
                f"cross_source_duplicates={len(early_duplicates)} boundary={boundary}"
            )
            merged = _run_global_stages(
                merged_boundary,
                cfg,
                data_dir,
                sources,
                start_after=boundary,
                until=args.until,
                engine=engine,
            )

            for source in sources:
                source_id = str(source["id"])
                summary["sources"][source_id] = {
                    "status": "ok",
                    "survivors": len(_filter_for_source(merged, source_id)),
                    "resume_from": args.resume_from,
                }
    except Exception as exc:
        print(f"[all] ERROR: {exc}", file=sys.stderr)
        for source in sources:
            source_id = str(source["id"])
            summary["sources"].setdefault(source_id, {"status": "error", "error": str(exc)})
        write_json(data_dir / "reports" / "summary.json", summary)
        return 1

    if args.until == "latency":
        merged.sort(key=lambda proxy: proxy.tests.latency_ms if proxy.tests.latency_ms is not None else float("inf"))
    elif args.until == "download":
        merged.sort(key=lambda proxy: proxy.tests.download_mbps if proxy.tests.download_mbps is not None else -1, reverse=True)
    elif args.until == "upload":
        merged.sort(key=lambda proxy: proxy.tests.upload_mbps if proxy.tests.upload_mbps is not None else -1, reverse=True)
    elif args.until == "exit-ip":
        merged.sort(key=lambda proxy: (proxy.tests.exit_ip is None, proxy.tests.exit_ip or "", -(proxy.tests.download_mbps or 0)))
    elif args.until in {"geo", "render", "publish"}:
        merged.sort(
            key=lambda proxy: (
                proxy.tests.geo.get("country_code") or "ZZ",
                proxy.tests.exit_ip is None,
                proxy.tests.exit_ip or "",
            )
        )

    write_jsonl(data_dir / "work" / "all" / f"{args.until}.jsonl", merged)
    write_json(data_dir / "reports" / "summary.json", summary)

    all_sources_ok = bool(summary["sources"]) and all(v["status"] == "ok" for v in summary["sources"].values())
    full_source_set = not selected or selected == configured_ids
    if args.until == "publish":
        if all_sources_ok and full_source_set:
            txt_path, jsonl_path = publish_merged(data_dir, merged, cfg.get("diversity", {}))
            print(f"[all] published={len(merged)} txt={txt_path} jsonl={jsonl_path}")
        elif not full_source_set:
            print("[all] publish_skipped=partial_source_selection")
        else:
            print("[all] publish_skipped=source_error")

    print(f"[all] survivors={len(merged)} cross_source_duplicates={len(early_duplicates)}")
    return 0 if all_sources_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
