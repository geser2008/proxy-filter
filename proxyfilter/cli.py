#!/usr/bin/python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

from proxyfilter.batch_latency import check_latency_batched
from proxyfilter.debug_latency import debug_latency_proxy, find_proxy_in_work
from proxyfilter.exit_ip import check_exit_ip_many, discover_direct_ip
from proxyfilter.geoip import enrich_geo_many
from proxyfilter.singbox_backend import SingBoxBackend
from proxyfilter.ingest import detect_and_parse
from proxyfilter.io import fetch_url, write_json, write_jsonl
from proxyfilter.model import ProxyConfig, TestState
from proxyfilter.probes import check_latency_many
from proxyfilter.publish import publish_merged, publish_source
from proxyfilter.render import render_proxy
from proxyfilter.resume import STAGE_ORDER, load_stage, stage_index, stage_should_run, validate_resume_range
from proxyfilter.security import check_static_security
from proxyfilter.speed import check_download_many, check_upload_many
from proxyfilter.tcpcheck import check_many


ENGINE_STAGES = {"core", "latency", "download", "upload", "exit-ip"}


def deduplicate(proxies):
    unique = {}
    duplicates = []
    for proxy in proxies:
        proxy.ensure_id()
        if proxy.id in unique:
            unique[proxy.id].merge_sources_from(proxy)
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


def _render_proxies(proxies, cfg):
    output_cfg = cfg.get("output", {})
    rename_template = str(output_cfg.get("rename_template", "{flag} [{source}] {name}"))
    include_original_name = bool(output_cfg.get("include_original_name", True))
    render_ok, render_rejected = [], []

    for proxy in proxies:
        result = render_proxy(
            proxy,
            rename_template=rename_template,
            include_original_name=include_original_name,
        )
        proxy.tests.render = {
            "status": "pass" if result.ok else "fail",
            "name": result.name,
            "uri": result.uri,
            "error": result.error,
        }
        if result.ok:
            proxy.tests.status = "render_pass"
            render_ok.append(proxy)
        else:
            proxy.tests.status = "rejected_render"
            render_rejected.append(proxy)

    return render_ok, render_rejected


def _proxy_source_ids(proxy: ProxyConfig) -> set[str]:
    return {source.id for source in proxy.provenance_sources() if source.id}


def _source_survivor_count(proxies: list[ProxyConfig], source_id: str) -> int:
    return sum(1 for proxy in proxies if source_id in _proxy_source_ids(proxy))


def _read_proxy_jsonl(path: Path) -> list[ProxyConfig]:
    if not path.is_file():
        return []
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


def _load_previous_working(data_dir: Path, selected: set[str]) -> tuple[list[ProxyConfig], Path]:
    path = data_dir / "state" / "working.jsonl"
    proxies = _read_proxy_jsonl(path)
    if selected:
        proxies = [proxy for proxy in proxies if _proxy_source_ids(proxy) & selected]
    return proxies, path


def _reset_tests(proxies: list[ProxyConfig]) -> None:
    for proxy in proxies:
        proxy.tests = TestState()


def _ingest_sources(
    sources: list[dict],
    data_dir: Path,
    summary: dict,
) -> tuple[list[ProxyConfig], bool]:
    raw_dir = data_dir / "raw"
    reports_dir = data_dir / "reports"
    raw_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    parsed_all: list[ProxyConfig] = []
    all_ok = True

    for source in sources:
        source_id = str(source["id"])
        source_name = str(source.get("name", source_id))
        try:
            print(f"[{source_id}] download {source['url']}")
            raw = fetch_url(source["url"])
            (raw_dir / f"{source_id}.raw").write_bytes(raw)

            proxies, parse_errors, detected_format = detect_and_parse(raw, source_id, source_name)
            for proxy in proxies:
                proxy.source.format = detected_format
                proxy.sources = proxy.provenance_sources()
            parsed_all.extend(proxies)
            write_json(reports_dir / f"{source_id}-parse-errors.json", parse_errors)
            summary["sources"][source_id] = {
                "status": "ok",
                "parsed": len(proxies),
                "parse_errors": len(parse_errors),
                "format": detected_format,
            }
            print(f"[{source_id}] parsed={len(proxies)} errors={len(parse_errors)} format={detected_format}")
        except Exception as exc:
            all_ok = False
            summary["sources"][source_id] = {"status": "error", "error": str(exc)}
            print(f"[{source_id}] ERROR: {exc}", file=sys.stderr)

    return parsed_all, all_ok


def _sort_for_stage(proxies: list[ProxyConfig], stage: str) -> None:
    if stage == "latency":
        proxies.sort(key=lambda proxy: proxy.tests.latency_ms if proxy.tests.latency_ms is not None else float("inf"))
    elif stage == "download":
        proxies.sort(key=lambda proxy: proxy.tests.download_mbps if proxy.tests.download_mbps is not None else -1, reverse=True)
    elif stage == "upload":
        proxies.sort(key=lambda proxy: proxy.tests.upload_mbps if proxy.tests.upload_mbps is not None else -1, reverse=True)
    elif stage == "exit-ip":
        proxies.sort(key=lambda proxy: (proxy.tests.exit_ip is None, proxy.tests.exit_ip or "", -(proxy.tests.download_mbps or 0)))
    elif stage in {"geo", "render", "publish"}:
        proxies.sort(
            key=lambda proxy: (
                proxy.tests.geo.get("country_code") or "ZZ",
                proxy.tests.exit_ip is None,
                proxy.tests.exit_ip or "",
            )
        )


def process_proxies(
    current: list[ProxyConfig],
    cfg: dict,
    data_dir: Path,
    until: str,
    engine,
    *,
    resume_from: str | None = None,
) -> list[ProxyConfig]:
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)

    if stage_should_run("dedup", resume_from):
        current, duplicates = deduplicate(current)
        _reset_tests(current)
        write_jsonl(work / "02-unique.jsonl", current)
        write_jsonl(work / "02-duplicates.jsonl", duplicates)
        print(f"[all] unique={len(current)} duplicates={len(duplicates)}")
        if until == "dedup":
            return current

    if stage_should_run("security", resume_from):
        sec_cfg = cfg.get("filters", {}).get("security", {})
        safe, rejected = [], []
        for proxy in current:
            ok, _ = check_static_security(proxy, reject_allow_insecure=sec_cfg.get("reject_allow_insecure", True))
            (safe if ok else rejected).append(proxy)
        write_jsonl(work / "03-safe.jsonl", safe)
        write_jsonl(work / "03-rejected-security.jsonl", rejected)
        print(f"[all] security_pass={len(safe)} rejected={len(rejected)}")
        current = safe
        if until == "security":
            return current

    if stage_should_run("tcp", resume_from):
        tcp_cfg = cfg.get("filters", {}).get("tcp", {})
        if tcp_cfg.get("enabled", True):
            passed, tcp_rejected = check_many(
                current,
                timeout=float(tcp_cfg.get("timeout_seconds", 3)),
                workers=int(tcp_cfg.get("workers", 64)),
            )
        else:
            passed, tcp_rejected = current, []
        write_jsonl(work / "04-tcp-ok.jsonl", passed)
        write_jsonl(work / "04-rejected-tcp.jsonl", tcp_rejected)
        print(f"[all] tcp_pass={len(passed)} rejected={len(tcp_rejected)}")
        current = passed
        if until == "tcp":
            return current

    if stage_should_run("core", resume_from):
        core_ok, core_rejected = [], []
        for idx, proxy in enumerate(current, 1):
            ok, error = engine.validate(proxy)
            proxy.tests.core = {"status": "pass" if ok else "fail", "error": error}
            proxy.tests.status = "core_valid" if ok else "rejected_core"
            (core_ok if ok else core_rejected).append(proxy)
            if idx % 100 == 0:
                print(f"[all] core_checked={idx}/{len(current)}")
        write_jsonl(work / "05-core-ok.jsonl", core_ok)
        write_jsonl(work / "05-rejected-core.jsonl", core_rejected)
        print(f"[all] core_pass={len(core_ok)} rejected={len(core_rejected)}")
        current = core_ok
        if until == "core":
            return current

    if stage_should_run("latency", resume_from):
        latency_cfg = cfg.get("filters", {}).get("latency", {})
        latency_mode = str(latency_cfg.get("mode", "singbox-api")).lower()
        primary_url = str(
            latency_cfg.get(
                "primary_url",
                latency_cfg.get("test_url", "https://www.gstatic.com/generate_204"),
            )
        )
        fallback_url = str(latency_cfg.get("fallback_url", "")).strip() or None
        common_latency_args = {
            "url": primary_url,
            "timeout": float(latency_cfg.get("timeout_seconds", 8)),
            "max_ms": float(latency_cfg.get("max_ms", 800)),
            "workers": int(latency_cfg.get("workers", 32)),
        }

        print(f"[all] latency_mode={latency_mode}")
        if latency_mode in {"singbox-api", "api", "batch"}:
            latency_ok, latency_rejected = check_latency_batched(
                current,
                engine,
                **common_latency_args,
                batch_size=int(latency_cfg.get("batch_size", 128)),
                fallback_url=fallback_url,
                recovery_enabled=bool(latency_cfg.get("recovery_enabled", False)),
            )
        elif latency_mode == "curl":
            latency_ok, latency_rejected = check_latency_many(
                current,
                engine,
                **common_latency_args,
                curl_command=str(latency_cfg.get("command", "curl")),
            )
        else:
            raise ValueError(f"unsupported latency mode: {latency_mode}")

        _sort_for_stage(latency_ok, "latency")
        write_jsonl(work / "06-latency-ok.jsonl", latency_ok)
        write_jsonl(work / "06-rejected-latency.jsonl", latency_rejected)
        print(f"[all] latency_pass={len(latency_ok)} rejected={len(latency_rejected)}")
        current = latency_ok
        if until == "latency":
            return current

    if stage_should_run("download", resume_from):
        speed_cfg = cfg.get("filters", {}).get("speed", {})
        speed_transfer_timeout = float(speed_cfg.get("transfer_timeout_seconds", speed_cfg.get("timeout_seconds", 30)))
        speed_connect_timeout = float(speed_cfg.get("connect_timeout_seconds", 10))
        speed_workers = int(speed_cfg.get("workers", 1))
        speed_curl = str(speed_cfg.get("command", "curl"))

        configured_fallback = str(speed_cfg.get("download_fallback_url", "")).strip()
        if configured_fallback:
            download_fallback_urls = [configured_fallback]
        else:
            # Backward-compatible old config, but intentionally keep only one
            # alternate provider so CacheFly is never followed by a retry chain.
            download_fallback_urls = _as_string_list(speed_cfg.get("download_fallback_urls", []))[:1]

        download_ok, download_rejected = check_download_many(
            current,
            engine,
            url=str(speed_cfg.get("download_url", "")),
            timeout=speed_transfer_timeout,
            connect_timeout=speed_connect_timeout,
            min_mbps=float(speed_cfg.get("min_download_mbps", 30)),
            workers=speed_workers,
            curl_command=speed_curl,
            fallback_urls=download_fallback_urls,
            stream_stages=speed_cfg.get("download_streams"),
            min_stream_bytes=int(speed_cfg.get("download_min_stream_bytes", 5_000_000)),
        )
        write_jsonl(work / "07-download-ok.jsonl", download_ok)
        write_jsonl(work / "07-rejected-download.jsonl", download_rejected)
        print(f"[all] download_pass={len(download_ok)} rejected={len(download_rejected)}")
        current = download_ok
        if until == "download":
            return current

    if stage_should_run("upload", resume_from):
        speed_cfg = cfg.get("filters", {}).get("speed", {})
        speed_transfer_timeout = float(speed_cfg.get("transfer_timeout_seconds", speed_cfg.get("timeout_seconds", 30)))
        speed_connect_timeout = float(speed_cfg.get("connect_timeout_seconds", 10))
        speed_workers = int(speed_cfg.get("workers", 1))
        speed_curl = str(speed_cfg.get("command", "curl"))
        upload_fallback_urls = _as_string_list(speed_cfg.get("upload_fallback_urls", []))
        upload_fallback_http_codes = _as_int_set(
            speed_cfg.get("upload_fallback_http_codes"),
            [429, 500, 502, 503, 504],
        )

        upload_ok, upload_rejected = check_upload_many(
            current,
            engine,
            url=str(speed_cfg.get("upload_url", "")),
            upload_bytes=int(speed_cfg.get("upload_bytes", 10_000_000)),
            timeout=speed_transfer_timeout,
            connect_timeout=speed_connect_timeout,
            min_mbps=float(speed_cfg.get("min_upload_mbps", 10)),
            workers=speed_workers,
            curl_command=speed_curl,
            fallback_urls=upload_fallback_urls,
            fallback_http_codes=upload_fallback_http_codes,
            stream_stages=speed_cfg.get("upload_streams"),
            min_stream_bytes=int(speed_cfg.get("upload_min_stream_bytes", 1_000_000)),
        )
        write_jsonl(work / "08-upload-ok.jsonl", upload_ok)
        write_jsonl(work / "08-rejected-upload.jsonl", upload_rejected)
        print(f"[all] upload_pass={len(upload_ok)} rejected={len(upload_rejected)}")
        current = upload_ok
        if until == "upload":
            return current

    if stage_should_run("exit-ip", resume_from):
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
            print(f"[all] direct_wan_ip={direct_ip}")
        elif reject_direct and not direct_ips:
            raise ValueError("exit_ip.direct_ips is required when auto_discover_direct_ip is false")

        exit_ok, exit_rejected = check_exit_ip_many(
            current,
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
        print(f"[all] exit_ip_pass={len(exit_ok) - unknown_count} unknown={unknown_count} rejected={len(exit_rejected)}")
        current = exit_ok
        if until == "exit-ip":
            return current

    if stage_should_run("geo", resume_from):
        geo_cfg = cfg.get("filters", {}).get("geo", {})
        geo_ok = enrich_geo_many(
            current,
            provider=str(geo_cfg.get("provider", "ipwhois")),
            url_template=str(geo_cfg.get("url_template", "https://ipwho.is/{ip}")),
            timeout=float(geo_cfg.get("timeout_seconds", 8)),
            workers=int(geo_cfg.get("workers", 4)),
            curl_command=str(geo_cfg.get("command", "curl")),
        )
        write_jsonl(work / "10-geo.jsonl", geo_ok)
        geo_success = sum(1 for proxy in geo_ok if proxy.tests.geo.get("status") == "ok")
        geo_unknown = sum(1 for proxy in geo_ok if proxy.tests.geo.get("status") == "unknown")
        geo_errors = len(geo_ok) - geo_success - geo_unknown
        print(f"[all] geo_ok={geo_success} unknown={geo_unknown} errors={geo_errors}")
        current = geo_ok
        if until == "geo":
            return current

    if stage_should_run("render", resume_from):
        render_ok, render_rejected = _render_proxies(current, cfg)
        write_jsonl(work / "11-render-ok.jsonl", render_ok)
        write_jsonl(work / "11-rejected-render.jsonl", render_rejected)
        print(f"[all] render_pass={len(render_ok)} rejected={len(render_rejected)}")
        current = render_ok
        if until == "render":
            return current

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
    configured_ids = {str(source.get("id")) for source in configured_sources}
    selected = set(args.source or [])
    if selected:
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
        test_url = str(
            latency_cfg.get(
                "primary_url",
                latency_cfg.get("test_url", "https://www.gstatic.com/generate_204"),
            )
        )
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

    start_index = stage_index(args.resume_from) + 1 if args.resume_from else 0
    end_index = stage_index(args.until)
    stages_to_run = STAGE_ORDER[start_index:end_index + 1]
    needs_engine = any(stage in ENGINE_STAGES for stage in stages_to_run)
    engine = build_engine(cfg, data_dir) if needs_engine else None
    if engine is not None:
        print("[engine] " + engine.version().splitlines()[0])

    sources = [source for source in configured_sources if not selected or str(source.get("id")) in selected]
    summary = {"sources": {}}
    all_sources_ok = True
    work = data_dir / "work"
    work.mkdir(parents=True, exist_ok=True)

    if args.resume_from is not None:
        try:
            current, resume_path = load_stage(data_dir, args.resume_from)
        except (FileNotFoundError, ValueError) as exc:
            parser.error(str(exc))
        if selected:
            current = [proxy for proxy in current if _proxy_source_ids(proxy) & selected]
        print(f"[all] resume_from={args.resume_from} records={len(current)} file={resume_path}")
        for source in sources:
            source_id = str(source["id"])
            summary["sources"][source_id] = {
                "status": "ok",
                "survivors": _source_survivor_count(current, source_id),
                "resume_from": args.resume_from,
            }
        if args.until == args.resume_from:
            _sort_for_stage(current, args.until)
            summary["pipeline"] = {
                "status": "ok",
                "stage": args.until,
                "survivors": len(current),
                "resume_from": args.resume_from,
            }
            write_json(data_dir / "reports" / "summary.json", summary)
            return 0
    else:
        parsed, all_sources_ok = _ingest_sources(sources, data_dir, summary)
        write_jsonl(work / "01-parsed.jsonl", parsed)
        summary["parsed"] = len(parsed)
        if args.until == "parse":
            write_json(data_dir / "reports" / "summary.json", summary)
            return 0 if all_sources_ok else 1

        previous, previous_path = _load_previous_working(data_dir, selected)
        summary["previous_working"] = len(previous)
        summary["previous_working_file"] = str(previous_path)
        print(f"[all] previous_working={len(previous)} file={previous_path}")
        current = [*parsed, *previous]

    try:
        current = process_proxies(
            current,
            cfg,
            data_dir,
            args.until,
            engine,
            resume_from=args.resume_from,
        )
    except Exception as exc:
        summary["pipeline"] = {"status": "error", "error": str(exc)}
        write_json(data_dir / "reports" / "summary.json", summary)
        print(f"[all] ERROR: {exc}", file=sys.stderr)
        return 1

    _sort_for_stage(current, args.until)

    if args.until == "publish":
        working = list(current)
        for proxy in working:
            proxy.tests.status = "published"

        # Preserve source-specific subscriptions without duplicating work-stage files.
        for source in sources:
            source_id = str(source["id"])
            source_summary = summary["sources"].get(source_id) or {}
            if source_summary.get("status") != "ok":
                print(f"[{source_id}] publish_skipped=source_error")
                continue
            source_proxies = [proxy for proxy in working if source_id in _proxy_source_ids(proxy)]
            txt_path, jsonl_path = publish_source(data_dir, source_id, source_proxies)
            print(f"[{source_id}] published={len(source_proxies)} txt={txt_path} jsonl={jsonl_path}")
            source_summary["survivors"] = len(source_proxies)

        full_source_set = not selected or selected == configured_ids
        if all_sources_ok and full_source_set:
            diversity_cfg = cfg.get("filters", {}).get("diversity", cfg.get("diversity", {}))
            selected_for_publish = list(working)
            txt_path, jsonl_path = publish_merged(data_dir, selected_for_publish, diversity_cfg)
            write_jsonl(work / "12-published.jsonl", selected_for_publish)
            write_jsonl(data_dir / "state" / "working.jsonl", working)
            current = selected_for_publish
            summary["working"] = len(working)
            summary["published"] = len(current)
            print(f"[all] published={len(current)} working={len(working)} txt={txt_path} jsonl={jsonl_path}")
        elif not full_source_set:
            write_jsonl(work / "12-published.jsonl", working)
            current = working
            print("[all] publish_skipped=partial_source_selection state_update_skipped=true")
        else:
            write_jsonl(work / "12-published.jsonl", working)
            current = working
            print("[all] publish_skipped=source_error state_update_skipped=true")

    for source in sources:
        source_id = str(source["id"])
        source_summary = summary["sources"].get(source_id)
        if source_summary and source_summary.get("status") == "ok":
            source_summary["survivors"] = _source_survivor_count(current, source_id)
            source_summary["resume_from"] = args.resume_from

    summary["pipeline"] = {
        "status": "ok",
        "stage": args.until,
        "survivors": len(current),
        "resume_from": args.resume_from,
    }
    write_json(data_dir / "reports" / "summary.json", summary)
    print(f"[all] survivors={len(current)}")
    return 0 if all_sources_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())