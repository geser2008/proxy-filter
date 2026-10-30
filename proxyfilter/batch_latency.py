from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import urlopen

from .model import ProxyConfig
from .singbox_backend import SingBoxBackend


@dataclass(slots=True)
class BatchLatencyResult:
    ok: bool
    latency_ms: float | None = None
    error: str | None = None


def _free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _wait_port(host: str, port: int, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"sing-box batch process exited {process.returncode}")
        try:
            with socket.create_connection((host, port), timeout=0.15):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("sing-box Clash API startup timeout")


def _api_delay(host: str, port: int, tag: str, url: str, timeout: float) -> BatchLatencyResult:
    query = urlencode({"url": url, "timeout": max(1, int(timeout * 1000))})
    endpoint = f"http://{host}:{port}/proxies/{quote(tag, safe='')}/delay?{query}"
    try:
        with urlopen(endpoint, timeout=timeout + 2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        delay = payload.get("delay")
        if delay is None:
            return BatchLatencyResult(False, error=f"missing delay in Clash API response: {payload!r}")
        return BatchLatencyResult(True, latency_ms=float(delay))
    except HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace").strip()
        except Exception:
            detail = ""
        return BatchLatencyResult(False, error=f"clash_api_http_{exc.code}: {detail or exc.reason}")
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        return BatchLatencyResult(False, error=str(exc))


def _render_batch_config(
    engine: SingBoxBackend,
    proxies: list[ProxyConfig],
    api_port: int,
    test_url: str,
) -> tuple[dict[str, Any], dict[str, ProxyConfig]]:
    outbounds: list[dict[str, Any]] = []
    tag_map: dict[str, ProxyConfig] = {}

    for index, proxy in enumerate(proxies):
        tag = f"p-{index:04d}-{proxy.ensure_id()[:10]}"
        outbound = engine._render_outbound(proxy)
        outbound["tag"] = tag
        outbounds.append(outbound)
        tag_map[tag] = proxy

    group_tag = "latency-urltest"
    outbounds.append({
        "type": "urltest",
        "tag": group_tag,
        "outbounds": list(tag_map),
        "url": test_url,
        "interval": "1h",
        "tolerance": 0,
        "idle_timeout": "1h",
    })

    config: dict[str, Any] = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "dns-direct", "server": "1.1.1.1"}]},
        "outbounds": outbounds,
        "route": {"final": group_tag, "default_domain_resolver": "dns-direct"},
        "experimental": {"clash_api": {"external_controller": f"{engine.listen_host}:{api_port}"}},
    }
    return config, tag_map


def _run_batch(
    proxies: list[ProxyConfig],
    engine: SingBoxBackend,
    *,
    url: str,
    timeout: float,
    workers: int,
) -> dict[str, BatchLatencyResult]:
    engine.runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime = Path(tempfile.mkdtemp(prefix="latency-batch-", dir=engine.runtime_dir))
    config_path = runtime / "config.json"
    log_path = runtime / "sing-box.log"
    api_port = _free_port(engine.listen_host)
    process: subprocess.Popen[str] | None = None

    try:
        config, tag_map = _render_batch_config(engine, proxies, api_port, url)
        config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        check = subprocess.run([engine.command, "check", "-c", str(config_path)], text=True, capture_output=True, timeout=30)
        if check.returncode != 0:
            detail = (check.stderr or check.stdout).strip()
            raise RuntimeError(detail or "sing-box batch config check failed")

        with log_path.open("w", encoding="utf-8") as log_fh:
            process = subprocess.Popen(
                [engine.command, "run", "-c", str(config_path)],
                text=True,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        _wait_port(engine.listen_host, api_port, process, engine.startup_timeout)

        results: dict[str, BatchLatencyResult] = {}
        with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
            future_map = {
                pool.submit(_api_delay, engine.listen_host, api_port, tag, url, timeout): tag
                for tag in tag_map
            }
            for future in as_completed(future_map):
                tag = future_map[future]
                try:
                    results[tag] = future.result()
                except Exception as exc:
                    results[tag] = BatchLatencyResult(False, error=str(exc))

        return {tag_map[tag].ensure_id(): result for tag, result in results.items()}
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=engine.shutdown_timeout)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
        shutil.rmtree(runtime, ignore_errors=True)


def _is_retryable_latency_error(result: BatchLatencyResult) -> bool:
    if result.ok or not result.error:
        return False
    error = result.error.lower()
    return (
        error.startswith("clash_api_http_503:")
        or error.startswith("clash_api_http_504:")
        or "timed out" in error
        or "timeout" in error
    )


def check_latency_batched(
    proxies: list[ProxyConfig],
    engine: SingBoxBackend,
    *,
    url: str,
    timeout: float,
    max_ms: float,
    workers: int = 32,
    batch_size: int = 128,
    retry_batch_size: int = 16,
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    batch_size = max(1, int(batch_size))
    retry_batch_size = max(1, int(retry_batch_size))
    first_results: dict[str, BatchLatencyResult] = {}

    for offset in range(0, len(proxies), batch_size):
        batch = proxies[offset : offset + batch_size]
        results = _run_batch(batch, engine, url=url, timeout=timeout, workers=workers)
        first_results.update(results)
        print(f"[latency] batch={offset // batch_size + 1} checked={min(offset + len(batch), len(proxies))}/{len(proxies)}")

    retry_candidates = [
        proxy for proxy in proxies
        if _is_retryable_latency_error(
            first_results.get(proxy.ensure_id(), BatchLatencyResult(False, error="missing batch result"))
        )
    ]
    final_results = dict(first_results)

    if retry_candidates:
        recovered = 0
        for offset in range(0, len(retry_candidates), retry_batch_size):
            batch = retry_candidates[offset : offset + retry_batch_size]
            retry_results = _run_batch(batch, engine, url=url, timeout=timeout, workers=min(workers, len(batch)))
            final_results.update(retry_results)
            recovered += sum(1 for result in retry_results.values() if result.ok)
            print(
                f"[latency-retry] batch={offset // retry_batch_size + 1} "
                f"checked={min(offset + len(batch), len(retry_candidates))}/{len(retry_candidates)}"
            )
        print(f"[latency-retry] candidates={len(retry_candidates)} recovered={recovered}")

    threshold_enabled = max_ms >= 0

    for proxy in proxies:
        proxy_id = proxy.ensure_id()
        first = first_results.get(proxy_id, BatchLatencyResult(False, error="missing batch result"))
        result = final_results.get(proxy_id, first)
        proxy.tests.latency_ms = result.latency_ms
        passed_threshold = (
            result.ok
            and result.latency_ms is not None
            and (not threshold_enabled or result.latency_ms <= max_ms)
        )
        attempts = [{"ok": first.ok, "latency_ms": first.latency_ms, "error": first.error}]
        if _is_retryable_latency_error(first):
            attempts.append({"ok": result.ok, "latency_ms": result.latency_ms, "error": result.error})
        proxy.tests.latency = {
            "status": "pass" if passed_threshold else "fail",
            "latency_ms": result.latency_ms,
            "http_code": None,
            "error": result.error,
            "method": "sing-box-clash-api",
            "attempts": attempts,
        }
        if not result.ok:
            proxy.tests.status = "rejected_latency_error"
            rejected.append(proxy)
        elif not passed_threshold:
            proxy.tests.status = "rejected_latency_threshold"
            rejected.append(proxy)
        else:
            proxy.tests.status = "latency_pass"
            passed.append(proxy)

    return passed, rejected
