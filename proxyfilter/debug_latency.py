from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
from typing import Any, Iterable

from .batch_latency import _api_delay, _free_port, _render_batch_config, _wait_port
from .model import ProxyConfig
from .singbox_backend import SingBoxBackend


_STAGE_FILES = (
    "06-rejected-latency.jsonl",
    "06-latency-ok.jsonl",
    "05-core-ok.jsonl",
    "04-tcp-ok.jsonl",
    "03-safe.jsonl",
    "02-unique.jsonl",
    "01-parsed.jsonl",
)


def find_proxy_in_work(
    data_dir: Path,
    proxy_ref: str,
    source_ids: Iterable[str] | None = None,
) -> tuple[ProxyConfig, Path]:
    """Find one proxy by full id or unique id prefix in existing work JSONL.

    Stage files are searched from the latest latency result backwards so the
    returned object retains the most useful existing test state. Repeated
    copies of the same proxy across pipeline stages are de-duplicated by id.
    """
    ref = proxy_ref.strip().lower()
    if not ref:
        raise ValueError("empty proxy id/prefix")

    work_root = data_dir / "work"
    if source_ids:
        source_dirs = [work_root / source_id for source_id in source_ids]
    else:
        source_dirs = [path for path in sorted(work_root.iterdir()) if path.is_dir() and path.name != "all"] if work_root.exists() else []

    matches: dict[str, tuple[ProxyConfig, Path]] = {}
    for source_dir in source_dirs:
        for filename in _STAGE_FILES:
            path = source_dir / filename
            if not path.is_file():
                continue
            with path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"invalid JSON in {path}:{lineno}: {exc}") from exc
                    proxy_id = str(data.get("id", "")).lower()
                    if proxy_id.startswith(ref) and proxy_id not in matches:
                        matches[proxy_id] = (ProxyConfig.from_dict(data), path)

    if not matches:
        scope = ", ".join(source_ids or []) or "all sources"
        raise ValueError(f"proxy id/prefix {proxy_ref!r} not found in work data ({scope})")
    if len(matches) > 1:
        ids = ", ".join(sorted(proxy_id[:16] for proxy_id in matches))
        raise ValueError(f"proxy id/prefix {proxy_ref!r} is ambiguous: {ids}")
    return next(iter(matches.values()))


def _stop_process(process: subprocess.Popen[str] | None, shutdown_timeout: float) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=shutdown_timeout)
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


def debug_latency_proxy(
    proxy: ProxyConfig,
    engine: SingBoxBackend,
    *,
    url: str,
    timeout: float,
    source_path: Path | None = None,
) -> tuple[dict[str, Any], Path]:
    """Reproduce the Clash API latency test for one proxy with debug logging.

    Unlike normal batch latency runs, the runtime directory is intentionally
    preserved for inspection. It contains proxy.json, config.json,
    sing-box.log and result.json.
    """
    proxy_id = proxy.ensure_id()
    runtime = engine.runtime_dir / "debug" / proxy_id
    if runtime.exists():
        shutil.rmtree(runtime)
    runtime.mkdir(parents=True, exist_ok=True)

    proxy_path = runtime / "proxy.json"
    config_path = runtime / "config.json"
    log_path = runtime / "sing-box.log"
    result_path = runtime / "result.json"

    proxy_path.write_text(json.dumps(proxy.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    api_port = _free_port(engine.listen_host)
    config, tag_map = _render_batch_config(engine, [proxy], api_port, url)
    config["log"] = {"level": "debug", "timestamp": True}
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    result_payload: dict[str, Any] = {
        "id": proxy_id,
        "source_work_file": str(source_path) if source_path is not None else None,
        "test_url": url,
        "timeout_seconds": timeout,
        "method": "sing-box-clash-api-debug",
        "ok": False,
        "latency_ms": None,
        "error": None,
        "check": None,
    }

    check = subprocess.run(
        [engine.command, "check", "-c", str(config_path)],
        text=True,
        capture_output=True,
        timeout=30,
    )
    result_payload["check"] = {
        "returncode": check.returncode,
        "stdout": check.stdout,
        "stderr": check.stderr,
    }
    if check.returncode != 0:
        detail = (check.stderr or check.stdout).strip()
        result_payload["error"] = detail or "sing-box debug config check failed"
        result_path.write_text(json.dumps(result_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result_payload, runtime

    process: subprocess.Popen[str] | None = None
    try:
        with log_path.open("w", encoding="utf-8") as log_fh:
            process = subprocess.Popen(
                [engine.command, "run", "-c", str(config_path)],
                text=True,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        _wait_port(engine.listen_host, api_port, process, engine.startup_timeout)
        tag = next(iter(tag_map))
        delay_result = _api_delay(engine.listen_host, api_port, tag, url, timeout)
        result_payload["ok"] = delay_result.ok
        result_payload["latency_ms"] = delay_result.latency_ms
        result_payload["error"] = delay_result.error
    except Exception as exc:
        result_payload["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        _stop_process(process, engine.shutdown_timeout)
        result_path.write_text(json.dumps(result_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    return result_payload, runtime
