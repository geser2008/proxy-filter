#!/usr/bin/env python3
"""Offline, credential-free check of native XHTTP support in the installed core.

Uses ONLY synthetic UUIDs/endpoints and runs sing-box check, never sing-box run.
Safe to share the printed diagnostics: no real URI or checkpoint is loaded.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

UUID = "00000000-0000-0000-0000-000000000001"


def make_config(transport: dict) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "udp", "tag": "dns-direct", "server": "1.1.1.1"}]},
        "inbounds": [
            {"type": "mixed", "tag": "probe-in", "listen": "127.0.0.1",
             "listen_port": 18080},
        ],
        "outbounds": [{
            "type": "vless", "tag": "proxy-out",
            "server": "example.org", "server_port": 443,
            "uuid": UUID, "domain_resolver": "dns-direct",
            "tls": {"enabled": True, "server_name": "example.org"},
            "transport": transport,
        }],
        "route": {"final": "proxy-out", "default_domain_resolver": "dns-direct"},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="sing-box")
    args = parser.parse_args()
    cases = (
        ("ws_control", {"type": "ws", "path": "/probe"}),
        ("xhttp_minimal", {"type": "xhttp"}),
        ("xhttp_path", {"type": "xhttp", "path": "/probe"}),
        ("xhttp_mode", {"type": "xhttp", "mode": "stream-up", "path": "/probe"}),
    )
    try:
        version = subprocess.run(
            [args.binary, "version"], capture_output=True, text=True,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        parser.error(f"core version probe failed: {type(exc).__name__}")
    print((version.stdout or "").splitlines()[0] if version.stdout else "version: unavailable")
    for label, transport in cases:
        with tempfile.TemporaryDirectory(prefix="proxyfilter-xhttp-smoke-") as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(make_config(transport)), encoding="utf-8")
            path.chmod(0o600)
            try:
                proc = subprocess.run(
                    [args.binary, "check", "-c", str(path)],
                    capture_output=True, text=True, timeout=20, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                print(f"{label}: {type(exc).__name__}")
                continue
            print(f"{label}: {'PASS' if proc.returncode == 0 else 'FAIL'}")
            if proc.returncode:
                # The config contains only the fixed, public values in this
                # script. No real proxy, passwords or URI are ever loaded.
                print((proc.stderr or proc.stdout or "(no diagnostic)").strip())


if __name__ == "__main__":
    main()
