from __future__ import annotations

"""Headless proxy-core abstraction and sing-box 1.14+ backend.

A worker renders one canonical ProxyConfig into a short-lived sing-box config,
validates it with ``sing-box check``, starts the core as an unprivileged child
bound only to loopback, and exposes a local mixed (SOCKS/HTTP) endpoint to probes.
No persistent sing-box daemon is required.
"""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from typing import Any, Protocol

from .model import ProxyConfig


class EngineError(RuntimeError):
    pass


@dataclass(slots=True)
class EngineSession:
    proxy_id: str
    host: str
    port: int
    process: subprocess.Popen[str] | None = None
    runtime_path: Path | None = None
    config_path: Path | None = None
    log_path: Path | None = None

    @property
    def socks_url(self) -> str:
        return f"socks5h://{self.host}:{self.port}"

    @property
    def http_url(self) -> str:
        return f"http://{self.host}:{self.port}"


class EngineBackend(Protocol):
    def validate(self, proxy: ProxyConfig) -> tuple[bool, str | None]: ...
    def start(self, proxy: ProxyConfig) -> EngineSession: ...
    def stop(self, session: EngineSession) -> None: ...


def _truthy(value: Any) -> bool:
    """Convert only explicit boolean forms; never guess an invalid value as False."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise EngineError(f"invalid boolean value: {value!r}")


def _list_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [v.strip() for v in str(value).split(",")]


def _first(params: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first present alias, including explicit empty/null values."""
    for key in keys:
        if key in params:
            return params[key]
    return default


def _has_any(params: dict[str, Any], *keys: str) -> bool:
    return any(key in params for key in keys)


def _integer_or_original(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value.strip())
    return value


class SingBoxBackend:
    """Temporary sing-box worker backend.

    Tested target: sing-box 1.14.x. Input conversion supports common URI/Clash
    forms and passes native sing-box outbounds through almost verbatim. Source
    values are not repaired or replaced with guessed defaults. ``sing-box check``
    is the final compatibility authority whenever a source field has a lossless
    target representation.
    """

    def __init__(
        self,
        command: str = "sing-box",
        runtime_dir: str = "/srv/proxy-filter/data/runtime",
        listen_host: str = "127.0.0.1",
        startup_timeout: float = 5.0,
        shutdown_timeout: float = 3.0,
    ) -> None:
        self.command = command
        self.runtime_dir = Path(runtime_dir)
        self.listen_host = listen_host
        self.startup_timeout = startup_timeout
        self.shutdown_timeout = shutdown_timeout

    def version(self) -> str:
        proc = subprocess.run(
            [self.command, "version"], text=True, capture_output=True, timeout=10
        )
        if proc.returncode != 0:
            raise EngineError(proc.stderr.strip() or "sing-box version failed")
        return proc.stdout.strip()

    def validate(self, proxy: ProxyConfig) -> tuple[bool, str | None]:
        runtime = self._new_runtime(proxy)
        try:
            config_path = runtime / "config.json"
            self._write_config(config_path, proxy, self._free_port())
            proc = subprocess.run(
                [self.command, "check", "-c", str(config_path)],
                text=True,
                capture_output=True,
                timeout=20,
            )
            if proc.returncode == 0:
                return True, None
            detail = (proc.stderr or proc.stdout).strip()
            return False, detail or f"sing-box check exited {proc.returncode}"
        except Exception as exc:
            return False, str(exc)
        finally:
            shutil.rmtree(runtime, ignore_errors=True)

    def start(self, proxy: ProxyConfig) -> EngineSession:
        runtime = self._new_runtime(proxy)
        config_path = runtime / "config.json"
        log_path = runtime / "singbox.log"
        port = self._free_port()
        self._write_config(config_path, proxy, port)

        check = subprocess.run(
            [self.command, "check", "-c", str(config_path)],
            text=True,
            capture_output=True,
            timeout=20,
        )
        if check.returncode != 0:
            shutil.rmtree(runtime, ignore_errors=True)
            raise EngineError((check.stderr or check.stdout).strip() or "sing-box check failed")

        log_fh = log_path.open("w", encoding="utf-8")
        try:
            proc = subprocess.Popen(
                [self.command, "run", "-c", str(config_path)],
                text=True,
                stdout=log_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log_fh.close()

        session = EngineSession(
            proxy_id=proxy.ensure_id(),
            host=self.listen_host,
            port=port,
            process=proc,
            runtime_path=runtime,
            config_path=config_path,
            log_path=log_path,
        )

        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                detail = self._read_log(log_path)
                self.stop(session)
                raise EngineError(detail or f"sing-box exited {proc.returncode}")
            try:
                with socket.create_connection((self.listen_host, port), timeout=0.15):
                    return session
            except OSError:
                time.sleep(0.05)

        detail = self._read_log(log_path)
        self.stop(session)
        raise EngineError(detail or "sing-box startup timeout")

    def stop(self, session: EngineSession) -> None:
        proc = session.process
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=self.shutdown_timeout)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
        if session.runtime_path is not None:
            shutil.rmtree(session.runtime_path, ignore_errors=True)

    def render_config(self, proxy: ProxyConfig, listen_port: int) -> dict[str, Any]:
        outbound = self._render_outbound(proxy)
        return {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {"type": "udp", "tag": "dns-direct", "server": "1.1.1.1"}
                ]
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "probe-in",
                    "listen": self.listen_host,
                    "listen_port": listen_port,
                }
            ],
            "outbounds": [outbound],
            "route": {
                "final": "proxy-out",
                "default_domain_resolver": "dns-direct",
            },
        }

    def _render_outbound(self, proxy: ProxyConfig) -> dict[str, Any]:
        p = proxy.params
        protocol = proxy.protocol.lower()
        if protocol == "hy2":
            protocol = "hysteria2"

        # Native sing-box input: preserve fields and only restore the canonical
        # endpoint/tag fields removed by ingest. domain_resolver belongs to the
        # isolated probe environment, not to source-profile repair.
        if proxy.original_format == "sing-box":
            out = dict(p)
            out.update(
                {
                    "type": protocol,
                    "tag": "proxy-out",
                    "server": proxy.server,
                    "server_port": proxy.port,
                }
            )
            out.setdefault("domain_resolver", "dns-direct")
            return out

        base = {
            "type": protocol if protocol != "ss" else "shadowsocks",
            "tag": "proxy-out",
            "server": proxy.server,
            "server_port": proxy.port,
        }

        if protocol == "vless":
            out: dict[str, Any] = dict(base)
            if "uuid" in p:
                out["uuid"] = p["uuid"]
            if "flow" in p:
                out["flow"] = p["flow"]
            self._apply_tls(out, p, protocol)
            self._apply_transport(out, p)

        elif protocol == "vmess":
            out = dict(base)
            if _has_any(p, "uuid", "id"):
                out["uuid"] = _first(p, "uuid", "id")
            if _has_any(p, "security", "scy", "cipher"):
                out["security"] = _first(p, "security", "scy", "cipher")
            if _has_any(p, "alter_id", "alterId", "aid"):
                out["alter_id"] = _integer_or_original(_first(p, "alter_id", "alterId", "aid"))
            self._apply_tls(out, p, protocol)
            self._apply_transport(out, p)

        elif protocol == "trojan":
            out = dict(base)
            if "password" in p:
                out["password"] = p["password"]
            # TLS is protocol-implied for Trojan; enabling it is format translation,
            # not a guessed replacement for a source parameter.
            self._apply_tls(out, p, protocol, default_enabled=True)
            self._apply_transport(out, p)

        elif protocol == "ss":
            out = dict(base)
            if _has_any(p, "method", "cipher"):
                out["method"] = _first(p, "method", "cipher")
            if "password" in p:
                out["password"] = p["password"]
            if "plugin" in p:
                plugin = p["plugin"]
                if isinstance(plugin, str) and ";" in plugin and not _has_any(p, "plugin_opts", "plugin-opts"):
                    name, opts = plugin.split(";", 1)
                    out["plugin"] = name
                    out["plugin_opts"] = opts
                else:
                    out["plugin"] = plugin
                    if _has_any(p, "plugin_opts", "plugin-opts"):
                        out["plugin_opts"] = _first(p, "plugin_opts", "plugin-opts")

        elif protocol == "hysteria2":
            out = dict(base)
            if _has_any(p, "password", "auth"):
                out["password"] = _first(p, "password", "auth")
            if _has_any(p, "up_mbps", "up-mbps"):
                out["up_mbps"] = _integer_or_original(_first(p, "up_mbps", "up-mbps"))
            if _has_any(p, "down_mbps", "down-mbps"):
                out["down_mbps"] = _integer_or_original(_first(p, "down_mbps", "down-mbps"))
            if "obfs" in p:
                obfs_type = p["obfs"]
                if isinstance(obfs_type, dict):
                    out["obfs"] = dict(obfs_type)
                elif _has_any(p, "obfs-password", "obfs_password"):
                    out["obfs"] = {
                        "type": obfs_type,
                        "password": _first(p, "obfs-password", "obfs_password"),
                    }
            self._apply_tls(out, p, protocol, default_enabled=True)

        elif protocol == "tuic":
            out = dict(base)
            if "uuid" in p:
                out["uuid"] = p["uuid"]
            if "password" in p:
                out["password"] = p["password"]
            if _has_any(p, "congestion_control", "congestion-controller"):
                out["congestion_control"] = _first(p, "congestion_control", "congestion-controller")
            if _has_any(p, "udp_relay_mode", "udp-relay-mode"):
                out["udp_relay_mode"] = _first(p, "udp_relay_mode", "udp-relay-mode")
            self._apply_tls(out, p, protocol, default_enabled=True)

        else:
            raise EngineError(f"unsupported sing-box outbound protocol: {protocol}")

        out["domain_resolver"] = "dns-direct"
        return out

    def _apply_tls(
        self,
        out: dict[str, Any],
        p: dict[str, Any],
        protocol: str,
        default_enabled: bool = False,
    ) -> None:
        if isinstance(p.get("tls"), dict):
            out["tls"] = dict(p["tls"])
            return

        security_value = _first(p, "security", default="")
        security = "" if security_value is None else str(security_value).lower()
        native_tls_present = "tls" in p
        native_tls = p.get("tls")
        native_tls_text = "" if native_tls is None else str(native_tls).strip().lower()
        enabled = default_enabled or security in {"tls", "reality"} or native_tls_text in {"tls", "reality"}
        if native_tls_present and native_tls_text not in {"tls", "reality"}:
            enabled = _truthy(native_tls) or enabled
        if not enabled:
            return

        tls: dict[str, Any] = {"enabled": True}
        if _has_any(p, "sni", "server_name", "servername", "server-name"):
            tls["server_name"] = _first(p, "sni", "server_name", "servername", "server-name")

        if _has_any(p, "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure"):
            tls["insecure"] = _truthy(
                _first(p, "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure")
            )

        if "alpn" in p:
            tls["alpn"] = _list_value(p["alpn"])

        if _has_any(p, "fp", "client-fingerprint", "fingerprint"):
            tls["utls"] = {
                "enabled": True,
                "fingerprint": _first(p, "fp", "client-fingerprint", "fingerprint"),
            }

        reality_opts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
        if security == "reality" or reality_opts:
            reality: dict[str, Any] = {"enabled": True}
            if _has_any(p, "pbk", "public_key"):
                reality["public_key"] = _first(p, "pbk", "public_key")
            elif "public-key" in reality_opts:
                reality["public_key"] = reality_opts["public-key"]
            if _has_any(p, "sid", "short_id"):
                reality["short_id"] = _first(p, "sid", "short_id")
            elif "short-id" in reality_opts:
                reality["short_id"] = reality_opts["short-id"]
            tls["reality"] = reality

        out["tls"] = tls

    def _apply_transport(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        native = p.get("transport")
        if isinstance(native, dict):
            out["transport"] = dict(native)
            return

        network_value = _first(p, "network", "net", "type", default="")
        network = "" if network_value is None else str(network_value).lower()
        ws_opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else None
        grpc_opts = p.get("grpc-opts") if isinstance(p.get("grpc-opts"), dict) else None

        if network in {"ws", "websocket"} or ws_opts is not None:
            opts = ws_opts or {}
            transport: dict[str, Any] = {"type": "ws"}
            if "path" in p:
                transport["path"] = p["path"]
            elif "path" in opts:
                transport["path"] = opts["path"]
            headers: dict[str, Any] = {}
            if isinstance(opts.get("headers"), dict):
                headers.update(opts["headers"])
            if "host" in p:
                headers.setdefault("Host", p["host"])
            if headers:
                transport["headers"] = headers
            out["transport"] = transport
            return

        if network == "grpc" or grpc_opts is not None:
            opts = grpc_opts or {}
            transport = {"type": "grpc"}
            if _has_any(p, "serviceName", "service_name"):
                transport["service_name"] = _first(p, "serviceName", "service_name")
            elif "grpc-service-name" in opts:
                transport["service_name"] = opts["grpc-service-name"]
            out["transport"] = transport
            return

        if network in {"http", "h2"}:
            transport = {"type": "http"}
            if "path" in p:
                transport["path"] = p["path"]
            if "host" in p:
                transport["host"] = _list_value(p["host"])
            out["transport"] = transport
            return

        if network in {"httpupgrade", "http-upgrade"}:
            transport = {"type": "httpupgrade"}
            if "path" in p:
                transport["path"] = p["path"]
            if "host" in p:
                transport["host"] = p["host"]
            out["transport"] = transport

    def _write_config(self, path: Path, proxy: ProxyConfig, listen_port: int) -> None:
        path.write_text(
            json.dumps(self.render_config(proxy, listen_port), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def _new_runtime(self, proxy: ProxyConfig) -> Path:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        proxy_id = proxy.ensure_id()[:12]
        return Path(tempfile.mkdtemp(prefix=f"{proxy_id}-", dir=self.runtime_dir))

    def _free_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.listen_host, 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def _read_log(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[-8000:].strip()
        except OSError:
            return ""
