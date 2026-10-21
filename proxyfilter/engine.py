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
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _list_value(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [str(v) for v in value if str(v)]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def _first(params: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in params and params[key] not in (None, ""):
            return params[key]
    return default


class SingBoxBackend:
    """Temporary sing-box worker backend.

    Tested target: sing-box 1.14.x.  Input conversion intentionally supports the
    common URI/Clash forms and passes native sing-box outbounds through almost
    verbatim.  ``sing-box check`` is the final compatibility authority: an
    upstream profile that cannot be represented safely is rejected before any
    network probe is run.
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
        log_path = runtime / "sing-box.log"
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

        # Native sing-box input: preserve supported fields and only restore the
        # canonical endpoint/tag fields removed by ingest.
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

        if protocol == "vless":
            out: dict[str, Any] = {
                "type": "vless",
                "tag": "proxy-out",
                "server": proxy.server,
                "server_port": proxy.port,
                "uuid": str(_first(p, "uuid", default="")),
            }
            flow = _first(p, "flow")
            if flow:
                out["flow"] = str(flow)
            self._apply_tls(out, p, protocol)
            self._apply_transport(out, p)

        elif protocol == "vmess":
            out = {
                "type": "vmess",
                "tag": "proxy-out",
                "server": proxy.server,
                "server_port": proxy.port,
                "uuid": str(_first(p, "uuid", "id", default="")),
                "security": str(_first(p, "security", "scy", "cipher", default="auto")),
                "alter_id": int(_first(p, "alter_id", "alterId", "aid", default=0) or 0),
            }
            self._apply_tls(out, p, protocol)
            self._apply_transport(out, p)

        elif protocol == "trojan":
            out = {
                "type": "trojan",
                "tag": "proxy-out",
                "server": proxy.server,
                "server_port": proxy.port,
                "password": str(_first(p, "password", default="")),
            }
            # Trojan normally requires TLS even when the URI omits security=tls.
            self._apply_tls(out, p, protocol, default_enabled=True)
            self._apply_transport(out, p)

        elif protocol == "ss":
            out = {
                "type": "shadowsocks",
                "tag": "proxy-out",
                "server": proxy.server,
                "server_port": proxy.port,
                "method": str(_first(p, "method", "cipher", default="")),
                "password": str(_first(p, "password", default="")),
            }
            plugin = _first(p, "plugin")
            if plugin:
                plugin_text = str(plugin)
                if ";" in plugin_text and not _first(p, "plugin_opts", "plugin-opts"):
                    name, opts = plugin_text.split(";", 1)
                    out["plugin"] = name
                    out["plugin_opts"] = opts
                else:
                    out["plugin"] = plugin_text
                    opts = _first(p, "plugin_opts", "plugin-opts")
                    if opts:
                        out["plugin_opts"] = str(opts)

        elif protocol == "hysteria2":
            out = {
                "type": "hysteria2",
                "tag": "proxy-out",
                "server": proxy.server,
                "server_port": proxy.port,
                "password": str(_first(p, "password", "auth", default="")),
            }
            up = _first(p, "up_mbps", "up-mbps")
            down = _first(p, "down_mbps", "down-mbps")
            if up not in (None, ""):
                out["up_mbps"] = int(float(up))
            if down not in (None, ""):
                out["down_mbps"] = int(float(down))
            obfs_type = _first(p, "obfs")
            obfs_password = _first(p, "obfs-password", "obfs_password")
            if isinstance(obfs_type, dict):
                out["obfs"] = obfs_type
            elif obfs_type and obfs_password:
                out["obfs"] = {"type": str(obfs_type), "password": str(obfs_password)}
            self._apply_tls(out, p, protocol, default_enabled=True)

        elif protocol == "tuic":
            out = {
                "type": "tuic",
                "tag": "proxy-out",
                "server": proxy.server,
                "server_port": proxy.port,
                "uuid": str(_first(p, "uuid", default="")),
                "password": str(_first(p, "password", default="")),
            }
            cc = _first(p, "congestion_control", "congestion-controller", "congestion_control")
            if cc:
                out["congestion_control"] = str(cc)
            udp_relay = _first(p, "udp_relay_mode", "udp-relay-mode")
            if udp_relay:
                out["udp_relay_mode"] = str(udp_relay)
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
        native_tls = p.get("tls")
        if isinstance(native_tls, dict):
            tls = dict(native_tls)
            tls.setdefault("enabled", True)
            out["tls"] = tls
            return

        security = str(_first(p, "security", default="")).lower()
        enabled = default_enabled or security in {"tls", "reality"} or _truthy(native_tls)
        if not enabled:
            return

        tls: dict[str, Any] = {"enabled": True}
        server_name = _first(p, "sni", "server_name", "servername", "server-name")
        if server_name:
            tls["server_name"] = str(server_name)

        insecure = _first(p, "allowInsecure", "allow_insecure", "skip-cert-verify", "insecure")
        if insecure is not None:
            tls["insecure"] = _truthy(insecure)

        alpn = _list_value(_first(p, "alpn"))
        if alpn:
            tls["alpn"] = alpn

        fp = _first(p, "fp", "client-fingerprint", "fingerprint")
        if fp and str(fp).lower() not in {"", "none"}:
            tls["utls"] = {"enabled": True, "fingerprint": str(fp)}

        reality_opts = p.get("reality-opts") if isinstance(p.get("reality-opts"), dict) else {}
        if security == "reality" or reality_opts:
            public_key = _first(p, "pbk", "public_key", default=reality_opts.get("public-key"))
            short_id = _first(p, "sid", "short_id", default=reality_opts.get("short-id"))
            reality: dict[str, Any] = {"enabled": True}
            if public_key:
                reality["public_key"] = str(public_key)
            if short_id is not None:
                reality["short_id"] = str(short_id)
            tls["reality"] = reality

        out["tls"] = tls

    def _apply_transport(self, out: dict[str, Any], p: dict[str, Any]) -> None:
        native = p.get("transport")
        if isinstance(native, dict):
            out["transport"] = native
            return

        # Clash forms first.
        network = str(_first(p, "network", "net", "type", default="")).lower()
        ws_opts = p.get("ws-opts") if isinstance(p.get("ws-opts"), dict) else None
        grpc_opts = p.get("grpc-opts") if isinstance(p.get("grpc-opts"), dict) else None

        if network in {"ws", "websocket"} or ws_opts is not None:
            opts = ws_opts or {}
            transport: dict[str, Any] = {"type": "ws"}
            path = _first(p, "path", default=opts.get("path"))
            if path:
                transport["path"] = str(path)
            headers: dict[str, Any] = {}
            if isinstance(opts.get("headers"), dict):
                headers.update(opts["headers"])
            host = _first(p, "host")
            if host:
                headers.setdefault("Host", str(host))
            if headers:
                transport["headers"] = headers
            out["transport"] = transport
            return

        if network == "grpc" or grpc_opts is not None:
            opts = grpc_opts or {}
            service = _first(p, "serviceName", "service_name", default=opts.get("grpc-service-name"))
            transport = {"type": "grpc"}
            if service:
                transport["service_name"] = str(service)
            out["transport"] = transport
            return

        if network in {"http", "h2"}:
            transport = {"type": "http"}
            path = _first(p, "path")
            if path:
                transport["path"] = str(path)
            hosts = _list_value(_first(p, "host"))
            if hosts:
                transport["host"] = hosts
            out["transport"] = transport
            return

        if network in {"httpupgrade", "http-upgrade"}:
            transport = {"type": "httpupgrade"}
            path = _first(p, "path")
            host = _first(p, "host")
            if path:
                transport["path"] = str(path)
            if host:
                transport["host"] = str(host)
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
