from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any
import hashlib
import json


@dataclass(slots=True)
class SourceInfo:
    id: str
    name: str
    format: str = "unknown"


@dataclass(slots=True)
class TestState:
    security: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "reasons": []})
    tcp: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "latency_ms": None})
    core: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "error": None})
    latency: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "latency_ms": None, "http_code": None, "error": None})
    download: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "mbps": None, "error": None})
    upload: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "mbps": None, "error": None})
    latency_ms: float | None = None
    download_mbps: float | None = None
    upload_mbps: float | None = None
    exit_ip: str | None = None
    country: str | None = None
    status: str = "parsed"


@dataclass(slots=True)
class ProxyConfig:
    source: SourceInfo
    protocol: str
    server: str
    port: int
    name: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    original_format: str = ""
    original_raw: str = ""
    tests: TestState = field(default_factory=TestState)
    id: str = ""

    def identity_payload(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.lower(),
            "server": self.server.strip().lower(),
            "port": int(self.port),
            "params": self._canonical_params(self.params),
        }

    @staticmethod
    def _canonical_params(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: ProxyConfig._canonical_params(value[k]) for k in sorted(value) if k not in {"name", "tag", "ps"}}
        if isinstance(value, list):
            return [ProxyConfig._canonical_params(v) for v in value]
        return value

    def ensure_id(self) -> str:
        payload = json.dumps(self.identity_payload(), ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        self.id = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.id

    def to_dict(self) -> dict[str, Any]:
        if not self.id:
            self.ensure_id()
        d = asdict(self)
        d["config"] = {
            "protocol": d.pop("protocol"),
            "server": d.pop("server"),
            "port": d.pop("port"),
            "name": d.pop("name"),
            "params": d.pop("params"),
        }
        d["original"] = {
            "format": d.pop("original_format"),
            "raw": d.pop("original_raw"),
        }
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProxyConfig":
        source_data = data.get("source") or {}
        config = data.get("config") or {}
        original = data.get("original") or {}
        tests_data = data.get("tests") or {}
        tests = TestState(
            security=tests_data.get("security", {"status": "pending", "reasons": []}),
            tcp=tests_data.get("tcp", {"status": "pending", "latency_ms": None}),
            core=tests_data.get("core", {"status": "pending", "error": None}),
            latency=tests_data.get("latency", {"status": "pending", "latency_ms": None, "http_code": None, "error": None}),
            download=tests_data.get("download", {"status": "pending", "mbps": None, "error": None}),
            upload=tests_data.get("upload", {"status": "pending", "mbps": None, "error": None}),
            latency_ms=tests_data.get("latency_ms"),
            download_mbps=tests_data.get("download_mbps"),
            upload_mbps=tests_data.get("upload_mbps"),
            exit_ip=tests_data.get("exit_ip"),
            country=tests_data.get("country"),
            status=tests_data.get("status", "parsed"),
        )
        proxy = cls(
            source=SourceInfo(
                str(source_data.get("id", "")),
                str(source_data.get("name", "")),
                str(source_data.get("format", "unknown")),
            ),
            protocol=str(config.get("protocol", "")),
            server=str(config.get("server", "")),
            port=int(config.get("port", 0)),
            name=str(config.get("name", "")),
            params=dict(config.get("params") or {}),
            original_format=str(original.get("format", "")),
            original_raw=str(original.get("raw", "")),
            tests=tests,
            id=str(data.get("id", "")),
        )
        if not proxy.id:
            proxy.ensure_id()
        return proxy
