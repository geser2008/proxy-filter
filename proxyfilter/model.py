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
    exit_ip_probe: dict[str, Any] = field(default_factory=lambda: {"status": "pending", "ip": None, "error": None})
    geo: dict[str, Any] = field(default_factory=lambda: {
        "status": "pending",
        "ip": None,
        "country_code": None,
        "country": None,
        "flag": None,
        "asn": None,
        "org": None,
        "isp": None,
        "error": None,
    })
    diversity: dict[str, Any] = field(default_factory=lambda: {
        "status": "pending",
        "cluster_type": None,
        "cluster_key": None,
        "cluster_size": None,
        "latency_rank": None,
        "download_rank": None,
        "upload_rank": None,
        "rank_sum": None,
        "overall_rank": None,
        "reason": None,
    })
    render: dict[str, Any] = field(default_factory=lambda: {
        "status": "pending",
        "name": None,
        "uri": None,
        "error": None,
    })
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
    sources: list[SourceInfo] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sources = self._merge_source_lists([self.source], self.sources)

    @staticmethod
    def _merge_source_lists(*groups: list[SourceInfo]) -> list[SourceInfo]:
        merged: list[SourceInfo] = []
        seen: set[str] = set()
        for group in groups:
            for source in group:
                key = source.id
                if key in seen:
                    continue
                seen.add(key)
                merged.append(source)
        return merged

    def provenance_sources(self) -> list[SourceInfo]:
        return self._merge_source_lists([self.source], self.sources)

    def merge_sources_from(self, other: "ProxyConfig") -> None:
        self.sources = self._merge_source_lists(self.provenance_sources(), other.provenance_sources())

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
        self.sources = self.provenance_sources()
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
        sources_data = data.get("sources") or []
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
            exit_ip_probe=tests_data.get("exit_ip_probe", {"status": "pending", "ip": None, "error": None}),
            geo=tests_data.get("geo", {
                "status": "pending",
                "ip": None,
                "country_code": None,
                "country": None,
                "flag": None,
                "asn": None,
                "org": None,
                "isp": None,
                "error": None,
            }),
            diversity=tests_data.get("diversity", {
                "status": "pending",
                "cluster_type": None,
                "cluster_key": None,
                "cluster_size": None,
                "latency_rank": None,
                "download_rank": None,
                "upload_rank": None,
                "rank_sum": None,
                "overall_rank": None,
                "reason": None,
            }),
            render=tests_data.get("render", {
                "status": "pending",
                "name": None,
                "uri": None,
                "error": None,
            }),
            latency_ms=tests_data.get("latency_ms"),
            download_mbps=tests_data.get("download_mbps"),
            upload_mbps=tests_data.get("upload_mbps"),
            exit_ip=tests_data.get("exit_ip"),
            country=tests_data.get("country"),
            status=tests_data.get("status", "parsed"),
        )
        source = SourceInfo(
            str(source_data.get("id", "")),
            str(source_data.get("name", "")),
            str(source_data.get("format", "unknown")),
        )
        sources = [
            SourceInfo(
                str(item.get("id", "")),
                str(item.get("name", "")),
                str(item.get("format", "unknown")),
            )
            for item in sources_data
            if isinstance(item, dict)
        ]
        proxy = cls(
            source=source,
            protocol=str(config.get("protocol", "")),
            server=str(config.get("server", "")),
            port=int(config.get("port", 0)),
            name=str(config.get("name", "")),
            params=dict(config.get("params") or {}),
            original_format=str(original.get("format", "")),
            original_raw=str(original.get("raw", "")),
            tests=tests,
            id=str(data.get("id", "")),
            sources=sources,
        )
        if not proxy.id:
            proxy.ensure_id()
        return proxy
