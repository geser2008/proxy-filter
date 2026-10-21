from __future__ import annotations

"""Headless proxy-core abstraction.

The project intentionally does not depend on a GUI client.  A backend adapter turns
one canonical ProxyConfig into a temporary core configuration, starts an
unprivileged child process bound to loopback, and exposes only a short-lived local
proxy endpoint to the probe layer.

The first backend target is sing-box. Xray can be added behind the same interface.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .model import ProxyConfig


@dataclass(slots=True)
class EngineSession:
    proxy_id: str
    host: str
    port: int
    process_pid: int | None = None
    runtime_path: Path | None = None

    @property
    def socks_url(self) -> str:
        return f"socks5h://{self.host}:{self.port}"


class EngineBackend(Protocol):
    def validate(self, proxy: ProxyConfig) -> tuple[bool, str | None]:
        """Return whether the selected core can represent/validate this profile."""
        ...

    def start(self, proxy: ProxyConfig) -> EngineSession:
        """Start a temporary loopback-only core instance for one proxy."""
        ...

    def stop(self, session: EngineSession) -> None:
        """Terminate the core instance and remove temporary state."""
        ...


class SingBoxBackend:
    """Placeholder for the first real headless backend.

    The generator/start-stop implementation will be added after canonical fields
    for all supported protocols are finalized. Keeping the interface here now
    prevents probe and pipeline code from becoming coupled to sing-box details.
    """

    def __init__(
        self,
        command: str = "sing-box",
        runtime_dir: str = "/srv/proxy-filter/data/runtime",
        listen_host: str = "127.0.0.1",
    ) -> None:
        self.command = command
        self.runtime_dir = Path(runtime_dir)
        self.listen_host = listen_host

    def validate(self, proxy: ProxyConfig) -> tuple[bool, str | None]:
        raise NotImplementedError("sing-box config generation/validation is the next implementation stage")

    def start(self, proxy: ProxyConfig) -> EngineSession:
        raise NotImplementedError("sing-box worker start/stop is the next implementation stage")

    def stop(self, session: EngineSession) -> None:
        raise NotImplementedError("sing-box worker start/stop is the next implementation stage")
