from __future__ import annotations

"""Isolated Throne adapter.

The rest of proxy-filter must not depend on thronectl command syntax or JSON field
names.  Once the exact installed Throne version is inspected, implement import,
latency, speed and IP methods here only.
"""

from dataclasses import dataclass
import json
import subprocess


@dataclass(slots=True)
class ThroneResult:
    profile_id: str
    latency_ms: float | None = None
    download_mbps: float | None = None
    upload_mbps: float | None = None
    exit_ip: str | None = None
    raw: dict | None = None


class ThroneAdapter:
    def __init__(self, command: str = "thronectl", timeout: int = 900):
        self.command = command
        self.timeout = timeout

    def _run_json(self, *args: str):
        proc = subprocess.run(
            [self.command, "--json", *args],
            check=True,
            text=True,
            capture_output=True,
            timeout=self.timeout,
        )
        return json.loads(proc.stdout)

    def status(self):
        return self._run_json("status")

    def latency(self, profile_ids: list[str]):
        raise NotImplementedError("Map to the exact installed thronectl JSON schema after first host test")

    def speed(self, profile_ids: list[str]):
        raise NotImplementedError("Map to the exact installed thronectl JSON schema after first host test")

    def ip(self, profile_ids: list[str]):
        raise NotImplementedError("Map to the exact installed thronectl JSON schema after first host test")
