from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import time

from .model import ProxyConfig


def _check_one(proxy: ProxyConfig, timeout: float) -> tuple[ProxyConfig, bool, float | None, str | None]:
    started = time.monotonic()
    try:
        with socket.create_connection((proxy.server, proxy.port), timeout=timeout):
            elapsed = (time.monotonic() - started) * 1000.0
            return proxy, True, round(elapsed, 2), None
    except OSError as exc:
        return proxy, False, None, str(exc)


def check_many(proxies: list[ProxyConfig], timeout: float = 3.0, workers: int = 64) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(_check_one, p, timeout) for p in proxies]
        for future in as_completed(futures):
            proxy, ok, latency, error = future.result()
            proxy.tests.tcp = {"status": "pass" if ok else "reject", "latency_ms": latency, "error": error}
            proxy.tests.status = "tcp_pass" if ok else "rejected_tcp"
            (passed if ok else rejected).append(proxy)
    return passed, rejected
