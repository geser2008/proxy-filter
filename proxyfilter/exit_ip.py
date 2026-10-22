from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import subprocess

from .engine import EngineBackend, EngineError
from .model import ProxyConfig


@dataclass(slots=True)
class ExitIPResult:
    ok: bool
    ip: str | None = None
    http_code: int | None = None
    error: str | None = None


def _parse_ip(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("empty exit IP response")
    return str(ipaddress.ip_address(text))


def _curl_ip(
    *,
    url: str,
    timeout: float,
    curl_command: str,
    proxy_url: str | None = None,
) -> ExitIPResult:
    command = [
        curl_command,
        "--silent",
        "--show-error",
        "--fail",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
        "--write-out",
        "\n%{http_code}",
    ]
    if proxy_url:
        command.extend(["--proxy", proxy_url])
    command.append(url)

    try:
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout + 5,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return ExitIPResult(False, error=str(exc))

    lines = proc.stdout.rstrip("\n").splitlines()
    http_code = None
    body = ""
    if lines:
        try:
            http_code = int(lines[-1])
            body = "\n".join(lines[:-1]).strip()
        except ValueError:
            body = proc.stdout.strip()

    if proc.returncode != 0:
        return ExitIPResult(
            False,
            http_code=http_code,
            error=(proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}",
        )

    try:
        return ExitIPResult(True, ip=_parse_ip(body), http_code=http_code)
    except ValueError as exc:
        return ExitIPResult(False, http_code=http_code, error=str(exc))


def discover_direct_ip(*, url: str, timeout: float, curl_command: str = "curl") -> str:
    result = _curl_ip(url=url, timeout=timeout, curl_command=curl_command)
    if not result.ok or not result.ip:
        raise RuntimeError(f"failed to discover direct WAN IP: {result.error or 'unknown error'}")
    return result.ip


def _probe_one(
    proxy: ProxyConfig,
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    curl_command: str,
) -> ExitIPResult:
    session = None
    try:
        session = engine.start(proxy)
        return _curl_ip(
            url=url,
            timeout=timeout,
            curl_command=curl_command,
            proxy_url=session.socks_url,
        )
    except EngineError as exc:
        return ExitIPResult(False, error=str(exc))
    finally:
        if session is not None:
            engine.stop(session)


def check_exit_ip_many(
    proxies: list[ProxyConfig],
    engine: EngineBackend,
    *,
    url: str,
    timeout: float,
    reject_direct_wan_ip: bool,
    direct_ips: set[str] | None = None,
    workers: int = 4,
    curl_command: str = "curl",
) -> tuple[list[ProxyConfig], list[ProxyConfig]]:
    if not url:
        raise ValueError("exit_ip.url is required")

    normalized_direct_ips: set[str] = set()
    for value in direct_ips or set():
        normalized_direct_ips.add(_parse_ip(value))

    passed: list[ProxyConfig] = []
    rejected: list[ProxyConfig] = []
    total = len(proxies)
    checked = 0

    def record(proxy: ProxyConfig, result: ExitIPResult) -> None:
        nonlocal checked
        proxy.tests.exit_ip = result.ip
        leaked = bool(result.ok and result.ip and result.ip in normalized_direct_ips)
        proxy.tests.exit_ip_probe = {
            "status": "pass" if result.ok and not leaked else "fail",
            "ip": result.ip,
            "http_code": result.http_code,
            "error": result.error,
            "direct_wan_match": leaked,
            "method": "curl-socks5h",
        }
        if not result.ok:
            proxy.tests.status = "rejected_exit_ip_error"
            rejected.append(proxy)
        elif reject_direct_wan_ip and leaked:
            proxy.tests.status = "rejected_exit_ip_direct_wan"
            rejected.append(proxy)
        else:
            proxy.tests.status = "exit_ip_pass"
            passed.append(proxy)
        checked += 1
        print(f"[exit-ip] checked={checked}/{total}")

    if workers <= 1:
        for proxy in proxies:
            record(
                proxy,
                _probe_one(proxy, engine, url=url, timeout=timeout, curl_command=curl_command),
            )
        return passed, rejected

    with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
        futures = {
            pool.submit(_probe_one, proxy, engine, url=url, timeout=timeout, curl_command=curl_command): proxy
            for proxy in proxies
        }
        for future in as_completed(futures):
            proxy = futures[future]
            try:
                result = future.result()
            except Exception as exc:
                result = ExitIPResult(False, error=str(exc))
            record(proxy, result)

    return passed, rejected
