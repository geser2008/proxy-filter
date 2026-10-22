from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json
import subprocess
from urllib.parse import quote

from .model import ProxyConfig


@dataclass(slots=True)
class GeoIPResult:
    ok: bool
    ip: str | None = None
    country_code: str | None = None
    country: str | None = None
    flag: str | None = None
    asn: int | None = None
    org: str | None = None
    isp: str | None = None
    error: str | None = None


def _parse_ipwhois(payload: str, expected_ip: str) -> GeoIPResult:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return GeoIPResult(False, ip=expected_ip, error=f"invalid JSON: {exc}")

    if not isinstance(data, dict):
        return GeoIPResult(False, ip=expected_ip, error="GeoIP response is not an object")
    if data.get("success") is not True:
        return GeoIPResult(False, ip=expected_ip, error=str(data.get("message") or "GeoIP lookup failed"))

    country_code = str(data.get("country_code") or "").upper() or None
    country = str(data.get("country") or "") or None

    flag_data = data.get("flag") or {}
    flag = str(flag_data.get("emoji") or "") or None if isinstance(flag_data, dict) else None

    connection = data.get("connection") or {}
    if not isinstance(connection, dict):
        connection = {}

    asn_raw = connection.get("asn")
    try:
        asn = int(asn_raw) if asn_raw is not None else None
    except (TypeError, ValueError):
        asn = None

    response_ip = str(data.get("ip") or expected_ip)
    return GeoIPResult(
        True,
        ip=response_ip,
        country_code=country_code,
        country=country,
        flag=flag,
        asn=asn,
        org=str(connection.get("org") or "") or None,
        isp=str(connection.get("isp") or "") or None,
    )


def _lookup_ipwhois(
    ip: str,
    *,
    url_template: str,
    timeout: float,
    curl_command: str,
) -> GeoIPResult:
    if "{ip}" not in url_template:
        return GeoIPResult(False, ip=ip, error="geo.url_template must contain {ip}")
    url = url_template.replace("{ip}", quote(ip, safe=""))
    try:
        proc = subprocess.run(
            [
                curl_command,
                "--silent",
                "--show-error",
                "--fail",
                "--connect-timeout",
                str(timeout),
                "--max-time",
                str(timeout),
                url,
            ],
            text=True,
            capture_output=True,
            timeout=timeout + 5,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return GeoIPResult(False, ip=ip, error=str(exc))

    if proc.returncode != 0:
        return GeoIPResult(
            False,
            ip=ip,
            error=(proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}",
        )
    return _parse_ipwhois(proc.stdout, ip)


def enrich_geo_many(
    proxies: list[ProxyConfig],
    *,
    provider: str = "ipwhois",
    url_template: str = "https://ipwho.is/{ip}",
    timeout: float = 8,
    workers: int = 4,
    curl_command: str = "curl",
) -> list[ProxyConfig]:
    provider_name = provider.strip().lower()
    if provider_name != "ipwhois":
        raise ValueError(f"unsupported GeoIP provider: {provider}")

    unique_ips = sorted({proxy.tests.exit_ip for proxy in proxies if proxy.tests.exit_ip})
    results: dict[str, GeoIPResult] = {}
    total = len(unique_ips)
    checked = 0

    def lookup(ip: str) -> GeoIPResult:
        return _lookup_ipwhois(
            ip,
            url_template=url_template,
            timeout=timeout,
            curl_command=curl_command,
        )

    if workers <= 1:
        for ip in unique_ips:
            results[ip] = lookup(ip)
            checked += 1
            print(f"[geo] checked={checked}/{total}")
    else:
        with ThreadPoolExecutor(max_workers=max(1, int(workers))) as pool:
            futures = {pool.submit(lookup, ip): ip for ip in unique_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    results[ip] = future.result()
                except Exception as exc:
                    results[ip] = GeoIPResult(False, ip=ip, error=str(exc))
                checked += 1
                print(f"[geo] checked={checked}/{total}")

    for proxy in proxies:
        ip = proxy.tests.exit_ip
        if not ip:
            proxy.tests.geo = {
                "status": "unknown",
                "ip": None,
                "country_code": None,
                "country": None,
                "flag": None,
                "asn": None,
                "org": None,
                "isp": None,
                "error": "exit IP is unknown",
                "provider": provider_name,
            }
            continue

        result = results[ip]
        proxy.tests.geo = {
            "status": "ok" if result.ok else "error",
            "ip": result.ip,
            "country_code": result.country_code,
            "country": result.country,
            "flag": result.flag,
            "asn": result.asn,
            "org": result.org,
            "isp": result.isp,
            "error": result.error,
            "provider": provider_name,
        }
        if result.ok:
            proxy.tests.country = result.country_code

    return proxies
