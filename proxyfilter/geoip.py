from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import ipaddress
import json
import subprocess
from urllib.parse import quote

from .engine import EngineBackend, EngineError
from .failure_reason import classify_error
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
    reason: str | None = None
    provider: str | None = None
    url: str | None = None
    http_code: int | None = None


def _flag_from_code(country_code: str | None) -> str | None:
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return None
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def _same_ip(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left) == ipaddress.ip_address(right)
    except ValueError:
        return left.strip() == right.strip()


def _validate_geo_result(result: GeoIPResult, expected_ip: str) -> GeoIPResult:
    if not result.ok:
        return result

    if result.ip:
        if not _same_ip(result.ip, expected_ip):
            result.ok = False
            result.error = f"GeoIP response IP {result.ip} does not match requested IP {expected_ip}"
            result.reason = "ip_mismatch"
            return result
    else:
        result.ip = expected_ip

    country_code = (result.country_code or "").strip().upper()
    if len(country_code) != 2 or not country_code.isalpha():
        result.ok = False
        result.country_code = None
        result.flag = None
        result.error = "GeoIP response is missing a valid country_code"
        result.reason = "incomplete_response"
        return result

    result.country_code = country_code
    if not result.flag:
        result.flag = _flag_from_code(country_code)
    return result


def _parse_ipwhois(payload: str, expected_ip: str) -> GeoIPResult:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return GeoIPResult(False, ip=expected_ip, error=f"invalid JSON: {exc}", reason="invalid_response")

    if not isinstance(data, dict):
        return GeoIPResult(False, ip=expected_ip, error="GeoIP response is not an object", reason="invalid_response")
    if data.get("success") is not True:
        return GeoIPResult(False, ip=expected_ip, error=str(data.get("message") or "GeoIP lookup failed"), reason="provider_error")

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

    return _validate_geo_result(
        GeoIPResult(
            True,
            ip=str(data.get("ip") or "") or None,
            country_code=country_code,
            country=country,
            flag=flag or _flag_from_code(country_code),
            asn=asn,
            org=str(connection.get("org") or "") or None,
            isp=str(connection.get("isp") or "") or None,
        ),
        expected_ip,
    )


def _parse_ipapi(payload: str, expected_ip: str) -> GeoIPResult:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        return GeoIPResult(False, ip=expected_ip, error=f"invalid JSON: {exc}", reason="invalid_response")

    if not isinstance(data, dict):
        return GeoIPResult(False, ip=expected_ip, error="GeoIP response is not an object", reason="invalid_response")
    if data.get("error") is True:
        return GeoIPResult(False, ip=expected_ip, error=str(data.get("reason") or data.get("message") or "GeoIP lookup failed"), reason="provider_error")

    country_code = str(data.get("country_code") or "").upper() or None
    asn_raw = str(data.get("asn") or "").upper()
    if asn_raw.startswith("AS"):
        asn_raw = asn_raw[2:]
    try:
        asn = int(asn_raw) if asn_raw else None
    except ValueError:
        asn = None

    return _validate_geo_result(
        GeoIPResult(
            True,
            ip=str(data.get("ip") or "") or None,
            country_code=country_code,
            country=str(data.get("country_name") or "") or None,
            flag=_flag_from_code(country_code),
            asn=asn,
            org=str(data.get("org") or "") or None,
            isp=str(data.get("org") or "") or None,
        ),
        expected_ip,
    )


def _provider_parser(provider: str):
    name = provider.strip().lower()
    if name == "ipwhois":
        return _parse_ipwhois
    if name == "ipapi":
        return _parse_ipapi
    raise ValueError(f"unsupported GeoIP provider: {provider}")


def _lookup_provider(
    ip: str,
    *,
    provider: str,
    url_template: str,
    timeout: float,
    curl_command: str,
    proxy_url: str | None = None,
) -> GeoIPResult:
    provider_name = provider.strip().lower()
    parser = _provider_parser(provider_name)
    if "{ip}" not in url_template:
        return GeoIPResult(False, ip=ip, provider=provider_name, error="geo URL template must contain {ip}", reason="invalid_config")

    url = url_template.replace("{ip}", quote(ip, safe=""))
    command = [
        curl_command,
        "--silent",
        "--show-error",
        "--fail",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
    ]
    if proxy_url:
        command.extend(["--proxy", proxy_url])
    command.append(url)

    try:
        proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout + 5)
    except (subprocess.TimeoutExpired, OSError) as exc:
        error = str(exc)
        return GeoIPResult(False, ip=ip, provider=provider_name, url=url, error=error, reason=classify_error(error))

    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout).strip() or f"curl exited {proc.returncode}"
        return GeoIPResult(False, ip=ip, provider=provider_name, url=url, error=error, reason=classify_error(error))

    result = parser(proc.stdout, ip)
    result.provider = provider_name
    result.url = url
    if not result.ok and not result.reason:
        result.reason = classify_error(result.error)
    return result


def _lookup_ipwhois(
    ip: str,
    *,
    url_template: str,
    timeout: float,
    curl_command: str,
    proxy_url: str | None = None,
) -> GeoIPResult:
    return _lookup_provider(
        ip,
        provider="ipwhois",
        url_template=url_template,
        timeout=timeout,
        curl_command=curl_command,
        proxy_url=proxy_url,
    )


def _attempt_dict(result: GeoIPResult) -> dict:
    return {
        "provider": result.provider,
        "url": result.url,
        "ok": result.ok,
        "http_code": result.http_code,
        "reason": result.reason,
        "error": result.error,
    }


def enrich_geo_many(
    proxies: list[ProxyConfig],
    *,
    engine: EngineBackend | None = None,
    provider: str = "ipwhois",
    url_template: str = "https://ipwho.is/{ip}",
    fallback_enabled: bool = True,
    fallback_provider: str | None = "ipapi",
    fallback_url_template: str | None = "https://ipapi.co/{ip}/json/",
    timeout: float = 8,
    workers: int = 4,
    curl_command: str = "curl",
) -> list[ProxyConfig]:
    provider_name = provider.strip().lower()
    _provider_parser(provider_name)

    fallback_name = None
    if fallback_enabled:
        fallback_name = (fallback_provider or "").strip().lower() or None
        if fallback_name:
            _provider_parser(fallback_name)
        if fallback_name == provider_name:
            fallback_name = None
            fallback_url_template = None
    else:
        fallback_url_template = None

    representatives: dict[str, ProxyConfig] = {}
    for proxy in proxies:
        if proxy.tests.exit_ip and proxy.tests.exit_ip not in representatives:
            representatives[proxy.tests.exit_ip] = proxy

    unique_ips = sorted(representatives)
    results: dict[str, tuple[GeoIPResult, list[dict], bool]] = {}
    total = len(unique_ips)
    checked = 0

    def lookup(ip: str) -> tuple[GeoIPResult, list[dict], bool]:
        session = None
        proxy_url = None
        try:
            if engine is not None:
                session = engine.start(representatives[ip])
                proxy_url = session.socks_url

            primary = _validate_geo_result(
                _lookup_provider(
                    ip,
                    provider=provider_name,
                    url_template=url_template,
                    timeout=timeout,
                    curl_command=curl_command,
                    proxy_url=proxy_url,
                ),
                ip,
            )
            attempts = [_attempt_dict(primary)]
            if primary.ok or not fallback_name or not fallback_url_template:
                return primary, attempts, False

            fallback = _validate_geo_result(
                _lookup_provider(
                    ip,
                    provider=fallback_name,
                    url_template=fallback_url_template,
                    timeout=timeout,
                    curl_command=curl_command,
                    proxy_url=proxy_url,
                ),
                ip,
            )
            attempts.append(_attempt_dict(fallback))
            return fallback, attempts, True
        except EngineError as exc:
            error = str(exc)
            failed = GeoIPResult(False, ip=ip, provider=None, error=error, reason=classify_error(error))
            return failed, [], False
        finally:
            if session is not None:
                engine.stop(session)

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
                    error = str(exc)
                    failed = GeoIPResult(False, ip=ip, provider=None, error=error, reason=classify_error(error))
                    results[ip] = (failed, [], False)
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
                "provider": None,
                "fallback_used": False,
                "transport": "proxy" if engine is not None else "direct",
                "attempts": [],
                "reason": "exit_ip_unknown",
                "error": "exit IP is unknown",
            }
            continue

        result, attempts, fallback_used = results[ip]
        if result.ok:
            reason = None
            error = None
            selected_provider = result.provider
        else:
            reason = "all_providers_failed" if len(attempts) > 1 else (result.reason or "geo_lookup_failed")
            error = result.error or "GeoIP lookup failed"
            selected_provider = None

        proxy.tests.geo = {
            "status": "ok" if result.ok else "error",
            "ip": result.ip,
            "country_code": result.country_code,
            "country": result.country,
            "flag": result.flag,
            "asn": result.asn,
            "org": result.org,
            "isp": result.isp,
            "provider": selected_provider,
            "fallback_used": fallback_used,
            "transport": "proxy" if engine is not None else "direct",
            "attempts": attempts,
            "reason": reason,
            "error": error,
        }
        if result.ok:
            proxy.tests.country = result.country_code

    return proxies
