import unittest
from unittest.mock import patch

from proxyfilter.geoip import (
    GeoIPResult,
    _parse_ipapi,
    _parse_ipapi_com,
    _parse_ipapi_is,
    _parse_ipinfo,
    _parse_ipwhois,
    enrich_geo_many,
)
from proxyfilter.model import ProxyConfig, SourceInfo


class GeoIPTests(unittest.TestCase):
    def test_parse_ipwhois_response(self):
        result = _parse_ipwhois(
            '{"ip":"203.0.113.7","success":true,"country":"Netherlands","country_code":"NL",'
            '"flag":{"emoji":"🇳🇱"},"connection":{"asn":64500,"org":"Example Org","isp":"Example ISP"}}',
            "203.0.113.7",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.country_code, "NL")
        self.assertEqual(result.flag, "🇳🇱")
        self.assertEqual(result.asn, 64500)
        self.assertEqual(result.org, "Example Org")

    def test_parse_ipapi_response(self):
        result = _parse_ipapi(
            '{"ip":"203.0.113.7","country_code":"NL","country_name":"Netherlands",'
            '"asn":"AS64500","org":"Example Org"}',
            "203.0.113.7",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.country_code, "NL")
        self.assertEqual(result.country, "Netherlands")
        self.assertEqual(result.asn, 64500)
        self.assertEqual(result.flag, "🇳🇱")

    def test_parse_ipapi_com_response(self):
        result = _parse_ipapi_com(
            '{"status":"success","country":"United States","countryCode":"US",'
            '"isp":"GTHost","org":"GTHost","as":"AS63023 GTHost","query":"169.197.140.224"}',
            "169.197.140.224",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.country_code, "US")
        self.assertEqual(result.country, "United States")
        self.assertEqual(result.flag, "🇺🇸")
        self.assertEqual(result.asn, 63023)
        self.assertEqual(result.org, "GTHost")
        self.assertEqual(result.isp, "GTHost")

    def test_parse_ipinfo_response(self):
        result = _parse_ipinfo(
            '{"ip":"31.59.143.147","city":"Warsaw","region":"Mazovia","country":"PL",'
            '"org":"AS197574 ExpressHost Ltd"}',
            "31.59.143.147",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.country_code, "PL")
        self.assertEqual(result.flag, "🇵🇱")
        self.assertEqual(result.asn, 197574)
        self.assertEqual(result.org, "ExpressHost Ltd")

    def test_parse_ipapi_is_full_response(self):
        result = _parse_ipapi_is(
            '{"ip":"31.59.143.147","is_bogon":false,'
            '"company":{"name":"ExpressHost Ltd"},'
            '"asn":{"asn":197574,"org":"ExpressHost Ltd"},'
            '"location":{"country":"Poland","country_code":"PL"}}',
            "31.59.143.147",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.country_code, "PL")
        self.assertEqual(result.country, "Poland")
        self.assertEqual(result.flag, "🇵🇱")
        self.assertEqual(result.asn, 197574)
        self.assertEqual(result.org, "ExpressHost Ltd")

    def test_parse_ipapi_is_anonymous_response_is_incomplete_without_country_code(self):
        result = _parse_ipapi_is(
            '{"ip":"31.59.143.147","is_bogon":false,"company":"ExpressHost Ltd",'
            '"asn":"AS197574 ExpressHost Ltd","city":"Warsaw","region":"Mazovia",'
            '"country":"Poland","timezone":"Europe/Warsaw"}',
            "31.59.143.147",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "incomplete_response")
        self.assertEqual(result.country, "Poland")
        self.assertEqual(result.asn, 197574)

    def test_failed_provider_response_is_not_success(self):
        result = _parse_ipwhois(
            '{"ip":"203.0.113.7","success":false,"message":"Reserved range"}',
            "203.0.113.7",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "Reserved range")
        self.assertEqual(result.reason, "provider_error")

    def test_duplicate_exit_ips_are_looked_up_once(self):
        first = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        second = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.2", 443)
        first.tests.exit_ip = "203.0.113.7"
        second.tests.exit_ip = "203.0.113.7"

        response = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code="NL",
            country="Netherlands",
            flag="🇳🇱",
            asn=64500,
            org="Example Org",
            isp="Example ISP",
            provider="ipwhois",
            url="https://ipwho.is/203.0.113.7",
        )
        with patch("proxyfilter.geoip._lookup_provider", return_value=response) as lookup:
            enriched = enrich_geo_many([first, second], workers=1, fallback_provider=None)

        self.assertEqual(enriched, [first, second])
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(first.tests.geo["country_code"], "NL")
        self.assertEqual(second.tests.geo["asn"], 64500)

    def test_primary_success_does_not_call_fallback(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        primary = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code="NL",
            country="Netherlands",
            provider="ipwhois",
            url="https://ipwho.is/203.0.113.7",
        )
        with patch("proxyfilter.geoip._lookup_provider", return_value=primary) as lookup:
            enrich_geo_many([proxy], workers=1)

        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(proxy.tests.geo["provider"], "ipwhois")
        self.assertFalse(proxy.tests.geo["fallback_used"])
        self.assertEqual(len(proxy.tests.geo["attempts"]), 1)

    def test_failed_primary_uses_ipapi_once_and_records_both_attempts(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        primary = GeoIPResult(
            False,
            ip="203.0.113.7",
            error="curl: (28) timeout",
            reason="timeout",
            provider="ipwhois",
            url="https://ipwho.is/203.0.113.7",
        )
        fallback = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code="NL",
            country="Netherlands",
            asn=64500,
            provider="ipapi",
            url="https://ipapi.co/203.0.113.7/json/",
        )
        with patch("proxyfilter.geoip._lookup_provider", side_effect=[primary, fallback]) as lookup:
            enrich_geo_many([proxy], workers=1)

        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(proxy.tests.geo["status"], "ok")
        self.assertEqual(proxy.tests.geo["provider"], "ipapi")
        self.assertTrue(proxy.tests.geo["fallback_used"])
        self.assertIsNone(proxy.tests.geo["reason"])
        self.assertIsNone(proxy.tests.geo["error"])
        self.assertEqual(
            [(item["provider"], item["ok"], item["reason"]) for item in proxy.tests.geo["attempts"]],
            [("ipwhois", False, "timeout"), ("ipapi", True, None)],
        )

    def test_both_providers_failed_records_aggregate_failure(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        failures = [
            GeoIPResult(False, ip="203.0.113.7", error="timeout", reason="timeout", provider="ipwhois", url="primary"),
            GeoIPResult(False, ip="203.0.113.7", error="rate limited", reason="provider_error", provider="ipapi", url="fallback"),
        ]
        with patch("proxyfilter.geoip._lookup_provider", side_effect=failures):
            enrich_geo_many([proxy], workers=1)

        self.assertEqual(proxy.tests.geo["status"], "error")
        self.assertIsNone(proxy.tests.geo["provider"])
        self.assertTrue(proxy.tests.geo["fallback_used"])
        self.assertEqual(proxy.tests.geo["reason"], "all_providers_failed")
        self.assertEqual(len(proxy.tests.geo["attempts"]), 2)

    def test_unknown_exit_ip_is_kept_without_lookup(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        with patch("proxyfilter.geoip._lookup_provider") as lookup:
            enriched = enrich_geo_many([proxy], workers=1)

        self.assertEqual(enriched, [proxy])
        self.assertEqual(lookup.call_count, 0)
        self.assertEqual(proxy.tests.geo["status"], "unknown")
        self.assertEqual(proxy.tests.geo["reason"], "exit_ip_unknown")
        self.assertEqual(proxy.tests.geo["attempts"], [])
        self.assertEqual(proxy.tests.status, "parsed")


if __name__ == "__main__":
    unittest.main()
