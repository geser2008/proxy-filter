import unittest
from unittest.mock import patch

from proxyfilter.geoip import GeoIPResult, _parse_ipapi, _parse_ipwhois, enrich_geo_many
from proxyfilter.model import ProxyConfig, SourceInfo


class GeoIPValidationTests(unittest.TestCase):
    def test_ipwhois_rejects_response_for_different_ip(self):
        result = _parse_ipwhois(
            '{"ip":"203.0.113.8","success":true,"country":"Netherlands","country_code":"NL"}',
            "203.0.113.7",
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.ip, "203.0.113.8")
        self.assertEqual(result.reason, "ip_mismatch")

    def test_ipapi_rejects_response_for_different_ip(self):
        result = _parse_ipapi(
            '{"ip":"203.0.113.8","country_code":"NL","country_name":"Netherlands"}',
            "203.0.113.7",
        )

        self.assertFalse(result.ok)
        self.assertEqual(result.ip, "203.0.113.8")
        self.assertEqual(result.reason, "ip_mismatch")

    def test_incomplete_primary_success_uses_fallback(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        primary = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code=None,
            country=None,
            asn=64500,
            provider="ipwhois",
            url="primary",
        )
        fallback = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code="NL",
            country="Netherlands",
            asn=None,
            provider="ipapi",
            url="fallback",
        )

        with patch("proxyfilter.geoip._lookup_provider", side_effect=[primary, fallback]) as lookup:
            enrich_geo_many([proxy], workers=1)

        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(proxy.tests.geo["status"], "ok")
        self.assertEqual(proxy.tests.geo["provider"], "ipapi")
        self.assertTrue(proxy.tests.geo["fallback_used"])
        self.assertEqual(proxy.tests.geo["country_code"], "NL")
        self.assertEqual(
            [(item["provider"], item["ok"], item["reason"]) for item in proxy.tests.geo["attempts"]],
            [("ipwhois", False, "incomplete_response"), ("ipapi", True, None)],
        )

    def test_incomplete_fallback_is_final_failure(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        primary = GeoIPResult(
            False,
            ip="203.0.113.7",
            error="timeout",
            reason="timeout",
            provider="ipwhois",
            url="primary",
        )
        fallback = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code=None,
            country="Netherlands",
            asn=64500,
            provider="ipapi",
            url="fallback",
        )

        with patch("proxyfilter.geoip._lookup_provider", side_effect=[primary, fallback]):
            enrich_geo_many([proxy], workers=1)

        self.assertEqual(proxy.tests.geo["status"], "error")
        self.assertIsNone(proxy.tests.geo["provider"])
        self.assertTrue(proxy.tests.geo["fallback_used"])
        self.assertEqual(proxy.tests.geo["reason"], "all_providers_failed")
        self.assertEqual(proxy.tests.geo["attempts"][1]["reason"], "incomplete_response")

    def test_country_code_is_minimum_success_even_without_asn(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        primary = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code="NL",
            country="Netherlands",
            asn=None,
            provider="ipwhois",
            url="primary",
        )

        with patch("proxyfilter.geoip._lookup_provider", return_value=primary) as lookup:
            enrich_geo_many([proxy], workers=1)

        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(proxy.tests.geo["status"], "ok")
        self.assertEqual(proxy.tests.geo["provider"], "ipwhois")
        self.assertFalse(proxy.tests.geo["fallback_used"])
        self.assertIsNone(proxy.tests.geo["asn"])


if __name__ == "__main__":
    unittest.main()
