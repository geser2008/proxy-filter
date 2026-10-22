import unittest
from unittest.mock import patch

from proxyfilter.geoip import GeoIPResult, _parse_ipwhois, enrich_geo_many
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

    def test_failed_provider_response_is_not_success(self):
        result = _parse_ipwhois(
            '{"ip":"203.0.113.7","success":false,"message":"Reserved range"}',
            "203.0.113.7",
        )
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "Reserved range")

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
        )
        with patch("proxyfilter.geoip._lookup_ipwhois", return_value=response) as lookup:
            enriched = enrich_geo_many([first, second], workers=1)

        self.assertEqual(enriched, [first, second])
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(first.tests.geo["country_code"], "NL")
        self.assertEqual(second.tests.geo["asn"], 64500)

    def test_unknown_exit_ip_is_kept_without_lookup(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        with patch("proxyfilter.geoip._lookup_ipwhois") as lookup:
            enriched = enrich_geo_many([proxy], workers=1)

        self.assertEqual(enriched, [proxy])
        self.assertEqual(lookup.call_count, 0)
        self.assertEqual(proxy.tests.geo["status"], "unknown")
        self.assertEqual(proxy.tests.status, "parsed")


if __name__ == "__main__":
    unittest.main()
