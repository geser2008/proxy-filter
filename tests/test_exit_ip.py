import unittest
from unittest.mock import patch

from proxyfilter.exit_ip import ExitIPResult, _parse_ip, check_exit_ip_many
from proxyfilter.model import ProxyConfig, SourceInfo


class ExitIPTests(unittest.TestCase):
    def test_parse_ipv4(self):
        self.assertEqual(_parse_ip("203.0.113.7\n"), "203.0.113.7")

    def test_parse_ipv6_is_normalized(self):
        self.assertEqual(_parse_ip("2001:0db8:0:0::1"), "2001:db8::1")

    def test_invalid_response_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_ip("not-an-ip")

    def test_direct_wan_match_is_rejected(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        with patch(
            "proxyfilter.exit_ip._probe_one",
            return_value=ExitIPResult(True, ip="203.0.113.7", http_code=200),
        ):
            passed, rejected = check_exit_ip_many(
                [proxy],
                object(),
                url="https://example.invalid/ip",
                timeout=5,
                reject_direct_wan_ip=True,
                direct_ips={"203.0.113.7"},
                workers=1,
            )
        self.assertEqual(passed, [])
        self.assertEqual(rejected, [proxy])
        self.assertEqual(proxy.tests.status, "rejected_exit_ip_direct_wan")
        self.assertTrue(proxy.tests.exit_ip_probe["direct_wan_match"])

    def test_different_exit_ip_passes(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        with patch(
            "proxyfilter.exit_ip._probe_one",
            return_value=ExitIPResult(True, ip="198.51.100.9", http_code=200),
        ):
            passed, rejected = check_exit_ip_many(
                [proxy],
                object(),
                url="https://example.invalid/ip",
                timeout=5,
                reject_direct_wan_ip=True,
                direct_ips={"203.0.113.7"},
                workers=1,
            )
        self.assertEqual(passed, [proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(proxy.tests.exit_ip, "198.51.100.9")
        self.assertEqual(proxy.tests.status, "exit_ip_pass")

    def test_unknown_exit_ip_is_kept_by_default(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        with patch(
            "proxyfilter.exit_ip._probe_one",
            return_value=ExitIPResult(False, http_code=0, error="timeout"),
        ):
            passed, rejected = check_exit_ip_many(
                [proxy],
                object(),
                url="https://example.invalid/ip",
                timeout=5,
                reject_direct_wan_ip=True,
                direct_ips={"203.0.113.7"},
                workers=1,
            )
        self.assertEqual(passed, [proxy])
        self.assertEqual(rejected, [])
        self.assertIsNone(proxy.tests.exit_ip)
        self.assertEqual(proxy.tests.status, "exit_ip_unknown")
        self.assertEqual(proxy.tests.exit_ip_probe["status"], "unknown")

    def test_unknown_exit_ip_can_be_rejected(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        with patch(
            "proxyfilter.exit_ip._probe_one",
            return_value=ExitIPResult(False, http_code=0, error="timeout"),
        ):
            passed, rejected = check_exit_ip_many(
                [proxy],
                object(),
                url="https://example.invalid/ip",
                timeout=5,
                reject_direct_wan_ip=True,
                reject_unknown_exit_ip=True,
                direct_ips={"203.0.113.7"},
                workers=1,
            )
        self.assertEqual(passed, [])
        self.assertEqual(rejected, [proxy])
        self.assertEqual(proxy.tests.status, "rejected_exit_ip_error")
        self.assertEqual(proxy.tests.exit_ip_probe["status"], "fail")


if __name__ == "__main__":
    unittest.main()
