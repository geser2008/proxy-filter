import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import (
    SpeedResult,
    _download_with_fallbacks,
    _mbps,
    _parse_curl_metrics,
    _parse_curl_writeout,
)


class SpeedProbeTests(unittest.TestCase):
    def test_parse_curl_metrics(self):
        size, elapsed, http_code = _parse_curl_metrics("10000000\t2.5\t200")
        self.assertEqual(size, 10_000_000)
        self.assertEqual(elapsed, 2.5)
        self.assertEqual(http_code, 200)

    def test_parse_failed_curl_writeout_keeps_http_code(self):
        size, elapsed, http_code = _parse_curl_writeout("0\t0.25\t429")
        self.assertEqual(size, 0)
        self.assertEqual(elapsed, 0.25)
        self.assertEqual(http_code, 429)

    def test_mbps_uses_decimal_megabits(self):
        self.assertEqual(_mbps(10_000_000, 2.0), 40.0)

    def test_zero_size_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_curl_metrics("0\t1.0\t200")

    def test_zero_time_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_curl_metrics("1000\t0\t200")

    def test_429_retries_fallback_and_preserves_attempts(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        responses = [
            SpeedResult(False, http_code=429, error="rate limited", url="https://primary.example/test"),
            SpeedResult(True, mbps=150.0, bytes_transferred=100_000_000, time_seconds=5.333, http_code=200, url="https://fallback.example/test"),
        ]
        with patch("proxyfilter.speed._download_one", side_effect=responses) as probe:
            result = _download_with_fallbacks(
                proxy,
                object(),
                url="https://primary.example/test",
                fallback_urls=["https://fallback.example/test"],
                fallback_http_codes={429},
                timeout=30,
                curl_command="curl",
            )
        self.assertTrue(result.ok)
        self.assertEqual(result.url, "https://fallback.example/test")
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(result.attempts[0]["http_code"], 429)
        self.assertEqual(probe.call_count, 2)

    def test_non_retryable_failure_does_not_use_fallback(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        response = SpeedResult(False, error="SOCKS failure", url="https://primary.example/test")
        with patch("proxyfilter.speed._download_one", return_value=response) as probe:
            result = _download_with_fallbacks(
                proxy,
                object(),
                url="https://primary.example/test",
                fallback_urls=["https://fallback.example/test"],
                fallback_http_codes={429},
                timeout=30,
                curl_command="curl",
            )
        self.assertFalse(result.ok)
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(probe.call_count, 1)


if __name__ == "__main__":
    unittest.main()
