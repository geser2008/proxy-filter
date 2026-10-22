import unittest
from pathlib import Path
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import (
    SpeedResult,
    _download_with_fallbacks,
    _mbps,
    _parse_curl_metrics,
    _parse_curl_writeout,
    _upload_with_fallbacks,
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

    def test_upload_http_100_partial_retries_same_url_without_expect(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "trojan", "127.0.0.1", 443)
        responses = [
            SpeedResult(
                False,
                bytes_transferred=14_000_000,
                time_seconds=1.5,
                http_code=100,
                error="curl: (56) unexpected eof while reading",
                url="https://primary.example/up",
            ),
            SpeedResult(
                True,
                mbps=90.0,
                bytes_transferred=20_000_000,
                time_seconds=1.777,
                http_code=200,
                url="https://primary.example/up",
                expect_disabled=True,
            ),
        ]
        with patch("proxyfilter.speed._upload_one", side_effect=responses) as probe:
            result = _upload_with_fallbacks(
                proxy,
                object(),
                url="https://primary.example/up",
                fallback_urls=[],
                fallback_http_codes={429, 500, 502, 503, 504},
                payload_path=Path("/tmp/payload"),
                timeout=30,
                curl_command="curl",
            )
        self.assertTrue(result.ok)
        self.assertEqual(len(result.attempts), 2)
        self.assertFalse(result.attempts[0]["expect_disabled"])
        self.assertTrue(result.attempts[1]["expect_disabled"])
        self.assertFalse(probe.call_args_list[0].kwargs["disable_expect"])
        self.assertTrue(probe.call_args_list[1].kwargs["disable_expect"])

    def test_upload_zero_byte_transport_failure_retries_once(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)
        responses = [
            SpeedResult(
                False,
                bytes_transferred=0,
                http_code=0,
                error="curl: (97) cannot complete SOCKS5 connection",
                url="https://primary.example/up",
            ),
            SpeedResult(
                True,
                mbps=80.0,
                bytes_transferred=20_000_000,
                time_seconds=2.0,
                http_code=200,
                url="https://primary.example/up",
            ),
        ]
        with patch("proxyfilter.speed._upload_one", side_effect=responses) as probe:
            result = _upload_with_fallbacks(
                proxy,
                object(),
                url="https://primary.example/up",
                fallback_urls=[],
                fallback_http_codes={429, 500, 502, 503, 504},
                payload_path=Path("/tmp/payload"),
                timeout=30,
                curl_command="curl",
            )
        self.assertTrue(result.ok)
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(probe.call_args_list[0].kwargs["disable_expect"], False)
        self.assertEqual(probe.call_args_list[1].kwargs["disable_expect"], False)

    def test_upload_zero_byte_transport_failure_only_retries_once(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        response = SpeedResult(
            False,
            bytes_transferred=0,
            http_code=0,
            error="curl: (28) timeout with 0 bytes received",
            url="https://primary.example/up",
        )
        with patch("proxyfilter.speed._upload_one", return_value=response) as probe:
            result = _upload_with_fallbacks(
                proxy,
                object(),
                url="https://primary.example/up",
                fallback_urls=[],
                fallback_http_codes={429, 500, 502, 503, 504},
                payload_path=Path("/tmp/payload"),
                timeout=30,
                curl_command="curl",
            )
        self.assertFalse(result.ok)
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(probe.call_count, 2)

    def test_upload_http_failure_is_not_transport_retried(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)
        response = SpeedResult(
            False,
            bytes_transferred=0,
            http_code=403,
            error="HTTP 403",
            url="https://primary.example/up",
        )
        with patch("proxyfilter.speed._upload_one", return_value=response) as probe:
            result = _upload_with_fallbacks(
                proxy,
                object(),
                url="https://primary.example/up",
                fallback_urls=[],
                fallback_http_codes={429, 500, 502, 503, 504},
                payload_path=Path("/tmp/payload"),
                timeout=30,
                curl_command="curl",
            )
        self.assertFalse(result.ok)
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(probe.call_count, 1)


if __name__ == "__main__":
    unittest.main()
