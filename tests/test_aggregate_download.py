import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import (
    SpeedResult,
    _download_staged,
    _expected_download_bytes,
    _split_download_urls,
)


class AggregateDownloadTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)

    def test_cloudflare_stage_keeps_total_payload_constant(self):
        original = "https://speed.cloudflare.com/__down?bytes=50000000"
        for streams in (1, 2, 4, 8):
            urls = _split_download_urls(original, streams)
            self.assertEqual(len(urls), streams)
            self.assertEqual(sum(_expected_download_bytes(url) or 0 for url in urls), 50_000_000)

    def test_unknown_endpoint_is_repeated_without_rewriting(self):
        url = "https://example.com/file.bin"
        self.assertEqual(_split_download_urls(url, 4), [url, url, url, url])

    def test_staged_download_returns_highest_aggregate_rate(self):
        responses = [
            SpeedResult(True, mbps=30.0, bytes_transferred=50_000_000, time_seconds=13.3, http_code=200),
            SpeedResult(True, mbps=58.0, bytes_transferred=50_000_000, time_seconds=6.9, http_code=200),
            SpeedResult(True, mbps=108.0, bytes_transferred=50_000_000, time_seconds=3.7, http_code=200),
            SpeedResult(True, mbps=190.0, bytes_transferred=50_000_000, time_seconds=2.1, http_code=200),
        ]
        with patch("proxyfilter.speed._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                fallback_urls=[],
                fallback_http_codes={429},
                timeout=30,
                curl_command="curl",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 190.0)
        self.assertEqual([stage["streams"] for stage in result.stages], [1, 2, 4, 8])
        self.assertEqual(probe.call_count, 4)

    def test_later_stage_failure_keeps_best_successful_stage(self):
        responses = [
            SpeedResult(True, mbps=35.0, bytes_transferred=50_000_000, time_seconds=11.4, http_code=200),
            SpeedResult(True, mbps=66.0, bytes_transferred=50_000_000, time_seconds=6.1, http_code=200),
            SpeedResult(False, error="timeout"),
        ]
        with patch("proxyfilter.speed._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                fallback_urls=[],
                fallback_http_codes={429},
                timeout=30,
                curl_command="curl",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 66.0)
        self.assertEqual([stage["streams"] for stage in result.stages], [1, 2, 4])
        self.assertEqual(probe.call_count, 3)


if __name__ == "__main__":
    unittest.main()
