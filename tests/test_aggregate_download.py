import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import (
    SpeedResult,
    _download_staged,
    _expected_download_bytes,
    _normalize_download_stream_stages,
    _split_download_urls,
    _stage_requests,
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

    def test_cachefly_range_stage_keeps_total_payload_constant(self):
        requests = _stage_requests(
            "https://cachefly.cachefly.net/100mb.test",
            4,
            total_bytes=80_000_000,
        )
        self.assertEqual(
            requests,
            [
                (
                    "https://cachefly.cachefly.net/100mb.test",
                    ["Range: bytes=0-19999999"],
                    20_000_000,
                ),
                (
                    "https://cachefly.cachefly.net/100mb.test",
                    ["Range: bytes=20000000-39999999"],
                    20_000_000,
                ),
                (
                    "https://cachefly.cachefly.net/100mb.test",
                    ["Range: bytes=40000000-59999999"],
                    20_000_000,
                ),
                (
                    "https://cachefly.cachefly.net/100mb.test",
                    ["Range: bytes=60000000-79999999"],
                    20_000_000,
                ),
            ],
        )

    def test_unknown_endpoint_is_repeated_without_rewriting(self):
        url = "https://example.com/file.bin"
        self.assertEqual(_split_download_urls(url, 4), [url, url, url, url])

    def test_stream_stages_accept_arbitrary_count_and_values(self):
        self.assertEqual(_normalize_download_stream_stages([1, 3, 7, 10, 16]), (1, 3, 7, 10, 16))
        self.assertEqual(_normalize_download_stream_stages([3, 6, 12]), (3, 6, 12))
        self.assertEqual(_normalize_download_stream_stages(10), (10,))

    def test_stream_stages_default_when_omitted(self):
        self.assertEqual(_normalize_download_stream_stages(None), (1, 2, 4, 8))

    def test_stream_stages_reject_invalid_values(self):
        for value in ([], [0], [-1], [1, 1], [1.5], [True], ["bad"]):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _normalize_download_stream_stages(value)

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

    def test_custom_stages_are_used_in_configured_order(self):
        responses = [
            SpeedResult(True, mbps=75.0, bytes_transferred=50_000_000, time_seconds=5.3, http_code=200),
            SpeedResult(True, mbps=155.0, bytes_transferred=50_000_000, time_seconds=2.6, http_code=200),
            SpeedResult(True, mbps=240.0, bytes_transferred=50_000_000, time_seconds=1.7, http_code=200),
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
                stream_stages=(3, 6, 10),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 240.0)
        self.assertEqual([stage["streams"] for stage in result.stages], [3, 6, 10])
        self.assertEqual([call.kwargs["streams"] for call in probe.call_args_list], [3, 6, 10])

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

    def test_retryable_primary_failure_reruns_full_stages_on_cachefly(self):
        responses = [
            SpeedResult(
                False,
                http_code=429,
                error="rate limited",
                url="https://speed.cloudflare.com/__down?bytes=80000000",
                backend="cloudflare",
            ),
            SpeedResult(
                True,
                mbps=45.0,
                bytes_transferred=80_000_000,
                time_seconds=14.2,
                http_code=206,
                url="https://cachefly.cachefly.net/100mb.test",
                backend="cachefly",
            ),
            SpeedResult(
                True,
                mbps=82.0,
                bytes_transferred=80_000_000,
                time_seconds=7.8,
                http_code=206,
                url="https://cachefly.cachefly.net/100mb.test",
                backend="cachefly",
            ),
            SpeedResult(
                True,
                mbps=140.0,
                bytes_transferred=80_000_000,
                time_seconds=4.6,
                http_code=206,
                url="https://cachefly.cachefly.net/100mb.test",
                backend="cachefly",
            ),
        ]
        with patch("proxyfilter.speed._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url="https://speed.cloudflare.com/__down?bytes=80000000",
                fallback_urls=["https://cachefly.cachefly.net/100mb.test"],
                fallback_http_codes={429},
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2, 4),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "cachefly")
        self.assertEqual(result.mbps, 140.0)
        self.assertEqual(
            [(stage["backend"], stage["streams"]) for stage in result.stages],
            [("cloudflare", 1), ("cachefly", 1), ("cachefly", 2), ("cachefly", 4)],
        )
        self.assertEqual([call.kwargs["streams"] for call in probe.call_args_list], [1, 1, 2, 4])
        self.assertEqual(
            [call.kwargs["url"] for call in probe.call_args_list],
            [
                "https://speed.cloudflare.com/__down?bytes=80000000",
                "https://cachefly.cachefly.net/100mb.test",
                "https://cachefly.cachefly.net/100mb.test",
                "https://cachefly.cachefly.net/100mb.test",
            ],
        )
        self.assertEqual(
            [call.kwargs["total_bytes"] for call in probe.call_args_list],
            [80_000_000, 80_000_000, 80_000_000, 80_000_000],
        )


if __name__ == "__main__":
    unittest.main()
