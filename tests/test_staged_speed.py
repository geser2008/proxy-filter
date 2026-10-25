import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult
from proxyfilter.speed_staged import (
    _download_staged,
    _upload_staged,
    check_download_many,
    check_upload_many,
)


class StagedSpeedRegressionTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)

    def test_download_timeout_continues_to_more_streams(self):
        responses = [
            SpeedResult(False, mbps=10.0, bytes_transferred=50_000_000, error="curl: (28) Operation timed out", backend="cloudflare"),
            SpeedResult(False, mbps=20.0, bytes_transferred=60_000_000, error="curl: (28) Operation timed out", backend="cloudflare"),
            SpeedResult(True, mbps=75.0, bytes_transferred=80_000_000, time_seconds=8.5, http_code=200, backend="cloudflare"),
            SpeedResult(True, mbps=95.0, bytes_transferred=80_000_000, time_seconds=6.7, http_code=200, backend="cloudflare"),
        ]
        with patch("proxyfilter.speed._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url="https://speed.cloudflare.com/__down?bytes=80000000",
                fallback_urls=[],
                fallback_http_codes={429},
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2, 4, 10),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 95.0)
        self.assertEqual([call.kwargs["streams"] for call in probe.call_args_list], [1, 2, 4, 10])

    def test_cachefly_timeout_also_continues_to_more_streams(self):
        responses = [
            SpeedResult(False, http_code=429, error="HTTP 429", backend="cloudflare"),
            SpeedResult(False, mbps=8.0, bytes_transferred=40_000_000, error="curl: (28) Operation timed out", backend="cachefly"),
            SpeedResult(False, mbps=18.0, bytes_transferred=55_000_000, error="curl: (28) Operation timed out", backend="cachefly"),
            SpeedResult(True, mbps=72.0, bytes_transferred=80_000_000, time_seconds=8.9, http_code=206, backend="cachefly"),
            SpeedResult(True, mbps=88.0, bytes_transferred=80_000_000, time_seconds=7.3, http_code=206, backend="cachefly"),
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
                stream_stages=(1, 2, 4, 10),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "cachefly")
        self.assertEqual(result.mbps, 88.0)
        self.assertEqual([call.kwargs["streams"] for call in probe.call_args_list], [1, 1, 2, 4, 10])

    def test_cloudflare_timeout_does_not_trigger_cachefly(self):
        responses = [
            SpeedResult(False, error="curl: (28) Connection timed out", backend="cloudflare"),
            SpeedResult(False, error="curl: (28) Operation timed out", backend="cloudflare"),
            SpeedResult(False, error="curl: (28) Operation timed out", backend="cloudflare"),
            SpeedResult(False, error="curl: (28) Operation timed out", backend="cloudflare"),
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
                stream_stages=(1, 2, 4, 10),
            )

        self.assertFalse(result.ok)
        self.assertEqual(probe.call_count, 4)
        self.assertTrue(all(call.kwargs["url"].startswith("https://speed.cloudflare.com/") for call in probe.call_args_list))

    def test_non_timeout_cloudflare_failure_triggers_cachefly(self):
        responses = [
            SpeedResult(False, error="curl: (35) TLS connect error", backend="cloudflare"),
            SpeedResult(True, mbps=80.0, bytes_transferred=80_000_000, time_seconds=8.0, http_code=206, backend="cachefly"),
            SpeedResult(True, mbps=100.0, bytes_transferred=80_000_000, time_seconds=6.4, http_code=206, backend="cachefly"),
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
                stream_stages=(1, 2),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "cachefly")
        self.assertEqual([call.kwargs["url"] for call in probe.call_args_list], [
            "https://speed.cloudflare.com/__down?bytes=80000000",
            "https://cachefly.cachefly.net/100mb.test",
            "https://cachefly.cachefly.net/100mb.test",
        ])

    def test_all_download_timeouts_are_rejected_by_speed(self):
        timeout_result = SpeedResult(
            False,
            mbps=15.0,
            error="curl: (28) Operation timed out",
            backend="cloudflare",
            stages=[
                {"backend": "cloudflare", "streams": 1, "skipped": False, "ok": False, "mbps": 8.0, "error": "curl: (28) Operation timed out"},
                {"backend": "cloudflare", "streams": 2, "skipped": False, "ok": False, "mbps": 12.0, "error": "curl: (28) Operation timed out"},
                {"backend": "cloudflare", "streams": 4, "skipped": False, "ok": False, "mbps": 14.0, "error": "curl: (28) Operation timed out"},
                {"backend": "cloudflare", "streams": 10, "skipped": False, "ok": False, "mbps": 15.0, "error": "curl: (28) Operation timed out"},
            ],
        )
        with patch("proxyfilter.speed_staged._download_staged", return_value=timeout_result):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__down?bytes=80000000",
                timeout=30,
                min_mbps=50,
                stream_stages=(1, 2, 4, 10),
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_threshold")
        self.assertEqual(self.proxy.tests.download["best_partial_mbps"], 15.0)
        self.assertEqual(self.proxy.tests.download["best_partial_streams"], 10)

    def test_upload_staged_uses_fixed_total_payload_and_best_rate(self):
        responses = [
            SpeedResult(True, mbps=12.0, bytes_transferred=20_000_000, backend="upload"),
            SpeedResult(True, mbps=28.0, bytes_transferred=20_000_000, backend="upload"),
            SpeedResult(True, mbps=55.0, bytes_transferred=20_000_000, backend="upload"),
            SpeedResult(True, mbps=70.0, bytes_transferred=20_000_000, backend="upload"),
        ]
        with patch("proxyfilter.speed_staged._upload_parallel_stage", side_effect=responses) as probe:
            result = _upload_staged(
                self.proxy,
                object(),
                url="https://speed.cloudflare.com/__up",
                upload_bytes=20_000_000,
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2, 4, 10),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 70.0)
        self.assertEqual([call.kwargs["streams"] for call in probe.call_args_list], [1, 2, 4, 10])
        self.assertEqual([call.kwargs["total_bytes"] for call in probe.call_args_list], [20_000_000] * 4)

    def test_upload_timeout_continues_to_more_streams(self):
        responses = [
            SpeedResult(False, mbps=8.0, bytes_transferred=10_000_000, error="curl: (28) Operation timed out", backend="upload"),
            SpeedResult(False, mbps=14.0, bytes_transferred=14_000_000, error="curl: (28) Operation timed out", backend="upload"),
            SpeedResult(True, mbps=35.0, bytes_transferred=20_000_000, backend="upload"),
            SpeedResult(True, mbps=60.0, bytes_transferred=20_000_000, backend="upload"),
        ]
        with patch("proxyfilter.speed_staged._upload_parallel_stage", side_effect=responses) as probe:
            result = _upload_staged(
                self.proxy,
                object(),
                url="https://speed.cloudflare.com/__up",
                upload_bytes=20_000_000,
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2, 4, 10),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 60.0)
        self.assertEqual(probe.call_count, 4)

    def test_all_upload_timeouts_are_rejected_by_speed(self):
        timeout_result = SpeedResult(
            False,
            mbps=9.0,
            error="curl: (28) Operation timed out",
            backend="upload",
            stages=[
                {"backend": "upload", "streams": 1, "skipped": False, "ok": False, "mbps": 4.0, "error": "curl: (28) Operation timed out"},
                {"backend": "upload", "streams": 2, "skipped": False, "ok": False, "mbps": 6.0, "error": "curl: (28) Operation timed out"},
                {"backend": "upload", "streams": 4, "skipped": False, "ok": False, "mbps": 8.0, "error": "curl: (28) Operation timed out"},
                {"backend": "upload", "streams": 10, "skipped": False, "ok": False, "mbps": 9.0, "error": "curl: (28) Operation timed out"},
            ],
        )
        with patch("proxyfilter.speed_staged._upload_staged", return_value=timeout_result):
            passed, rejected = check_upload_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__up",
                upload_bytes=20_000_000,
                timeout=30,
                min_mbps=20,
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_upload_threshold")
        self.assertEqual(self.proxy.tests.upload["best_partial_mbps"], 9.0)
        self.assertEqual(self.proxy.tests.upload["best_partial_streams"], 10)


if __name__ == "__main__":
    unittest.main()
