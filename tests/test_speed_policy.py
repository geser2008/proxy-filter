import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult
from proxyfilter.speed_policy import (
    _download_staged,
    _fallback_allowed,
    _stage_classification,
    check_download_many,
)


class DownloadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)
        self.primary = "https://speed.cloudflare.com/__down?bytes=80000000"
        self.fallback = "https://cachefly.cachefly.net/100mb.test"

    def test_timeout_with_transfer_is_performance_timeout(self):
        result = SpeedResult(
            False,
            mbps=12.0,
            bytes_transferred=60_000_000,
            error="curl: (97) SOCKS failure",
            attempts=[
                {"ok": False, "error": "curl: (28) Operation timed out", "bytes": 60_000_000},
                {"ok": False, "error": "curl: (97) SOCKS failure", "bytes": 0},
            ],
        )
        self.assertEqual(_stage_classification(result), "performance_timeout")

    def test_zero_transfer_socks_failure_is_transport_error(self):
        result = SpeedResult(
            False,
            bytes_transferred=0,
            error="curl: (97) cannot complete SOCKS5 connection",
            attempts=[
                {"ok": False, "error": "curl: (97) cannot complete SOCKS5 connection", "bytes": 0},
                {"ok": False, "error": "curl: (97) cannot complete SOCKS5 connection", "bytes": 0},
            ],
        )
        self.assertEqual(_stage_classification(result), "transport_error")
        self.assertFalse(_fallback_allowed(result))

    def test_tls_eof_does_not_fallback_to_cachefly(self):
        tls_error = SpeedResult(
            False,
            bytes_transferred=0,
            error="curl: (35) TLS connect error: unexpected eof while reading",
            backend="cloudflare",
        )
        with patch("proxyfilter.speed_policy.base._download_parallel_stage", return_value=tls_error) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[self.fallback],
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2, 4, 10),
            )

        self.assertFalse(result.ok)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(result.stages[0]["classification"], "transport_error")

    def test_socks_error_does_not_fallback_to_cachefly(self):
        socks_error = SpeedResult(
            False,
            bytes_transferred=0,
            error="curl: (97) cannot complete SOCKS5 connection",
            backend="cloudflare",
        )
        with patch("proxyfilter.speed_policy.base._download_parallel_stage", return_value=socks_error) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[self.fallback],
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2),
            )

        self.assertFalse(result.ok)
        self.assertEqual(probe.call_count, 1)

    def test_http_403_falls_back_to_cachefly(self):
        self.assertTrue(_fallback_allowed(SpeedResult(False, http_code=403, error="HTTP 403")))

    def test_http_429_falls_back_to_cachefly(self):
        responses = [
            SpeedResult(False, http_code=429, error="HTTP 429", backend="cloudflare"),
            SpeedResult(
                True,
                mbps=90.0,
                bytes_transferred=80_000_000,
                time_seconds=7.1,
                http_code=206,
                backend="cachefly",
            ),
        ]
        with patch("proxyfilter.speed_policy.base._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[self.fallback],
                timeout=30,
                curl_command="curl",
                stream_stages=(1,),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "cachefly")
        self.assertEqual(probe.call_count, 2)

    def test_http_5xx_falls_back(self):
        responses = [
            SpeedResult(False, http_code=503, error="HTTP 503", backend="cloudflare"),
            SpeedResult(
                True,
                mbps=75.0,
                bytes_transferred=80_000_000,
                time_seconds=8.5,
                http_code=206,
                backend="cachefly",
            ),
        ]
        with patch("proxyfilter.speed_policy.base._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[self.fallback],
                timeout=30,
                curl_command="curl",
                stream_stages=(1,),
            )

        self.assertTrue(result.ok)
        self.assertEqual(probe.call_count, 2)

    def test_other_http_status_does_not_fallback(self):
        self.assertFalse(_fallback_allowed(SpeedResult(False, http_code=404, error="HTTP 404")))

    def test_invalid_payload_falls_back_to_cachefly(self):
        responses = [
            SpeedResult(
                False,
                bytes_transferred=25,
                expected_bytes=80_000_000,
                payload_valid=False,
                http_code=200,
                error="invalid download payload",
                backend="cloudflare",
            ),
            SpeedResult(
                True,
                mbps=70.0,
                bytes_transferred=80_000_000,
                time_seconds=9.1,
                http_code=206,
                backend="cachefly",
            ),
        ]
        with patch("proxyfilter.speed_policy.base._download_parallel_stage", side_effect=responses) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[self.fallback],
                timeout=30,
                curl_command="curl",
                stream_stages=(1,),
            )

        self.assertTrue(result.ok)
        self.assertEqual(probe.call_count, 2)

    def test_mixed_timeout_and_socks_with_transfer_continues_next_stage(self):
        mixed = SpeedResult(
            False,
            mbps=14.0,
            bytes_transferred=70_000_000,
            error="curl: (97) SOCKS failure",
            backend="cloudflare",
            attempts=[
                {"ok": False, "error": "curl: (28) Operation timed out", "bytes": 70_000_000},
                {"ok": False, "error": "curl: (97) SOCKS failure", "bytes": 0},
            ],
        )
        success = SpeedResult(
            True,
            mbps=120.0,
            bytes_transferred=80_000_000,
            time_seconds=5.3,
            http_code=200,
            backend="cloudflare",
        )
        with patch(
            "proxyfilter.speed_policy.base._download_parallel_stage",
            side_effect=[mixed, success],
        ) as probe:
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[self.fallback],
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "cloudflare")
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(result.stages[0]["classification"], "performance_timeout")
        self.assertEqual(result.stages[1]["classification"], "success")

    def test_fastest_partial_timeout_stage_wins_threshold(self):
        responses = [
            SpeedResult(
                False,
                mbps=95.0,
                bytes_transferred=60_000_000,
                expected_bytes=80_000_000,
                time_seconds=5.05,
                http_code=200,
                error="curl: (28) Operation timed out",
                backend="cloudflare",
                failure_reason="timeout",
                curl_exit_code=28,
            ),
            SpeedResult(
                False,
                mbps=55.0,
                bytes_transferred=45_000_000,
                expected_bytes=80_000_000,
                time_seconds=6.54,
                http_code=200,
                error="curl: (28) Operation timed out",
                backend="cloudflare",
                failure_reason="timeout",
                curl_exit_code=28,
            ),
        ]
        with patch(
            "proxyfilter.speed_policy.base._download_parallel_stage",
            side_effect=responses,
        ):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url=self.primary,
                timeout=30,
                min_mbps=80,
                fallback_urls=[self.fallback],
                stream_stages=(1, 8),
            )

        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(self.proxy.tests.download_mbps, 95.0)
        self.assertEqual(self.proxy.tests.download["best_partial_mbps"], 95.0)
        self.assertEqual(self.proxy.tests.download["best_partial_streams"], 1)
        self.assertEqual(self.proxy.tests.download["selected_streams"], 1)

    def test_partial_timeout_stage_payload_is_not_marked_complete(self):
        partial = SpeedResult(
            False,
            mbps=95.0,
            bytes_transferred=60_000_000,
            expected_bytes=80_000_000,
            payload_valid=True,
            time_seconds=5.05,
            http_code=200,
            error="curl: (28) Operation timed out",
            backend="cloudflare",
            failure_reason="timeout",
            curl_exit_code=28,
        )
        with patch("proxyfilter.speed_policy.base._download_parallel_stage", return_value=partial):
            result = _download_staged(
                self.proxy,
                object(),
                url=self.primary,
                fallback_urls=[],
                timeout=30,
                curl_command="curl",
                stream_stages=(8,),
            )

        self.assertIsNone(result.stages[0]["payload_valid"])

    def test_all_performance_timeouts_are_rejected_by_threshold(self):
        timeout_result = SpeedResult(
            False,
            mbps=15.0,
            bytes_transferred=75_000_000,
            error="curl: (28) Operation timed out",
            backend="cloudflare",
            stages=[
                {
                    "backend": "cloudflare",
                    "streams": 1,
                    "skipped": False,
                    "ok": False,
                    "mbps": 15.0,
                    "classification": "performance_timeout",
                },
                {
                    "backend": "cloudflare",
                    "streams": 2,
                    "skipped": False,
                    "ok": False,
                    "mbps": 25.0,
                    "classification": "performance_timeout",
                },
            ],
        )
        with patch("proxyfilter.speed_policy._download_staged", return_value=timeout_result):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url=self.primary,
                timeout=30,
                min_mbps=50,
                fallback_urls=[self.fallback],
                stream_stages=(1, 2),
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_threshold")

    def test_zero_transfer_transport_failure_is_download_error(self):
        transport_result = SpeedResult(
            False,
            bytes_transferred=0,
            error="curl: (97) cannot complete SOCKS5 connection",
            backend="cloudflare",
            stages=[
                {
                    "backend": "cloudflare",
                    "streams": 1,
                    "skipped": False,
                    "ok": False,
                    "classification": "transport_error",
                }
            ],
        )
        with patch("proxyfilter.speed_policy._download_staged", return_value=transport_result):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url=self.primary,
                timeout=30,
                min_mbps=50,
                fallback_urls=[self.fallback],
                stream_stages=(1,),
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_error")


if __name__ == "__main__":
    unittest.main()
