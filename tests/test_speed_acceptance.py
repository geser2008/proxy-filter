import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult, check_download_many, check_upload_many


class SpeedAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)

    def test_download_timeout_with_partial_high_mbps_passes_threshold(self):
        result = SpeedResult(
            False,
            mbps=250.0,
            bytes_transferred=10_000_000,
            time_seconds=0.32,
            http_code=200,
            error="curl: (28) Operation timed out",
            url="https://speed.cloudflare.com/__down?bytes=50000000",
            backend="cloudflare",
            failure_reason="timeout",
            curl_exit_code=28,
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                timeout=30,
                min_mbps=20,
                workers=1,
                stream_stages=(1,),
            )

        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(self.proxy.tests.status, "download_pass")
        self.assertEqual(self.proxy.tests.download_mbps, 250.0)

    def test_download_timeout_with_partial_low_mbps_is_threshold_reject(self):
        result = SpeedResult(
            False,
            mbps=5.0,
            bytes_transferred=10_000_000,
            time_seconds=16.0,
            http_code=200,
            error="curl: (28) Operation timed out",
            url="https://speed.cloudflare.com/__down?bytes=50000000",
            backend="cloudflare",
            failure_reason="timeout",
            curl_exit_code=28,
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                timeout=30,
                min_mbps=20,
                workers=1,
                stream_stages=(1,),
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_threshold")

    def test_download_timeout_without_measurement_is_error(self):
        result = SpeedResult(
            False,
            mbps=None,
            bytes_transferred=0,
            time_seconds=30.0,
            http_code=0,
            error="curl: (28) Operation timed out",
            url="https://speed.cloudflare.com/__down?bytes=50000000",
            backend="cloudflare",
            failure_reason="timeout",
            curl_exit_code=28,
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                timeout=30,
                min_mbps=20,
                workers=1,
                stream_stages=(1,),
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_error")

    def test_stalled_download_is_error_even_with_partial_high_mbps(self):
        result = SpeedResult(
            False,
            mbps=250.0,
            bytes_transferred=10_000_000,
            time_seconds=0.32,
            http_code=200,
            error="curl: (28) Operation too slow. Less than 1 bytes/sec transferred the last 10 seconds",
            url="https://speed.cloudflare.com/__down?bytes=50000000",
            backend="cloudflare",
            failure_reason="stalled_transfer",
            curl_exit_code=28,
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                timeout=30,
                min_mbps=20,
                workers=1,
                stream_stages=(1,),
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_error")
        self.assertEqual(self.proxy.tests.download["failure_reason"], "stalled_transfer")

    def test_non_timeout_transport_failure_is_error_even_with_partial_mbps(self):
        result = SpeedResult(
            False,
            mbps=180.0,
            bytes_transferred=8_000_000,
            time_seconds=0.35,
            http_code=200,
            error="curl: (56) Connection reset by peer",
            url="https://example.invalid/upload",
            failure_reason="curl_error_56",
            curl_exit_code=56,
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_upload_many(
                [self.proxy],
                object(),
                url="https://example.invalid/upload",
                upload_bytes=20_000_000,
                timeout=30,
                min_mbps=20,
                workers=1,
            )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_upload_error")

    def test_upload_timeout_with_partial_measurement_uses_threshold(self):
        result = SpeedResult(
            False,
            mbps=45.0,
            bytes_transferred=10_000_000,
            time_seconds=1.777,
            http_code=200,
            error="curl: (28) Operation timed out",
            url="https://example.invalid/upload",
            failure_reason="timeout",
            curl_exit_code=28,
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_upload_many(
                [self.proxy],
                object(),
                url="https://example.invalid/upload",
                upload_bytes=20_000_000,
                timeout=30,
                min_mbps=20,
                workers=1,
            )

        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(self.proxy.tests.status, "upload_pass")

    def test_successful_measurement_still_passes_threshold(self):
        result = SpeedResult(
            True,
            mbps=75.0,
            bytes_transferred=50_000_000,
            time_seconds=5.333,
            http_code=200,
            url="https://speed.cloudflare.com/__down?bytes=50000000",
            backend="cloudflare",
        )
        with patch("proxyfilter.speed._run_many", return_value=[(self.proxy, result)]):
            passed, rejected = check_download_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__down?bytes=50000000",
                timeout=30,
                min_mbps=20,
                workers=1,
                stream_stages=(1,),
            )

        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(self.proxy.tests.status, "download_pass")


if __name__ == "__main__":
    unittest.main()
