import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult, check_download_many, check_upload_many


class SpeedAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)

    def test_failed_download_with_partial_high_mbps_is_rejected_as_error(self):
        result = SpeedResult(
            False,
            mbps=250.0,
            bytes_transferred=10_000_000,
            time_seconds=0.32,
            http_code=200,
            error="curl: (28) operation timed out",
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

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertEqual(self.proxy.tests.status, "rejected_download_error")
        self.assertEqual(self.proxy.tests.download_mbps, 250.0)
        self.assertEqual(self.proxy.tests.download["status"], "fail")

    def test_failed_upload_with_partial_high_mbps_is_rejected_as_error(self):
        result = SpeedResult(
            False,
            mbps=180.0,
            bytes_transferred=8_000_000,
            time_seconds=0.35,
            http_code=200,
            error="curl: (56) connection reset by peer",
            url="https://example.invalid/upload",
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
        self.assertEqual(self.proxy.tests.upload_mbps, 180.0)
        self.assertEqual(self.proxy.tests.upload["status"], "fail")

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
