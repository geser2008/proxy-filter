from __future__ import annotations

import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult, check_download_many, check_upload_many


class SpeedThresholdSemanticsTests(unittest.TestCase):
    def _proxy(self, suffix: str) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "test", "plain"),
            "vless",
            "example.com",
            443,
            f"p{suffix}",
            {"uuid": f"00000000-0000-0000-0000-0000000000{suffix:0>2}", "security": "tls"},
            "vless-uri",
            "",
        )
        proxy.ensure_id()
        return proxy

    @patch("proxyfilter.speed._run_many")
    def test_download_timeout_measurement_is_compared_with_threshold(self, run_many) -> None:
        slow = self._proxy("1")
        fast = self._proxy("2")
        unknown = self._proxy("3")
        run_many.return_value = [
            (
                slow,
                SpeedResult(
                    False,
                    mbps=27.0,
                    error="curl: (28) timeout",
                    failure_reason="timeout",
                    curl_exit_code=28,
                ),
            ),
            (
                fast,
                SpeedResult(
                    False,
                    mbps=80.0,
                    error="curl: (28) timeout",
                    failure_reason="timeout",
                    curl_exit_code=28,
                ),
            ),
            (
                unknown,
                SpeedResult(
                    False,
                    mbps=None,
                    error="curl: (28) timeout",
                    failure_reason="timeout",
                    curl_exit_code=28,
                ),
            ),
        ]

        passed, rejected = check_download_many(
            [slow, fast, unknown],
            object(),
            url="https://speed.cloudflare.com/__down?bytes=80000000",
            timeout=30,
            min_mbps=50,
            workers=1,
            stream_stages=[1],
        )

        self.assertEqual([p.id for p in passed], [fast.id])
        self.assertEqual({p.id for p in rejected}, {slow.id, unknown.id})
        self.assertEqual(slow.tests.status, "rejected_download_threshold")
        self.assertEqual(fast.tests.status, "download_pass")
        self.assertEqual(unknown.tests.status, "rejected_download_error")

    @patch("proxyfilter.speed._run_many")
    def test_upload_timeout_measurement_is_compared_with_threshold(self, run_many) -> None:
        slow = self._proxy("4")
        fast = self._proxy("5")
        unknown = self._proxy("6")
        run_many.return_value = [
            (
                slow,
                SpeedResult(
                    False,
                    mbps=9.0,
                    error="curl: (28) timeout",
                    failure_reason="timeout",
                    curl_exit_code=28,
                ),
            ),
            (
                fast,
                SpeedResult(
                    False,
                    mbps=40.0,
                    error="curl: (28) timeout",
                    failure_reason="timeout",
                    curl_exit_code=28,
                ),
            ),
            (
                unknown,
                SpeedResult(
                    False,
                    mbps=None,
                    error="curl: (28) timeout",
                    failure_reason="timeout",
                    curl_exit_code=28,
                ),
            ),
        ]

        passed, rejected = check_upload_many(
            [slow, fast, unknown],
            object(),
            url="https://speed.cloudflare.com/__up",
            upload_bytes=1024,
            timeout=30,
            min_mbps=20,
            workers=1,
        )

        self.assertEqual([p.id for p in passed], [fast.id])
        self.assertEqual({p.id for p in rejected}, {slow.id, unknown.id})
        self.assertEqual(slow.tests.status, "rejected_upload_threshold")
        self.assertEqual(fast.tests.status, "upload_pass")
        self.assertEqual(unknown.tests.status, "rejected_upload_error")


if __name__ == "__main__":
    unittest.main()
