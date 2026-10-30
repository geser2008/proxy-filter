import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter import speed_reliability


class DownloadRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)
        self.proxy.ensure_id()
        self.kwargs = {
            "url": "https://speed.cloudflare.com/__down?bytes=80000000",
            "timeout": 30,
            "min_mbps": 80,
            "workers": 1,
            "stream_stages": [8],
        }

    def test_transient_technical_failure_is_retried_once_and_can_recover(self):
        calls = 0

        def fake_check(proxies, engine, **kwargs):
            nonlocal calls
            calls += 1
            proxy = proxies[0]
            if calls == 1:
                proxy.tests.status = "rejected_download_error"
                proxy.tests.download_mbps = None
                proxy.tests.download = {
                    "status": "fail",
                    "backend": "cloudflare",
                    "mbps": None,
                    "payload_valid": None,
                    "error": "curl: (35) TLS connect error",
                    "failure_reason": "curl_error_35",
                    "stages": [
                        {
                            "backend": "cloudflare",
                            "streams": 8,
                            "skipped": False,
                            "ok": False,
                            "classification": "transport_error",
                            "error": "curl: (35) TLS connect error",
                        }
                    ],
                }
                return [], [proxy]

            proxy.tests.status = "download_pass"
            proxy.tests.download_mbps = 120.0
            proxy.tests.download = {
                "status": "pass",
                "backend": "cloudflare",
                "mbps": 120.0,
                "bytes": 80_000_000,
                "expected_bytes": 80_000_000,
                "payload_valid": True,
                "error": None,
                "failure_reason": None,
                "stages": [
                    {
                        "backend": "cloudflare",
                        "streams": 8,
                        "skipped": False,
                        "ok": True,
                        "classification": "success",
                        "mbps": 120.0,
                    }
                ],
            }
            return [proxy], []

        with patch(
            "proxyfilter.speed_reliability.speed_policy.check_download_many",
            side_effect=fake_check,
        ) as check:
            passed, rejected = speed_reliability.check_download_many(
                [self.proxy],
                object(),
                recovery_enabled=True,
                **self.kwargs,
            )

        self.assertEqual(check.call_count, 2)
        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertTrue(self.proxy.tests.download["recovery_enabled"])
        self.assertTrue(self.proxy.tests.download["recovery_attempted"])
        self.assertTrue(self.proxy.tests.download["recovered"])
        self.assertEqual(
            self.proxy.tests.download["recovery_initial_failure_reason"],
            "curl_error_35",
        )

    def test_threshold_rejection_is_not_retried(self):
        self.proxy.tests.status = "rejected_download_threshold"
        self.proxy.tests.download_mbps = 50.0
        self.proxy.tests.download = {
            "status": "fail",
            "backend": "cloudflare",
            "mbps": 50.0,
            "bytes": 80_000_000,
            "expected_bytes": 80_000_000,
            "payload_valid": True,
            "error": None,
            "failure_reason": None,
            "stages": [
                {
                    "backend": "cloudflare",
                    "streams": 8,
                    "skipped": False,
                    "ok": True,
                    "classification": "success",
                    "mbps": 50.0,
                }
            ],
        }

        with patch(
            "proxyfilter.speed_reliability.speed_policy.check_download_many",
            return_value=([], [self.proxy]),
        ) as check:
            passed, rejected = speed_reliability.check_download_many(
                [self.proxy],
                object(),
                recovery_enabled=True,
                **self.kwargs,
            )

        self.assertEqual(check.call_count, 1)
        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertTrue(self.proxy.tests.download["recovery_enabled"])
        self.assertFalse(self.proxy.tests.download["recovery_attempted"])
        self.assertFalse(self.proxy.tests.download["recovered"])

    def test_recovery_disabled_keeps_single_attempt(self):
        self.proxy.tests.status = "rejected_download_error"
        self.proxy.tests.download_mbps = None
        self.proxy.tests.download = {
            "status": "fail",
            "backend": "cloudflare",
            "mbps": None,
            "payload_valid": None,
            "error": "curl: (97) cannot complete SOCKS5 connection",
            "failure_reason": "curl_error_97",
            "stages": [
                {
                    "backend": "cloudflare",
                    "streams": 8,
                    "skipped": False,
                    "ok": False,
                    "classification": "transport_error",
                }
            ],
        }

        with patch(
            "proxyfilter.speed_reliability.speed_policy.check_download_many",
            return_value=([], [self.proxy]),
        ) as check:
            passed, rejected = speed_reliability.check_download_many(
                [self.proxy],
                object(),
                recovery_enabled=False,
                **self.kwargs,
            )

        self.assertEqual(check.call_count, 1)
        self.assertEqual(passed, [])
        self.assertEqual(rejected, [self.proxy])
        self.assertFalse(self.proxy.tests.download["recovery_enabled"])
        self.assertFalse(self.proxy.tests.download["recovery_attempted"])


if __name__ == "__main__":
    unittest.main()
