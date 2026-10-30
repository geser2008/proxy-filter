import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter import speed_semantics


class UploadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)

    def test_fastest_partial_timeout_stage_wins_threshold(self):
        self.proxy.tests.upload_mbps = 40.0
        self.proxy.tests.upload = {
            "status": "fail",
            "mbps": 40.0,
            "aggregate_mbps": 40.0,
            "payload_valid": True,
            "http_code": 200,
            "error": "curl: (28) Operation timed out",
            "failure_reason": "timeout",
            "stages": [
                {
                    "backend": "upload",
                    "streams": 1,
                    "skipped": False,
                    "ok": False,
                    "mbps": 70.0,
                    "bytes": 15_000_000,
                    "expected_bytes": 20_000_000,
                    "payload_valid": True,
                    "time_seconds": 2.0,
                    "http_code": 200,
                    "error": "curl: (28) Operation timed out",
                    "failure_reason": "timeout",
                },
                {
                    "backend": "upload",
                    "streams": 8,
                    "skipped": False,
                    "ok": False,
                    "mbps": 40.0,
                    "bytes": 12_000_000,
                    "expected_bytes": 20_000_000,
                    "payload_valid": True,
                    "time_seconds": 3.0,
                    "http_code": 200,
                    "error": "curl: (28) Operation timed out",
                    "failure_reason": "timeout",
                },
            ],
        }
        self.proxy.tests.status = "rejected_upload_threshold"

        with patch(
            "proxyfilter.speed_semantics.speed_staged.check_upload_many",
            return_value=([], [self.proxy]),
        ):
            passed, rejected = speed_semantics.check_upload_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__up",
                upload_bytes=20_000_000,
                timeout=30,
                min_mbps=50,
                stream_stages=(1, 8),
            )

        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(self.proxy.tests.status, "upload_pass")
        self.assertEqual(self.proxy.tests.upload_mbps, 70.0)
        self.assertEqual(self.proxy.tests.upload["selected_streams"], 1)
        self.assertEqual(self.proxy.tests.upload["best_partial_streams"], 1)
        self.assertIsNone(self.proxy.tests.upload["payload_valid"])
        self.assertIsNone(self.proxy.tests.upload["stages"][0]["payload_valid"])
        self.assertIsNone(self.proxy.tests.upload["stages"][1]["payload_valid"])

    def test_completed_upload_stage_is_not_replaced_by_partial_timeout(self):
        self.proxy.tests.upload_mbps = 55.0
        self.proxy.tests.upload = {
            "status": "pass",
            "mbps": 55.0,
            "aggregate_mbps": 55.0,
            "payload_valid": True,
            "bytes": 20_000_000,
            "expected_bytes": 20_000_000,
            "http_code": 200,
            "error": None,
            "failure_reason": None,
            "stages": [
                {
                    "backend": "upload",
                    "streams": 1,
                    "skipped": False,
                    "ok": True,
                    "mbps": 55.0,
                    "bytes": 20_000_000,
                    "expected_bytes": 20_000_000,
                    "payload_valid": True,
                    "http_code": 200,
                    "error": None,
                },
                {
                    "backend": "upload",
                    "streams": 8,
                    "skipped": False,
                    "ok": False,
                    "mbps": 90.0,
                    "bytes": 18_000_000,
                    "expected_bytes": 20_000_000,
                    "payload_valid": True,
                    "http_code": 200,
                    "error": "curl: (28) Operation timed out",
                    "failure_reason": "timeout",
                },
            ],
        }
        self.proxy.tests.status = "upload_pass"

        with patch(
            "proxyfilter.speed_semantics.speed_staged.check_upload_many",
            return_value=([self.proxy], []),
        ):
            passed, rejected = speed_semantics.check_upload_many(
                [self.proxy],
                object(),
                url="https://speed.cloudflare.com/__up",
                upload_bytes=20_000_000,
                timeout=30,
                min_mbps=50,
                stream_stages=(1, 8),
            )

        self.assertEqual(passed, [self.proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(self.proxy.tests.upload_mbps, 55.0)
        self.assertTrue(self.proxy.tests.upload["payload_valid"])
        self.assertIsNone(self.proxy.tests.upload["stages"][1]["payload_valid"])


if __name__ == "__main__":
    unittest.main()
