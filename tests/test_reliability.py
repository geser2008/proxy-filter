import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.output_policy import render_proxies
from proxyfilter.reliability import analyze_stream_reliability, annotate_download_reliability


SOURCE = SourceInfo("test", "test", "plain")


def make_proxy() -> ProxyConfig:
    proxy = ProxyConfig(
        SOURCE,
        "ss",
        "203.0.113.20",
        8388,
        "old",
        {"method": "aes-256-gcm", "password": "secret"},
    )
    proxy.tests.download_mbps = 120.0
    proxy.tests.download = {"status": "pass", "mbps": 120.0, "stages": []}
    return proxy


class ReliabilityTests(unittest.TestCase):
    def test_uniform_timeouts_are_not_degraded(self):
        stages = [
            {
                "streams": 4,
                "skipped": False,
                "classification": "performance_timeout",
                "stream_results": [
                    {"ok": False, "bytes": 10_000_000, "error": "curl: (28) Operation timed out"},
                    {"ok": False, "bytes": 11_000_000, "error": "curl: (28) Operation timed out"},
                    {"ok": False, "bytes": 9_000_000, "error": "curl: (28) Operation timed out"},
                    {"ok": False, "bytes": 12_000_000, "error": "curl: (28) Operation timed out"},
                ],
            }
        ]
        result = analyze_stream_reliability(stages)
        self.assertEqual(result["status"], "stable")
        self.assertFalse(result["degraded"])

    def test_success_and_failed_sibling_streams_are_degraded(self):
        stages = [
            {
                "backend": "cloudflare",
                "streams": 10,
                "skipped": False,
                "classification": "performance_timeout",
                "stream_results": [
                    {"ok": True, "bytes": 8_000_000, "error": None},
                    {"ok": False, "bytes": 2_000_000, "error": "curl: (28) Operation timed out"},
                    {"ok": False, "bytes": 0, "error": "curl: (97) SOCKS failure"},
                ],
            }
        ]
        result = analyze_stream_reliability(stages)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(result["mixed_stage_count"], 1)
        self.assertIn("mixed_success_failure", result["mixed_stages"][0]["reasons"])
        self.assertIn("mixed_timeout_transport", result["mixed_stages"][0]["reasons"])

    def test_annotation_is_serialized_inside_download(self):
        proxy = make_proxy()
        proxy.tests.download["stages"] = [
            {
                "streams": 2,
                "skipped": False,
                "stream_results": [
                    {"ok": True, "bytes": 40_000_000, "error": None},
                    {"ok": False, "bytes": 0, "error": "curl: (97) SOCKS failure"},
                ],
            }
        ]
        annotate_download_reliability(proxy)
        serialized = proxy.to_dict()
        self.assertEqual(serialized["tests"]["download"]["stream_reliability"], "degraded")
        self.assertTrue(serialized["tests"]["download"]["stream_reliability_details"]["degraded"])

    def test_output_policy_excludes_degraded_when_disabled(self):
        proxy = make_proxy()
        proxy.tests.download["stages"] = [
            {
                "streams": 2,
                "skipped": False,
                "stream_results": [
                    {"ok": True, "bytes": 40_000_000, "error": None},
                    {"ok": False, "bytes": 0, "error": "curl: (97) SOCKS failure"},
                ],
            }
        ]
        cfg = {
            "filters": {"speed": {"include_unreliable_proxies": False}},
            "output": {"rename_template": "{protocol}", "include_stream_reliability": True},
        }
        accepted, rejected = render_proxies([proxy], cfg)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected, [proxy])
        self.assertEqual(proxy.tests.status, "excluded_unreliable")
        self.assertEqual(proxy.tests.render["status"], "excluded")

    def test_output_policy_keeps_degraded_and_marks_subscription_name(self):
        proxy = make_proxy()
        proxy.tests.download["stages"] = [
            {
                "streams": 2,
                "skipped": False,
                "stream_results": [
                    {"ok": True, "bytes": 40_000_000, "error": None},
                    {"ok": False, "bytes": 0, "error": "curl: (97) SOCKS failure"},
                ],
            }
        ]
        cfg = {
            "filters": {"speed": {"include_unreliable_proxies": True}},
            "output": {"rename_template": "{protocol}", "include_stream_reliability": True},
        }
        accepted, rejected = render_proxies([proxy], cfg)
        self.assertEqual(rejected, [])
        self.assertEqual(accepted, [proxy])
        self.assertIn("reliability:degraded", proxy.tests.render["name"])
        self.assertIn("reliability%3Adegraded", proxy.tests.render["uri"])


if __name__ == "__main__":
    unittest.main()
