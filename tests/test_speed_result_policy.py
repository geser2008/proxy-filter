from __future__ import annotations

import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter import speed_result_policy


class SpeedResultPolicyTests(unittest.TestCase):
    def _proxy(self, name: str) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "test", "plain"),
            "vless",
            "example.com",
            443,
            name,
            {"uuid": f"00000000-0000-0000-0000-00000000000{name[-1]}", "security": "tls"},
        )
        proxy.ensure_id()
        return proxy

    @patch("proxyfilter.speed_result_policy.speed_reliability.check_download_many")
    def test_download_threshold_result_uses_numeric_speed(self, underlying) -> None:
        low = self._proxy("p1")
        fast = self._proxy("p2")
        unknown = self._proxy("p3")
        technical = self._proxy("p4")

        for proxy, mbps in ((low, 27.0), (fast, 72.0), (unknown, None)):
            proxy.tests.download_mbps = mbps
            proxy.tests.download = {"status": "fail", "mbps": mbps, "error": "timeout"}
            proxy.tests.status = "rejected_download_threshold"
        technical.tests.download_mbps = 120.0
        technical.tests.download = {"status": "fail", "mbps": 120.0, "error": "invalid payload"}
        technical.tests.status = "rejected_download_error"

        underlying.return_value = ([], [low, fast, unknown, technical])
        passed, rejected = speed_result_policy.check_download_many(
            [low, fast, unknown, technical], object(), min_mbps=50
        )

        self.assertEqual([p.id for p in passed], [fast.id])
        self.assertEqual({p.id for p in rejected}, {low.id, unknown.id, technical.id})
        self.assertEqual(low.tests.status, "rejected_download_threshold")
        self.assertEqual(unknown.tests.status, "rejected_download_error")
        self.assertEqual(technical.tests.status, "rejected_download_error")

    @patch("proxyfilter.speed_result_policy.speed_staged.check_upload_many")
    def test_upload_threshold_result_uses_numeric_speed(self, underlying) -> None:
        low = self._proxy("p1")
        fast = self._proxy("p2")
        unknown = self._proxy("p3")
        for proxy, mbps in ((low, 12.0), (fast, 25.0), (unknown, None)):
            proxy.tests.upload_mbps = mbps
            proxy.tests.upload = {"status": "fail", "mbps": mbps, "error": "timeout"}
            proxy.tests.status = "rejected_upload_threshold"

        underlying.return_value = ([], [low, fast, unknown])
        passed, rejected = speed_result_policy.check_upload_many(
            [low, fast, unknown], object(), min_mbps=20
        )

        self.assertEqual([p.id for p in passed], [fast.id])
        self.assertEqual({p.id for p in rejected}, {low.id, unknown.id})
        self.assertEqual(low.tests.status, "rejected_upload_threshold")
        self.assertEqual(unknown.tests.status, "rejected_upload_error")


if __name__ == "__main__":
    unittest.main()
