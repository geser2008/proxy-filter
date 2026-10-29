from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

from proxyfilter.batch_latency import BatchLatencyResult, _failed_outbound_index, check_latency_batched
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.resume import stage_should_run


class LatencyGateTests(unittest.TestCase):
    def _proxy(self, suffix: str) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "Test", "plain"),
            "vless",
            "example.com",
            443,
            params={"uuid": f"00000000-0000-0000-0000-0000000000{suffix}", "security": "tls"},
            original_format="vless-uri",
            original_raw=f"vless://00000000-0000-0000-0000-0000000000{suffix}@example.com:443?security=tls",
        )
        proxy.ensure_id()
        return proxy

    def test_production_latency_skips_tcp_and_core_diagnostics(self) -> None:
        with patch.object(sys, "argv", ["proxy_filter.py", "--until", "latency"]):
            self.assertFalse(stage_should_run("tcp", None))
            self.assertFalse(stage_should_run("core", None))
            self.assertTrue(stage_should_run("latency", None))

        with patch.object(sys, "argv", ["proxy_filter.py", "--until", "tcp"]):
            self.assertTrue(stage_should_run("tcp", None))
            self.assertFalse(stage_should_run("core", None))

        with patch.object(sys, "argv", ["proxy_filter.py", "--until", "core"]):
            self.assertFalse(stage_should_run("tcp", None))
            self.assertTrue(stage_should_run("core", None))

    def test_singbox_error_outbound_index_is_extracted(self) -> None:
        self.assertEqual(
            _failed_outbound_index('FATAL initialize outbound[17]: uTLS is required by reality client'),
            17,
        )
        self.assertEqual(
            _failed_outbound_index('decode config: outbounds[3].pcs: json: unknown field "pcs"'),
            3,
        )
        self.assertIsNone(_failed_outbound_index("global config error"))

    @patch("proxyfilter.batch_latency._run_batch")
    def test_config_failure_is_not_retried_on_fallback(self, run_batch) -> None:
        broken = self._proxy("01")
        runtime_fail = self._proxy("02")
        good = self._proxy("03")

        run_batch.side_effect = [
            {
                broken.id: BatchLatencyResult(False, error='json: unknown field "pcs"', category="config"),
                runtime_fail.id: BatchLatencyResult(False, error="clash_api_http_504: timeout", category="runtime"),
                good.id: BatchLatencyResult(True, latency_ms=120.0),
            },
            {
                runtime_fail.id: BatchLatencyResult(True, latency_ms=180.0),
            },
        ]

        passed, rejected = check_latency_batched(
            [broken, runtime_fail, good],
            object(),
            url="https://primary.example/204",
            fallback_url="https://fallback.example/204",
            timeout=8,
            max_ms=800,
            workers=4,
            batch_size=128,
        )

        self.assertEqual({proxy.id for proxy in passed}, {runtime_fail.id, good.id})
        self.assertEqual([proxy.id for proxy in rejected], [broken.id])
        self.assertEqual(broken.tests.status, "rejected_latency_config")
        self.assertEqual(broken.tests.latency["category"], "config")
        self.assertEqual(len(broken.tests.latency["attempts"]), 1)
        self.assertEqual(len(runtime_fail.tests.latency["attempts"]), 2)
        self.assertEqual(run_batch.call_count, 2)


if __name__ == "__main__":
    unittest.main()
