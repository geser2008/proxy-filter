from __future__ import annotations

import unittest
from unittest.mock import patch

from proxyfilter.batch_latency import BatchLatencyResult, check_latency_batched
from proxyfilter.model import ProxyConfig, SourceInfo


class BatchLatencyRetryTests(unittest.TestCase):
    def _proxy(self, name: str) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "test", "plain"),
            "vless",
            "example.com",
            443,
            name,
            {"uuid": f"00000000-0000-0000-0000-00000000000{name[-1]}", "security": "tls"},
            "vless-uri",
            "",
        )
        proxy.ensure_id()
        return proxy

    @patch("proxyfilter.batch_latency._run_batch")
    def test_retries_503_504_and_timeout_once_on_same_url(self, run_batch) -> None:
        p503 = self._proxy("p1")
        p504 = self._proxy("p2")
        ptimeout = self._proxy("p3")
        pok = self._proxy("p4")

        run_batch.side_effect = [
            {
                p503.id: BatchLatencyResult(False, error='clash_api_http_503: {"message":"An error occurred"}'),
                p504.id: BatchLatencyResult(False, error='clash_api_http_504: {"message":"Timeout"}'),
                ptimeout.id: BatchLatencyResult(False, error="timed out"),
                pok.id: BatchLatencyResult(True, latency_ms=120.0),
            },
            {
                p503.id: BatchLatencyResult(True, latency_ms=224.0),
                p504.id: BatchLatencyResult(True, latency_ms=325.0),
                ptimeout.id: BatchLatencyResult(False, error="timed out"),
            },
        ]

        passed, rejected = check_latency_batched(
            [p503, p504, ptimeout, pok],
            object(),
            url="https://example.com/generate_204",
            timeout=8,
            max_ms=800,
            workers=32,
            batch_size=128,
            retry_batch_size=16,
        )

        self.assertEqual({p.id for p in passed}, {p503.id, p504.id, pok.id})
        self.assertEqual([p.id for p in rejected], [ptimeout.id])
        self.assertEqual(len(p503.tests.latency["attempts"]), 2)
        self.assertEqual(len(p504.tests.latency["attempts"]), 2)
        self.assertEqual(len(ptimeout.tests.latency["attempts"]), 2)
        self.assertEqual(run_batch.call_count, 2)
        first_call = run_batch.call_args_list[0]
        retry_call = run_batch.call_args_list[1]
        self.assertEqual(first_call.kwargs["url"], retry_call.kwargs["url"])

    @patch("proxyfilter.batch_latency._run_batch")
    def test_negative_max_ms_disables_value_threshold_only(self, run_batch) -> None:
        slow = self._proxy("p1")
        failed = self._proxy("p2")
        run_batch.return_value = {
            slow.id: BatchLatencyResult(True, latency_ms=5000.0),
            failed.id: BatchLatencyResult(False, error="connection refused"),
        }

        passed, rejected = check_latency_batched(
            [slow, failed],
            object(),
            url="https://example.com/generate_204",
            timeout=8,
            max_ms=-1,
            workers=2,
            batch_size=128,
        )

        self.assertEqual([p.id for p in passed], [slow.id])
        self.assertEqual([p.id for p in rejected], [failed.id])
        self.assertEqual(slow.tests.status, "latency_pass")
        self.assertEqual(failed.tests.status, "rejected_latency_error")


if __name__ == "__main__":
    unittest.main()
