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

        first = {
            p503.id: BatchLatencyResult(False, error='clash_api_http_503: {"message":"An error occurred"}'),
            p504.id: BatchLatencyResult(False, error='clash_api_http_504: {"message":"Timeout"}'),
            ptimeout.id: BatchLatencyResult(False, error="timed out"),
            pok.id: BatchLatencyResult(True, latency_ms=120.0),
        }
        retry = {
            p503.id: BatchLatencyResult(True, latency_ms=224.0),
            p504.id: BatchLatencyResult(True, latency_ms=1800.0),
            ptimeout.id: BatchLatencyResult(False, error="timed out"),
        }
        run_batch.side_effect = [first, retry]

        passed, rejected = check_latency_batched(
            [p503, p504, ptimeout, pok],
            object(),
            url="https://example.com/generate_204",
            timeout=8,
            max_ms=-1,
            workers=32,
            batch_size=128,
            retry_batch_size=16,
        )

        self.assertEqual({p.id for p in passed}, {p503.id, p504.id, pok.id})
        self.assertEqual([p.id for p in rejected], [ptimeout.id])
        self.assertEqual(len(p503.tests.latency["attempts"]), 2)
        self.assertEqual(len(p504.tests.latency["attempts"]), 2)
        self.assertEqual(len(ptimeout.tests.latency["attempts"]), 2)
        self.assertEqual(len(pok.tests.latency["attempts"]), 1)
        self.assertEqual(p504.tests.latency_ms, 1800.0)
        self.assertEqual(run_batch.call_count, 2)
        self.assertEqual(run_batch.call_args_list[0].kwargs["url"], run_batch.call_args_list[1].kwargs["url"])

    @patch("proxyfilter.batch_latency._run_batch")
    def test_positive_max_ms_still_rejects_slow_success(self, run_batch) -> None:
        proxy = self._proxy("p1")
        run_batch.return_value = {proxy.id: BatchLatencyResult(True, latency_ms=1600.0)}

        passed, rejected = check_latency_batched(
            [proxy],
            object(),
            url="https://example.com/generate_204",
            timeout=8,
            max_ms=1500,
            workers=1,
        )

        self.assertEqual(passed, [])
        self.assertEqual(rejected, [proxy])
        self.assertEqual(proxy.tests.status, "rejected_latency_threshold")


if __name__ == "__main__":
    unittest.main()
