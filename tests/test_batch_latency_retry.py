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
    def test_retries_only_initial_503_once(self, run_batch) -> None:
        p503 = self._proxy("p1")
        p504 = self._proxy("p2")
        pok = self._proxy("p3")

        run_batch.side_effect = [
            {
                p503.id: BatchLatencyResult(False, error='clash_api_http_503: {"message":"An error occurred"}'),
                p504.id: BatchLatencyResult(False, error='clash_api_http_504: {"message":"Timeout"}'),
                pok.id: BatchLatencyResult(True, latency_ms=120.0),
            },
            {p503.id: BatchLatencyResult(True, latency_ms=224.0)},
        ]

        passed, rejected = check_latency_batched(
            [p503, p504, pok],
            object(),
            url="https://example.com/generate_204",
            timeout=8,
            max_ms=800,
            workers=32,
            batch_size=128,
            retry_503_batch_size=16,
        )

        self.assertEqual({p.id for p in passed}, {p503.id, pok.id})
        self.assertEqual([p.id for p in rejected], [p504.id])
        self.assertEqual(len(p503.tests.latency["attempts"]), 2)
        self.assertEqual(len(p504.tests.latency["attempts"]), 1)
        self.assertEqual(p503.tests.latency_ms, 224.0)
        self.assertEqual(run_batch.call_count, 2)


if __name__ == "__main__":
    unittest.main()
