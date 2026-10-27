from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from proxyfilter.core_category import classify_core_error
from proxyfilter.exit_ip import ExitIPResult, _lookup_with_fallback
from proxyfilter.io import write_json, write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.publish import publish_merged
from proxyfilter.reliability import annotate_download_reliability


class PipelineDiagnosticsTests(unittest.TestCase):
    def _proxy(self, suffix: int = 1) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "Test"),
            "vless",
            f"example{suffix}.com",
            443,
            params={"uuid": f"abc-{suffix}"},
        )
        proxy.ensure_id()
        proxy.tests.render = {
            "status": "pass",
            "name": f"test-{suffix}",
            "uri": f"vless://abc-{suffix}@example{suffix}.com:443#test-{suffix}",
            "error": None,
        }
        return proxy

    def test_core_categories(self):
        self.assertEqual(
            classify_core_error("unsupported XHTTP option"),
            "backend_unsupported",
        )
        self.assertEqual(
            classify_core_error("invalid boolean value for tls"),
            "invalid_config",
        )
        self.assertEqual(
            classify_core_error("sing-box check exited 1"),
            "runtime_error",
        )

    @patch("proxyfilter.exit_ip._curl_ip")
    def test_exit_ip_uses_one_independent_fallback(self, curl_ip):
        curl_ip.side_effect = [
            ExitIPResult(False, error="timeout", url="https://api.ipify.org"),
            ExitIPResult(True, ip="198.51.100.7", http_code=200, url="https://checkip.amazonaws.com"),
        ]
        result = _lookup_with_fallback(
            url="https://api.ipify.org",
            fallback_urls=["https://checkip.amazonaws.com"],
            timeout=5,
            curl_command="curl",
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.ip, "198.51.100.7")
        self.assertEqual(len(result.attempts), 2)
        self.assertEqual(curl_ip.call_count, 2)

    def test_reliability_is_top_level_and_does_not_change_pass(self):
        proxy = self._proxy()
        proxy.tests.download = {
            "status": "pass",
            "mbps": 80.0,
            "stages": [{
                "streams": 2,
                "skipped": False,
                "stream_results": [
                    {"ok": True, "bytes": 10, "error": None},
                    {"ok": False, "bytes": 0, "error": "curl: (97) SOCKS failure"},
                ],
            }],
        }
        result = annotate_download_reliability(proxy)
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(proxy.tests.download["status"], "pass")
        self.assertEqual(proxy.tests.reliability["status"], "degraded")
        self.assertEqual(proxy.tests.reliability["reason"], "transport")

    def test_publish_writes_qualified_selected_suppressed_and_published(self):
        first = self._proxy(1)
        second = self._proxy(2)
        for index, proxy in enumerate((first, second), 1):
            proxy.tests.exit_ip = "198.51.100.10"
            proxy.tests.latency_ms = 100 + index
            proxy.tests.download_mbps = 100 - index
            proxy.tests.upload_mbps = 50 - index
            proxy.tests.geo = {"status": "ok", "asn": 64500}

        proxies = [first, second]
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            publish_merged(
                data_dir,
                proxies,
                {"enabled": True, "max_same_exit_ip": 1, "max_same_exit_subnet_asn": 2},
            )
            work = data_dir / "work"
            qualified = [json.loads(line) for line in (work / "12-qualified.jsonl").read_text().splitlines()]
            selected = [json.loads(line) for line in (work / "13-diversity-selected.jsonl").read_text().splitlines()]
            suppressed = [json.loads(line) for line in (work / "13-diversity-suppressed.jsonl").read_text().splitlines()]
            published = [json.loads(line) for line in (work / "14-published.jsonl").read_text().splitlines()]

            self.assertEqual(len(qualified), 2)
            self.assertEqual(len(selected), 1)
            self.assertEqual(len(suppressed), 1)
            self.assertEqual(len(published), 1)
            self.assertEqual(qualified[0]["tests"]["status"], "qualified")
            self.assertEqual(selected[0]["tests"]["status"], "diversity_selected")
            self.assertEqual(suppressed[0]["tests"]["status"], "diversity_suppressed")
            self.assertEqual(published[0]["tests"]["status"], "published")

    def test_summary_contains_rejection_reasons(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            work = data_dir / "work"

            core_bad = self._proxy(1)
            core_bad.tests.core = {"status": "fail", "error": "unsupported XHTTP option"}
            core_bad.tests.status = "rejected_core"
            write_jsonl(work / "05-core-ok.jsonl", [])
            write_jsonl(work / "05-rejected-core.jsonl", [core_bad])

            latency_bad = self._proxy(2)
            latency_bad.tests.latency = {
                "status": "fail",
                "latency_ms": None,
                "http_code": 504,
                "error": "clash_api_http_504: Timeout",
            }
            latency_bad.tests.status = "rejected_latency_error"
            write_jsonl(work / "06-latency-ok.jsonl", [])
            write_jsonl(work / "06-rejected-latency.jsonl", [latency_bad])

            summary_path = data_dir / "reports" / "summary.json"
            write_json(summary_path, {"pipeline": {"status": "ok", "stage": "publish"}})
            summary = json.loads(summary_path.read_text())

            self.assertEqual(summary["diagnostics"]["core"]["reasons"]["backend_unsupported"], 1)
            self.assertEqual(summary["diagnostics"]["latency"]["reasons"]["http_504"], 1)


if __name__ == "__main__":
    unittest.main()