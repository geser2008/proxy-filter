import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.failure_reason import annotate_failure_reasons, classify_error
from proxyfilter.io import write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo


class FailureReasonTests(unittest.TestCase):
    def _proxy(self) -> ProxyConfig:
        return ProxyConfig(SourceInfo("test", "test", "plain"), "ss", "example.com", 443)

    def test_classify_common_transport_errors(self):
        self.assertEqual(classify_error("curl: (28) Operation timed out"), "timeout")
        self.assertEqual(classify_error("Name or service not known"), "dns_error")
        self.assertEqual(classify_error("Connection refused"), "connection_refused")
        self.assertEqual(classify_error("cannot complete SOCKS5 connection"), "socks_error")
        self.assertEqual(classify_error("boom", http_code=503), "http_503")
        self.assertEqual(classify_error("bad", payload_valid=False), "invalid_payload")

    def test_threshold_rejections_get_explicit_reasons(self):
        proxy = self._proxy()
        proxy.tests.status = "rejected_download_threshold"
        proxy.tests.download = {"status": "fail", "mbps": 42.0, "error": None}
        annotate_failure_reasons(proxy)
        self.assertEqual(proxy.tests.download["reason"], "below_min_download_mbps")

        proxy.tests.status = "rejected_latency_threshold"
        proxy.tests.latency = {"status": "fail", "latency_ms": 2500.0, "error": None}
        annotate_failure_reasons(proxy)
        self.assertEqual(proxy.tests.latency["reason"], "above_max_latency")

    def test_exit_ip_direct_wan_has_reason(self):
        proxy = self._proxy()
        proxy.tests.status = "rejected_exit_ip_direct_wan"
        proxy.tests.exit_ip_probe = {
            "status": "fail",
            "ip": "203.0.113.10",
            "error": None,
            "direct_wan_match": True,
        }
        annotate_failure_reasons(proxy)
        self.assertEqual(proxy.tests.exit_ip_probe["reason"], "direct_wan_match")

    def test_write_jsonl_persists_reason_and_raw_error(self):
        proxy = self._proxy()
        proxy.tests.status = "rejected_tcp"
        proxy.tests.tcp = {
            "status": "reject",
            "latency_ms": None,
            "error": "[Errno 111] Connection refused",
        }
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "rejected.jsonl"
            write_jsonl(path, [proxy])
            record = json.loads(path.read_text(encoding="utf-8").strip())
        self.assertEqual(record["tests"]["tcp"]["reason"], "connection_refused")
        self.assertEqual(record["tests"]["tcp"]["error"], "[Errno 111] Connection refused")

    def test_security_keeps_all_reasons_and_exposes_primary_reason(self):
        proxy = self._proxy()
        proxy.tests.status = "rejected_security"
        proxy.tests.security = {
            "status": "reject",
            "reasons": ["certificate_verification_disabled", "missing_password"],
        }
        annotate_failure_reasons(proxy)
        self.assertEqual(proxy.tests.security["reason"], "certificate_verification_disabled")
        self.assertEqual(len(proxy.tests.security["reasons"]), 2)


if __name__ == "__main__":
    unittest.main()
