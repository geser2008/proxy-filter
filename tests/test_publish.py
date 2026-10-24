import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.publish import publish_merged, publish_source, subscription_text


class PublishTests(unittest.TestCase):
    def _proxy(self, uri: str = "vless://abc@example.com:443", suffix: int = 1) -> ProxyConfig:
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
            "uri": uri,
            "error": None,
        }
        return proxy

    def test_subscription_text_uses_rendered_uri(self):
        proxy = self._proxy("vless://abc@example.com:443#test")
        self.assertEqual(subscription_text([proxy]), "vless://abc@example.com:443#test\n")

    def test_unrendered_proxy_is_rejected(self):
        proxy = self._proxy()
        proxy.tests.render["status"] = "fail"
        with self.assertRaises(ValueError):
            subscription_text([proxy])

    def test_publish_source_writes_txt_and_jsonl_atomically(self):
        proxy = self._proxy("vless://abc@example.com:443#test")
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            txt_path, jsonl_path = publish_source(data_dir, "test", [proxy])

            self.assertEqual(txt_path.read_text(encoding="utf-8"), "vless://abc@example.com:443#test\n")
            record = json.loads(jsonl_path.read_text(encoding="utf-8").strip())
            self.assertEqual(record["id"], proxy.id)
            self.assertFalse(txt_path.with_suffix(".txt.tmp").exists())
            self.assertFalse(jsonl_path.with_suffix(".jsonl.tmp").exists())

    def test_publish_preserves_unicode_country_label_exactly(self):
        name = "🇳🇱 NL | 126ms | ↓105 ↑132 | trojan"
        uri = (
            "trojan://secret@example.com:443?security=tls"
            "#%F0%9F%87%B3%F0%9F%87%B1%20NL%20%7C%20126ms%20%7C%20"
            "%E2%86%93105%20%E2%86%91132%20%7C%20trojan"
        )
        proxy = self._proxy(uri)
        proxy.tests.render["name"] = name

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            txt_path, jsonl_path = publish_source(data_dir, "test", [proxy])

            self.assertIn("%F0%9F%87%B3%F0%9F%87%B1%20NL%20%7C", txt_path.read_text(encoding="utf-8"))
            record = json.loads(jsonl_path.read_text(encoding="utf-8").strip())
            self.assertEqual(record["tests"]["render"]["name"], name)

    def test_publish_merged_keeps_two_best_from_same_infrastructure(self):
        values = [
            (199, 164, 56, "80.174.118.30"),
            (211, 154, 53, "80.174.118.40"),
            (287, 152, 132, "80.174.118.50"),
            (334, 135, 69, "80.174.118.60"),
            (1364, 160, 94, "80.174.118.90"),
        ]
        proxies = []
        for idx, (latency, down, up, exit_ip) in enumerate(values, 1):
            proxy = self._proxy(f"vless://abc-{idx}@example{idx}.com:443#test-{idx}", suffix=idx)
            proxy.tests.latency_ms = latency
            proxy.tests.download_mbps = down
            proxy.tests.upload_mbps = up
            proxy.tests.exit_ip = exit_ip
            proxy.tests.geo = {"status": "ok", "asn": 30088}
            proxies.append(proxy)

        expected = [proxies[0].id, proxies[2].id]
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            txt_path, jsonl_path = publish_merged(data_dir, proxies)

            self.assertEqual([proxy.id for proxy in proxies], expected)
            self.assertEqual(len(txt_path.read_text(encoding="utf-8").splitlines()), 2)
            records = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([record["id"] for record in records], expected)
            report = json.loads((data_dir / "reports" / "diversity.json").read_text(encoding="utf-8"))
            self.assertEqual(report["input"], 5)
            self.assertEqual(report["selected"], 2)
            self.assertEqual(report["suppressed"], 3)


if __name__ == "__main__":
    unittest.main()
