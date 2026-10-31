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

    def test_publish_source_is_disabled(self):
        proxy = self._proxy("vless://abc@example.com:443#test")
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            result = publish_source(data_dir, "test", [proxy])

            self.assertEqual(result, (None, None))
            self.assertFalse((data_dir / "output").exists())

    def test_publish_preserves_unicode_country_label_exactly(self):
        name = "🇳🇱 NL | 126ms | ↓105 ↑132 | trojan"
        uri = (
            "trojan://secret@example.com:443?security=tls"
            "#%F0%9F%87%B3%F0%9F%87%B1%20NL%20%7C%20126ms%20%7C%20"
            "%E2%86%93105%20%E2%86%91132%20%7C%20trojan"
        )
        proxy = self._proxy(uri)
        proxy.tests.render["name"] = name
        proxy.tests.reliability = {"status": "stable", "reason": None, "details": {}}

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            publish_merged(data_dir, [proxy], {"enabled": False})

            text = (data_dir / "output" / "all.txt").read_text(encoding="utf-8")
            self.assertIn("%F0%9F%87%B3%F0%9F%87%B1%20NL%20%7C", text)

    def test_publish_merged_preserves_unmanaged_output_files(self):
        stable = self._proxy("vless://stable@example1.com:443#stable", suffix=1)
        unstable = self._proxy("vless://unstable@example2.com:443#unstable", suffix=2)
        stable.tests.reliability = {"status": "stable", "reason": None, "details": {}}
        unstable.tests.reliability = {"status": "degraded", "reason": "transport", "details": {}}
        for idx, proxy in enumerate((stable, unstable), 1):
            proxy.tests.latency_ms = 100 + idx
            proxy.tests.download_mbps = 100 - idx
            proxy.tests.upload_mbps = 50 - idx
            proxy.tests.exit_ip = f"203.0.113.{idx}"
            proxy.tests.geo = {"status": "ok", "asn": 64500 + idx}

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            output_dir = data_dir / "output"
            output_dir.mkdir(parents=True)
            (output_dir / "old-source.txt").write_text("keep me\n", encoding="utf-8")
            (output_dir / "all.jsonl").write_text("keep me too\n", encoding="utf-8")

            all_path, legacy_jsonl = publish_merged(data_dir, [stable, unstable], {"enabled": False})

            self.assertIsNone(legacy_jsonl)
            self.assertEqual(all_path, output_dir / "all.txt")
            self.assertEqual(
                sorted(path.name for path in output_dir.iterdir()),
                ["all.jsonl", "all.txt", "old-source.txt", "stable.txt", "unstable.txt"],
            )
            self.assertEqual((output_dir / "old-source.txt").read_text(encoding="utf-8"), "keep me\n")
            self.assertEqual((output_dir / "all.jsonl").read_text(encoding="utf-8"), "keep me too\n")
            self.assertEqual(len((output_dir / "all.txt").read_text().splitlines()), 2)
            self.assertEqual((output_dir / "stable.txt").read_text().splitlines(), [stable.tests.render["uri"]])
            self.assertEqual((output_dir / "unstable.txt").read_text().splitlines(), [unstable.tests.render["uri"]])
            counts = json.loads((data_dir / "reports" / "subscriptions.json").read_text())
            self.assertEqual(counts, {"all": 2, "stable": 1, "unstable": 1, "unclassified": 0})

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
            proxy.tests.reliability = {"status": "stable", "reason": None, "details": {}}
            proxies.append(proxy)

        expected = [proxies[0].id, proxies[2].id]
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            txt_path, legacy_jsonl = publish_merged(data_dir, proxies)

            self.assertIsNone(legacy_jsonl)
            self.assertEqual([proxy.id for proxy in proxies], expected)
            self.assertEqual(len(txt_path.read_text(encoding="utf-8").splitlines()), 2)
            published_records = [
                json.loads(line)
                for line in (data_dir / "work" / "14-published.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([record["id"] for record in published_records], expected)
            report = json.loads((data_dir / "reports" / "diversity.json").read_text(encoding="utf-8"))
            self.assertEqual(report["input"], 5)
            self.assertEqual(report["selected"], 2)
            self.assertEqual(report["suppressed"], 3)


if __name__ == "__main__":
    unittest.main()
