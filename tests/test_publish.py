import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.publish import publish_source, subscription_text


class PublishTests(unittest.TestCase):
    def _proxy(self, uri: str = "vless://abc@example.com:443") -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "Test"),
            "vless",
            "example.com",
            443,
            params={"uuid": "abc"},
        )
        proxy.ensure_id()
        proxy.tests.render = {
            "status": "pass",
            "name": "test",
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


if __name__ == "__main__":
    unittest.main()
