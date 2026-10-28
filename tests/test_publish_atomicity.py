from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.publish import publish_merged


class PublishAtomicityTests(unittest.TestCase):
    def _proxy(self, suffix: int, reliability: str) -> ProxyConfig:
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
        proxy.tests.reliability = {"status": reliability, "reason": None, "details": {}}
        proxy.tests.exit_ip = f"203.0.113.{suffix}"
        proxy.tests.geo = {"status": "ok", "asn": 64500 + suffix}
        return proxy

    def test_invalid_new_generation_leaves_previous_subscription_set_unchanged(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            output_dir = data_dir / "output"
            output_dir.mkdir(parents=True)
            old = {
                "all.txt": "old-all\n",
                "stable.txt": "old-stable\n",
                "unstable.txt": "old-unstable\n",
            }
            for name, text in old.items():
                (output_dir / name).write_text(text, encoding="utf-8")

            good = self._proxy(1, "stable")
            bad = self._proxy(2, "degraded")
            bad.tests.render["status"] = "fail"

            with self.assertRaises(ValueError):
                publish_merged(data_dir, [good, bad], {"enabled": False})

            self.assertEqual(
                {name: (output_dir / name).read_text(encoding="utf-8") for name in old},
                old,
            )

    def test_commit_failure_rolls_back_previous_subscription_set(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            output_dir = data_dir / "output"
            output_dir.mkdir(parents=True)
            old = {
                "all.txt": "old-all\n",
                "stable.txt": "old-stable\n",
                "unstable.txt": "old-unstable\n",
            }
            for name, text in old.items():
                (output_dir / name).write_text(text, encoding="utf-8")

            proxies = [self._proxy(1, "stable"), self._proxy(2, "degraded")]

            from proxyfilter import publish as publish_module

            real_replace = publish_module.os.replace
            commit_calls = 0

            def flaky_replace(src, dst):
                nonlocal commit_calls
                src_path = Path(src)
                dst_path = Path(dst)
                if src_path.parent.name == "new" and dst_path.parent == output_dir:
                    commit_calls += 1
                    if commit_calls == 2:
                        raise OSError("simulated commit failure")
                return real_replace(src, dst)

            with patch("proxyfilter.publish.os.replace", side_effect=flaky_replace):
                with self.assertRaises(OSError):
                    publish_merged(data_dir, proxies, {"enabled": False})

            self.assertEqual(
                {name: (output_dir / name).read_text(encoding="utf-8") for name in old},
                old,
            )


if __name__ == "__main__":
    unittest.main()
