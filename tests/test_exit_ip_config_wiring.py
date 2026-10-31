import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxyfilter import cli
from proxyfilter.model import ProxyConfig, SourceInfo


class ExitIPConfigWiringTests(unittest.TestCase):
    def _proxy(self):
        return ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)

    def test_exit_ip_fallback_is_enabled_by_default_and_uses_configured_url(self):
        proxy = self._proxy()
        cfg = {
            "filters": {
                "exit_ip": {
                    "url": "https://primary.example/ip",
                    "fallback_url": "https://fallback.example/ip",
                    "workers": 1,
                    "reject_direct_wan_ip": True,
                    "auto_discover_direct_ip": True,
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "proxyfilter.cli.discover_direct_ip", return_value="203.0.113.7"
        ) as discover, patch(
            "proxyfilter.cli.check_exit_ip_many", return_value=([proxy], [])
        ) as check:
            cli.process_proxies(
                [proxy],
                cfg,
                Path(tmpdir),
                "exit-ip",
                object(),
                resume_from="upload",
            )

        expected = ["https://fallback.example/ip"]
        self.assertEqual(discover.call_args.kwargs["fallback_urls"], expected)
        self.assertEqual(check.call_args.kwargs["fallback_urls"], expected)

    def test_exit_ip_fallback_can_be_disabled(self):
        proxy = self._proxy()
        cfg = {
            "filters": {
                "exit_ip": {
                    "url": "https://primary.example/ip",
                    "fallback_enabled": False,
                    "fallback_url": "https://fallback.example/ip",
                    "workers": 1,
                    "reject_direct_wan_ip": True,
                    "auto_discover_direct_ip": True,
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "proxyfilter.cli.discover_direct_ip", return_value="203.0.113.7"
        ) as discover, patch(
            "proxyfilter.cli.check_exit_ip_many", return_value=([proxy], [])
        ) as check:
            cli.process_proxies(
                [proxy],
                cfg,
                Path(tmpdir),
                "exit-ip",
                object(),
                resume_from="upload",
            )

        self.assertEqual(discover.call_args.kwargs["fallback_urls"], [])
        self.assertEqual(check.call_args.kwargs["fallback_urls"], [])


if __name__ == "__main__":
    unittest.main()
