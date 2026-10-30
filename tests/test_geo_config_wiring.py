import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxyfilter import cli
from proxyfilter.model import ProxyConfig, SourceInfo


class GeoConfigWiringTests(unittest.TestCase):
    def _proxy(self):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", "127.0.0.1", 443)
        proxy.tests.exit_ip = "203.0.113.7"
        return proxy

    def test_geo_fallback_is_enabled_by_default_and_uses_configured_provider(self):
        proxy = self._proxy()
        cfg = {
            "filters": {
                "geo": {
                    "provider": "ipwhois",
                    "url_template": "https://primary.example/{ip}",
                    "fallback_provider": "ipapi",
                    "fallback_url_template": "https://fallback.example/{ip}",
                    "workers": 1,
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "proxyfilter.cli.enrich_geo_many", return_value=[proxy]
        ) as enrich:
            cli.process_proxies(
                [proxy],
                cfg,
                Path(tmpdir),
                "geo",
                None,
                resume_from="exit-ip",
            )

        kwargs = enrich.call_args.kwargs
        self.assertTrue(kwargs["fallback_enabled"])
        self.assertEqual(kwargs["fallback_provider"], "ipapi")
        self.assertEqual(kwargs["fallback_url_template"], "https://fallback.example/{ip}")

    def test_geo_fallback_can_be_disabled(self):
        proxy = self._proxy()
        cfg = {
            "filters": {
                "geo": {
                    "provider": "ipwhois",
                    "url_template": "https://primary.example/{ip}",
                    "fallback_enabled": False,
                    "fallback_provider": "ipapi",
                    "fallback_url_template": "https://fallback.example/{ip}",
                    "workers": 1,
                }
            }
        }

        with tempfile.TemporaryDirectory() as tmpdir, patch(
            "proxyfilter.cli.enrich_geo_many", return_value=[proxy]
        ) as enrich:
            cli.process_proxies(
                [proxy],
                cfg,
                Path(tmpdir),
                "geo",
                None,
                resume_from="exit-ip",
            )

        kwargs = enrich.call_args.kwargs
        self.assertFalse(kwargs["fallback_enabled"])
        self.assertIsNone(kwargs["fallback_provider"])
        self.assertIsNone(kwargs["fallback_url_template"])


if __name__ == "__main__":
    unittest.main()
