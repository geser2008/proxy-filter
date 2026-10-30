import unittest
from unittest.mock import patch

from proxyfilter import cli
from proxyfilter.geoip import GeoIPResult, enrich_geo_many
from proxyfilter.model import ProxyConfig, SourceInfo


class _Session:
    def __init__(self, socks_url):
        self.socks_url = socks_url


class _Engine:
    def __init__(self):
        self.started = []
        self.stopped = []

    def start(self, proxy):
        self.started.append(proxy)
        return _Session("socks5h://127.0.0.1:23456")

    def stop(self, session):
        self.stopped.append(session)


class GeoProxyTransportTests(unittest.TestCase):
    def _proxy(self, host):
        proxy = ProxyConfig(SourceInfo("test", "test"), "ss", host, 443)
        proxy.tests.exit_ip = "203.0.113.7"
        return proxy

    def test_geo_stage_requires_engine(self):
        self.assertIn("geo", cli.ENGINE_STAGES)

    def test_one_representative_session_per_unique_exit_ip(self):
        first = self._proxy("127.0.0.1")
        second = self._proxy("127.0.0.2")
        engine = _Engine()
        primary = GeoIPResult(
            False,
            ip="203.0.113.7",
            error="timeout",
            reason="timeout",
            provider="ipwhois",
            url="primary",
        )
        fallback = GeoIPResult(
            True,
            ip="203.0.113.7",
            country_code="NL",
            country="Netherlands",
            provider="ipapi",
            url="fallback",
        )

        with patch("proxyfilter.geoip._lookup_provider", side_effect=[primary, fallback]) as lookup:
            enrich_geo_many([first, second], engine=engine, workers=1)

        self.assertEqual(len(engine.started), 1)
        self.assertIs(engine.started[0], first)
        self.assertEqual(len(engine.stopped), 1)
        self.assertEqual(lookup.call_count, 2)
        self.assertEqual(lookup.call_args_list[0].kwargs["proxy_url"], "socks5h://127.0.0.1:23456")
        self.assertEqual(lookup.call_args_list[1].kwargs["proxy_url"], "socks5h://127.0.0.1:23456")
        self.assertEqual(first.tests.geo["transport"], "proxy")
        self.assertEqual(second.tests.geo["transport"], "proxy")
        self.assertEqual(first.tests.geo["country_code"], "NL")
        self.assertEqual(second.tests.geo["country_code"], "NL")


if __name__ == "__main__":
    unittest.main()
