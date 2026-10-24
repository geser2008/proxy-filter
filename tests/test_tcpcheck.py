from __future__ import annotations

import unittest
from unittest.mock import patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.tcpcheck import check_many


def make_proxy(protocol: str) -> ProxyConfig:
    return ProxyConfig(
        source=SourceInfo("test", "Test"),
        protocol=protocol,
        server="203.0.113.1",
        port=443,
    )


class TcpCheckTests(unittest.TestCase):
    def test_udp_protocols_skip_tcp_precheck(self):
        proxies = [
            make_proxy("hysteria2"),
            make_proxy("hy2"),
            make_proxy("tuic"),
        ]

        with patch("proxyfilter.tcpcheck.socket.create_connection") as connect:
            passed, rejected = check_many(
                proxies,
                timeout=0.1,
                workers=1,
            )

        self.assertEqual(len(passed), 3)
        self.assertEqual(rejected, [])
        connect.assert_not_called()

        for proxy in passed:
            self.assertEqual(proxy.tests.tcp["status"], "skipped")
            self.assertEqual(
                proxy.tests.tcp["reason"],
                "not_applicable_udp_protocol",
            )
            self.assertEqual(proxy.tests.status, "tcp_skipped")

    def test_tcp_protocol_still_uses_tcp_connect(self):
        proxy = make_proxy("vless")

        class DummySocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

        with patch(
            "proxyfilter.tcpcheck.socket.create_connection",
            return_value=DummySocket(),
        ) as connect:
            passed, rejected = check_many(
                [proxy],
                timeout=0.1,
                workers=1,
            )

        self.assertEqual(len(passed), 1)
        self.assertEqual(rejected, [])
        self.assertEqual(proxy.tests.tcp["status"], "pass")
        self.assertEqual(proxy.tests.status, "tcp_pass")
        connect.assert_called_once_with(
            ("203.0.113.1", 443),
            timeout=0.1,
        )


if __name__ == "__main__":
    unittest.main()
