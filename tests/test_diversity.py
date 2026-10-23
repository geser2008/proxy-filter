import unittest

from proxyfilter.diversity import infrastructure_key, select_diverse
from proxyfilter.model import ProxyConfig, SourceInfo


SOURCE = SourceInfo("test", "Test", "plain")


class DiversityTests(unittest.TestCase):
    @staticmethod
    def _proxy(
        suffix: int,
        latency: float,
        download: float,
        upload: float,
        *,
        exit_ip: str,
        asn=30088,
    ) -> ProxyConfig:
        proxy = ProxyConfig(
            SOURCE,
            "ss",
            f"202.50.253.{suffix}",
            19999,
            params={"method": "aes-256-gcm", "password": f"secret-{suffix}"},
        )
        proxy.ensure_id()
        proxy.tests.latency_ms = latency
        proxy.tests.download_mbps = download
        proxy.tests.upload_mbps = upload
        proxy.tests.exit_ip = exit_ip
        proxy.tests.geo = {"status": "ok", "asn": asn}
        return proxy

    def test_rank_sum_selects_best_balanced_two(self):
        a = self._proxy(18, 199, 164, 56, exit_ip="80.174.118.30")
        b = self._proxy(36, 211, 154, 53, exit_ip="80.174.118.40")
        c = self._proxy(54, 287, 152, 132, exit_ip="80.174.118.50")
        d = self._proxy(63, 334, 135, 69, exit_ip="80.174.118.60")
        e = self._proxy(99, 1364, 160, 94, exit_ip="80.174.118.90")

        selected, suppressed, report = select_diverse([a, b, c, d, e], max_per_cluster=2)

        self.assertEqual([proxy.id for proxy in selected], [a.id, c.id])
        self.assertEqual(len(suppressed), 3)
        self.assertEqual(a.tests.diversity["rank_sum"], 6)
        self.assertEqual(c.tests.diversity["rank_sum"], 8)
        self.assertEqual(e.tests.diversity["rank_sum"], 9)
        self.assertEqual(a.tests.diversity["overall_rank"], 1)
        self.assertEqual(c.tests.diversity["overall_rank"], 2)
        self.assertEqual(report[0]["cluster_key"], "80.174.118.0/24|AS30088")

    def test_same_exit_subnet_different_asn_is_not_same_cluster(self):
        a = self._proxy(1, 100, 100, 100, exit_ip="80.174.118.10", asn=30088)
        b = self._proxy(2, 110, 90, 90, exit_ip="80.174.118.20", asn=64500)

        selected, suppressed, report = select_diverse([a, b], max_per_cluster=1)

        self.assertEqual(len(selected), 2)
        self.assertEqual(len(suppressed), 0)
        self.assertEqual(len(report), 2)

    def test_unknown_exit_does_not_group_adjacent_server_addresses(self):
        a = self._proxy(10, 100, 100, 100, exit_ip="", asn=None)
        b = self._proxy(11, 110, 90, 90, exit_ip="", asn=None)

        self.assertNotEqual(infrastructure_key(a), infrastructure_key(b))
        selected, suppressed, _ = select_diverse([a, b], max_per_cluster=1)
        self.assertEqual(len(selected), 2)
        self.assertEqual(len(suppressed), 0)


if __name__ == "__main__":
    unittest.main()
