from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.publish import publish_merged
from proxyfilter.reliable_history import (
    format_reliability_name_metric,
    update_global_reliability,
)
from proxyfilter.render import render_uri


class ReliableNameMetricTests(unittest.TestCase):
    def _proxy(self, suffix: int = 1) -> ProxyConfig:
        proxy = ProxyConfig(
            SourceInfo("test", "Test", "plain"),
            "ss",
            f"203.0.113.{suffix}",
            8388,
            params={"method": "aes-256-gcm", "password": f"secret-{suffix}"},
        )
        proxy.ensure_id()
        name = f"🌐 ?? | 100ms | ↓100 ↑50 | ss | [test] | reliability:stable"
        proxy.tests.render = {
            "status": "pass",
            "name": name,
            "uri": render_uri(proxy, name),
            "error": None,
            "stream_reliability": "stable",
        }
        proxy.tests.reliability = {"status": "stable", "reason": None, "details": {}}
        return proxy

    def test_raw_metric_format(self):
        row = {"test_count": 15, "confirmed_passes": 13}
        self.assertEqual(
            format_reliability_name_metric(row, metric="raw", show_counts=True),
            "R87%(13/15)",
        )
        self.assertEqual(
            format_reliability_name_metric(row, metric="raw", show_counts=False),
            "R87%",
        )

    def test_bayesian_metric_format(self):
        self.assertEqual(
            format_reliability_name_metric(
                {"test_count": 3, "confirmed_passes": 3},
                metric="bayesian",
                show_counts=True,
            ),
            "B80%(3/3)",
        )
        self.assertEqual(
            format_reliability_name_metric(
                {"test_count": 15, "confirmed_passes": 13},
                metric="bayesian",
                show_counts=True,
            ),
            "B82%(13/15)",
        )

    def test_none_metric_is_empty(self):
        self.assertEqual(
            format_reliability_name_metric(
                {"test_count": 3, "confirmed_passes": 3},
                metric="none",
            ),
            "",
        )

    def test_invalid_metric_is_rejected(self):
        with self.assertRaises(ValueError):
            format_reliability_name_metric(
                {"test_count": 3, "confirmed_passes": 3},
                metric="weighted",
            )

    def test_only_eligible_proxy_gets_raw_marker_at_publish(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            db = data_dir / "history" / "proxy-history.sqlite3"
            reliable = self._proxy(1)
            ordinary = self._proxy(2)

            for _ in range(3):
                update_global_reliability(db, [reliable], [])
            update_global_reliability(db, [ordinary], [])

            proxies = [reliable, ordinary]
            publish_merged(
                data_dir,
                proxies,
                {"enabled": False},
                reliable_cfg={
                    "enabled": True,
                    "min_confirmed_passes": 3,
                    "min_consecutive_passes": 2,
                    "name_metric": "raw",
                    "name_show_counts": True,
                },
                history_cfg={"database": "history/proxy-history.sqlite3"},
            )

            self.assertTrue(reliable.tests.render["name"].endswith(" | R100%(3/3)"))
            self.assertNotIn(" | R", ordinary.tests.render["name"])
            self.assertNotIn(" | B", ordinary.tests.render["name"])
            self.assertEqual(
                reliable.tests.render["historical_reliability"],
                "R100%(3/3)",
            )
            self.assertEqual(len((data_dir / "output" / "reliable.txt").read_text().splitlines()), 1)

    def test_none_metric_does_not_change_eligible_proxy_name(self):
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            db = data_dir / "history" / "proxy-history.sqlite3"
            proxy = self._proxy(3)
            original_name = proxy.tests.render["name"]
            for _ in range(3):
                update_global_reliability(db, [proxy], [])

            publish_merged(
                data_dir,
                [proxy],
                {"enabled": False},
                reliable_cfg={
                    "enabled": True,
                    "min_confirmed_passes": 3,
                    "min_consecutive_passes": 2,
                    "name_metric": "none",
                    "name_show_counts": True,
                },
                history_cfg={"database": "history/proxy-history.sqlite3"},
            )

            self.assertEqual(proxy.tests.render["name"], original_name)
            self.assertEqual(len((data_dir / "output" / "reliable.txt").read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
