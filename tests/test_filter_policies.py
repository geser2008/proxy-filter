from __future__ import annotations

import unittest
from unittest.mock import patch

from proxyfilter.global_dedup import RunDeduplicator
from proxyfilter.measurement_policy import check_download_many, check_upload_many
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult


def _proxy(source_id: str, *, name: str = "p") -> ProxyConfig:
    proxy = ProxyConfig(
        SourceInfo(source_id, source_id, "plain"),
        "vless",
        "example.com",
        443,
        name,
        {"uuid": "00000000-0000-0000-0000-000000000001", "security": "tls"},
        "vless-uri",
        "",
    )
    proxy.ensure_id()
    return proxy


def _plain_deduplicate(proxies):
    unique = {}
    duplicates = []
    for proxy in proxies:
        proxy.ensure_id()
        if proxy.id in unique:
            unique[proxy.id].merge_sources_from(proxy)
            duplicates.append(proxy)
        else:
            unique[proxy.id] = proxy
    return list(unique.values()), duplicates


class GlobalDedupTests(unittest.TestCase):
    def test_duplicate_from_later_source_is_not_returned_for_network_tests(self):
        dedup = RunDeduplicator(_plain_deduplicate)
        first = _proxy("radikal")
        second = _proxy("delta")

        first_unique, _ = dedup([first])
        second_unique, second_duplicates = dedup([second])

        self.assertEqual(first_unique, [first])
        self.assertEqual(second_unique, [])
        self.assertEqual(second_duplicates, [second])
        self.assertEqual([source.id for source in first.sources], ["radikal", "delta"])

        merged, duplicates = dedup([first])
        self.assertEqual(merged, [first])
        self.assertEqual(duplicates, [])


class NumericSpeedPolicyTests(unittest.TestCase):
    @patch("proxyfilter.measurement_policy._BASE_DOWNLOAD")
    def test_download_numeric_partial_result_uses_threshold(self, base_download) -> None:
        proxy = _proxy("test")
        proxy.tests.download_mbps = 27.0
        proxy.tests.download = {"status": "fail", "mbps": 27.0, "error": "timeout"}
        proxy.tests.status = "rejected_download_error"
        base_download.return_value = ([], [proxy])

        passed, rejected = check_download_many([], object(), url="x", timeout=1, min_mbps=50)
        self.assertEqual(passed, [])
        self.assertEqual(rejected, [proxy])
        self.assertEqual(proxy.tests.status, "rejected_download_threshold")

    @patch("proxyfilter.measurement_policy._BASE_DOWNLOAD")
    def test_download_numeric_partial_result_can_pass_lower_threshold(self, base_download) -> None:
        proxy = _proxy("test")
        proxy.tests.download_mbps = 27.0
        proxy.tests.download = {"status": "fail", "mbps": 27.0, "error": "timeout"}
        proxy.tests.status = "rejected_download_error"
        base_download.return_value = ([], [proxy])

        passed, rejected = check_download_many([], object(), url="x", timeout=1, min_mbps=20)
        self.assertEqual(passed, [proxy])
        self.assertEqual(rejected, [])
        self.assertEqual(proxy.tests.status, "download_pass")

    @patch("proxyfilter.measurement_policy._BASE_UPLOAD")
    def test_upload_null_speed_remains_error(self, base_upload) -> None:
        proxy = _proxy("test")
        proxy.tests.upload_mbps = None
        proxy.tests.upload = {"status": "fail", "mbps": None, "error": "timeout"}
        base_upload.return_value = ([], [proxy])

        passed, rejected = check_upload_many([], object(), url="x", upload_bytes=1, timeout=1, min_mbps=20)
        self.assertEqual(passed, [])
        self.assertEqual(rejected, [proxy])
        self.assertEqual(proxy.tests.status, "rejected_upload_error")


if __name__ == "__main__":
    unittest.main()
