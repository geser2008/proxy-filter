import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from proxyfilter import cli, speed_policy, speed_reliability, speed_semantics, speed_staged
from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.payload_semantics import normalize_payload_valid
from proxyfilter.speed import SpeedResult


class SpeedMeasurementSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)

    def test_cli_uses_final_speed_policy_wrappers(self):
        self.assertIs(cli.check_download_many, speed_reliability.check_download_many)
        self.assertIs(cli.check_upload_many, speed_semantics.check_upload_many)

    def test_generic_download_backend_does_not_multiply_full_object_per_stream(self):
        one_stream = SpeedResult(
            True,
            mbps=40.0,
            bytes_transferred=10_000_000,
            time_seconds=2.0,
            http_code=200,
            url="https://example.com/file.bin",
            backend="generic",
        )
        with patch("proxyfilter.speed._download_parallel_stage", return_value=one_stream) as probe:
            result = speed_policy._download_staged(
                self.proxy,
                object(),
                url="https://example.com/file.bin",
                fallback_urls=[],
                timeout=30,
                curl_command="curl",
                stream_stages=(1, 2, 4),
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.mbps, 40.0)
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(probe.call_args.kwargs["streams"], 1)
        self.assertEqual(
            [(stage["streams"], stage["skipped"]) for stage in result.stages],
            [(1, False), (2, True), (4, True)],
        )

    def test_successful_short_upload_is_invalid_payload(self):
        proc = SimpleNamespace(returncode=0, stdout="1000\t1.0\t200", stderr="")
        with patch("proxyfilter.speed_staged.subprocess.run", return_value=proc):
            result = speed_staged._upload_via_socks(
                "socks5h://127.0.0.1:1080",
                url="https://example.com/upload",
                payload_path=Path("/tmp/payload.bin"),
                expected_bytes=2000,
                timeout=30,
                curl_command="curl",
                connect_timeout=10,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.bytes_transferred, 1000)
        self.assertEqual(result.expected_bytes, 2000)
        self.assertFalse(result.payload_valid)
        self.assertEqual(result.failure_reason, "invalid_payload")

    def test_payload_valid_true_requires_confirmed_complete_byte_count(self):
        record = {
            "payload_valid": True,
            "bytes": 20_000_000,
            "expected_bytes": 20_000_000,
        }
        normalize_payload_valid(record)
        self.assertIs(record["payload_valid"], True)

    def test_payload_valid_false_remains_explicit_invalid_payload(self):
        record = {
            "payload_valid": False,
            "bytes": 1_000,
            "expected_bytes": 20_000_000,
        }
        normalize_payload_valid(record)
        self.assertIs(record["payload_valid"], False)

    def test_unconfirmed_payload_is_unknown_not_true(self):
        record = {
            "payload_valid": True,
            "bytes": None,
            "expected_bytes": 20_000_000,
            "error": "curl: transport failure",
        }
        normalize_payload_valid(record)
        self.assertIsNone(record["payload_valid"])

    def test_partial_timeout_payload_is_unknown_not_invalid(self):
        record = {
            "payload_valid": True,
            "bytes": 5_000_000,
            "expected_bytes": 20_000_000,
            "failure_reason": "timeout",
        }
        normalize_payload_valid(record)
        self.assertIsNone(record["payload_valid"])


if __name__ == "__main__":
    unittest.main()
