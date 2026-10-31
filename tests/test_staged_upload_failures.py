from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import SpeedResult
from proxyfilter.speed_staged import _upload_parallel_stage, _upload_via_socks


class StagedUploadFailureTests(unittest.TestCase):
    def test_upload_curl_uses_low_speed_guard_and_preserves_timeout_reason(self) -> None:
        completed = SimpleNamespace(
            returncode=28,
            stdout="10000000\t40.0\t200",
            stderr="curl: (28) Operation timed out after 40000 milliseconds with 10000000 bytes sent",
        )
        with tempfile.NamedTemporaryFile() as payload:
            with patch("proxyfilter.speed_staged.subprocess.run", return_value=completed) as run:
                result = _upload_via_socks(
                    "socks5h://127.0.0.1:1080",
                    url="https://speed.cloudflare.com/__up",
                    payload_path=Path(payload.name),
                    expected_bytes=20_000_000,
                    timeout=30,
                    connect_timeout=10,
                    curl_command="curl",
                )

        self.assertFalse(result.ok)
        self.assertEqual(result.failure_reason, "timeout")
        self.assertEqual(result.curl_exit_code, 28)
        self.assertIsNotNone(result.mbps)
        command = run.call_args.args[0]
        self.assertIn("--speed-limit", command)
        self.assertIn("--speed-time", command)

    def test_upload_low_speed_abort_is_stalled_transfer(self) -> None:
        completed = SimpleNamespace(
            returncode=28,
            stdout="10000000\t15.0\t200",
            stderr="curl: (28) Operation too slow. Less than 1 bytes/sec transferred the last 10 seconds",
        )
        with tempfile.NamedTemporaryFile() as payload:
            with patch("proxyfilter.speed_staged.subprocess.run", return_value=completed):
                result = _upload_via_socks(
                    "socks5h://127.0.0.1:1080",
                    url="https://speed.cloudflare.com/__up",
                    payload_path=Path(payload.name),
                    expected_bytes=20_000_000,
                    timeout=30,
                    connect_timeout=10,
                    curl_command="curl",
                )

        self.assertFalse(result.ok)
        self.assertEqual(result.failure_reason, "stalled_transfer")
        self.assertEqual(result.curl_exit_code, 28)
        self.assertIsNotNone(result.mbps)

    def test_parallel_upload_preserves_first_transport_failure_diagnostics(self) -> None:
        proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)
        engine = MagicMock()
        engine.start.return_value = SimpleNamespace(socks_url="socks5h://127.0.0.1:1080")
        failed = SpeedResult(
            False,
            mbps=None,
            bytes_transferred=0,
            time_seconds=0.3,
            http_code=0,
            error="curl: (97) cannot complete SOCKS5 connection",
            failure_reason="curl_error_97",
            curl_exit_code=97,
        )
        success = SpeedResult(
            True,
            mbps=20.0,
            bytes_transferred=10_000_000,
            time_seconds=4.0,
            http_code=200,
            payload_valid=True,
        )
        with patch(
            "proxyfilter.speed_staged._upload_stream_with_retries",
            side_effect=[failed, success],
        ):
            result = _upload_parallel_stage(
                proxy,
                engine,
                url="https://speed.cloudflare.com/__up",
                streams=2,
                total_bytes=20_000_000,
                timeout=30,
                curl_command="curl",
                connect_timeout=10,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.failure_reason, "curl_error_97")
        self.assertEqual(result.curl_exit_code, 97)
        self.assertEqual(result.attempts[0]["failure_reason"], "curl_error_97")
        self.assertEqual(result.attempts[0]["curl_exit_code"], 97)


if __name__ == "__main__":
    unittest.main()
