import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.speed import _download_via_socks, _max_operation_time, _upload_one


class SpeedTimeoutTests(unittest.TestCase):
    def test_max_operation_time_adds_connect_and_transfer_budgets(self):
        self.assertEqual(_max_operation_time(30, 10), 40)
        self.assertEqual(_max_operation_time(30.0, 10.0), 40.0)

    def test_max_operation_time_rejects_non_positive_transfer_timeout(self):
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "speed.transfer_timeout_seconds must be greater than zero",
                ):
                    _max_operation_time(value, 10)

    def test_download_curl_uses_separate_connect_and_transfer_budgets(self):
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "80000000\t2.5\t200",
                "stderr": "",
            },
        )()

        with patch("proxyfilter.speed.subprocess.run", return_value=completed) as run:
            result = _download_via_socks(
                "socks5h://127.0.0.1:1080",
                url="https://speed.cloudflare.com/__down?bytes=80000000",
                timeout=30,
                connect_timeout=10,
                curl_command="curl",
            )

        self.assertTrue(result.ok)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--connect-timeout") + 1], "10.0")
        self.assertEqual(command[command.index("--max-time") + 1], "40.0")
        self.assertEqual(run.call_args.kwargs["timeout"], 45.0)

    def test_upload_curl_uses_separate_connect_and_transfer_budgets(self):
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": "20000000\t4.0\t200",
                "stderr": "",
            },
        )()
        proxy = ProxyConfig(SourceInfo("test", "test"), "vless", "127.0.0.1", 443)
        engine = MagicMock()
        engine.start.return_value = SimpleNamespace(socks_url="socks5h://127.0.0.1:1080")

        with tempfile.NamedTemporaryFile() as payload:
            payload_path = Path(payload.name)
            with patch("proxyfilter.speed.subprocess.run", return_value=completed) as run:
                result = _upload_one(
                    proxy,
                    engine,
                    url="https://speed.cloudflare.com/__up",
                    payload_path=payload_path,
                    timeout=30,
                    connect_timeout=10,
                    curl_command="curl",
                )

        self.assertTrue(result.ok)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--connect-timeout") + 1], "10.0")
        self.assertEqual(command[command.index("--max-time") + 1], "40.0")
        self.assertEqual(run.call_args.kwargs["timeout"], 45.0)
        engine.stop.assert_called_once_with(engine.start.return_value)


if __name__ == "__main__":
    unittest.main()
