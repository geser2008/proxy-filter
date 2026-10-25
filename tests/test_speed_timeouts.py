import unittest
from unittest.mock import patch

from proxyfilter.speed import _download_via_socks, _max_operation_time


class SpeedTimeoutTests(unittest.TestCase):
    def test_max_operation_time_adds_connect_and_transfer_budgets(self):
        self.assertEqual(_max_operation_time(30, 10), 40)

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


if __name__ == "__main__":
    unittest.main()
