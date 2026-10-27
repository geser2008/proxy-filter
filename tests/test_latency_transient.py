from __future__ import annotations

import unittest

from proxyfilter.batch_latency import BatchLatencyResult, _is_retryable_transient


class LatencyTransientTests(unittest.TestCase):
    def test_retries_temporary_network_errors(self):
        for error in (
            "[Errno 104] Connection reset by peer",
            "<urlopen error Temporary failure in name resolution>",
            "Remote end closed connection without response",
        ):
            with self.subTest(error=error):
                self.assertTrue(_is_retryable_transient(BatchLatencyResult(False, error=error)))

    def test_does_not_retry_permanent_error(self):
        self.assertFalse(
            _is_retryable_transient(BatchLatencyResult(False, error="certificate verify failed"))
        )


if __name__ == "__main__":
    unittest.main()