import unittest

from proxyfilter.speed import _mbps, _parse_curl_metrics


class SpeedProbeTests(unittest.TestCase):
    def test_parse_curl_metrics(self):
        size, elapsed, http_code = _parse_curl_metrics("10000000\t2.5\t200")
        self.assertEqual(size, 10_000_000)
        self.assertEqual(elapsed, 2.5)
        self.assertEqual(http_code, 200)

    def test_mbps_uses_decimal_megabits(self):
        self.assertEqual(_mbps(10_000_000, 2.0), 40.0)

    def test_zero_size_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_curl_metrics("0\t1.0\t200")

    def test_zero_time_is_rejected(self):
        with self.assertRaises(ValueError):
            _parse_curl_metrics("1000\t0\t200")


if __name__ == "__main__":
    unittest.main()
