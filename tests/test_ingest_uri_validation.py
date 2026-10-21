from __future__ import annotations

import unittest

from proxyfilter.ingest import parse_uri
from proxyfilter.model import SourceInfo


class URIValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = SourceInfo("test", "test", "plain")

    def test_rejects_bare_percent_in_query_value(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?encryption=none&type=ws&path=/%"
        )
        with self.assertRaisesRegex(ValueError, "invalid URI percent escape"):
            parse_uri(uri, self.source)

    def test_accepts_valid_percent_escape(self) -> None:
        uri = (
            "vless://00000000-0000-0000-0000-000000000001@example.com:443"
            "?encryption=none&type=ws&path=%2Fapi"
        )
        proxy = parse_uri(uri, self.source)
        self.assertEqual(proxy.params["path"], "/api")


if __name__ == "__main__":
    unittest.main()
