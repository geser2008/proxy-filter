from __future__ import annotations

import sys
import unittest
from unittest.mock import patch

import proxy_filter


class LauncherDefaultsTests(unittest.TestCase):
    def test_default_paths_and_publish_until(self):
        merged = {"sources": []}
        seen_argv = []

        def fake_cli_main():
            seen_argv[:] = sys.argv
            return 0

        with (
            patch.object(sys, "argv", ["proxy_filter.py"]),
            patch("proxy_filter.merged_config", return_value=merged) as merge,
            patch("proxy_filter.yaml.safe_dump"),
            patch("proxy_filter.cli.main", side_effect=fake_cli_main) as cli_main,
        ):
            rc = proxy_filter.main()

        self.assertEqual(rc, 0)
        merge.assert_called_once()
        config_path, sources_path = merge.call_args.args
        self.assertEqual(str(config_path), proxy_filter.DEFAULT_CONFIG_PATH)
        self.assertEqual(str(sources_path), proxy_filter.DEFAULT_SOURCES_PATH)
        self.assertIn("--until", seen_argv)
        self.assertEqual(seen_argv[seen_argv.index("--until") + 1], "publish")
        cli_main.assert_called_once_with()

    def test_explicit_until_is_preserved(self):
        seen_argv = []

        def fake_cli_main():
            seen_argv[:] = sys.argv
            return 0

        with (
            patch.object(sys, "argv", ["proxy_filter.py", "--until", "core"]),
            patch("proxy_filter.merged_config", return_value={"sources": []}),
            patch("proxy_filter.yaml.safe_dump"),
            patch("proxy_filter.cli.main", side_effect=fake_cli_main),
        ):
            rc = proxy_filter.main()

        self.assertEqual(rc, 0)
        self.assertEqual(seen_argv[seen_argv.index("--until") + 1], "core")


if __name__ == "__main__":
    unittest.main()
