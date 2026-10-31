from __future__ import annotations

import os
from pathlib import Path
import unittest
from unittest.mock import patch

from proxyfilter.cli import build_engine
from proxyfilter.singbox_auto import (
    SingBoxBackend,
    detect_backend_mode,
    normalize_backend_mode,
    resolve_singbox_command,
)
from proxyfilter.singbox_modes import SingBoxBackend as ModeSingBoxBackend


class SingBoxAutoTests(unittest.TestCase):
    def test_version_classifier_treats_all_extended_variants_as_extended(self) -> None:
        samples = (
            "sing-box version 1.14.3-extended-2.7.3",
            "sing-box version 1.14.3-extended-2.7.3-lite",
            "sing-box version 1.14.3-extended-light",
            "sing-box extended-light 1.14.3",
        )
        for version_text in samples:
            with self.subTest(version_text=version_text):
                self.assertEqual(detect_backend_mode(version_text), "extended")

    def test_standard_version_is_standard(self) -> None:
        self.assertEqual(detect_backend_mode("sing-box version 1.14.3"), "standard")

    def test_explicit_extended_alias_is_normalized(self) -> None:
        self.assertEqual(normalize_backend_mode("extended-light"), "extended")
        self.assertEqual(normalize_backend_mode("extended-lite"), "extended")

    @patch("proxyfilter.singbox_auto.shutil.which", return_value="/usr/bin/sing-box")
    def test_default_command_is_resolved_from_path(self, which) -> None:
        self.assertEqual(resolve_singbox_command("sing-box"), "/usr/bin/sing-box")
        which.assert_called_once_with("sing-box")

    @patch("proxyfilter.singbox_auto.shutil.which")
    def test_explicit_command_path_wins(self, which) -> None:
        self.assertEqual(resolve_singbox_command("/opt/sing-box/bin/sing-box"), "/opt/sing-box/bin/sing-box")
        which.assert_not_called()

    @patch("proxyfilter.singbox_auto.shutil.which", return_value="/usr/local/bin/sing-box")
    @patch(
        "proxyfilter.singbox_auto._ModeSingBoxBackend.version",
        return_value="sing-box version 1.14.3-extended-light",
    )
    def test_backend_auto_detects_extended_light(self, version, which) -> None:
        backend = SingBoxBackend()
        self.assertEqual(backend.command, "/usr/local/bin/sing-box")
        self.assertEqual(backend.backend_mode, "extended")
        self.assertEqual(backend.version(), "sing-box version 1.14.3-extended-light")
        version.assert_called_once()
        which.assert_called_once_with("sing-box")

    @patch("proxyfilter.singbox_auto.shutil.which", return_value="/usr/bin/sing-box")
    @patch(
        "proxyfilter.singbox_auto._ModeSingBoxBackend.version",
        return_value="sing-box version 1.14.3",
    )
    def test_environment_mode_no_longer_overrides_detected_version(self, version, which) -> None:
        with patch.dict(os.environ, {"PROXYFILTER_SINGBOX_MODE": "extended"}):
            backend = SingBoxBackend()
        self.assertEqual(backend.backend_mode, "standard")

    def test_mode_adapter_default_is_standard_even_with_legacy_environment_variable(self) -> None:
        with patch.dict(os.environ, {"PROXYFILTER_SINGBOX_MODE": "extended"}):
            backend = ModeSingBoxBackend()
        self.assertEqual(backend.backend_mode, "standard")

    @patch("proxyfilter.singbox_auto.shutil.which", return_value="/usr/local/bin/sing-box")
    @patch(
        "proxyfilter.singbox_auto._ModeSingBoxBackend.version",
        return_value="sing-box version 1.14.3-extended-2.7.3-lite",
    )
    def test_cli_build_engine_uses_auto_detected_extended_backend(self, version, which) -> None:
        backend = build_engine({}, Path("/tmp/proxy-filter-test"))
        self.assertIsInstance(backend, SingBoxBackend)
        self.assertEqual(backend.command, "/usr/local/bin/sing-box")
        self.assertEqual(backend.backend_mode, "extended")
        self.assertEqual(backend.version(), "sing-box version 1.14.3-extended-2.7.3-lite")
        version.assert_called_once()
        which.assert_called_once_with("sing-box")

    @patch("proxyfilter.singbox_auto.shutil.which")
    @patch(
        "proxyfilter.singbox_auto._ModeSingBoxBackend.version",
        return_value="sing-box version 1.14.3",
    )
    def test_cli_build_engine_preserves_explicit_command(self, version, which) -> None:
        backend = build_engine(
            {"engine": {"command": "/opt/sing-box/bin/sing-box"}},
            Path("/tmp/proxy-filter-test"),
        )
        self.assertEqual(backend.command, "/opt/sing-box/bin/sing-box")
        self.assertEqual(backend.backend_mode, "standard")
        version.assert_called_once()
        which.assert_not_called()


if __name__ == "__main__":
    unittest.main()
