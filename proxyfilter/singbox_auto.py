from __future__ import annotations

"""Automatic sing-box executable and backend-mode selection.

Production runs normally use the ``sing-box`` found in ``PATH``.  An explicit
``engine.command`` still wins and may point at any executable path.  Backend
mode is derived from the installed binary's version string: every build whose
version contains ``extended`` (including extended-light/lite variants) uses the
native parser backend; all other builds use the standard JSON mapper.
"""

import shutil
import subprocess
from typing import Any

from .engine import EngineError
from .singbox_modes import SingBoxBackend as _ModeSingBoxBackend


def resolve_singbox_command(command: str | None = None) -> str:
    """Resolve the configured sing-box command without overriding explicit paths."""
    configured = str(command or "").strip()
    if configured and configured != "sing-box":
        return configured
    return shutil.which("sing-box") or (configured or "sing-box")


def normalize_backend_mode(mode: str) -> str:
    """Normalize explicit/internal mode aliases to the two production modes."""
    text = str(mode).strip().lower()
    if text == "standard":
        return "standard"
    if "extended" in text:
        return "extended"
    raise EngineError(f"unsupported sing-box backend mode: {mode}")


def detect_backend_mode(version_text: str) -> str:
    """Classify standard vs extended from ``sing-box version`` output."""
    return "extended" if "extended" in str(version_text).lower() else "standard"


class SingBoxBackend(_ModeSingBoxBackend):
    """Dual-mode backend with automatic executable and mode discovery."""

    def __init__(self, *args: Any, backend_mode: str | None = None, **kwargs: Any) -> None:
        kwargs["command"] = resolve_singbox_command(kwargs.get("command", "sing-box"))
        self._detected_version: str | None = None

        # Always pass an explicit mode to the legacy adapter so its old
        # PROXYFILTER_SINGBOX_MODE environment override cannot affect production.
        initial_mode = normalize_backend_mode(backend_mode) if backend_mode is not None else "standard"
        super().__init__(*args, backend_mode=initial_mode, **kwargs)

        if backend_mode is None:
            try:
                self._detected_version = super().version()
            except (EngineError, OSError, subprocess.SubprocessError):
                # Keep construction usable for diagnostics/tests; the normal CLI
                # immediately calls version() and will surface a missing/broken
                # executable before any engine stage starts.
                self.backend_mode = "standard"
            else:
                self.backend_mode = detect_backend_mode(self._detected_version)

    def version(self) -> str:
        if self._detected_version is not None:
            return self._detected_version
        version_text = super().version()
        self._detected_version = version_text
        self.backend_mode = detect_backend_mode(version_text)
        return version_text
