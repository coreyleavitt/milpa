"""Profile data types — runtime resolution context.

DATA TYPES ONLY.  No predicate evaluation, no subprocess, no I/O.

``Profile.from_environment`` takes the Nim version as an injected string
(default ``"0.0.0"``); it NEVER spawns ``nim --version``.  The subprocess
that queries the live Nim version lives in ``cli.py`` and is passed in.

Predicate evaluation (``_filter_manifest_by_profile``) is a resolver step
(Stage 9), run before the solver input is built.  This module represents
predicates as data only.

RFC §4.2 boundary criteria:
  - No imports from ``manifest.py``, ``solver.py``, or any I/O layer.
  - Importable in tests without a Nim toolchain present.
  - ``Profile.from_environment`` reads env vars ``MILPA_TARGET_*``
    (§6.6) in exactly one place.
"""

from __future__ import annotations

import os
import platform as _platform
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Platform / arch normalization
# ---------------------------------------------------------------------------

_OS_MAP: dict[str, str] = {
    "darwin": "macosx",
    "windows": "windows",
    "linux": "linux",
    "freebsd": "freebsd",
    "openbsd": "openbsd",
    "netbsd": "netbsd",
}

_ARCH_MAP: dict[str, str] = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "i386": "i386",
    "i686": "i386",
}


def _detect_platform() -> str:
    raw = _platform.system().lower()
    return _OS_MAP.get(raw, raw)


def _detect_arch() -> str:
    raw = _platform.machine().lower()
    return _ARCH_MAP.get(raw, raw)


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Profile:
    """Runtime profile against which predicates are evaluated.

    Fields:
      platform: Nim ``hostOS`` token (e.g. ``"linux"``, ``"macosx"``).
      arch:     Nim ``hostCPU`` token (e.g. ``"amd64"``, ``"arm64"``).
      nim:      Nim version string (e.g. ``"2.0.0"``).  Injected, never
                queried via subprocess here.
      milpa:    milpa version string.  Overridable via
                ``MILPA_TARGET_MILPA`` env var.
      flags:    Frozenset of active feature flag names (default-true +
                explicitly enabled).  Empty set at manifest-parse time;
                the resolver populates this after reading the ``flags``
                block.
    """

    platform: str
    arch: str
    nim: str
    milpa: str
    flags: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_environment(
        cls,
        *,
        nim_version: str | None = None,
        milpa_version: str = "0.0.0",
        flags: frozenset[str] | None = None,
    ) -> Profile:
        """Construct a ``Profile`` from the current environment.

        ``nim_version`` is an injected string (default ``"0.0.0"``).
        The subprocess that queries ``nim --version`` lives in
        ``cli.py`` — never here.

        Environment variable overrides (§6.6):
          ``MILPA_TARGET_PLATFORM``  → ``platform``
          ``MILPA_TARGET_ARCH``      → ``arch``
          ``MILPA_TARGET_NIM``       → ``nim``
          ``MILPA_TARGET_MILPA``     → ``milpa``
        """
        effective_platform = (
            os.environ.get("MILPA_TARGET_PLATFORM") or _detect_platform()
        )
        effective_arch = os.environ.get("MILPA_TARGET_ARCH") or _detect_arch()
        effective_nim = os.environ.get("MILPA_TARGET_NIM") or nim_version or "0.0.0"
        effective_milpa = os.environ.get("MILPA_TARGET_MILPA") or milpa_version

        return cls(
            platform=effective_platform,
            arch=effective_arch,
            nim=effective_nim,
            milpa=effective_milpa,
            flags=flags if flags is not None else frozenset(),
        )
