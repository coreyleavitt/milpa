"""Profile data types — runtime resolution context.

DATA TYPES ONLY.  No predicate evaluation, no subprocess, no I/O.

``Profile.from_environment`` takes the Nim version as an injected string
(default ``"0.0.0"``); it NEVER spawns ``nim --version``.  The subprocess
that queries the live Nim version lives in ``cli.py`` and is passed in.

Predicate evaluation (``filter_manifest``) is a resolver step (Stage 9),
run before the solver input is built.  This module represents predicates
as data only.

RFC §4.2 boundary criteria:
  - No imports from ``manifest.py``, ``solver.py``, or any I/O layer.
  - Importable in tests without a Nim toolchain present.
  - ``Profile.from_environment`` reads env vars ``MILPA_TARGET_*``
    (§6.6) in exactly one place.
"""

from __future__ import annotations

import os
import platform as _platform
from dataclasses import dataclass

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
      platform: Nim ``hostOS`` token (e.g. ``"linux"``, ``"macosx"``), or
                ``None`` when the axis is absent (partial profile).
      arch:     Nim ``hostCPU`` token (e.g. ``"amd64"``, ``"arm64"``), or
                ``None`` when the axis is absent.
      nim:      Nim version string (e.g. ``"2.0.0"``), or ``None``.
                Injected, never queried via subprocess here.
      milpa:    milpa version string, or ``None``.  Overridable via
                ``MILPA_TARGET_MILPA`` env var.

    An absent axis (``None``) means every predicate over that axis evaluates
    to ``false`` regardless of negation (§3.C / §6 resolver-semantics).
    This is distinct from an absent *whole* profile (``None`` where a
    ``Profile`` is expected), which disables non-flag filtering entirely.

    Construction:
      - ``Profile.partial(...)`` — explicit partial constructor; axes not
        provided are ``None``; no env-var coupling. Use for resolver unit
        tests and the conformance runner.
      - ``Profile.from_environment(...)`` — CLI path; reads ``MILPA_TARGET_*``
        env vars and host-defaults every absent axis (``cli-contract §8``).
    """

    platform: str | None
    arch: str | None
    nim: str | None
    milpa: str | None

    @classmethod
    def partial(
        cls,
        *,
        platform: str | None = None,
        arch: str | None = None,
        nim: str | None = None,
        milpa: str | None = None,
    ) -> "Profile":
        """Explicit partial constructor — any axis not provided is ``None``.

        No env-var coupling.  Use this for:
          - Resolver *behavior* unit tests (use ``Profile.partial(...)``).
          - The conformance runner building a profile from ``MILPA_TARGET_*``
            reads (where only the axes present in the ``env`` file are set).

        Reserve ``from_environment()`` for tests explicitly about host-default
        behavior.
        """
        return cls(
            platform=platform,
            arch=arch,
            nim=nim,
            milpa=milpa,
        )

    @classmethod
    def from_environment(
        cls,
        *,
        nim_version: str | None = None,
        milpa_version: str = "0.0.0",
    ) -> "Profile":
        """Construct a ``Profile`` from the current environment.

        ``nim_version`` is an injected string (default ``"0.0.0"``).
        The subprocess that queries ``nim --version`` lives in
        ``cli.py`` — never here.

        Host-defaults every absent axis (``cli-contract §8``):
          - ``MILPA_TARGET_PLATFORM``  → ``platform`` (fallback: host OS)
          - ``MILPA_TARGET_ARCH``      → ``arch``     (fallback: host arch)
          - ``MILPA_TARGET_NIM``       → ``nim``      (fallback: ``nim_version``
                                                       or ``"0.0.0"``)
          - ``MILPA_TARGET_MILPA``     → ``milpa``    (fallback: ``milpa_version``)
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
        )
