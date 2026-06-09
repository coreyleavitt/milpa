"""Host / target profile for conditional dep resolution (#26).

A Profile carries the values the resolver evaluates per-dep predicates
against: target platform, target arch, available Nim version, milpa's
own version. Profiles can be constructed from the host environment or
overridden via env vars for cross-resolution.
"""

import os
import platform as _stdlib_platform
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    """The target context that conditional dep predicates evaluate
    against. Single source of truth — no scattered globals."""
    platform: str          # e.g. "linux", "macosx", "windows"
    arch: str              # e.g. "amd64", "arm64", "i386"
    nim: str               # semver version of the target nim ("2.0.4")
    milpa: str             # semver version of milpa itself

    @classmethod
    def from_environment(
        cls,
        *,
        nim_version_query: Callable[[], str] | None = None,
        milpa_version: str | None = None,
    ) -> "Profile":
        """Detect the host profile.

        OS + arch normalized to Nim conventions; Nim version queried
        via the injected callable (defaults to `nim --version`).
        Env vars override individual fields:
            MILPA_TARGET_PLATFORM, MILPA_TARGET_ARCH, MILPA_TARGET_NIM,
            MILPA_TARGET_MILPA
        The `milpa` field defaults to this implementation's own version
        (milpa.__version__) when neither the env var nor an explicit
        `milpa_version` argument is supplied.
        """
        plat = os.environ.get("MILPA_TARGET_PLATFORM") or _detect_platform()
        arch = os.environ.get("MILPA_TARGET_ARCH") or _detect_arch()
        nim_v = os.environ.get("MILPA_TARGET_NIM")
        if nim_v is None:
            q = nim_version_query or _query_nim_version
            try:
                nim_v = q()
            except Exception:
                nim_v = "0.0.0"     # unknown; conditional deps on `nim` won't match
        milpa_v = (
            os.environ.get("MILPA_TARGET_MILPA")
            or milpa_version
            or _milpa_version()
        )
        return cls(platform=plat, arch=arch, nim=nim_v, milpa=milpa_v)


def _milpa_version() -> str:
    """This implementation's own version, for the `milpa` predicate.

    Reads `milpa.__version__` (the single source of truth, also surfaced
    by `milpa --version`). Falls back to "0.0.0" if it cannot be
    imported, so conditional deps gated on `milpa` simply won't match
    rather than crashing.
    """
    try:
        from . import __version__
        return __version__
    except Exception:
        return "0.0.0"


def _detect_platform() -> str:
    """Map Python platform.system() to Nim's `hostOS` vocabulary."""
    sys = _stdlib_platform.system().lower()
    return {
        "darwin": "macosx",
        "windows": "windows",
        "linux": "linux",
        "freebsd": "freebsd",
        "openbsd": "openbsd",
        "netbsd": "netbsd",
    }.get(sys, sys)


def _detect_arch() -> str:
    """Map Python platform.machine() to Nim's `hostCPU` vocabulary."""
    m = _stdlib_platform.machine().lower()
    return {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "i386": "i386",
        "i686": "i386",
    }.get(m, m)


def _query_nim_version() -> str:
    out = subprocess.run(
        ["nim", "--version"],
        capture_output=True, text=True, check=True,
    ).stdout
    m = re.search(r"Version (\d+\.\d+\.\d+)", out)
    if not m:
        raise RuntimeError(f"could not parse nim version from: {out!r}")
    return m.group(1)
