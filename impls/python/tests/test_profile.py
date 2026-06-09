"""Profile detection from host environment (#26)."""

import pytest

from milpa.profile import Profile


def test_profile_from_environment_uses_injected_nim_query(monkeypatch):
    """nim_version_query is injectable so we don't shell out in tests."""
    # Drop env overrides; should fall back to detection
    monkeypatch.delenv("MILPA_TARGET_PLATFORM", raising=False)
    monkeypatch.delenv("MILPA_TARGET_ARCH", raising=False)
    monkeypatch.delenv("MILPA_TARGET_NIM", raising=False)

    p = Profile.from_environment(nim_version_query=lambda: "2.0.4")
    # nim from injected query
    assert p.nim == "2.0.4"
    # platform + arch detected from stdlib — just check shape, not value
    assert isinstance(p.platform, str) and p.platform != ""
    assert isinstance(p.arch, str) and p.arch != ""


def test_profile_from_environment_tolerates_nim_query_failure(monkeypatch):
    """If `nim --version` errors (nim not installed), fall back to
    a sentinel rather than raising — conditional deps on `nim` will
    just not match."""
    monkeypatch.delenv("MILPA_TARGET_NIM", raising=False)

    def boom():
        raise FileNotFoundError("nim not found")

    p = Profile.from_environment(nim_version_query=boom)
    assert p.nim == "0.0.0"


def test_milpa_target_env_vars_override_detection(monkeypatch):
    """MILPA_TARGET_PLATFORM / ARCH / NIM override host detection —
    supports cross-resolution (`milpa fetch` targeting windows from linux)."""
    monkeypatch.setenv("MILPA_TARGET_PLATFORM", "windows")
    monkeypatch.setenv("MILPA_TARGET_ARCH", "arm64")
    monkeypatch.setenv("MILPA_TARGET_NIM", "1.6.20")

    # nim query MUST NOT be invoked when env is set
    def boom():
        raise AssertionError("nim_version_query must not run with env override")

    p = Profile.from_environment(nim_version_query=boom)
    assert p.platform == "windows"
    assert p.arch == "arm64"
    assert p.nim == "1.6.20"
