"""Tests for `milpa store ls` and `milpa store path` — C-store-ro slice (Phase C).

TDD: these tests were written BEFORE the implementation; they drive the
RED→GREEN loop.

Spec authority: spec/identity.md §3 — <root>/<algorithm>/<64hex>/.
Error codes: STORE-AMBIGUOUS-PREFIX, CAS-NOT-IN-STORE.

All tests point MILPA_CACHE_DIR at a per-test tmp directory so they never
touch the real host store.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store_entry(store_root: Path, hex64: str, algo: str = "dag-sha256") -> Path:
    """Create a bare CAS-layout directory for a given 64-hex digest.

    This bypasses content-hashing intentionally: the store-ls / store-path
    subcommands are READ-ONLY and only inspect directory names.  Constructing
    entries with controlled hex names is the standard technique for testing
    prefix matching without needing real content that hashes to a chosen value.
    """
    entry = store_root / algo / hex64
    entry.mkdir(parents=True, exist_ok=True)
    # Place a sentinel file so the directory is non-empty (mirrors a real admit).
    (entry / "dummy.nim").write_text("# test sentinel\n", encoding="utf-8")
    return entry


def _run_store(args: list[str], store_root: Path) -> subprocess.CompletedProcess:
    """Run `milpa store <args>` with MILPA_CACHE_DIR pointing at store_root."""
    import os

    env = os.environ.copy()
    env["MILPA_CACHE_DIR"] = str(store_root)
    # Suppress the real index to keep tests fully offline.
    env["MILPA_INDEX_URL"] = ""

    return subprocess.run(
        [sys.executable, "-m", "milpa", "store"] + args,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# Behaviour 1 — store ls: two entries → lex-sorted output
# ---------------------------------------------------------------------------


def test_store_ls_two_entries_sorted(tmp_path: Path) -> None:
    """store ls with 2 admitted entries prints both identities, lex-sorted."""
    store_root = tmp_path / "cas"
    hex_a = "a" * 64
    hex_b = "b" * 64
    _make_store_entry(store_root, hex_b)  # admitted out-of-order intentionally
    _make_store_entry(store_root, hex_a)

    result = _run_store(["ls"], store_root)

    assert result.returncode == 0, f"stderr: {result.stderr}"
    lines = result.stdout.strip().splitlines()
    assert lines == [f"dag-sha256:{hex_a}", f"dag-sha256:{hex_b}"], (
        f"Expected lex-sorted identities, got: {lines!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 2 — store ls: empty store → no output, exit 0
# ---------------------------------------------------------------------------


def test_store_ls_empty_store(tmp_path: Path) -> None:
    """store ls on an empty store produces no output and exits 0."""
    store_root = tmp_path / "cas"
    store_root.mkdir(parents=True, exist_ok=True)

    result = _run_store(["ls"], store_root)

    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert result.stdout == "", f"Expected empty stdout, got: {result.stdout!r}"


# ---------------------------------------------------------------------------
# Behaviour 3 — store path: full identity present → absolute path, exit 0
# ---------------------------------------------------------------------------


def test_store_path_full_identity_present(tmp_path: Path) -> None:
    """store path with a full identity returns the absolute path, exit 0."""
    store_root = tmp_path / "cas"
    hex64 = "c" * 64
    entry = _make_store_entry(store_root, hex64)
    identity = f"dag-sha256:{hex64}"

    result = _run_store(["path", identity], store_root)

    assert result.returncode == 0, f"stderr: {result.stderr}"
    reported = result.stdout.strip()
    assert reported == str(entry), (
        f"Expected {entry!r}, got {reported!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 4 — store path: full identity absent → CAS-NOT-IN-STORE, exit 1
# ---------------------------------------------------------------------------


def test_store_path_full_identity_absent(tmp_path: Path) -> None:
    """store path with absent full identity → CAS-NOT-IN-STORE, exit 1."""
    store_root = tmp_path / "cas"
    store_root.mkdir(parents=True, exist_ok=True)
    identity = "dag-sha256:" + "d" * 64

    result = _run_store(["path", identity], store_root)

    assert result.returncode == 1, f"stdout: {result.stdout}"
    assert "milpa-error: CAS-NOT-IN-STORE" in result.stderr, (
        f"Expected CAS-NOT-IN-STORE in stderr: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 5 — store path: ≥16-char unique prefix → resolves to entry path
# ---------------------------------------------------------------------------


def test_store_path_unique_prefix(tmp_path: Path) -> None:
    """store path with a ≥16-char unique prefix resolves to the entry's path."""
    store_root = tmp_path / "cas"
    # Two entries that share only the first 8 hex chars; our prefix (16 chars)
    # uniquely identifies hex_a.
    hex_a = "aaaa1111" + "0" * 56  # first 8 = "aaaa1111", positions 8-15 = "00000000"
    hex_b = "aaaa1111" + "1" * 56  # first 8 = "aaaa1111", positions 8-15 = "11111111"
    entry_a = _make_store_entry(store_root, hex_a)
    _make_store_entry(store_root, hex_b)

    # Prefix that matches only hex_a (first 16 chars are "aaaa111100000000")
    prefix = "dag-sha256:" + hex_a[:16]

    result = _run_store(["path", prefix], store_root)

    assert result.returncode == 0, f"stderr: {result.stderr}"
    reported = result.stdout.strip()
    assert reported == str(entry_a), (
        f"Expected {entry_a!r}, got {reported!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 6 — store path: prefix matching 2 entries → STORE-AMBIGUOUS-PREFIX
# ---------------------------------------------------------------------------


def test_store_path_ambiguous_prefix(tmp_path: Path) -> None:
    """store path with prefix matching >1 entry → STORE-AMBIGUOUS-PREFIX, exit 1."""
    store_root = tmp_path / "cas"
    # Two entries sharing the same 32-char prefix; a 16-char prefix hits both.
    shared = "abcdef1234567890" * 2  # 32 chars shared
    hex_a = shared + "a" * 32
    hex_b = shared + "b" * 32
    _make_store_entry(store_root, hex_a)
    _make_store_entry(store_root, hex_b)

    prefix = "dag-sha256:" + shared[:16]  # 16 chars → matches both

    result = _run_store(["path", prefix], store_root)

    assert result.returncode == 1, f"stdout: {result.stdout}"
    assert "milpa-error: STORE-AMBIGUOUS-PREFIX" in result.stderr, (
        f"Expected STORE-AMBIGUOUS-PREFIX in stderr: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 7 — store path: prefix < 16 chars → STORE-AMBIGUOUS-PREFIX (too short)
# ---------------------------------------------------------------------------


def test_store_path_prefix_too_short(tmp_path: Path) -> None:
    """store path with a prefix shorter than 16 hex chars → STORE-AMBIGUOUS-PREFIX."""
    store_root = tmp_path / "cas"
    hex64 = "e" * 64
    _make_store_entry(store_root, hex64)

    # 15 hex chars — below the 16-char minimum
    prefix = "dag-sha256:" + "e" * 15

    result = _run_store(["path", prefix], store_root)

    assert result.returncode == 1, f"stdout: {result.stdout}"
    assert "milpa-error: STORE-AMBIGUOUS-PREFIX" in result.stderr, (
        f"Expected STORE-AMBIGUOUS-PREFIX in stderr (too-short prefix): {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 8 — store path: bare 64-hex (no dag-sha256: prefix) is accepted
# ---------------------------------------------------------------------------


def test_store_path_bare_64hex_accepted(tmp_path: Path) -> None:
    """store path accepts bare 64-hex identity (no algorithm prefix)."""
    store_root = tmp_path / "cas"
    hex64 = "f" * 64
    entry = _make_store_entry(store_root, hex64)

    result = _run_store(["path", hex64], store_root)

    assert result.returncode == 0, f"stderr: {result.stderr}"
    reported = result.stdout.strip()
    assert reported == str(entry), (
        f"Expected {entry!r}, got {reported!r}"
    )


# ---------------------------------------------------------------------------
# Behaviour 9 — store path: bare ≥16-char prefix (no algorithm prefix) is accepted
# ---------------------------------------------------------------------------


def test_store_path_bare_prefix_accepted(tmp_path: Path) -> None:
    """store path accepts a bare hex prefix (no algorithm prefix) ≥16 chars."""
    store_root = tmp_path / "cas"
    hex64 = "1234567890abcdef" + "0" * 48  # unique 16-char prefix
    entry = _make_store_entry(store_root, hex64)

    prefix = hex64[:16]  # bare, 16 hex chars

    result = _run_store(["path", prefix], store_root)

    assert result.returncode == 0, f"stderr: {result.stderr}"
    reported = result.stdout.strip()
    assert reported == str(entry), (
        f"Expected {entry!r}, got {reported!r}"
    )
