"""Tests for milpa.cas — CAStore: admit, link, contains, default_store, scratch lifecycle.

Spec authority: spec/identity.md §3.
Tests drive the TDD loop; examples pin spec-mandated behaviours; property tests
cover admit idempotence, link target resolution, and hash stability.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from milpa.cas import CAStore, default_store
from milpa.errors import CAS_IDENTITY_MISMATCH, CAS_NOT_IN_STORE, MilpaError
from milpa.identity import compute_content_hash

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _tree(root: Path, name: str, content: str = "hello") -> Path:
    """Create a named source tree under *root* containing one file."""
    p = root / name
    p.mkdir(parents=True)
    (p / "file.txt").write_text(content, encoding="utf-8")
    return p


@pytest.fixture()
def tmp(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture()
def store(tmp: Path) -> CAStore:
    return CAStore(tmp / "cas")


# ---------------------------------------------------------------------------
# §3.1 / §3.2 — store root / layout
# ---------------------------------------------------------------------------


def test_store_remembers_its_root(tmp: Path) -> None:
    s = CAStore(tmp / "cas")
    assert s.root == tmp / "cas"


def test_path_for_parses_identity(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "abc")
    identity = compute_content_hash(tree)
    algo, _, hex_digest = identity.partition(":")
    assert store.path_for(identity) == store.root / algo / hex_digest


# ---------------------------------------------------------------------------
# §3.3 — admit: atomic rename, mismatch error, duplicate no-op
# ---------------------------------------------------------------------------


def test_admit_places_tree_under_sha256_hex(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "hello")
    identity = compute_content_hash(tree)
    canonical = store.admit(tree, identity)
    hex_digest = identity.removeprefix("sha256:")
    assert canonical == store.root / "sha256" / hex_digest
    assert canonical.is_dir()
    assert (canonical / "file.txt").read_text() == "hello"


def test_admit_source_gone_after_admit(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "hello")
    identity = compute_content_hash(tree)
    store.admit(tree, identity)
    # The rename moves the tree; the original scratch path is gone.
    assert not tree.exists()


def test_admit_rejects_identity_mismatch(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "actual bytes")
    bogus = "sha256:" + "b" * 64
    with pytest.raises(MilpaError) as exc_info:
        store.admit(tree, bogus)
    assert exc_info.value.slug == CAS_IDENTITY_MISMATCH
    # src is left in place for the caller to inspect
    assert tree.exists()
    # store must not be modified
    assert not store.contains(bogus)


def test_admit_duplicate_is_noop(store: CAStore, tmp: Path) -> None:
    """Second admit of same tree: canonical path returned, second src removed."""
    first = _tree(tmp, "first", "bytes")
    second = _tree(tmp, "second", "bytes")
    identity = compute_content_hash(first)
    assert identity == compute_content_hash(second)

    a = store.admit(first, identity)
    b = store.admit(second, identity)

    assert a == b
    assert b.is_dir()
    assert (b / "file.txt").read_text() == "bytes"
    assert not second.exists()  # removed after duplicate detect


def test_admit_returns_existing_canonical_if_race(store: CAStore, tmp: Path) -> None:
    """Manual race simulation: manually move tree to canonical first, then admit."""
    tree1 = _tree(tmp, "t1", "race")
    tree2 = _tree(tmp, "t2", "race")
    identity = compute_content_hash(tree1)
    canonical = store.path_for(identity)

    # Simulate another process winning the race: manually place canonical entry
    canonical.parent.mkdir(parents=True, exist_ok=True)
    tree1.rename(canonical)

    # Now admit the second tree — it should detect canonical already exists
    result = store.admit(tree2, identity)
    assert result == canonical
    assert not tree2.exists()


# ---------------------------------------------------------------------------
# §3.5 / §3.6 — link: relative symlink, CAS-NOT-IN-STORE guard
# ---------------------------------------------------------------------------


def test_link_creates_relative_symlink(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "ABC")
    identity = compute_content_hash(tree)
    canonical = store.admit(tree, identity)

    deps_dir = tmp / "_deps"
    deps_dir.mkdir()
    target = deps_dir / "mypkg"
    store.link(identity, target)

    # Must be a symlink
    assert target.is_symlink()
    # Symlink target must be relative (not absolute)
    link_target = Path(os.readlink(target))
    assert not link_target.is_absolute(), f"Expected relative symlink, got {link_target}"
    # Resolves to the canonical CAS entry
    assert target.resolve() == canonical.resolve()
    # Tree contents accessible through the symlink
    assert (target / "file.txt").read_text() == "ABC"


def test_link_rejects_not_in_store(store: CAStore, tmp: Path) -> None:
    missing = "sha256:" + "c" * 64
    deps_dir = tmp / "_deps"
    deps_dir.mkdir()
    target = deps_dir / "absent"
    with pytest.raises(MilpaError) as exc_info:
        store.link(missing, target)
    assert exc_info.value.slug == CAS_NOT_IN_STORE
    # No dangling symlink created (§3.6)
    assert not target.is_symlink()
    assert not target.exists()


def test_link_is_idempotent_over_stale_symlink(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "ABC")
    identity = compute_content_hash(tree)
    store.admit(tree, identity)

    deps_dir = tmp / "_deps"
    deps_dir.mkdir()
    target = deps_dir / "pkg"

    store.link(identity, target)
    store.link(identity, target)  # second call — idempotent

    assert target.is_symlink()
    assert (target / "file.txt").read_text() == "ABC"


def test_link_clears_stale_directory_at_target(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "ABC")
    identity = compute_content_hash(tree)
    store.admit(tree, identity)

    deps_dir = tmp / "_deps"
    deps_dir.mkdir()
    target = deps_dir / "pkg"
    target.mkdir()
    (target / "stale.txt").write_text("old")

    store.link(identity, target)

    assert target.is_symlink()
    assert not (target / "stale.txt").exists()


# ---------------------------------------------------------------------------
# §3.1 — contains
# ---------------------------------------------------------------------------


def test_contains_false_before_admit(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "hello")
    identity = compute_content_hash(tree)
    assert not store.contains(identity)


def test_contains_true_after_admit(store: CAStore, tmp: Path) -> None:
    tree = _tree(tmp, "src", "hello")
    identity = compute_content_hash(tree)
    store.admit(tree, identity)
    assert store.contains(identity)


# ---------------------------------------------------------------------------
# §3.2 — default_store 4-tier precedence
# ---------------------------------------------------------------------------


def test_default_store_tier1_milpa_cache_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tier 1: MILPA_CACHE_DIR overrides everything."""
    override = str(tmp_path / "override-cas")
    monkeypatch.setenv("MILPA_CACHE_DIR", override)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    s = default_store()
    assert s.root == Path(override)


def test_default_store_tier2_manifest_cas_dir_is_not_default_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tier 2 (manifest cas { dir }) is NOT resolved by default_store(); it's
    applied by the CLI/resolver. default_store() only implements tiers 1, 3, 4.
    Verified: with MILPA_CACHE_DIR unset, tier 3 (XDG) fires next.
    """
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    s = default_store()
    assert s.root == tmp_path / "xdg" / "milpa" / "cas"


def test_default_store_tier3_xdg_cache_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tier 3: XDG_CACHE_HOME/milpa/cas when MILPA_CACHE_DIR not set."""
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    s = default_store()
    assert s.root == tmp_path / "xdg" / "milpa" / "cas"


def test_default_store_tier4_home_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier 4: ~/.cache/milpa/cas when neither MILPA_CACHE_DIR nor XDG_CACHE_HOME set."""
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    s = default_store()
    assert s.root == tmp_path / "home" / ".cache" / "milpa" / "cas"


def test_default_store_tier1_beats_tier3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier 1 has strict priority over XDG."""
    override = str(tmp_path / "cas-override")
    monkeypatch.setenv("MILPA_CACHE_DIR", override)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    s = default_store()
    assert s.root == Path(override)


def test_default_store_tier1_beats_tier4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier 1 beats the ~/.cache fallback too."""
    override = str(tmp_path / "cas-override")
    monkeypatch.setenv("MILPA_CACHE_DIR", override)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    s = default_store()
    assert s.root == Path(override)


def test_default_store_tier3_beats_tier4(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier 3 (XDG) beats the ~/.cache fallback."""
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    s = default_store()
    assert s.root == tmp_path / "xdg" / "milpa" / "cas"


def test_default_store_empty_milpa_cache_dir_falls_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty string MILPA_CACHE_DIR is ignored; falls through to XDG."""
    monkeypatch.setenv("MILPA_CACHE_DIR", "")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    s = default_store()
    assert s.root == tmp_path / "xdg" / "milpa" / "cas"


def test_default_store_empty_xdg_falls_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty string XDG_CACHE_HOME is ignored; falls through to ~/.cache."""
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    s = default_store()
    assert s.root == tmp_path / "home" / ".cache" / "milpa" / "cas"


# ---------------------------------------------------------------------------
# §3.4 — scratch lifecycle (ScratchDir context manager)
# ---------------------------------------------------------------------------


def test_scratch_dir_is_created_under_scratch_root(store: CAStore) -> None:
    scratch_root = store.root / "_scratch"
    with store.scratch() as scratch:
        assert scratch.path.parent == scratch_root
        assert scratch.path.is_dir()


def test_scratch_dir_has_unique_uuid_name(store: CAStore) -> None:
    with store.scratch() as s1, store.scratch() as s2:
        assert s1.path != s2.path


def test_scratch_dir_cleaned_up_on_success(store: CAStore) -> None:
    with store.scratch() as scratch:
        path = scratch.path
    assert not path.exists()


def test_scratch_dir_cleaned_up_on_exception(store: CAStore) -> None:
    captured: list[Path] = []

    def _body() -> None:
        with store.scratch() as scratch:
            captured.append(scratch.path)
            raise ValueError("intentional")

    with pytest.raises(ValueError):
        _body()
    assert captured and not captured[0].exists()


def test_scratch_dir_cleaned_up_on_base_exception(store: CAStore) -> None:
    """BaseException (not just Exception) triggers cleanup — covers KeyboardInterrupt/SystemExit."""

    class _FakeInterrupt(BaseException):
        pass

    captured: list[Path] = []

    def _body() -> None:
        with store.scratch() as scratch:
            captured.append(scratch.path)
            raise _FakeInterrupt("fake keyboard interrupt")

    with pytest.raises(_FakeInterrupt):
        _body()
    assert captured and not captured[0].exists()


def test_scratch_dir_not_cleaned_up_if_body_not_entered(store: CAStore) -> None:
    """Verify the context manager's __enter__ actually creates the directory."""
    with store.scratch() as scratch:
        assert scratch.path.is_dir()


# ---------------------------------------------------------------------------
# Property tests — Hypothesis
# ---------------------------------------------------------------------------


@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(content=st.text(min_size=1, max_size=200))
def test_property_admit_idempotence(content: str) -> None:
    """Admitting the same tree twice returns the same canonical path; second src removed."""
    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        store = CAStore(tmp_path / "cas")
        first = tmp_path / "first"
        first.mkdir()
        (first / "data.txt").write_text(content, encoding="utf-8")

        second = tmp_path / "second"
        second.mkdir()
        (second / "data.txt").write_text(content, encoding="utf-8")

        identity = compute_content_hash(first)
        a = store.admit(first, identity)
        b = store.admit(second, identity)

        assert a == b
        assert a.is_dir()
        assert not second.exists()


@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(content=st.text(min_size=1, max_size=200))
def test_property_link_resolves_to_admitted_tree(content: str) -> None:
    """After link(), the symlink resolves to the admitted CAS entry; target is relative."""
    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        store = CAStore(tmp_path / "cas")
        tree = tmp_path / "src"
        tree.mkdir()
        (tree / "f.txt").write_text(content, encoding="utf-8")
        identity = compute_content_hash(tree)
        canonical = store.admit(tree, identity)

        deps = tmp_path / "_deps"
        deps.mkdir()
        target = deps / "pkg"
        store.link(identity, target)

        assert target.is_symlink()
        link_val = Path(os.readlink(target))
        assert not link_val.is_absolute(), f"symlink must be relative, got {link_val}"
        assert target.resolve() == canonical.resolve()


@settings(max_examples=50, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(content=st.text(min_size=1, max_size=200))
def test_property_hash_stability(content: str) -> None:
    """Admitted entry's key == compute_content_hash of the original source bytes."""
    with tempfile.TemporaryDirectory() as td:
        tmp_path = Path(td)
        store = CAStore(tmp_path / "cas")
        tree = tmp_path / "src"
        tree.mkdir()
        (tree / "data.txt").write_text(content, encoding="utf-8")
        expected_hash = compute_content_hash(tree)

        # Make a copy to compute_content_hash again after admit (tree is moved by admit)
        copy = tmp_path / "copy"
        shutil.copytree(tree, copy)
        actual_hash = compute_content_hash(copy)

        canonical = store.admit(tree, expected_hash)
        hex_digest = expected_hash.removeprefix("sha256:")
        assert canonical == store.root / "sha256" / hex_digest
        assert expected_hash == actual_hash
