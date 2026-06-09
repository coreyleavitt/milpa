"""Global content-addressed store (#35).

CAStore is the on-disk realization of milpa's identity model: bytes are
indexed by their content hash, materialized exactly once per host, and
shared across every project that references them via symlinks from
_deps/<name>/.

See docs/rfc-content-addressed-identity.md Phase C and
docs/rfc-toolchain-content-addressing.md.
"""

from pathlib import Path

import pytest

from milpa.cas import CAStore, CASError, default_store
from milpa.identity import compute_content_hash


def _scratch_tree(root: Path, name: str = "scratch", content: str = "hello") -> Path:
    """Build a small directory tree at root/name and return its path."""
    p = root / name
    p.mkdir(parents=True)
    (p / "file.txt").write_text(content)
    return p


def test_admit_places_tree_under_sha256_hex(tmp_path):
    """Tracer: admit(scratch, identity) materializes the tree at
    <root>/sha256/<hex>/ and returns that canonical path."""
    store = CAStore(root=tmp_path / "cas")
    scratch = _scratch_tree(tmp_path)
    identity = compute_content_hash(scratch)

    canonical = store.admit(scratch, identity)

    hex_digest = identity.split(":", 1)[1]
    assert canonical == tmp_path / "cas" / "sha256" / hex_digest
    assert canonical.is_dir()
    assert (canonical / "file.txt").read_text() == "hello"


def test_contains_reflects_admit_state(tmp_path):
    """contains(identity) is False before admit, True after."""
    store = CAStore(root=tmp_path / "cas")
    scratch = _scratch_tree(tmp_path)
    identity = compute_content_hash(scratch)

    assert store.contains(identity) is False
    store.admit(scratch, identity)
    assert store.contains(identity) is True


def test_duplicate_admit_is_idempotent_and_drops_second_src(tmp_path):
    """A second admit for the same identity returns the same canonical
    path; the second scratch is removed from disk (no leftover)."""
    store = CAStore(root=tmp_path / "cas")
    first = _scratch_tree(tmp_path, "first", content="bytes")
    second = _scratch_tree(tmp_path, "second", content="bytes")
    identity = compute_content_hash(first)
    # Sanity: same contents → same hash
    assert identity == compute_content_hash(second)

    canonical_a = store.admit(first, identity)
    canonical_b = store.admit(second, identity)

    assert canonical_a == canonical_b
    assert canonical_b.is_dir()
    assert (canonical_b / "file.txt").read_text() == "bytes"
    # Second scratch was cleaned up
    assert not second.exists()


def test_admit_rejects_src_whose_bytes_dont_match_claimed_identity(tmp_path):
    """Structural assertion: admit hashes src and refuses if the
    computed identity disagrees with the claimed one. Defends against
    bugs where a stale identity is passed in."""
    store = CAStore(root=tmp_path / "cas")
    scratch = _scratch_tree(tmp_path, content="actual contents")
    bogus_identity = f"sha256:{'b' * 64}"

    with pytest.raises(CASError) as exc:
        store.admit(scratch, bogus_identity)

    msg = str(exc.value).lower()
    assert "identity" in msg or "hash" in msg
    # Scratch is left untouched for the caller to inspect / clean up
    assert scratch.exists()
    # Store was not polluted
    assert not store.contains(bogus_identity)


def test_link_creates_symlink_resolving_to_cas_entry(tmp_path):
    """link(identity, target) writes a symlink at target whose contents
    are the CAS entry."""
    store = CAStore(root=tmp_path / "cas")
    scratch = _scratch_tree(tmp_path, content="ABC")
    identity = compute_content_hash(scratch)
    canonical = store.admit(scratch, identity)

    target = tmp_path / "_deps" / "foo"
    target.parent.mkdir(parents=True)
    store.link(identity, target)

    assert target.is_symlink()
    assert target.resolve() == canonical.resolve()
    # Following the symlink, the tree is visible
    assert (target / "file.txt").read_text() == "ABC"


def test_link_uses_relative_target_for_portability(tmp_path):
    """Symlink target is a path *relative* to the symlink's directory,
    not an absolute host path. Reason: portability under bind-mounts —
    a project's _deps/<name> symlink should resolve identically whether
    the project tree is at /home/foo/projects/x on the host or /work
    inside a container (with only the project tree mounted).

    Containerized builds were repeatedly broken when symlinks pointed
    at absolute host paths the container couldn't see.
    """
    import os
    store = CAStore(root=tmp_path / ".milpa" / "cas")
    scratch = _scratch_tree(tmp_path, content="ABC")
    identity = compute_content_hash(scratch)
    store.admit(scratch, identity)

    target = tmp_path / "_deps" / "foo"
    target.parent.mkdir(parents=True)
    store.link(identity, target)

    # The link's stored target string is relative — does NOT start with /
    link_target = os.readlink(target)
    assert not os.path.isabs(link_target), (
        f"expected relative symlink target; got {link_target!r}"
    )
    # The relative target still resolves to the CAS entry from the
    # symlink's location.
    assert target.resolve() == store.path_for(identity).resolve()


def test_default_store_honors_milpa_cache_dir(tmp_path, monkeypatch):
    """MILPA_CACHE_DIR wins over everything."""
    monkeypatch.setenv("MILPA_CACHE_DIR", str(tmp_path / "override"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    store = default_store()
    assert store.root == tmp_path / "override"


def test_default_store_falls_back_to_xdg_cache_home(tmp_path, monkeypatch):
    """Without MILPA_CACHE_DIR, XDG_CACHE_HOME/milpa/cas is used."""
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    store = default_store()
    assert store.root == tmp_path / "xdg" / "milpa" / "cas"


def test_default_store_falls_back_to_home_cache(tmp_path, monkeypatch):
    """With neither env var set, ~/.cache/milpa/cas is used."""
    monkeypatch.delenv("MILPA_CACHE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    store = default_store()
    assert store.root == tmp_path / "home" / ".cache" / "milpa" / "cas"


# ---------------------------------------------------------------------------
# Integration with FetcherRegistry
# ---------------------------------------------------------------------------


def test_fetcher_registry_routes_through_cas_and_symlinks_dest(tmp_path):
    """When a CAStore is attached, FetcherRegistry.fetch:
      - lands the bytes in the CAS under their identity
      - makes `dest` a symlink resolving to the CAS entry
    A second fetch of identical bytes (different name) ends up linked
    to the same CAS entry — no second materialization on disk.
    """
    from dataclasses import dataclass

    from milpa.fetchers import (
        FetcherRegistry,
        Provenance,
        ProvenanceReceipt,
    )

    @dataclass(frozen=True)
    class StubProvenance(Provenance):
        payload: str

    @dataclass(frozen=True)
    class StubReceipt(ProvenanceReceipt):
        marker: str

        def transport_fields(self) -> dict[str, str]:
            return {"marker": self.marker}

    class StubFetcher:
        def can_handle(self, p): return isinstance(p, StubProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "file.txt").write_text(p.payload)
            return StubReceipt(marker=name)

    store = CAStore(root=tmp_path / "cas")
    registry = FetcherRegistry(store=store)
    registry.register(StubFetcher())

    deps_dir = tmp_path / "_deps"
    deps_dir.mkdir()

    result_a = registry.fetch(
        "alpha", StubProvenance(payload="ABC"), dest=deps_dir / "alpha",
    )
    result_b = registry.fetch(
        "beta", StubProvenance(payload="ABC"), dest=deps_dir / "beta",
    )

    # Both ended up with the same identity (same bytes)
    assert result_a.identity == result_b.identity
    # Both _deps/ entries are symlinks to the CAS
    assert (deps_dir / "alpha").is_symlink()
    assert (deps_dir / "beta").is_symlink()
    # Resolving each follows to the canonical CAS entry
    canonical = store.path_for(result_a.identity)
    assert (deps_dir / "alpha").resolve() == canonical.resolve()
    assert (deps_dir / "beta").resolve() == canonical.resolve()
    # Contents visible through the symlink
    assert (deps_dir / "alpha" / "file.txt").read_text() == "ABC"


def test_cas_admissible_false_provenances_bypass_the_store(tmp_path):
    """Provenance subclasses that mark themselves cas_admissible=False
    (local deps, workspace members) are NOT admitted to the store.
    Their bytes land directly at dest — edits to the user's tree stay
    visible."""
    from dataclasses import dataclass

    from milpa.fetchers import (
        FetcherRegistry,
        Provenance,
        ProvenanceReceipt,
    )

    @dataclass(frozen=True)
    class EditableProvenance(Provenance):
        cas_admissible = False

    @dataclass(frozen=True)
    class EditableReceipt(ProvenanceReceipt):
        def transport_fields(self) -> dict[str, str]:
            return {"kind": "editable"}

    class EditableFetcher:
        def can_handle(self, p): return isinstance(p, EditableProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "file.txt").write_text("editable")
            return EditableReceipt()

    store = CAStore(root=tmp_path / "cas")
    registry = FetcherRegistry(store=store)
    registry.register(EditableFetcher())

    dest = tmp_path / "_deps" / "x"
    result = registry.fetch("x", EditableProvenance(), dest=dest)

    # Wrote directly to dest (no symlink)
    assert not dest.is_symlink()
    assert dest.is_dir()
    assert (dest / "file.txt").read_text() == "editable"
    # CAS stays empty for this identity
    assert not store.contains(result.identity)
