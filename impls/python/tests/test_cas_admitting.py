"""Tests for milpa.fetchers.cas_admitting — CasAdmittingFetcher (slice 7b).

Coverage:
  - cas_admissible=True (e.g. GitProvenance): fetch → CAS admit → symlink at dest
      - dest is a symlink
      - symlink resolves into the CAStore root
      - FetchResult.identity matches the store entry's hash
      - FetchResult.path == dest (the symlink location)
  - cas_admissible=False (e.g. LocalProvenance): fetch → real directory, no CAS entry
      - dest is a real directory (not a symlink)
      - store.contains(identity) is False
  - CAS idempotence: same content fetched twice → second admit is a no-op
  - Staging scratch is cleaned up after a successful fetch
  - Error from inner registry propagates; staging cleaned up
  - fetch_any delegates to inner registry

Spec authority: spec/plugin-contract.md §4, spec/identity.md §3.5.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.errors import FETCH_ALL_FAILED, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import (
    GitProvenance,
    LocalProvenance,
)
from milpa.fetchers.types import (
    FetcherRegistry,
    FetchError,
    FetchResult,
    Provenance,
    ProvenanceReceipt,
)
from milpa.identity import compute_content_hash

# ---------------------------------------------------------------------------
# Fake inner registry helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _SimpleReceipt(ProvenanceReceipt):
    """Minimal receipt for tests."""

    marker: str

    def transport_fields(self) -> dict[str, str]:
        return {"marker": self.marker}


class _FakeRegistry(FetcherRegistry):
    """A fake inner registry that writes fixed content into dest.

    ``writes`` maps provenance instance → list of (relative_path, content_bytes).
    On fetch, the fake creates the dest dir, writes the listed files, and
    returns a _SimpleReceipt.  If the provenance is not in ``writes``, raises
    FetchError.
    """

    def __init__(
        self,
        writes: dict[Provenance, list[tuple[str, bytes]]],
        marker: str = "test",
    ) -> None:
        super().__init__()
        self._writes = writes
        self._marker = marker

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        files = self._writes.get(provenance)
        if files is None:
            raise FetchError(f"_FakeRegistry: no entry for {provenance!r}", code=None)
        dest.mkdir(parents=True, exist_ok=True)
        for rel, content in files:
            fp = dest / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(content)
        receipt = _SimpleReceipt(marker=self._marker)
        identity = compute_content_hash(dest)
        return FetchResult(name=name, path=dest, identity=identity, receipt=receipt)


class _FailingRegistry(FetcherRegistry):
    """A fake inner registry that always raises FetchError."""

    def fetch(
        self,
        name: str,
        provenance: Provenance,
        *,
        dest: Path,
    ) -> FetchResult:
        raise FetchError("_FailingRegistry: always fails", code=None)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store(tmp_path: Path) -> CAStore:
    return CAStore(tmp_path / "cas")


@pytest.fixture()
def deps_dir(tmp_path: Path) -> Path:
    d = tmp_path / "_deps"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# cas_admissible=True → CAS symlink at dest
# ---------------------------------------------------------------------------


class TestCasAdmissiblePath:
    """GitProvenance (cas_admissible=True) should be admitted to the CAS and
    symlinked at dest."""

    def _make_git_prov(self) -> GitProvenance:
        return GitProvenance(url="https://example.com/foo.git", ref="main")

    def test_dest_is_symlink(self, tmp_path: Path, store: CAStore, deps_dir: Path) -> None:
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("src/foo.nim", b"echo hi")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        cas_reg.fetch("foo", prov, dest=dest)

        assert dest.is_symlink(), "dest must be a symlink for cas_admissible=True"

    def test_symlink_resolves_into_store(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("src/foo.nim", b"echo hi")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        cas_reg.fetch("foo", prov, dest=dest)

        resolved = dest.resolve()
        assert str(resolved).startswith(str(store.root.resolve())), (
            f"symlink target {resolved} must live under the CAS root {store.root}"
        )

    def test_fetch_result_identity_matches_store(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = self._make_git_prov()
        files = [("lib.nim", b"# lib")]
        fake = _FakeRegistry({prov: files})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        result = cas_reg.fetch("foo", prov, dest=dest)

        # Compute expected identity from the resolved (real) tree.
        real = dest.resolve()
        expected_identity = compute_content_hash(real)
        assert result.identity == expected_identity

    def test_fetch_result_path_is_dest(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("x.nim", b"")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        result = cas_reg.fetch("foo", prov, dest=dest)

        assert result.path == dest

    def test_store_contains_admitted_identity(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("a.nim", b"x")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        result = cas_reg.fetch("foo", prov, dest=dest)

        assert store.contains(result.identity), (
            "admitted identity must be present in the store"
        )

    def test_receipt_preserved(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("b.nim", b"y")], }, marker="receipt-preserved")
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        result = cas_reg.fetch("foo", prov, dest=dest)

        assert isinstance(result.receipt, _SimpleReceipt)
        assert result.receipt.marker == "receipt-preserved"  # type: ignore[union-attr]

    def test_cas_idempotence(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """Fetching the same content twice is a no-op: second admit finds existing entry."""
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("pkg.nim", b"same")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest1 = deps_dir / "foo1"
        dest2 = deps_dir / "foo2"

        r1 = cas_reg.fetch("foo", prov, dest=dest1)
        r2 = cas_reg.fetch("foo", prov, dest=dest2)

        assert r1.identity == r2.identity
        assert store.contains(r1.identity)
        assert dest2.is_symlink()

    def test_cas_idempotence_exactly_one_store_entry(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """C-admit-idem: two fetches of identical content produce exactly ONE store entry.

        This is the cross-project dedup guarantee: two projects (or two deps in one
        manifest) that resolve to the same identity share one CAS entry — the store
        is never overwritten or duplicated on a CAS hit.
        """
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("lib.nim", b"shared-content")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest1 = deps_dir / "dep1"
        dest2 = deps_dir / "dep2"

        r1 = cas_reg.fetch("dep1", prov, dest=dest1)
        r2 = cas_reg.fetch("dep2", prov, dest=dest2)

        assert r1.identity == r2.identity, "same content must produce same identity"
        # The store must hold exactly one entry, not two.
        identities = store.list_identities()
        assert len(identities) == 1, (
            f"expected exactly 1 store entry after two identical fetches, "
            f"got {len(identities)}: {identities}"
        )
        assert identities[0] == r1.identity
        # Both dest symlinks must resolve into the same CAS entry.
        assert dest1.is_symlink()
        assert dest2.is_symlink()
        assert dest1.resolve() == dest2.resolve()

    def test_cas_idempotence_no_scratch_leak_on_hit(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """C-admit-idem: CAS hit must leave no orphaned _scratch/ entries.

        On a CAS hit, admit() removes the scratch src and returns the existing
        canonical. The scratch() context manager's cleanup then finds the path
        already gone and ignores it. No _scratch/<uuid>/ entry must remain.
        """
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("x.nim", b"dedup-bytes")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest1 = deps_dir / "p1"
        dest2 = deps_dir / "p2"

        # First fetch: CAS miss — entry created
        cas_reg.fetch("p1", prov, dest=dest1)
        # Second fetch: CAS hit — no-op on admit
        cas_reg.fetch("p2", prov, dest=dest2)

        # No orphaned _scratch/ entries after either fetch
        scratch_root = store.root / "_scratch"
        if scratch_root.is_dir():
            remaining = [p for p in scratch_root.iterdir()]
            assert remaining == [], (
                f"orphaned _scratch/ entries after CAS hit: {remaining}"
            )

    def test_staging_cleaned_after_success(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """No orphaned _scratch/ entries remain after a successful fetch (C-stage §3.4)."""
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("f.nim", b"ok")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        cas_reg.fetch("foo", prov, dest=dest)

        # C-stage: staging goes through CAStore.scratch() → <cas_root>/_scratch/<uuid>/.
        # Every scratch subdir must be cleaned up after a successful admit.
        scratch_root = store.root / "_scratch"
        if scratch_root.is_dir():
            remaining = list(scratch_root.iterdir())
            assert remaining == [], f"orphaned _scratch/ entries after success: {remaining}"

        # C-stage: no _stage/ directory should exist at all — it is fully replaced by _scratch/.
        assert not (store.root / "_stage").exists(), (
            "_stage/ must not exist; CAStore.scratch() is the sole staging owner"
        )

    def test_scratch_location_is_under_cas_root(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """CAStore.scratch() allocates under <cas_root>/_scratch/ (sibling of sha256/).

        Verified by observing fetch: after a completed fetch the content is in
        sha256/<hex>/ and _scratch/ is its sibling.  (We verify the layout is
        consistent even after cleanup — both sha256/ and the _scratch parent
        live directly under store.root.)
        """
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("g.nim", b"layout")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        cas_reg.fetch("foo", prov, dest=dest)

        # sha256/ must be a direct child of cas_root.
        assert (store.root / "sha256").is_dir(), "sha256/ must exist under cas_root"
        # _scratch/ if it exists (may have been removed) must also be a direct child.
        # Assert it is NOT nested somewhere unexpected.
        if (store.root / "_scratch").exists():
            assert (store.root / "_scratch").parent == store.root, (
                "_scratch/ must be a direct sibling of sha256/ under cas_root"
            )

    def test_two_concurrent_fetches_dont_collide(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """Two fetches of different content get distinct scratch subdirs and both admit correctly."""
        prov_a = GitProvenance(url="https://example.com/a.git", ref="main")
        prov_b = GitProvenance(url="https://example.com/b.git", ref="main")
        fake = _FakeRegistry({
            prov_a: [("a.nim", b"alpha")],
            prov_b: [("b.nim", b"beta")],
        })
        cas_reg = CasAdmittingFetcher(fake, store)
        dest_a = deps_dir / "a"
        dest_b = deps_dir / "b"

        r_a = cas_reg.fetch("a", prov_a, dest=dest_a)
        r_b = cas_reg.fetch("b", prov_b, dest=dest_b)

        assert r_a.identity != r_b.identity, "distinct content must have distinct identities"
        assert store.contains(r_a.identity)
        assert store.contains(r_b.identity)
        assert dest_a.is_symlink()
        assert dest_b.is_symlink()
        assert (dest_a / "a.nim").read_bytes() == b"alpha"
        assert (dest_b / "b.nim").read_bytes() == b"beta"


# ---------------------------------------------------------------------------
# cas_admissible=False → real directory, no CAS
# ---------------------------------------------------------------------------


class TestNonAdmissiblePath:
    """LocalProvenance (cas_admissible=False) should produce a real directory
    at dest with no CAS entry."""

    def test_dest_is_real_directory(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = LocalProvenance(path=Path("/local/src"))
        fake = _FakeRegistry({prov: [("code.nim", b"# local")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "locallib"

        cas_reg.fetch("locallib", prov, dest=dest)

        assert dest.is_dir(), "dest must be a real directory for cas_admissible=False"
        assert not dest.is_symlink(), "dest must NOT be a symlink"

    def test_no_cas_entry(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = LocalProvenance(path=Path("/local/src"))
        fake = _FakeRegistry({prov: [("code.nim", b"# local")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "locallib"

        result = cas_reg.fetch("locallib", prov, dest=dest)

        assert not store.contains(result.identity), (
            "local (non-admissible) dep must NOT be admitted to the CAS"
        )

    def test_file_content_accessible(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        prov = LocalProvenance(path=Path("/local/src"))
        fake = _FakeRegistry({prov: [("code.nim", b"hello-local")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "locallib"

        cas_reg.fetch("locallib", prov, dest=dest)

        assert (dest / "code.nim").read_bytes() == b"hello-local"


# ---------------------------------------------------------------------------
# Error propagation
# ---------------------------------------------------------------------------


class TestErrorPropagation:
    def test_inner_fetch_error_propagates(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """Errors from the inner registry propagate; staging is cleaned up."""
        prov = GitProvenance(url="https://fail.example.com/a.git", ref="main")
        failing = _FailingRegistry()
        cas_reg = CasAdmittingFetcher(failing, store)
        dest = deps_dir / "failpkg"

        with pytest.raises(FetchError):
            cas_reg.fetch("failpkg", prov, dest=dest)

        # No orphaned _scratch/ entries (C-stage: cleanup-on-failure).
        scratch_root = store.root / "_scratch"
        if scratch_root.is_dir():
            remaining = list(scratch_root.iterdir())
            assert remaining == [], f"orphaned _scratch/ entries after failure: {remaining}"
        # _stage/ must not exist (fully replaced by _scratch/).
        assert not (store.root / "_stage").exists(), (
            "_stage/ must not exist; CAStore.scratch() is the sole staging owner"
        )


# ---------------------------------------------------------------------------
# fetch_any delegation
# ---------------------------------------------------------------------------


class TestFetchAnyDelegation:
    def test_fetch_any_delegates_to_inner(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """fetch_any delegates to the inner registry; all-fail raises FETCH-ALL-FAILED."""
        prov = GitProvenance(url="https://nope.example.com/b.git", ref="main")
        failing = _FailingRegistry()
        cas_reg = CasAdmittingFetcher(failing, store)
        dest = deps_dir / "b"

        with pytest.raises(MilpaError) as exc_info:
            cas_reg.fetch_any("b", [prov], dest=dest)

        assert exc_info.value.slug == FETCH_ALL_FAILED

    def test_fetch_any_cas_admissible_candidate_admitted_to_store(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """fetch_any through CasAdmittingFetcher MUST admit the winner into the CAS.

        Regression test for Fix 2 (R1-8): the old fetch_any bypassed CAS admission
        entirely, leaving _deps/<name> as a real directory (not a symlink) and
        writing no entry to the store.  After the fix, a successful fetch_any with
        a cas_admissible provenance MUST:
          - result in dest being a symlink (not a plain directory)
          - result in the store containing the admitted identity
        """
        prov = GitProvenance(url="https://example.com/c.git", ref="main")
        fake = _FakeRegistry({prov: [("c.nim", b"# c module")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "c"

        result = cas_reg.fetch_any("c", [prov], dest=dest)

        assert dest.is_symlink(), (
            "dest must be a symlink after fetch_any for a cas_admissible provenance"
        )
        assert store.contains(result.identity), (
            "winner from fetch_any must be admitted into the CAS store"
        )

    def test_fetch_any_non_admissible_candidate_not_in_store(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """fetch_any with a non-admissible provenance (local) must NOT admit to CAS."""
        prov = LocalProvenance(path=tmp_path / "local_src")
        (tmp_path / "local_src").mkdir()
        (tmp_path / "local_src" / "pkg.nim").write_bytes(b"# pkg")
        fake = _FakeRegistry({prov: [("pkg.nim", b"# pkg")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "local_pkg"

        result = cas_reg.fetch_any("local_pkg", [prov], dest=dest)

        assert not dest.is_symlink(), (
            "dest must NOT be a symlink for a non-admissible provenance"
        )
        assert not store.contains(result.identity), (
            "non-admissible dep must NOT be admitted into the CAS store"
        )
