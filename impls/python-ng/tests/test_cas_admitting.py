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

    def test_staging_cleaned_after_success(
        self, tmp_path: Path, store: CAStore, deps_dir: Path
    ) -> None:
        """No orphaned _stage/ entries remain after a successful fetch."""
        prov = self._make_git_prov()
        fake = _FakeRegistry({prov: [("f.nim", b"ok")]})
        cas_reg = CasAdmittingFetcher(fake, store)
        dest = deps_dir / "foo"

        cas_reg.fetch("foo", prov, dest=dest)

        stage_root = store.root / "_stage"
        if stage_root.is_dir():
            staged = list(stage_root.iterdir())
            assert staged == [], f"orphaned staging entries: {staged}"


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

        # No orphaned staging entries.
        stage_root = store.root / "_stage"
        if stage_root.is_dir():
            staged = list(stage_root.iterdir())
            assert staged == [], f"orphaned staging entries after failure: {staged}"


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
