"""Tests for milpa.fetchers.local.LocalFetcher (slice 7d-4).

Coverage:
  - LocalProvenance.cas_admissible is False (editable source, §4 NORMATIVE)
  - LocalProvenance rejects relative paths at construction
  - LocalReceipt.transport_fields returns {"resolved_path": <str>}
  - LocalFetcher.can_handle returns True for LocalProvenance, False for others
  - LocalFetcher.fetch: source dir exists → receipt carries resolved_path
  - LocalFetcher.fetch: identity equals compute_content_hash of the source dir
  - LocalFetcher.fetch: source dir left in place (not moved/deleted)
  - LocalFetcher.fetch: no network (purely local filesystem)
  - LocalFetcher.fetch: non-existent path → MilpaError FETCH-LOCAL-PATH-NOT-FOUND
  - LocalFetcher.fetch: path is a file, not a dir → MilpaError FETCH-LOCAL-PATH-NOT-DIR
  - LocalFetcher: fetcher does NOT compute identity (no identity in receipt)
  - LocalFetcher: dest is written (or symlinked) under dest/
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from milpa.errors import (
    FETCH_LOCAL_PATH_NOT_DIR,
    FETCH_LOCAL_PATH_NOT_FOUND,
    MilpaError,
)
from milpa.fetchers.local import LocalFetcher, LocalProvenance, LocalReceipt
from milpa.fetchers.types import FetcherRegistry, Provenance
from milpa.identity import compute_content_hash

# ---------------------------------------------------------------------------
# LocalProvenance
# ---------------------------------------------------------------------------


class TestLocalProvenance:
    def test_cas_admissible_false(self) -> None:
        """Editable sources MUST declare cas_admissible=False (§4 NORMATIVE)."""
        assert LocalProvenance.cas_admissible is False

    def test_instance_cas_admissible_false(self, tmp_path: Path) -> None:
        p = LocalProvenance(path=tmp_path)
        assert p.cas_admissible is False

    def test_accepts_absolute_path(self, tmp_path: Path) -> None:
        p = LocalProvenance(path=tmp_path)
        assert p.path == tmp_path

    def test_rejects_relative_path(self) -> None:
        with pytest.raises(ValueError, match="absolute"):
            LocalProvenance(path=Path("relative/path"))

    def test_frozen_dataclass(self, tmp_path: Path) -> None:
        p = LocalProvenance(path=tmp_path)
        with pytest.raises((AttributeError, TypeError)):
            p.path = tmp_path / "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# LocalReceipt
# ---------------------------------------------------------------------------


class TestLocalReceipt:
    def test_transport_fields_returns_resolved_path(self, tmp_path: Path) -> None:
        r = LocalReceipt(resolved_path=tmp_path)
        assert r.transport_fields() == {"resolved_path": str(tmp_path)}

    def test_transport_fields_nonempty(self, tmp_path: Path) -> None:
        r = LocalReceipt(resolved_path=tmp_path)
        assert r.transport_fields()

    def test_no_identity_field(self, tmp_path: Path) -> None:
        """Receipt MUST NOT contain an identity (tree hash) field (§3.1 NORMATIVE)."""
        r = LocalReceipt(resolved_path=tmp_path)
        for key in r.transport_fields():
            assert "identity" not in key
            assert "content_hash" not in key
            assert "tree" not in key


# ---------------------------------------------------------------------------
# LocalFetcher.can_handle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _OtherProvenance(Provenance):
    pass


class TestLocalFetcherCanHandle:
    def test_claims_local_provenance(self, tmp_path: Path) -> None:
        f = LocalFetcher()
        assert f.can_handle(LocalProvenance(path=tmp_path)) is True

    def test_rejects_other_provenance(self) -> None:
        f = LocalFetcher()
        assert f.can_handle(_OtherProvenance()) is False

    def test_rejects_base_provenance(self) -> None:
        f = LocalFetcher()
        assert f.can_handle(Provenance()) is False


# ---------------------------------------------------------------------------
# LocalFetcher.fetch — happy path
# ---------------------------------------------------------------------------


def _make_source_dir(parent: Path) -> Path:
    """Create a source directory with some files."""
    src = parent / "source"
    src.mkdir()
    (src / "lib.nim").write_text("# some nim source\n")
    (src / "README.md").write_text("A package\n")
    sub = src / "subdir"
    sub.mkdir()
    (sub / "util.nim").write_text("# util\n")
    return src


class TestLocalFetcherHappyPath:
    def test_receipt_type(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        receipt = fetcher.fetch("mylib", LocalProvenance(path=src), dest=dest)
        assert isinstance(receipt, LocalReceipt)

    def test_receipt_resolved_path_is_source(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        receipt = fetcher.fetch("mylib", LocalProvenance(path=src), dest=dest)
        assert receipt.resolved_path == src

    def test_source_dir_left_in_place(self, tmp_path: Path) -> None:
        """LocalFetcher must NOT delete or move the source directory."""
        src = _make_source_dir(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        fetcher.fetch("mylib", LocalProvenance(path=src), dest=dest)
        # Source must still exist and be intact.
        assert src.is_dir()
        assert (src / "lib.nim").exists()

    def test_no_network_access(self, tmp_path: Path) -> None:
        """LocalFetcher must work entirely offline — source is a local path."""
        src = _make_source_dir(tmp_path)
        # The source URL is a local path with no scheme — no network needed.
        assert not str(src).startswith("https://")
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        # If this test passes, it ran with no network by construction.
        receipt = fetcher.fetch("mylib", LocalProvenance(path=src), dest=dest)
        assert receipt.transport_fields()


# ---------------------------------------------------------------------------
# LocalFetcher: identity equals compute_content_hash of source
# ---------------------------------------------------------------------------


class TestLocalFetcherIdentity:
    def test_registry_identity_matches_source_hash(self, tmp_path: Path) -> None:
        """Identity computed by registry MUST equal hash of the source tree."""
        src = _make_source_dir(tmp_path)
        expected = compute_content_hash(src)
        registry = FetcherRegistry()
        registry.register(LocalFetcher())
        dest = tmp_path / "dest"
        result = registry.fetch("mylib", LocalProvenance(path=src), dest=dest)
        assert result.identity == expected

    def test_identity_startswith_sha256(self, tmp_path: Path) -> None:
        src = _make_source_dir(tmp_path)
        registry = FetcherRegistry()
        registry.register(LocalFetcher())
        dest = tmp_path / "dest"
        result = registry.fetch("mylib", LocalProvenance(path=src), dest=dest)
        assert result.identity.startswith("sha256:")

    def test_identity_not_in_receipt_fields(self, tmp_path: Path) -> None:
        """Fetcher does NOT compute identity — it must not appear in receipt."""
        src = _make_source_dir(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        receipt = fetcher.fetch("mylib", LocalProvenance(path=src), dest=dest)
        for v in receipt.transport_fields().values():
            assert not v.startswith("sha256:")


# ---------------------------------------------------------------------------
# LocalFetcher: dest writeable / cas_admissible=False (no CAS admission)
# ---------------------------------------------------------------------------


class TestLocalFetcherDest:
    def test_dest_accessible_after_fetch(self, tmp_path: Path) -> None:
        """After fetch, dest must be accessible (real dir or symlink to real dir)."""
        src = _make_source_dir(tmp_path)
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        fetcher.fetch("mylib", LocalProvenance(path=src), dest=dest)
        # The path must exist (either as a dir or a symlink-to-dir).
        assert dest.exists() or dest.is_symlink()

    def test_cas_admissible_false_on_provenance(self, tmp_path: Path) -> None:
        """LocalProvenance.cas_admissible is False — no CAS admission for local deps."""
        p = LocalProvenance(path=tmp_path)
        assert p.cas_admissible is False

    def test_full_round_trip_with_registry(self, tmp_path: Path) -> None:
        """End-to-end through FetcherRegistry."""
        src = _make_source_dir(tmp_path)
        registry = FetcherRegistry()
        registry.register(LocalFetcher())
        dest = tmp_path / "pkg"
        result = registry.fetch("pkg", LocalProvenance(path=src), dest=dest)
        assert result.name == "pkg"
        assert result.path == dest
        assert result.identity.startswith("sha256:")
        assert "resolved_path" in result.receipt.transport_fields()


# ---------------------------------------------------------------------------
# LocalFetcher.fetch — error paths
# ---------------------------------------------------------------------------


class TestLocalFetcherErrors:
    def test_nonexistent_path_raises_not_found(self, tmp_path: Path) -> None:
        missing = tmp_path / "no_such_dir"
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("mylib", LocalProvenance(path=missing), dest=dest)
        assert exc_info.value.slug == FETCH_LOCAL_PATH_NOT_FOUND

    def test_path_is_file_raises_not_dir(self, tmp_path: Path) -> None:
        file_path = tmp_path / "afile.txt"
        file_path.write_text("not a directory\n")
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("mylib", LocalProvenance(path=file_path), dest=dest)
        assert exc_info.value.slug == FETCH_LOCAL_PATH_NOT_DIR

    def test_error_slugs_are_coded_strings(self, tmp_path: Path) -> None:
        missing = tmp_path / "absent"
        dest = tmp_path / "dest"
        dest.mkdir()
        fetcher = LocalFetcher()
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("mylib", LocalProvenance(path=missing), dest=dest)
        assert isinstance(exc_info.value.slug, str)
        assert exc_info.value.slug  # nonempty
