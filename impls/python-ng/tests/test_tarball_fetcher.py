"""Tests for milpa.fetchers.tarball (slice 7d-3).

All tests are offline — the HTTP transport is injected; no real network access.

Coverage:
  - Successful fetch: archive bytes → extracted tree, receipt.archive_sha256 correct.
  - TOFU (first-use): expected_sha256=None → sha recorded in receipt, no assertion.
  - Mismatch: expected_sha256 set but wrong → FETCH-SHA256-MISMATCH before extraction.
  - Hash prefix: sha256:-prefixed expected value accepted.
  - strip_components honored: top-level directory stripped from extracted paths.
  - can_handle: True for TarballProvenance, False for others.
  - Download failure: transport raises → FETCH-DOWNLOAD-FAILED.
  - Extraction failure: corrupt archive → FETCH-EXTRACT-FAILED.
  - Receipt non-empty: transport_fields() carries archive_sha256.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import tempfile
from pathlib import Path

import pytest

from milpa.errors import (
    FETCH_DOWNLOAD_FAILED,
    FETCH_EXTRACT_FAILED,
    FETCH_SHA256_MISMATCH,
    MilpaError,
)
from milpa.fetchers.tarball import (
    TarballFetcher,
    TarballProvenance,
    TarballReceipt,
)
from milpa.fetchers.types import Provenance

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _build_tar_gz(files: dict[str, bytes], prefix: str = "") -> bytes:
    """Build a gzip-compressed tar archive in memory.

    ``prefix`` is prepended to every entry name to simulate a top-level
    directory (used to test ``strip_components``).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            entry_name = f"{prefix}/{name}" if prefix else name
            info = tarfile.TarInfo(name=entry_name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _build_tar(files: dict[str, bytes], prefix: str = "") -> bytes:
    """Build a plain (uncompressed) tar archive in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for name, content in files.items():
            entry_name = f"{prefix}/{name}" if prefix else name
            info = tarfile.TarInfo(name=entry_name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_transport(data: bytes) -> object:
    """Return a callable that always returns ``data`` (injected HttpGet)."""
    def _get(url: str) -> bytes:
        return data
    return _get


def _make_failing_transport(exc: Exception) -> object:
    """Return a callable that always raises ``exc``."""
    def _get(url: str) -> bytes:
        raise exc
    return _get


# ---------------------------------------------------------------------------
# TarballProvenance construction
# ---------------------------------------------------------------------------


def test_tarball_provenance_defaults() -> None:
    p = TarballProvenance(url="https://example.com/lib-1.0.tar.gz")
    assert p.url == "https://example.com/lib-1.0.tar.gz"
    assert p.expected_sha256 is None
    assert p.strip_components == 0
    assert p.cas_admissible is True


def test_tarball_provenance_with_sha() -> None:
    sha = "a" * 64
    p = TarballProvenance(
        url="https://example.com/lib.tar.gz",
        expected_sha256=sha,
        strip_components=1,
    )
    assert p.expected_sha256 == sha
    assert p.strip_components == 1


# ---------------------------------------------------------------------------
# can_handle dispatch
# ---------------------------------------------------------------------------


def test_can_handle_tarball_provenance() -> None:
    fetcher = TarballFetcher(http_get=_make_transport(b""))
    assert fetcher.can_handle(TarballProvenance(url="https://x.com/x.tar.gz")) is True


def test_can_handle_rejects_base_provenance() -> None:
    fetcher = TarballFetcher(http_get=_make_transport(b""))
    # A plain Provenance (base class) is not a TarballProvenance.
    assert fetcher.can_handle(Provenance()) is False


# ---------------------------------------------------------------------------
# Successful fetch — gzip archive
# ---------------------------------------------------------------------------


def test_fetch_returns_correct_archive_sha256() -> None:
    files = {"src/main.nim": b"# hello"}
    archive = _build_tar_gz(files)
    expected_sha = _sha256(archive)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)

    assert isinstance(receipt, TarballReceipt)
    assert receipt.archive_sha256 == expected_sha


def test_fetch_tree_materialized_correctly() -> None:
    files = {
        "main.nim": b"import os",
        "util.nim": b"proc helper() = discard",
    }
    archive = _build_tar_gz(files)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "main.nim").read_bytes() == b"import os"
        assert (dest / "util.nim").read_bytes() == b"proc helper() = discard"


# ---------------------------------------------------------------------------
# TOFU first-use: expected_sha256 is None — sha recorded but not asserted
# ---------------------------------------------------------------------------


def test_tofu_first_use_no_assertion() -> None:
    archive = _build_tar_gz({"README": b"hi"})
    expected_sha = _sha256(archive)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", expected_sha256=None)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)

    # Receipt always carries the sha — the resolver will record it.
    assert receipt.archive_sha256 == expected_sha


# ---------------------------------------------------------------------------
# SHA-256 verification: bare hex and sha256:-prefixed
# ---------------------------------------------------------------------------


def test_expected_sha256_bare_hex_matches() -> None:
    archive = _build_tar_gz({"f.nim": b"x"})
    sha = _sha256(archive)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", expected_sha256=sha)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
    assert receipt.archive_sha256 == sha


def test_expected_sha256_prefixed_matches() -> None:
    archive = _build_tar_gz({"f.nim": b"y"})
    sha = _sha256(archive)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(
        url="https://host/pkg.tar.gz",
        expected_sha256=f"sha256:{sha}",
    )

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
    assert receipt.archive_sha256 == sha


def test_sha256_mismatch_raises_before_extraction() -> None:
    archive = _build_tar_gz({"danger.nim": b"bad content"})
    wrong_sha = "0" * 64

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(
        url="https://host/pkg.tar.gz",
        expected_sha256=wrong_sha,
    )

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
        assert exc_info.value.slug == FETCH_SHA256_MISMATCH
        # dest should be empty (extraction was not attempted)
        assert not dest.exists() or not any(dest.iterdir())


def test_sha256_mismatch_prefixed_raises() -> None:
    archive = _build_tar_gz({"f.nim": b"x"})
    wrong = f"sha256:{'0' * 64}"

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", expected_sha256=wrong)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug == FETCH_SHA256_MISMATCH


# ---------------------------------------------------------------------------
# strip_components
# ---------------------------------------------------------------------------


def test_strip_components_1() -> None:
    """top-level directory stripped, inner files land directly in dest."""
    files = {
        "pkg-1.0/src/main.nim": b"strip me",
        "pkg-1.0/LICENSE": b"MIT",
    }
    archive = _build_tar_gz(files)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", strip_components=1)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "src" / "main.nim").read_bytes() == b"strip me"
        assert (dest / "LICENSE").read_bytes() == b"MIT"
        # Top-level dir itself should NOT appear as a child.
        assert not (dest / "pkg-1.0").exists()


def test_strip_components_0_keeps_prefix() -> None:
    """strip_components=0 (default) preserves the full entry path."""
    files = {
        "topdir/file.nim": b"content",
    }
    archive = _build_tar_gz(files)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", strip_components=0)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "topdir" / "file.nim").read_bytes() == b"content"


# ---------------------------------------------------------------------------
# Download failure
# ---------------------------------------------------------------------------


def test_download_failure_raises_fetch_download_failed() -> None:
    def _fail(url: str) -> bytes:
        raise RuntimeError("connection refused")

    fetcher = TarballFetcher(http_get=_fail)
    prov = TarballProvenance(url="https://host/pkg.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_download_milpa_error_propagates() -> None:
    """MilpaError from transport propagates unchanged (not double-wrapped)."""
    original = MilpaError(FETCH_DOWNLOAD_FAILED, "curl failed", url="https://x.com/f.tar.gz")

    def _fail(url: str) -> bytes:
        raise original

    fetcher = TarballFetcher(http_get=_fail)
    prov = TarballProvenance(url="https://x.com/f.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    # Same instance propagated.
    assert exc_info.value is original


# ---------------------------------------------------------------------------
# Extraction failure (corrupt archive → FETCH-EXTRACT-FAILED)
# ---------------------------------------------------------------------------


def test_corrupt_archive_raises_fetch_extract_failed() -> None:
    garbage = b"not a tar archive at all -- just garbage bytes"

    fetcher = TarballFetcher(http_get=_make_transport(garbage))
    prov = TarballProvenance(url="https://host/garbage.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug == FETCH_EXTRACT_FAILED


# ---------------------------------------------------------------------------
# Plain tar (uncompressed) — safe_extract handles it
# ---------------------------------------------------------------------------


def test_plain_tar_extracted() -> None:
    files = {"readme.txt": b"plain"}
    archive = _build_tar(files)

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "readme.txt").read_bytes() == b"plain"
    assert receipt.archive_sha256 == _sha256(archive)


# ---------------------------------------------------------------------------
# Receipt
# ---------------------------------------------------------------------------


def test_receipt_transport_fields_non_empty() -> None:
    archive = _build_tar_gz({"f.nim": b"x"})
    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)

    fields = receipt.transport_fields()
    assert fields
    assert "archive_sha256" in fields
    assert fields["archive_sha256"] == _sha256(archive)
