"""TarballFetcher tests — fetch + verify + extract a tarball into dest.

Fetcher protocol (F1): returns a TarballReceipt; the registry
computes content_hash from the extracted source tree (identity
invariant preserved — fetchers can't influence identity).

Test fixtures build tar.gz archives in tmp_path and serve them via
file:// URLs. No real network required.
"""

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry, FetchError
from milpa.fetchers.tarball import (
    TarballFetcher,
    TarballProvenance,
    TarballReceipt,
)


def _make_tar_gz(path: Path, entries: dict[str, str]) -> str:
    """Build a tar.gz at `path` with the given file entries.
    Returns the sha256 hex of the resulting archive."""
    with tarfile.open(path, "w:gz") as tf:
        for name, content in entries.items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_tarball_fetcher_extracts_local_archive(tmp_path):
    """Tracer: a file:// tarball URL is fetched, extracted, and the
    registry computes content_hash from the extracted tree. The
    receipt records the archive's sha256."""
    archive = tmp_path / "pkg.tar.gz"
    archive_sha = _make_tar_gz(archive, {
        "pkg.nimble": 'srcDir = "src"\n',
        "src/pkg.nim": "echo 1\n",
    })

    registry = FetcherRegistry()
    registry.register(TarballFetcher())

    dest = tmp_path / "dest"
    result = registry.fetch(
        "pkg",
        TarballProvenance(url=f"file://{archive}"),
        dest=dest,
    )

    # Files extracted at dest
    assert (dest / "pkg.nimble").read_text() == 'srcDir = "src"\n'
    assert (dest / "src" / "pkg.nim").read_text() == "echo 1\n"
    # Registry-computed identity (sha256 of source tree)
    # Multihash form: "sha256:" + 64 hex chars
    assert result.content_hash.startswith("sha256:")
    assert len(result.content_hash) == len("sha256:") + 64
    assert all(c in "0123456789abcdef" for c in result.content_hash.split(":", 1)[1])
    # Receipt records the archive sha256 (provenance, not identity)
    assert isinstance(result.receipt, TarballReceipt)
    assert result.receipt.archive_sha256 == archive_sha


def test_tarball_fetcher_accepts_correct_expected_sha256(tmp_path):
    """expected_sha256 set to the correct hash → fetch succeeds.
    Pre-fetch integrity check is the strongest guarantee in the
    transport hierarchy (git can't do this)."""
    archive = tmp_path / "pkg.tar.gz"
    sha = _make_tar_gz(archive, {"f.txt": "content\n"})

    registry = FetcherRegistry()
    registry.register(TarballFetcher())

    result = registry.fetch(
        "pkg",
        TarballProvenance(url=f"file://{archive}", expected_sha256=sha),
        dest=tmp_path / "dest",
    )

    assert result.receipt.archive_sha256 == sha
    assert (tmp_path / "dest" / "f.txt").read_text() == "content\n"


def test_tarball_fetcher_rejects_wrong_expected_sha256_without_extracting(tmp_path):
    """expected_sha256 mismatch → FetchError BEFORE extraction.
    dest must not be created — this is the pre-fetch verification
    guarantee that makes tarballs strictly safer than git clones."""
    archive = tmp_path / "pkg.tar.gz"
    _make_tar_gz(archive, {"f.txt": "content\n"})

    registry = FetcherRegistry()
    registry.register(TarballFetcher())

    dest = tmp_path / "dest"
    with pytest.raises(FetchError) as exc:
        registry.fetch(
            "pkg",
            TarballProvenance(
                url=f"file://{archive}",
                expected_sha256="0" * 64,  # not the real hash
            ),
            dest=dest,
        )
    msg = str(exc.value)
    assert "mismatch" in msg.lower()
    assert "before extraction" in msg.lower()
    # Crucially: dest was NEVER created
    assert not dest.exists()


def test_tarball_fetcher_missing_url_raises_with_url_in_message(tmp_path):
    """A file:// URL that doesn't exist (or 404 over HTTP) →
    FetchError with the URL in the message."""
    registry = FetcherRegistry()
    registry.register(TarballFetcher())

    missing_url = f"file://{tmp_path}/nonexistent.tar.gz"

    with pytest.raises(FetchError) as exc:
        registry.fetch(
            "pkg",
            TarballProvenance(url=missing_url),
            dest=tmp_path / "dest",
        )
    assert missing_url in str(exc.value)


def test_tarball_fetcher_tofu_mode_records_actual_hash(tmp_path):
    """expected_sha256=None (TOFU): fetch succeeds without integrity
    check; receipt records the actual computed hash so the lockfile
    can pin it for subsequent fetches. This is the 'first fetch
    discovers the hash' workflow."""
    archive = tmp_path / "pkg.tar.gz"
    actual_sha = _make_tar_gz(archive, {"f.txt": "hello\n"})

    registry = FetcherRegistry()
    registry.register(TarballFetcher())

    result = registry.fetch(
        "pkg",
        TarballProvenance(url=f"file://{archive}", expected_sha256=None),
        dest=tmp_path / "dest",
    )

    # Fetch succeeded; receipt carries the actual hash for lockfile pinning
    assert result.receipt.archive_sha256 == actual_sha
    assert (tmp_path / "dest" / "f.txt").read_text() == "hello\n"
