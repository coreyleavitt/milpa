"""SafeExtractor tests — sandboxed archive extraction.

Used by TarballFetcher (F2 / #41) and future OCI/IPFS fetchers
(F6/F7) — anything that has to extract untrusted archive bytes into
a destination directory. Defends against zip-slip, symlink-escape,
decompression bombs, and excessive file counts.

Test fixtures build tar archives in tmp_path using the stdlib tarfile
module; no real network or external archives required.
"""

import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

from milpa.fetchers.safe_extract import (
    ExtractionError,
    ExtractionResult,
    SizeLimitError,
    SymlinkEscapeError,
    ZipSlipError,
    extract_tar,
)


def _make_tar_gz(path: Path, entries: dict[str, str | tuple]) -> None:
    """Build a tar.gz at `path` with the given entries.

    entries values:
      - str → file with that content
      - ("symlink", target) → symlink pointing at target
    """
    with tarfile.open(path, "w:gz") as tf:
        for name, val in entries.items():
            if isinstance(val, tuple) and val[0] == "symlink":
                info = tarfile.TarInfo(name=name)
                info.type = tarfile.SYMTYPE
                info.linkname = val[1]
                tf.addfile(info)
            else:
                data = val.encode() if isinstance(val, str) else val
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))


def test_extract_tar_simple_archive(tmp_path):
    """Tracer: a basic tar.gz with two files extracts to dest;
    ExtractionResult counts files and total bytes."""
    archive = tmp_path / "src.tar.gz"
    _make_tar_gz(archive, {
        "hello.txt": "hello\n",
        "src/lib.nim": "echo 1\n",
    })
    dest = tmp_path / "dest"

    result = extract_tar(archive, dest)

    assert isinstance(result, ExtractionResult)
    assert result.file_count == 2
    assert result.total_bytes == len("hello\n") + len("echo 1\n")
    assert (dest / "hello.txt").read_text() == "hello\n"
    assert (dest / "src" / "lib.nim").read_text() == "echo 1\n"


def test_extract_tar_rejects_zip_slip(tmp_path):
    """A tar entry whose path resolves outside dest is malicious.
    Reject with ZipSlipError before writing anything to that path."""
    archive = tmp_path / "evil.tar.gz"
    _make_tar_gz(archive, {
        "ok.txt": "fine\n",
        "../escaped.txt": "I escaped\n",
    })
    dest = tmp_path / "dest"

    with pytest.raises(ZipSlipError) as exc:
        extract_tar(archive, dest)
    assert "escaped.txt" in str(exc.value)
    # And the escaped file must not exist anywhere outside dest
    assert not (tmp_path / "escaped.txt").exists()


def test_extract_tar_rejects_symlink_escape(tmp_path):
    """A symlink entry whose target resolves outside dest is malicious.
    Reject with SymlinkEscapeError; the symlink must not be created."""
    archive = tmp_path / "evil.tar.gz"
    _make_tar_gz(archive, {
        "innocent.txt": "hello\n",
        "danger": ("symlink", "../../../../etc/passwd"),
    })
    dest = tmp_path / "dest"

    with pytest.raises(SymlinkEscapeError) as exc:
        extract_tar(archive, dest)
    msg = str(exc.value)
    assert "danger" in msg
    assert "../../../../etc/passwd" in msg or "escape" in msg.lower()
    # Symlink must NOT have been created
    assert not (dest / "danger").exists()
    assert not (dest / "danger").is_symlink()


def test_extract_tar_allows_symlink_inside_dest(tmp_path):
    """Symlinks within the dest tree are legitimate source content
    (e.g., a `latest -> v1.0` link in the source). Allow them."""
    archive = tmp_path / "ok.tar.gz"
    _make_tar_gz(archive, {
        "target.txt": "hello\n",
        "link.txt": ("symlink", "target.txt"),
    })
    dest = tmp_path / "dest"

    extract_tar(archive, dest)

    assert (dest / "link.txt").is_symlink()
    assert os.readlink(dest / "link.txt") == "target.txt"


def test_extract_tar_enforces_total_size_cap(tmp_path):
    """An archive whose decompressed total exceeds max_total_size
    raises SizeLimitError. Decompression-bomb defence."""
    archive = tmp_path / "bomb.tar.gz"
    # Two files of 1024 bytes each = 2048 total; cap of 1000 trips it.
    payload = "A" * 1024
    _make_tar_gz(archive, {
        "a.txt": payload,
        "b.txt": payload,
    })
    dest = tmp_path / "dest"

    with pytest.raises(SizeLimitError) as exc:
        extract_tar(archive, dest, max_total_size=1000)
    assert "size" in str(exc.value).lower()


def test_extract_tar_enforces_per_file_size_cap(tmp_path):
    """A single huge file in the archive exceeding max_file_size →
    SizeLimitError, regardless of total."""
    archive = tmp_path / "huge.tar.gz"
    _make_tar_gz(archive, {"huge.bin": "X" * 5000})
    dest = tmp_path / "dest"

    with pytest.raises(SizeLimitError):
        extract_tar(archive, dest, max_file_size=1000)


def test_extract_tar_strip_components_strips_leading_paths(tmp_path):
    """strip_components=1 removes the first path component from each
    entry. Github auto-tarballs put everything under <repo>-<sha>/;
    this strips that wrapper directory so dest is the package root."""
    archive = tmp_path / "pkg.tar.gz"
    _make_tar_gz(archive, {
        "pkg-v1.0.0/README.md": "# pkg\n",
        "pkg-v1.0.0/src/lib.nim": "echo 1\n",
        "pkg-v1.0.0/tests/test_lib.nim": "assert true\n",
    })
    dest = tmp_path / "dest"

    result = extract_tar(archive, dest, strip_components=1)

    # The wrapper directory is gone; contents directly at dest
    assert (dest / "README.md").read_text() == "# pkg\n"
    assert (dest / "src" / "lib.nim").read_text() == "echo 1\n"
    assert (dest / "tests" / "test_lib.nim").read_text() == "assert true\n"
    # The wrapper itself shouldn't exist
    assert not (dest / "pkg-v1.0.0").exists()
    assert result.file_count == 3


def test_extract_tar_strip_components_skips_entries_with_too_few_parts(tmp_path):
    """Entries with fewer path components than strip_components are
    skipped silently — they're parents being stripped past."""
    archive = tmp_path / "pkg.tar.gz"
    _make_tar_gz(archive, {
        "wrapper/file.txt": "kept\n",
        "lone.txt": "skipped\n",  # only 1 component; strip=1 drops it
    })
    dest = tmp_path / "dest"

    result = extract_tar(archive, dest, strip_components=1)

    assert (dest / "file.txt").read_text() == "kept\n"
    assert not (dest / "lone.txt").exists()
    assert result.file_count == 1
