"""Tests for milpa/fetchers/safe_extract.py.

All tarballs are built in-test using the ``tarfile`` module — no external
fixtures, no network access.

Attack-class coverage:
  - EXTRACT-ZIP-SLIP     (path traversal via ``../`` or absolute paths)
  - EXTRACT-SYMLINK-ESCAPE  (symlink target escapes dest)
  - EXTRACT-SIZE-LIMIT   (per-file / total-bytes / file-count caps)
"""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
from pathlib import Path

import pytest

from milpa.errors import (
    EXTRACT_SIZE_LIMIT,
    EXTRACT_SYMLINK_ESCAPE,
    EXTRACT_ZIP_SLIP,
    MilpaError,
)
from milpa.fetchers.safe_extract import ExtractionResult, Limits, extract_tar

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tar(entries: list[tuple[str, bytes, str, bytes]]) -> io.BytesIO:
    """Build an in-memory tar archive.

    Each entry is ``(name, typeflag, linkname, data)``.  The tarfile module is
    used with a ``TarInfo`` override so we can inject arbitrary names/types.

    ``typeflag`` (bytes, one char):
      - ``tarfile.REGTYPE`` (b'0')  — regular file
      - ``tarfile.DIRTYPE`` (b'5')  — directory
      - ``tarfile.SYMTYPE`` (b'2')  — symbolic link
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        for name, typeflag, linkname, data in entries:
            info = tarfile.TarInfo(name=name)
            info.type = typeflag
            info.size = len(data)
            if linkname:
                info.linkname = linkname
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def _make_file_entry(name: str, data: bytes) -> tuple[str, bytes, str, bytes]:
    return (name, tarfile.REGTYPE, "", data)


def _make_dir_entry(name: str) -> tuple[str, bytes, str, bytes]:
    return (name, tarfile.DIRTYPE, "", b"")


def _make_symlink_entry(name: str, target: str) -> tuple[str, bytes, str, bytes]:
    return (name, tarfile.SYMTYPE, target, b"")


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


def test_benign_tar_extracts_correctly() -> None:
    """A well-formed archive with files, a subdirectory, and a safe symlink."""
    tar = _make_tar(
        [
            _make_dir_entry("pkg/"),
            _make_file_entry("pkg/a.nim", b"# a"),
            _make_file_entry("pkg/sub/b.nim", b"# b"),
            _make_symlink_entry("pkg/link.nim", "a.nim"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        result = extract_tar(tar, dest)

    assert isinstance(result, ExtractionResult)
    assert result.file_count == 3   # a.nim, sub/b.nim, link.nim (symlink counts)
    assert result.total_bytes == len(b"# a") + len(b"# b")


def test_benign_tar_file_contents_are_correct() -> None:
    """Extracted file bytes match what was put in."""
    payload = b"hello milpa"
    tar = _make_tar([_make_file_entry("hello.txt", payload)])
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        extract_tar(tar, dest)
        assert (dest / "hello.txt").read_bytes() == payload


def test_safe_symlink_is_created() -> None:
    """A symlink whose target stays inside dest is allowed."""
    tar = _make_tar(
        [
            _make_file_entry("real.nim", b"x"),
            _make_symlink_entry("alias.nim", "real.nim"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        extract_tar(tar, dest)
        link = dest / "alias.nim"
        assert link.is_symlink()
        assert os.readlink(str(link)) == "real.nim"


def test_strip_components_drops_leading_dir() -> None:
    """strip_components=1 strips the top-level directory prefix."""
    tar = _make_tar(
        [
            _make_dir_entry("pkg-1.0/"),
            _make_file_entry("pkg-1.0/src/x.nim", b"x"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        extract_tar(tar, dest, strip_components=1)
        assert (dest / "src" / "x.nim").is_file()
        assert not (dest / "pkg-1.0").exists()


def test_strip_components_skips_too_shallow_entries() -> None:
    """Entries with fewer components than strip_components are silently skipped."""
    tar = _make_tar(
        [
            _make_dir_entry("pkg-1.0/"),
            _make_file_entry("pkg-1.0/a.nim", b"a"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        result = extract_tar(tar, dest, strip_components=2)
        # strip=2 needs at least 3 components; a.nim has 2 → skipped
        assert result.file_count == 0
        assert list(dest.iterdir()) == []


# ---------------------------------------------------------------------------
# EXTRACT-ZIP-SLIP
# ---------------------------------------------------------------------------


def test_zip_slip_via_parent_dir_rejected() -> None:
    """An entry with ``../`` in its name must raise EXTRACT-ZIP-SLIP."""
    tar = _make_tar([_make_file_entry("../escape.txt", b"pwned")])
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_ZIP_SLIP


def test_zip_slip_nested_traversal_rejected() -> None:
    """A nested traversal ``sub/../../escape`` must raise EXTRACT-ZIP-SLIP."""
    tar = _make_tar([_make_file_entry("sub/../../escape.txt", b"pwned")])
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_ZIP_SLIP


def test_zip_slip_absolute_path_rejected() -> None:
    """An entry whose name is an absolute path must raise EXTRACT-ZIP-SLIP."""
    # Build the tarball directly with a raw TarInfo to bypass tarfile's own safety.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 5
        tf.addfile(info, io.BytesIO(b"pwned"))
    buf.seek(0)

    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(buf, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_ZIP_SLIP


# ---------------------------------------------------------------------------
# EXTRACT-SYMLINK-ESCAPE
# ---------------------------------------------------------------------------


def test_symlink_escape_direct_rejected() -> None:
    """A symlink whose target directly escapes dest via ``../`` is rejected."""
    tar = _make_tar([_make_symlink_entry("link", "../../etc/passwd")])
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_SYMLINK_ESCAPE


def test_symlink_escape_absolute_target_rejected() -> None:
    """A symlink with an absolute target that escapes dest is rejected."""
    tar = _make_tar([_make_symlink_entry("link", "/etc/passwd")])
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_SYMLINK_ESCAPE


def test_symlink_escape_nested_rejected() -> None:
    """A symlink in a subdirectory that escapes dest is rejected."""
    tar = _make_tar(
        [
            _make_dir_entry("sub/"),
            _make_symlink_entry("sub/link", "../../../etc/passwd"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_SYMLINK_ESCAPE


# ---------------------------------------------------------------------------
# EXTRACT-SIZE-LIMIT — per-file
# ---------------------------------------------------------------------------


def test_per_file_size_cap_trips() -> None:
    """An entry exceeding ``max_file_size`` raises EXTRACT-SIZE-LIMIT."""
    tar = _make_tar([_make_file_entry("big.bin", b"\x00" * 600)])
    limits = Limits(max_file_size=100)
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_per_file_size_cap_exactly_at_limit_is_allowed() -> None:
    """An entry exactly at ``max_file_size`` is permitted."""
    data = b"x" * 100
    tar = _make_tar([_make_file_entry("exact.bin", data)])
    limits = Limits(max_file_size=100)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(tar, Path(dest_str), limits=limits)
    assert result.file_count == 1


# ---------------------------------------------------------------------------
# EXTRACT-SIZE-LIMIT — total bytes
# ---------------------------------------------------------------------------


def test_total_size_cap_trips() -> None:
    """Sum of entry sizes exceeding ``max_total_size`` raises EXTRACT-SIZE-LIMIT."""
    tar = _make_tar(
        [
            _make_file_entry("a", b"\x00" * 400),
            _make_file_entry("b", b"\x00" * 400),
        ]
    )
    limits = Limits(max_total_size=500, max_file_size=1000)
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_total_size_cap_exactly_at_limit_is_allowed() -> None:
    """Sum exactly at ``max_total_size`` is permitted."""
    data = b"y" * 200
    tar = _make_tar(
        [
            _make_file_entry("a", data),
            _make_file_entry("b", data),
        ]
    )
    limits = Limits(max_total_size=400, max_file_size=400)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(tar, Path(dest_str), limits=limits)
    assert result.total_bytes == 400


# ---------------------------------------------------------------------------
# EXTRACT-SIZE-LIMIT — file count
# ---------------------------------------------------------------------------


def test_file_count_cap_trips() -> None:
    """Exceeding ``max_file_count`` raises EXTRACT-SIZE-LIMIT."""
    tar = _make_tar(
        [
            _make_file_entry("f0", b"x"),
            _make_file_entry("f1", b"x"),
            _make_file_entry("f2", b"x"),
        ]
    )
    limits = Limits(max_file_count=2)
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_file_count_cap_exactly_at_limit_is_allowed() -> None:
    """File count exactly at ``max_file_count`` is permitted."""
    tar = _make_tar(
        [
            _make_file_entry("f0", b"x"),
            _make_file_entry("f1", b"x"),
        ]
    )
    limits = Limits(max_file_count=2)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(tar, Path(dest_str), limits=limits)
    assert result.file_count == 2


def test_symlinks_count_toward_file_count() -> None:
    """Symlinks are counted in ``file_count`` alongside regular files."""
    tar = _make_tar(
        [
            _make_file_entry("real.nim", b"x"),
            _make_symlink_entry("alias.nim", "real.nim"),
        ]
    )
    limits = Limits(max_file_count=2)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(tar, Path(dest_str), limits=limits)
    assert result.file_count == 2


def test_symlinks_over_file_count_cap_trips() -> None:
    """Symlinks push file_count over cap → EXTRACT-SIZE-LIMIT."""
    tar = _make_tar(
        [
            _make_file_entry("real.nim", b"x"),
            _make_symlink_entry("a1.nim", "real.nim"),
            _make_symlink_entry("a2.nim", "real.nim"),
        ]
    )
    limits = Limits(max_file_count=2)
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


# ---------------------------------------------------------------------------
# Misc / edge cases
# ---------------------------------------------------------------------------


def test_empty_archive_is_ok() -> None:
    """An archive with no entries returns zeroed counts."""
    tar = _make_tar([])
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(tar, Path(dest_str))
    assert result.file_count == 0
    assert result.total_bytes == 0


def test_dest_is_created_if_absent() -> None:
    """extract_tar creates dest if it does not exist yet."""
    tar = _make_tar([_make_file_entry("x.nim", b"x")])
    with tempfile.TemporaryDirectory() as root:
        dest = Path(root) / "new" / "subdir"
        extract_tar(tar, dest)
        assert dest.is_dir()
        assert (dest / "x.nim").is_file()


def test_default_limits_are_normative() -> None:
    """Default Limits match the spec-normative values (plugin-contract.md §2.1)."""
    lim = Limits()
    assert lim.max_total_size == 1 << 30
    assert lim.max_file_size == 1 << 28
    assert lim.max_file_count == 100_000
