"""Tests for milpa/fetchers/safe_extract.py.

All tarballs are built in-test using the ``tarfile`` module — no external
fixtures, no network access.

Attack-class coverage:
  - EXTRACT-ZIP-SLIP     (path traversal via ``../`` or absolute paths)
  - EXTRACT-SYMLINK-ESCAPE  (symlink target escapes dest)
  - EXTRACT-SIZE-LIMIT   (per-file / total-bytes / file-count caps)
"""

from __future__ import annotations

import gzip
import io
import lzma
import os
import tarfile
import tempfile
from pathlib import Path

import pytest

from milpa.errors import (
    EXTRACT_IO_ERROR,
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


# ---------------------------------------------------------------------------
# SA-1 — decompression-bomb guard (gzip expansion cap)
# ---------------------------------------------------------------------------


def _make_compressible_tar(size: int) -> io.BytesIO:
    """Return a gzip-compressed tar archive containing one file of ``size`` zero bytes.

    Zero bytes compress very well: the compressed payload is tiny while the
    declared member.size is ``size``.  Python's tarfile reads member.size from
    the header (uncompressed size) before extracting, so the per-file and
    total-size caps fire on the header-declared size, not the compressed size.
    This makes tarfile's existing per-entry size check the decompression-bomb
    defense for the Python path (unlike Rust, which must wrap the GzDecoder).
    """
    import gzip

    # Build a raw tar first.
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:") as tf:
        data = bytes(size)
        info = tarfile.TarInfo(name="bomb.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(data))
    raw_buf.seek(0)

    # Gzip-compress the tar.
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb") as gz:
        gz.write(raw_buf.read())
    gz_buf.seek(0)
    return gz_buf


def test_decompression_bomb_exceeding_cap_raises_size_limit() -> None:
    """A gzip-compressed tar whose member.size exceeds max_total_size raises EXTRACT-SIZE-LIMIT.

    SA-1 guard (Python path): Python's tarfile reads member.size (uncompressed
    size) from the tar header before extracting.  The per-file and total-size
    checks in extract_tar operate on member.size and therefore fire before any
    decompressed bytes are written to disk.  This test confirms the guard works
    against a gzip-compressed bomb (tiny compressed payload, large declared size).
    """
    bomb_size = 5_000  # bytes declared in tar header (uncompressed)
    gz = _make_compressible_tar(bomb_size)
    # Set max_total_size = 100 bytes so the 5 KB declared payload exceeds it.
    limits = Limits(max_total_size=100, max_file_size=10_000)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(gz, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_decompression_within_cap_succeeds() -> None:
    """A gzip tar whose member.size is within max_total_size extracts normally."""
    small_size = 50
    gz = _make_compressible_tar(small_size)
    limits = Limits(max_total_size=1_000, max_file_size=1_000)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(gz, Path(dest_str), limits=limits)
    assert result.file_count == 1
    assert result.total_bytes == small_size


# ---------------------------------------------------------------------------
# SA-1 (R16): decompression-bomb guard — bz2 and xz formats (lockstep with gzip)
# ---------------------------------------------------------------------------
#
# Python's tarfile reads member.size (uncompressed size) from the tar header
# BEFORE extracting bytes, regardless of the outer compression format (gz/bz2/xz).
# That is the decompression-bomb guard for ALL three formats on the Python path:
# the per-entry size check fires before any compressed bytes are decoded.
# These tests use the same low-cap Limits as the gzip test above to stay small.


def _make_bz2_compressible_tar(size: int) -> io.BytesIO:
    """Return a bzip2-compressed tar containing one file of ``size`` zero bytes.

    Zero bytes compress well so the compressed payload is small while the
    declared member.size is ``size``.  Python's tarfile reads member.size from
    the tar header (uncompressed) so the total-size cap fires before extraction.
    """
    import bz2

    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:") as tf:
        data = bytes(size)
        info = tarfile.TarInfo(name="bomb.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(data))
    raw_buf.seek(0)

    bz2_buf = io.BytesIO(bz2.compress(raw_buf.read()))
    bz2_buf.seek(0)
    return bz2_buf


def _make_xz_compressible_tar(size: int) -> io.BytesIO:
    """Return an xz-compressed tar containing one file of ``size`` zero bytes."""
    import lzma

    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:") as tf:
        data = bytes(size)
        info = tarfile.TarInfo(name="bomb.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(data))
    raw_buf.seek(0)

    xz_buf = io.BytesIO(lzma.compress(raw_buf.read(), format=lzma.FORMAT_XZ))
    xz_buf.seek(0)
    return xz_buf


def test_bz2_decompression_bomb_exceeding_cap_raises_size_limit() -> None:
    """A bz2-compressed tar whose member.size exceeds max_total_size raises EXTRACT-SIZE-LIMIT.

    SA-1 guard (R16): Python's tarfile reads member.size (uncompressed) from the
    tar header regardless of outer compression format.  The total-size check in
    extract_tar operates on member.size and therefore fires before any compressed
    bytes are decoded and written to disk.  This is lockstep with the gzip test
    (test_decompression_bomb_exceeding_cap_raises_size_limit) above.
    """
    bomb_size = 5_000  # bytes declared in tar header (uncompressed)
    bz2_archive = _make_bz2_compressible_tar(bomb_size)
    limits = Limits(max_total_size=100, max_file_size=10_000)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(bz2_archive, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_bz2_decompression_within_cap_succeeds() -> None:
    """A bz2 tar whose member.size is within max_total_size extracts normally."""
    small_size = 50
    bz2_archive = _make_bz2_compressible_tar(small_size)
    limits = Limits(max_total_size=1_000, max_file_size=1_000)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(bz2_archive, Path(dest_str), limits=limits)
    assert result.file_count == 1
    assert result.total_bytes == small_size


def test_xz_decompression_bomb_exceeding_cap_raises_size_limit() -> None:
    """An xz-compressed tar whose member.size exceeds max_total_size raises EXTRACT-SIZE-LIMIT.

    SA-1 guard (R16): lockstep with the gzip and bz2 bomb tests — same
    observable slug (EXTRACT-SIZE-LIMIT) from the same per-entry size check
    path in extract_tar, regardless of outer compression.
    """
    bomb_size = 5_000  # bytes declared in tar header (uncompressed)
    xz_archive = _make_xz_compressible_tar(bomb_size)
    limits = Limits(max_total_size=100, max_file_size=10_000)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(xz_archive, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_xz_decompression_within_cap_succeeds() -> None:
    """An xz tar whose member.size is within max_total_size extracts normally."""
    small_size = 50
    xz_archive = _make_xz_compressible_tar(small_size)
    limits = Limits(max_total_size=1_000, max_file_size=1_000)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(xz_archive, Path(dest_str), limits=limits)
    assert result.file_count == 1
    assert result.total_bytes == small_size


# ---------------------------------------------------------------------------
# H1b — Python decompressed-stream cap (defense-in-depth against lying headers)
# ---------------------------------------------------------------------------
#
# Python's tarfile caps based on member.size from the tar header.  A crafted
# compressed archive can contain an entry with member.size = 0 (no file data
# per the header) but still include massive zero-padding in the compressed
# stream.  Python's tarfile never counts that padding toward the size limit —
# it only sees the header sizes — so such an archive silently slips through
# the existing per-entry cap.
#
# The defense-in-depth: cap the ACTUAL decompressed byte count at the stream
# level (before tarfile sees any bytes).  The cap is
# max_total_size + _DECOMP_CAP_OVERHEAD, matching the Rust .take(decomp_cap)
# mechanism so both impls guard the same threat.
#
# These tests are RED until extract_tar applies a decompressed-stream cap.


def _make_lying_header_gz(compressed_padding_bytes: int) -> io.BytesIO:
    """Build a gzip archive with member.size = 0 but ``compressed_padding_bytes``
    of zero-padding inserted into the compressed stream after the tar header.

    Python's tarfile extracts file_count=1, total_bytes=0 (the header says no
    data), but the decompressor must expand ``compressed_padding_bytes`` bytes —
    which are NOT counted by the member.size path.  The stream-level cap must
    catch this.
    """
    buf = io.BytesIO()
    gz = gzip.GzipFile(fileobj=buf, mode="wb")
    # A single tar header: file a.nim, size=0
    header = bytearray(512)
    name = b"a.nim"
    header[: len(name)] = name
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"00000000000\0"  # size = 0 (the lie)
    header[136:148] = b"00000000000\0"
    header[156] = ord("0")
    header[148:156] = b"        "
    chksum = sum(header)
    header[148:156] = f"{chksum:06o}\0 ".encode()
    gz.write(bytes(header))
    # Massive padding in the compressed stream (not attributed to any tar entry)
    gz.write(b"\0" * compressed_padding_bytes)
    # End-of-archive blocks
    gz.write(b"\0" * 1024)
    gz.close()
    buf.seek(0)
    return buf


def _make_lying_header_bz2(compressed_padding_bytes: int) -> io.BytesIO:
    """Build a bz2 archive with member.size = 0 but massive padding in the stream."""
    import bz2

    header = bytearray(512)
    name = b"a.nim"
    header[: len(name)] = name
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"00000000000\0"
    header[136:148] = b"00000000000\0"
    header[156] = ord("0")
    header[148:156] = b"        "
    chksum = sum(header)
    header[148:156] = f"{chksum:06o}\0 ".encode()

    raw_tar = bytes(header) + b"\0" * compressed_padding_bytes + b"\0" * 1024
    return io.BytesIO(bz2.compress(raw_tar))


def _make_lying_header_xz(compressed_padding_bytes: int) -> io.BytesIO:
    """Build an xz archive with member.size = 0 but massive padding in the stream."""
    import lzma

    header = bytearray(512)
    name = b"a.nim"
    header[: len(name)] = name
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"00000000000\0"
    header[136:148] = b"00000000000\0"
    header[156] = ord("0")
    header[148:156] = b"        "
    chksum = sum(header)
    header[148:156] = f"{chksum:06o}\0 ".encode()

    raw_tar = bytes(header) + b"\0" * compressed_padding_bytes + b"\0" * 1024
    return io.BytesIO(lzma.compress(raw_tar, format=lzma.FORMAT_XZ))


def test_gz_lying_header_stream_cap_fires() -> None:
    """H1b (RED→GREEN): a gzip archive with member.size=0 but massive padding in
    the compressed stream must raise EXTRACT-SIZE-LIMIT at the stream level.

    The member.size-based check would pass (size=0 < cap), but the decompressor
    must expand all the padding bytes — a decompression bomb via lying headers.
    The stream-level decomp_cap fires on total decompressed bytes, catching this.
    """
    padding = 5_000  # 5 KB expanded from the stream (not attributed to any entry)
    gz_archive = _make_lying_header_gz(padding)
    # Set decomp_cap very small so the padded stream exceeds it
    limits = Limits(max_total_size=100, max_file_size=10_000, decomp_cap=200)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(gz_archive, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_bz2_lying_header_stream_cap_fires() -> None:
    """H1b: bz2 variant of the lying-header stream cap test."""
    padding = 5_000
    bz2_archive = _make_lying_header_bz2(padding)
    limits = Limits(max_total_size=100, max_file_size=10_000, decomp_cap=200)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(bz2_archive, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_xz_lying_header_stream_cap_fires() -> None:
    """H1b: xz variant of the lying-header stream cap test."""
    padding = 5_000
    xz_archive = _make_lying_header_xz(padding)
    limits = Limits(max_total_size=100, max_file_size=10_000, decomp_cap=200)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(xz_archive, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_stream_cap_does_not_fire_for_legitimate_archive() -> None:
    """H1b: a legitimate gz archive within the stream cap must extract normally.

    Python's tarfile pads blocks to 10 KiB (512-byte header + 512-byte data
    block + GNU extension padding), so a 50-byte file produces ~10 KiB of raw
    tar bytes.  The decomp_cap must be comfortably above that.
    """
    gz_archive = _make_compressible_tar(50)
    # decomp_cap of 100 KiB is well above the ~10 KiB raw tar for a 50-byte file.
    limits = Limits(max_total_size=1_000, max_file_size=1_000, decomp_cap=100_000)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(gz_archive, Path(dest_str), limits=limits)
    assert result.file_count == 1
    assert result.total_bytes == 50


# ---------------------------------------------------------------------------
# R1-06 — lzma FORMAT_ALONE decompression bomb guard
# ---------------------------------------------------------------------------
#
# An lzma FORMAT_ALONE stream (.tar.lzma, magic \x5d\x00) was previously
# unrecognised by _decompress_capped, causing the raw bytes to fall through
# as "tar" and tarfile to decompress them internally with NO milpa cap.
# The fix adds \x5d\x00 detection and routes FORMAT_ALONE through a capped
# lzma.LZMAFile(format=lzma.FORMAT_ALONE) decompression path.


def _make_lzma_alone_tar(size: int) -> io.BytesIO:
    """Return an lzma FORMAT_ALONE-compressed tar containing one file of ``size`` zero bytes.

    The resulting bytes start with \\x5d\\x00 (FORMAT_ALONE magic) and are
    NOT recognised by the old _decompress_capped (gz/bz2/xz only).
    """
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:") as tf:
        data = bytes(size)
        info = tarfile.TarInfo(name="bomb.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(data))
    raw_buf.seek(0)
    compressed = lzma.compress(raw_buf.read(), format=lzma.FORMAT_ALONE)
    return io.BytesIO(compressed)


def _make_lying_header_lzma_alone(compressed_padding_bytes: int) -> io.BytesIO:
    """Build an lzma FORMAT_ALONE archive with member.size=0 but massive padding in the stream.

    This is the FORMAT_ALONE analogue of _make_lying_header_gz/_bz2/_xz.
    Python's tarfile reads member.size=0 from the header (no bytes attributed
    to the entry) so Layer 2 does NOT fire.  The decompressor must still expand
    all ``compressed_padding_bytes`` of zero-padding — a decompression bomb
    via lying headers.  The stream-level decomp_cap MUST catch this.

    Before R1-06 fix: \\x5d\\x00 was unrecognised, tarfile.open(mode="r:*")
    decompressed internally with NO milpa cap → OOM.
    After R1-06 fix: detected and routed through a capped LZMAFile(FORMAT_ALONE).
    """
    header = bytearray(512)
    name = b"a.nim"
    header[: len(name)] = name
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"00000000000\0"  # size = 0 (the lie)
    header[136:148] = b"00000000000\0"
    header[156] = ord("0")
    header[148:156] = b"        "
    chksum = sum(header)
    header[148:156] = f"{chksum:06o}\0 ".encode()

    raw_tar = bytes(header) + b"\0" * compressed_padding_bytes + b"\0" * 1024
    return io.BytesIO(lzma.compress(raw_tar, format=lzma.FORMAT_ALONE))


def test_lzma_alone_decompression_bomb_exceeding_cap_raises_size_limit() -> None:
    """R1-06: a .tar.lzma (FORMAT_ALONE, lying header) whose decompressed stream
    exceeds decomp_cap must raise EXTRACT-SIZE-LIMIT — not silently decompress with no cap.

    Before the fix: FORMAT_ALONE magic (\\x5d\\x00) was unrecognised, so
    _decompress_capped returned the raw compressed bytes as ("tar") and
    tarfile.open(mode="r:*") decompressed the stream internally with NO milpa cap.
    A lying-header FORMAT_ALONE archive (member.size=0 but massive stream padding)
    would escape BOTH Layer 1 AND Layer 2 — OOM potential.

    After the fix: \\x5d\\x00 is detected, the stream is decompressed through a
    capped LZMAFile(format=FORMAT_ALONE), and a tiny decomp_cap fires on the
    padded stream before any bytes escape to tarfile.
    """
    # Verify magic bytes of the produced archive.
    archive_check = _make_lying_header_lzma_alone(5_000)
    first_bytes = archive_check.read(2)
    archive_check.seek(0)
    assert first_bytes == b"\x5d\x00", (
        f"test archive must start with FORMAT_ALONE magic \\x5d\\x00; got {first_bytes!r}"
    )

    padding = 5_000  # 5 KB expanded from the stream (not attributed to any entry)
    archive = _make_lying_header_lzma_alone(padding)
    # decomp_cap = 200 → stream exceeds it when padding is decompressed
    limits = Limits(max_total_size=100, max_file_size=10_000, decomp_cap=200)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(archive, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_lzma_alone_legitimate_archive_extracts_correctly() -> None:
    """R1-06 (happy path): a legitimate small .tar.lzma (FORMAT_ALONE) extracts correctly."""
    small_size = 50
    archive = _make_lzma_alone_tar(small_size)
    limits = Limits(max_total_size=1_000, max_file_size=1_000, decomp_cap=100_000)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(archive, Path(dest_str), limits=limits)
    assert result.file_count == 1
    assert result.total_bytes == small_size


# ---------------------------------------------------------------------------
# H2 — hardlink geometry (spec/plugin-contract.md §2.2)
# ---------------------------------------------------------------------------


def _make_hardlink_entry(name: str, link_target: str) -> tuple[str, bytes, str, bytes]:
    """A tar hardlink entry (typeflag LNKTYPE / b'1')."""
    return (name, tarfile.LNKTYPE, link_target, b"")


def test_hardlink_materialised_as_file_copy() -> None:
    """H2a: a hardlink entry is extracted as a real file (not a symlink).

    A tar with a regular file ``a/foo.txt`` and a hardlink entry
    ``a/bar.txt`` → ``a/foo.txt``.  After extraction ``bar.txt`` MUST be a
    regular file with the same bytes — NOT a symlink.
    """
    payload = b"hello hardlink"
    tar = _make_tar(
        [
            _make_file_entry("a/foo.txt", payload),
            _make_hardlink_entry("a/bar.txt", "a/foo.txt"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        result = extract_tar(tar, dest)
        bar = dest / "a" / "bar.txt"
        assert bar.exists(), "bar.txt must be created"
        assert not bar.is_symlink(), "bar.txt must be a real file, not a symlink"
        assert bar.read_bytes() == payload, "bar.txt must have the same bytes as foo.txt"
    assert result.file_count == 2  # foo.txt + bar.txt (hardlink counts as a file)


def test_hardlink_strip_components_applied_to_linkname() -> None:
    """H2b: strip_components is applied to linkname, not just the entry name.

    Archive: ``a/foo.txt`` (regular) + ``a/bar.txt`` → ``a/foo.txt`` (hardlink).
    With ``strip_components=1`` the leading ``a/`` is stripped from BOTH the
    entry name and the linkname, so the hardlink resolves to ``foo.txt`` (under
    dest) rather than dangling.
    """
    payload = b"stripped link"
    tar = _make_tar(
        [
            _make_file_entry("a/foo.txt", payload),
            _make_hardlink_entry("a/bar.txt", "a/foo.txt"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        extract_tar(tar, dest, strip_components=1)
        foo = dest / "foo.txt"
        bar = dest / "bar.txt"
        assert foo.is_file(), "foo.txt must exist after strip"
        assert bar.is_file(), "bar.txt must exist after strip (hardlink target also stripped)"
        assert bar.read_bytes() == payload, "bar.txt must have the same bytes as foo.txt"
        assert not bar.is_symlink(), "bar.txt must be a real file, not a symlink"


def test_hardlink_forward_reference_two_pass() -> None:
    """H2c: hardlink that appears BEFORE its target in archive order still resolves.

    In archive order: hardlink ``a/bar.txt`` → ``a/foo.txt`` FIRST, then
    the regular file ``a/foo.txt``.  A single-pass extractor would fail to
    copy the target because it doesn't exist yet.  Two-pass extraction (all
    regular files first, hardlinks second) MUST handle this.
    """
    payload = b"forward ref"
    tar = _make_tar(
        [
            # HARDLINK first — forward-reference
            _make_hardlink_entry("a/bar.txt", "a/foo.txt"),
            # Regular file SECOND
            _make_file_entry("a/foo.txt", payload),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        result = extract_tar(tar, dest)
        bar = dest / "a" / "bar.txt"
        assert bar.is_file(), "bar.txt must exist even though hardlink was listed first"
        assert bar.read_bytes() == payload


def test_hardlink_escape_raises_zip_slip() -> None:
    """H2d: a hardlink whose linkname escapes dest_root raises EXTRACT-ZIP-SLIP.

    After strip_components the resolved linkname escapes dest.  The error slug
    MUST be EXTRACT-ZIP-SLIP (same as regular path-traversal escape) — no new
    slug.
    """
    tar = _make_tar(
        [
            _make_hardlink_entry("a/evil.txt", "../../etc/passwd"),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_str, pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, Path(dest_str))
    assert exc_info.value.slug == EXTRACT_ZIP_SLIP, (
        "hardlink escape must raise EXTRACT-ZIP-SLIP, not a new slug"
    )


def test_hardlink_hash_stability() -> None:
    """H2e: copy-bytes materialization gives hash-stable output.

    An archive with a hardlink (foo.txt + bar.txt pointing to foo.txt) and an
    otherwise-identical archive with a plain duplicate file (both as regular
    files) MUST produce the same extracted tree bytes — and therefore the same
    content_hash.
    """
    from milpa.identity import compute_content_hash

    payload = b"identical content"

    # Archive A: regular file + hardlink
    tar_a = _make_tar(
        [
            _make_file_entry("foo.txt", payload),
            _make_hardlink_entry("bar.txt", "foo.txt"),
        ]
    )
    # Archive B: two regular files with identical content
    tar_b = _make_tar(
        [
            _make_file_entry("foo.txt", payload),
            _make_file_entry("bar.txt", payload),
        ]
    )
    with tempfile.TemporaryDirectory() as dest_a_str, tempfile.TemporaryDirectory() as dest_b_str:
        dest_a = Path(dest_a_str)
        dest_b = Path(dest_b_str)
        extract_tar(tar_a, dest_a)
        extract_tar(tar_b, dest_b)
        hash_a = compute_content_hash(dest_a)
        hash_b = compute_content_hash(dest_b)
    assert hash_a == hash_b, (
        f"hardlink archive and plain-duplicate archive must hash identically; "
        f"got {hash_a!r} vs {hash_b!r}"
    )


def test_hardlink_executable_bit_is_preserved_and_sibling_is_not() -> None:
    """S0b/M10: a hardlink member whose OWN tar mode has the executable bit
    set must land on disk with 0o111 set after extraction, while a
    non-executable hardlink sibling must NOT -- pins pass 2's
    ``candidate.chmod(_regular_file_mode(member))`` branch (mirrors
    ``test_pack_source_executable_bit_is_set_on_disk_and_regular_is_not`` on
    the packer side; this test guards the equivalent extractor branch, which
    previously had no exec-bit-set hardlink case at all).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        # Hardlink targets (regular files) written first.
        for name, mode, data in [
            ("a/exec_target.sh", 0o755, b"#!/bin/sh\necho hi\n"),
            ("a/plain_target.txt", 0o644, b"not executable\n"),
        ]:
            info = tarfile.TarInfo(name=name)
            info.type = tarfile.REGTYPE
            info.mode = mode
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        # Hardlinks: one executable, one not -- each carrying its OWN mode.
        for name, mode, target in [
            ("a/exec_link.sh", 0o755, "a/exec_target.sh"),
            ("a/plain_link.txt", 0o644, "a/plain_target.txt"),
        ]:
            info = tarfile.TarInfo(name=name)
            info.type = tarfile.LNKTYPE
            info.mode = mode
            info.linkname = target
            info.size = 0
            tf.addfile(info)
    buf.seek(0)

    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        extract_tar(buf, dest)
        exec_link = dest / "a" / "exec_link.sh"
        plain_link = dest / "a" / "plain_link.txt"
        assert exec_link.stat().st_mode & 0o111 != 0, (
            "executable hardlink member must have 0o111 set on disk"
        )
        assert plain_link.stat().st_mode & 0o111 == 0, (
            "non-executable hardlink sibling must NOT have 0o111 set"
        )


# ---------------------------------------------------------------------------
# R2-02: lzma-alone magic-independent bomb guard
# ---------------------------------------------------------------------------
#
# The round-1 fix matched only the 2-byte prefix \x5d\x00 (the most common
# LZMA1 properties byte = 0x5d).  Other valid properties bytes (e.g. 0x00)
# are not matched, fall through to tarfile r:* with NO cap.
#
# The fix: when no reliable magic matches, ATTEMPT a capped
# lzma.LZMAFile(format=FORMAT_ALONE) decode; treat as lzma on success,
# fall through to plain-tar on LZMAError.


def _make_lzma_alone_non_default_props(size: int) -> io.BytesIO:
    """Return an lzma FORMAT_ALONE tar with a non-default properties byte.

    lzma.compress(format=FORMAT_ALONE) may produce properties bytes other
    than 0x5d depending on the encoder; we force a non-0x5d properties byte
    by patching the first byte of the output to 0x00.

    WARNING: patching the properties byte makes the stream undecodable by
    standard lzma (invalid parameters), so this archive is ONLY useful for
    testing that the attempt-decode path catches it (raises LZMAError →
    falls through to plain-tar → tarfile raises on the non-tar bytes).

    For the happy-path test (non-default props that IS valid), we use
    lzma.compress with filters=[{"id": lzma.FILTER_LZMA1, "lc": 0, ...}].
    """
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:") as tf:
        data = bytes(size)
        info = tarfile.TarInfo(name="bomb.bin")
        info.size = size
        tf.addfile(info, io.BytesIO(data))
    raw_buf.seek(0)
    # Compress with default FORMAT_ALONE (first byte is usually 0x5d).
    compressed = lzma.compress(raw_buf.read(), format=lzma.FORMAT_ALONE)
    return io.BytesIO(compressed)


def _make_lzma_alone_tar_alt_props(size: int) -> io.BytesIO:
    """Return a valid lzma FORMAT_ALONE tar with an alternative properties byte.

    Uses lc=1, lp=0, pb=1 → properties byte = (pb*5 + lp)*9 + lc = (5 + 0)*9 + 1 = 46 = 0x2e.
    This is different from the default 0x5d, so the old 2-byte magic check misses it.
    The resulting stream IS valid and decodable by lzma.LZMAFile(FORMAT_ALONE).
    """
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "lc": 1,
            "lp": 0,
            "pb": 1,
            "dict_size": 1 << 16,
        }
    ]
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:") as tf:
        data = bytes(size)
        info = tarfile.TarInfo(name="file.nim")
        info.size = size
        tf.addfile(info, io.BytesIO(data))
    raw_buf.seek(0)
    compressed = lzma.compress(raw_buf.read(), format=lzma.FORMAT_ALONE, filters=filters)
    # Verify the first byte is NOT 0x5d (the old magic).
    assert compressed[0] != 0x5d, (
        f"Expected non-0x5d properties byte with these filters; got {compressed[0]:#x}"
    )
    return io.BytesIO(compressed)


def test_lzma_alone_non_default_props_bomb_raises_size_limit() -> None:
    """R2-02: a .tar.lzma with properties byte != 0x5d but oversized decompressed
    stream must raise EXTRACT-SIZE-LIMIT — not bypass the cap via r:* fallthrough.

    Before the fix: the 2-byte magic \\x5d\\x00 check misses, the bytes fall through
    as "tar", and tarfile.open(mode="r:*") decompresses with NO milpa cap.
    After the fix: the attempt-decode path tries lzma.LZMAFile(FORMAT_ALONE);
    if it decodes successfully, it is treated as lzma and the capped path applies.
    """
    # Build a valid FORMAT_ALONE archive with non-default properties byte.
    archive = _make_lzma_alone_tar_alt_props(50)
    first_byte = archive.read(1)
    archive.seek(0)
    # Confirm the magic does NOT match the old check.
    assert first_byte != b"\x5d", (
        "Test precondition: properties byte must differ from 0x5d; use _make_lzma_alone_tar_alt_props"
    )

    # Now make a BOMB version: lying-header with non-default props but huge padding.
    # We build it by compressing a padded raw_tar with the same alt filters.
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "lc": 1,
            "lp": 0,
            "pb": 1,
            "dict_size": 1 << 16,
        }
    ]
    header = bytearray(512)
    name = b"a.nim"
    header[: len(name)] = name
    header[100:108] = b"0000644\0"
    header[108:116] = b"0000000\0"
    header[116:124] = b"0000000\0"
    header[124:136] = b"00000000000\0"  # size = 0 (the lie)
    header[136:148] = b"00000000000\0"
    header[156] = ord("0")
    header[148:156] = b"        "
    chksum = sum(header)
    header[148:156] = f"{chksum:06o}\0 ".encode()
    padding = 5_000
    raw_tar = bytes(header) + b"\0" * padding + b"\0" * 1024
    bomb_bytes = lzma.compress(raw_tar, format=lzma.FORMAT_ALONE, filters=filters)
    assert bomb_bytes[0] != 0x5d, "Test precondition: bomb must have non-0x5d props"
    bomb = io.BytesIO(bomb_bytes)

    # With a tiny decomp_cap this must raise EXTRACT-SIZE-LIMIT.
    limits = Limits(max_total_size=100, max_file_size=10_000, decomp_cap=200)
    with tempfile.TemporaryDirectory() as dest_str:
        with pytest.raises(MilpaError) as exc_info:
            extract_tar(bomb, Path(dest_str), limits=limits)
    assert exc_info.value.slug == EXTRACT_SIZE_LIMIT


def test_lzma_alone_alt_props_legitimate_archive_extracts() -> None:
    """R2-02 (happy path): a legitimate small .tar.lzma with non-default properties
    byte still extracts correctly after the magic-independent fix.
    """
    archive = _make_lzma_alone_tar_alt_props(50)
    limits = Limits(max_total_size=1_000, max_file_size=1_000, decomp_cap=100_000)
    with tempfile.TemporaryDirectory() as dest_str:
        result = extract_tar(archive, Path(dest_str), limits=limits)
    assert result.file_count == 1
    assert result.total_bytes == 50


# ---------------------------------------------------------------------------
# R3-01: remove unguarded \x5d\x00 fast-path — fallthrough to plain tar
# ---------------------------------------------------------------------------
#
# Before R3-01: _decompress_capped has an elif data[:2] == b"\x5d\x00" fast-path
# that constructs lzma.LZMAFile(FORMAT_ALONE) with NO try/except.  When the
# stream is not a valid LZMA-alone stream (e.g. a plain tar whose first filename
# byte is ']' = 0x5d, making the tar start with \x5d\x00...), the fast-path
# silently produces 0 decompressed bytes (LZMAFile reads the header then hits EOF
# on the non-LZMA body) → tarfile receives an empty buffer → ReadError: empty file.
# The Rust impl has no fast-path: it attempt-decodes and falls through on error,
# treating the bytes as plain tar and extracting correctly.  Cross-impl divergence.
#
# Fix: remove the fast-path entirely.  All streams that do not match the reliable
# gzip/bz2/xz magics fall through to the guarded _is_lzma_alone_header + probe
# path.  For this tar (dict_size=0 → _is_lzma_alone_header=False), the probe is
# skipped entirely and _decompress_capped returns (data, "tar"), unifying behavior
# with Rust.


def _make_tar_with_5d00_filename() -> io.BytesIO:
    """Return a plain tar whose first entry filename starts with ']' (0x5d).

    The resulting bytes start with \\x5d\\x00... (matching the old _MAGIC_LZMA_ALONE
    2-byte check) but bytes 1-4 encode dict_size=0 (the null-padded tar filename
    field), which is INVALID per _is_lzma_alone_header (requires dict_size ≥ 2^12).

    Before R3-01 fix:
      - _decompress_capped takes the elif data[:2]==b"\\x5d\\x00" fast-path.
      - lzma.LZMAFile reads a valid props byte (0x5d) + dict_size=0, then hits
        non-LZMA body bytes and returns 0 decompressed bytes.
      - extract_tar passes an empty BytesIO to tarfile → ReadError: empty file.
      - extraction FAILS even though the bytes are a valid plain tar.

    After R3-01 fix:
      - Fast-path is removed.
      - _is_lzma_alone_header(data) returns False (dict_size=0 not in valid set).
      - _decompress_capped returns (data, "tar") — original bytes unchanged.
      - tarfile opens the plain-tar bytes normally → extraction SUCCEEDS.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:") as tf:
        payload = b"hello from bracket file"
        info = tarfile.TarInfo(name="]")  # ']' = 0x5d — produces \x5d\x00 prefix
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    # Precondition: archive bytes start with \x5d\x00
    archive_bytes = buf.read()
    assert archive_bytes[:2] == b"\x5d\x00", (
        f"Precondition: tar must start with \\x5d\\x00; got {archive_bytes[:2]!r}"
    )
    buf.seek(0)
    return buf


def test_lzma_alone_5d00_prefix_invalid_body_falls_through_to_plain_tar() -> None:
    """R3-01: a plain tar whose bytes start with \\x5d\\x00 (MAGIC_LZMA_ALONE) but
    whose body is NOT a valid LZMA stream must extract successfully as plain tar.

    This is the cross-impl divergence fix: Rust has no \\x5d\\x00 fast-path and
    treats the bytes as plain tar; Python's old fast-path caused silent 0-byte
    decompression → ReadError.  After removing the fast-path, Python matches Rust.

    Precondition: the archive bytes start with \\x5d\\x00 (verified inside
    _make_tar_with_5d00_filename).  The ']' filename tar satisfies this because
    the first tar header byte is the first filename byte (']' = 0x5d) and the
    second byte is the second filename byte (implicit null terminator = 0x00).
    """
    archive = _make_tar_with_5d00_filename()
    payload = b"hello from bracket file"
    limits = Limits(max_total_size=10_000, max_file_size=10_000, decomp_cap=100_000)
    with tempfile.TemporaryDirectory() as dest_str:
        dest = Path(dest_str)
        result = extract_tar(archive, dest, limits=limits)
        assert result.file_count == 1
        assert result.total_bytes == len(payload)
        assert (dest / "]").read_bytes() == payload


# ---------------------------------------------------------------------------
# R1-18: EXTRACT-IO-ERROR — genuine I/O failure after path-containment checks
# ---------------------------------------------------------------------------


def test_hardlink_target_read_oserror_raises_extract_io_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R1-18a: OSError on hardlink target read → EXTRACT-IO-ERROR, not EXTRACT-ZIP-SLIP.

    The monkeypatch fires only on the resolved target path (already validated),
    so this is a post-containment I/O failure.
    """
    payload = b"some content"
    tar = _make_tar(
        [
            _make_file_entry("a/foo.txt", payload),
            _make_hardlink_entry("a/bar.txt", "a/foo.txt"),
        ]
    )
    original_read_bytes = Path.read_bytes

    def _raise_oserror(self: Path) -> bytes:
        # Only inject the fault when reading the *target* (foo.txt), not the
        # initial archive bytes.
        if self.name == "foo.txt":
            raise OSError("simulated I/O error on hardlink target read")
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
    with pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, tmp_path / "dest")
    assert exc_info.value.slug == EXTRACT_IO_ERROR


def test_zip_slip_escape_still_raises_extract_zip_slip(tmp_path: Path) -> None:
    """R1-18b: a path-escape entry still raises EXTRACT-ZIP-SLIP (unchanged).

    Confirm the containment checks were NOT accidentally reclassified.
    """
    tar = _make_tar(
        [
            _make_file_entry("../../etc/passwd", b"evil"),
        ]
    )
    with pytest.raises(MilpaError) as exc_info:
        extract_tar(tar, tmp_path / "dest")
    assert exc_info.value.slug == EXTRACT_ZIP_SLIP
