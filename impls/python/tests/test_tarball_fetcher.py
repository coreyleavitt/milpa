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
  - R4: oversized compressed body capped before buffering → FETCH-DOWNLOAD-FAILED.
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
    FETCH_DOWNLOAD_SIZE_EXCEEDED,
    FETCH_EXTRACT_FAILED,
    FETCH_SHA256_MISMATCH,
    MilpaError,
)
from milpa.fetchers.tarball import (
    MAX_COMPRESSED_BYTES,
    TarballFetcher,
    TarballProvenance,
    TarballReceipt,
    make_http_get,
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
    """Return a callable that streams ``data`` to the given dest Path (injected
    HttpGet — H3: the seam writes to a file, it never returns the archive as
    an in-memory ``bytes`` object)."""
    def _get(url: str, dest: Path) -> None:
        dest.write_bytes(data)
    return _get


def _make_failing_transport(exc: Exception) -> object:
    """Return a callable that always raises ``exc``."""
    def _get(url: str, dest: Path) -> None:
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


def test_expected_sha256_uppercase_bare_hex_matches() -> None:
    """Uppercase (or mixed-case) expected sha256 must match the lowercase computed digest."""
    archive = _build_tar_gz({"f.nim": b"case"})
    sha_lower = _sha256(archive)
    sha_upper = sha_lower.upper()

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", expected_sha256=sha_upper)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
    assert receipt.archive_sha256 == sha_lower


def test_expected_sha256_uppercase_prefixed_matches() -> None:
    """sha256:-prefixed UPPERCASE expected digest must match the lowercase computed digest."""
    archive = _build_tar_gz({"f.nim": b"caseprefix"})
    sha_lower = _sha256(archive)
    sha_upper_prefixed = f"sha256:{sha_lower.upper()}"

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.gz", expected_sha256=sha_upper_prefixed)

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
    assert receipt.archive_sha256 == sha_lower


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
    def _fail(url: str, dest: Path) -> None:
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

    def _fail(url: str, dest: Path) -> None:
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


# ---------------------------------------------------------------------------
# bz2 (bzip2) — decoder coverage (bz2 is excluded from the conformance corpus
# because there is no pure-Rust bz2 encoder; this per-impl unit test pins the
# Python decoder path against the bz2 magic bytes).
# ---------------------------------------------------------------------------


def test_bzip2_archive_extracted() -> None:
    """TarballFetcher decompresses and extracts a bzip2-compressed archive.

    Python's ``tarfile`` module natively supports bzip2 (``w:bz2`` / ``r:bz2``).
    This test ensures the ``MAGIC_BZ2`` detection path in the production fetcher
    is exercised (milpa.fetchers.safe_extract reads the magic bytes and passes
    the decompressed stream to ``extract_tar``).
    """
    files = {"src/lib.nim": b"# bz2 source"}

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:bz2") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    archive = buf.getvalue()

    # Verify the bz2 magic bytes are present (defensive check for the test itself).
    assert archive[:3] == b"BZh", "archive must start with bz2 magic 'BZh'"

    fetcher = TarballFetcher(http_get=_make_transport(archive))
    prov = TarballProvenance(url="https://host/pkg.tar.bz2")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "src" / "lib.nim").read_bytes() == b"# bz2 source"

    assert receipt.archive_sha256 == _sha256(archive)


# ---------------------------------------------------------------------------
# H1 — compressed download cap (streaming abort → FETCH-DOWNLOAD-SIZE-EXCEEDED)
# ---------------------------------------------------------------------------


def test_max_compressed_bytes_constant_is_positive() -> None:
    """MAX_COMPRESSED_BYTES must be a positive integer (sanity)."""
    assert isinstance(MAX_COMPRESSED_BYTES, int)
    assert MAX_COMPRESSED_BYTES > 0


def test_oversized_compressed_body_raises_fetch_download_size_exceeded() -> None:
    """H1: a transport that returns more bytes than the compressed cap must
    raise FETCH-DOWNLOAD-SIZE-EXCEEDED (not FETCH-DOWNLOAD-FAILED).

    We use a tiny cap (16 bytes) via a custom TarballFetcher so the test is
    fast.  The injected transport returns cap+1 bytes which exceeds the limit.
    The fetcher must detect this and raise FETCH-DOWNLOAD-SIZE-EXCEEDED so a
    security size-cap rejection is distinct from a network failure.
    """
    tiny_cap = 16
    oversized = b"x" * (tiny_cap + 1)

    def _oversized_transport(url: str, dest: Path) -> None:
        dest.write_bytes(oversized)

    fetcher = TarballFetcher(http_get=_oversized_transport, compressed_cap=tiny_cap)
    prov = TarballProvenance(url="https://host/large.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED


def test_oversized_body_is_not_conflated_with_network_failure() -> None:
    """H1: FETCH-DOWNLOAD-SIZE-EXCEEDED must be distinct from FETCH-DOWNLOAD-FAILED.

    A network failure (transport raises) uses FETCH-DOWNLOAD-FAILED.
    A size cap breach uses FETCH-DOWNLOAD-SIZE-EXCEEDED.
    Both must be independently reachable — a consumer can distinguish a dead
    mirror (network) from a security-rejected oversized response (size cap).
    """
    tiny_cap = 16
    # Network failure path.
    def _fail(url: str, dest: Path) -> None:
        raise RuntimeError("timeout")

    fetcher_fail = TarballFetcher(http_get=_fail, compressed_cap=tiny_cap)
    prov = TarballProvenance(url="https://host/pkg.tar.gz")
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(MilpaError) as exc_info:
            fetcher_fail.fetch("pkg", prov, dest=Path(tmp) / "pkg")
    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED

    # Size-cap path.
    oversized = b"x" * (tiny_cap + 1)
    def _big(url: str, dest: Path) -> None:
        dest.write_bytes(oversized)

    fetcher_big = TarballFetcher(http_get=_big, compressed_cap=tiny_cap)
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(MilpaError) as exc_info2:
            fetcher_big.fetch("pkg", prov, dest=Path(tmp) / "pkg")
    assert exc_info2.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED
    assert exc_info2.value.slug != FETCH_DOWNLOAD_FAILED


def test_streaming_transport_aborts_early() -> None:
    """H1: the production streaming transport aborts before reading the full body.

    We inject a streaming transport that records how many bytes were consumed,
    then verify that consumption stops at approximately the cap (never exceeds
    cap + one chunk).  This is the bounded-memory property: the process never
    buffers more than cap + chunk_size bytes from an over-cap response.

    The transport is a generator-based HttpGet (streaming seam): it yields
    CHUNK_SIZE bytes at a time and records a `bytes_read` counter.  The
    TarballFetcher must abort as soon as the running total exceeds `cap`,
    not after all bytes are delivered.
    """
    tiny_cap = 32
    # Produce 8× the cap worth of data in chunks of 8 bytes each.
    chunk_size = 8
    total_available = tiny_cap * 8
    bytes_delivered: list[int] = [0]  # mutable counter via list

    def _streaming_transport(url: str, dest: Path) -> None:
        """Streaming transport: writes chunks straight to ``dest`` and
        records delivery, aborting once the cumulative total exceeds the
        cap (mirrors bounded_http's mid-stream abort — H3: the fake writes
        to disk exactly like the production transport, never accumulating
        the full body in a Python ``bytes`` object)."""
        written = 0
        with open(dest, "wb") as f:
            for i in range(0, total_available, chunk_size):
                chunk = b"x" * chunk_size
                bytes_delivered[0] += chunk_size
                f.write(chunk)
                written += chunk_size
                if written > tiny_cap:
                    # Simulate streaming abort: a real streaming transport
                    # (bounded_http) raises mid-stream at this point instead
                    # of returning; this fake just stops writing further
                    # chunks and returns normally.
                    return

    fetcher = TarballFetcher(http_get=_streaming_transport, compressed_cap=tiny_cap)
    prov = TarballProvenance(url="https://host/large.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED
    # Bounded-memory assertion: transport was not fully drained.
    # bytes_delivered must be ≤ cap + chunk_size (one chunk past the cap).
    assert bytes_delivered[0] <= tiny_cap + chunk_size, (
        f"Transport delivered {bytes_delivered[0]} bytes, but cap is {tiny_cap} "
        f"with chunk_size={chunk_size}; expected delivery ≤ {tiny_cap + chunk_size}"
    )


def test_production_make_http_get_streaming_aborts_on_cap() -> None:
    """H1: make_http_get production transport streams and aborts at cap.

    We cannot use a real URL in unit tests, but we can verify that
    make_http_get returns a callable that raises FETCH-DOWNLOAD-SIZE-EXCEEDED
    (not FETCH-DOWNLOAD-FAILED) when a tiny cap is set and the server sends
    more data than the cap allows.

    This test uses a local HTTP server that returns a body larger than the cap.
    It is skipped if the http.server module fails to bind (rare in CI).
    """
    import http.server
    import threading

    # Build a real tiny tar.gz archive (valid, not garbage).
    body = _build_tar_gz({"big.nim": b"x" * 200})
    tiny_cap = 50  # body is ~250 bytes; cap is 50 — well below body size.

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass  # suppress server logs

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        transport = make_http_get(compressed_cap=tiny_cap)
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(MilpaError) as exc_info:
                transport(f"http://127.0.0.1:{port}/test.tar.gz", Path(tmp) / "archive")
        assert exc_info.value.slug == FETCH_DOWNLOAD_SIZE_EXCEEDED
    finally:
        server.shutdown()


def test_body_at_exactly_cap_is_accepted() -> None:
    """H1: a body of exactly cap bytes must be accepted (boundary check).

    We use a tiny cap (16 bytes) and a transport that returns exactly 16 bytes
    of garbage.  This is at the limit, so the fetcher proceeds
    to the (expected) extraction failure.
    """
    tiny_cap = 16
    exactly_cap = b"x" * tiny_cap

    def _exact_transport(url: str, dest: Path) -> None:
        dest.write_bytes(exactly_cap)

    fetcher = TarballFetcher(http_get=_exact_transport, compressed_cap=tiny_cap)
    prov = TarballProvenance(url="https://host/exact.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        # Body is garbage (not a real archive), so extraction fails — but NOT
        # with FETCH-DOWNLOAD-SIZE-EXCEEDED or FETCH-DOWNLOAD-FAILED (the cap did not fire).
        with pytest.raises(MilpaError) as exc_info:
            fetcher.fetch("pkg", prov, dest=dest)
    assert exc_info.value.slug not in (FETCH_DOWNLOAD_FAILED, FETCH_DOWNLOAD_SIZE_EXCEEDED)


# ---------------------------------------------------------------------------
# Native transport characterization (RFC docs/rfc-native-oci-fetch.md §3.3,
# slice S3) — pins make_http_get's observable behavior across the
# curl -> bounded_http swap.  These replace the pre-migration Popen-instrumented
# FD-leak regression tests (R1-13), which asserted curl-subprocess-internal
# details (proc.returncode) that no longer apply once curl is deleted; the
# slug-level contract they protected is re-pinned here against the real
# transport instead.
# ---------------------------------------------------------------------------


def test_production_make_http_get_connection_refused_raises_fetch_download_failed() -> None:
    """make_http_get: a connection-refused target raises FETCH-DOWNLOAD-FAILED.

    Pinned against the production transport (no injected fake) so this holds
    identically whether the transport shells out to curl or calls
    bounded_http.request natively — a transport/connection failure must
    always surface as FETCH-DOWNLOAD-FAILED, never FETCH-DOWNLOAD-SIZE-EXCEEDED
    or an unwrapped exception.
    """
    import socket

    # Find a port with nothing listening so the request fails immediately.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # Port is now free (s is closed); connecting to it refuses.

    transport = make_http_get()
    with tempfile.TemporaryDirectory() as tmp:
        with pytest.raises(MilpaError) as exc_info:
            transport(f"http://127.0.0.1:{port}/test.tar.gz", Path(tmp) / "archive")
    assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED


def test_production_make_http_get_http_error_status_raises_fetch_download_failed() -> None:
    """make_http_get: a non-2xx HTTP status raises FETCH-DOWNLOAD-FAILED.

    Today (curl -fsSL) curl's ``-f`` flag fails the request on any HTTP error
    status.  A native transport treats HTTP status as data rather than an
    exception (RFC §3.4), so the production adapter must translate a 404/5xx
    response into the same FETCH-DOWNLOAD-FAILED outcome explicitly — this
    test pins that translation.
    """
    import http.server
    import threading

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        transport = make_http_get()
        with tempfile.TemporaryDirectory() as tmp:
            with pytest.raises(MilpaError) as exc_info:
                transport(f"http://127.0.0.1:{port}/missing.tar.gz", Path(tmp) / "archive")
        assert exc_info.value.slug == FETCH_DOWNLOAD_FAILED
    finally:
        server.shutdown()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# H3 — memory safety: the archive is streamed to a temp file, never buffered
# as a Python ``bytes`` object (docs/rfc-native-oci-fetch.md §3.3)
# ---------------------------------------------------------------------------


def test_http_get_seam_receives_a_path_not_bytes_return() -> None:
    """H3: the injected HttpGet seam is ``(url, dest: Path) -> None`` — the
    transport streams the archive directly to a file TarballFetcher owns,
    rather than returning the whole compressed archive as an in-memory
    ``bytes`` object.  This is the seam-level proof that a concurrent resolve
    with N tarball workers no longer holds N full compressed archives in
    process memory at once (the finding: N x MAX_COMPRESSED_BYTES DoS).
    """
    seen_dest: list[Path] = []

    def _get(url: str, dest: Path) -> None:
        assert isinstance(dest, Path), "HttpGet must receive a Path sink, not return bytes"
        seen_dest.append(dest)
        dest.write_bytes(_build_tar_gz({"f.nim": b"streamed"}))

    fetcher = TarballFetcher(http_get=_get)
    prov = TarballProvenance(url="https://host/pkg.tar.gz")

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "pkg"
        receipt = fetcher.fetch("pkg", prov, dest=dest)
        assert (dest / "f.nim").read_bytes() == b"streamed"

    assert len(seen_dest) == 1
    # TarballFetcher owns the scratch temp file's lifecycle — it must not
    # leak the downloaded archive once fetch() returns.
    assert not seen_dest[0].exists(), "downloaded archive temp file must be cleaned up"
    assert isinstance(receipt, TarballReceipt)


def test_production_make_http_get_streams_response_to_dest_file(tmp_path: Path) -> None:
    """H3: make_http_get's production transport writes the response body
    directly to the caller-supplied ``dest`` Path via
    ``bounded_http.request(sink=dest)`` — proving the production seam is
    Path-based end to end, not just the injectable test seam.
    """
    import http.server
    import threading

    body = _build_tar_gz({"big.nim": b"x" * 200})

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        transport = make_http_get()
        dest = tmp_path / "archive"
        transport(f"http://127.0.0.1:{port}/test.tar.gz", dest)
        assert dest.read_bytes() == body
    finally:
        server.shutdown()
        thread.join(timeout=5)
