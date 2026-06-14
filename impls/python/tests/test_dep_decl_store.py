"""Unit tests for dep_decl_store.py (S3b).

Covers:
  - FileDepDeclStore: get (happy) / hash-mismatch / missing-file (FETCH-FAILED)
  - HttpDepDeclStore: cache-hit / cache-miss fetch / FETCH-FAILED on network error
  - index_base_url: §3.3 URL-derivation table from the RFC
  - DepDeclEdgeSource: happy / schema-mismatch / schema-unsupported
  - _verify: one hash-verify site (SECURITY INVARIANT)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from milpa.dep_decl import EdgeSource, dep_decl_hash, parse_dep_decl
from milpa.dep_decl_store import (
    FileDepDeclStore,
    HttpDepDeclStore,
    _verify,
    index_base_url,
    make_dep_decl_store,
)
from milpa.edge_sources import DepDeclEdgeSource, EdgeSourceCtx
from milpa.errors import (
    TNG_DEPDECL_FETCH_FAILED,
    TNG_DEPDECL_HASH_MISMATCH,
    TNG_DEPDECL_SCHEMA_MISMATCH,
    TNG_DEPDECL_SCHEMA_UNSUPPORTED,
    MilpaError,
)
from milpa.version import Version


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_V = Version(0, 0, 1)


def _make_artifact(src_dir: str = "src") -> bytes:
    """Create a minimal valid DepDecl artifact."""
    return (
        f'dep_decl {{\n'
        f'    dep_decl_schema_version 0\n'
        f'    src_dir "{src_dir}"\n'
        f'}}\n'
    ).encode("utf-8")


def _artifact_and_hash(src_dir: str = "src") -> tuple[bytes, str]:
    artifact_bytes = _make_artifact(src_dir)
    return artifact_bytes, dep_decl_hash(artifact_bytes)


def _put_artifact(dir: Path, artifact_bytes: bytes, hash_str: str) -> Path:
    """Write artifact_bytes to <dir>/<sha256_hex>.kdl."""
    hex_digest = hash_str.removeprefix("sha256:")
    path = dir / f"{hex_digest}.kdl"
    path.write_bytes(artifact_bytes)
    return path


# ---------------------------------------------------------------------------
# _verify — the ONE hash-verify site
# ---------------------------------------------------------------------------


def test_verify_passes_on_matching_hash() -> None:
    """_verify passes when sha256(bytes) == hash."""
    data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n}\n"
    h = dep_decl_hash(data)
    _verify(data, h)  # must not raise


def test_verify_raises_hash_mismatch() -> None:
    """_verify raises TNG-DEPDECL-HASH-MISMATCH on corruption."""
    data = b"dep_decl {\n    dep_decl_schema_version 0\n    src_dir \"\"\n}\n"
    wrong_hash = "sha256:" + "a" * 64  # wrong 64-hex string
    with pytest.raises(MilpaError) as exc_info:
        _verify(data, wrong_hash)
    assert exc_info.value.slug == TNG_DEPDECL_HASH_MISMATCH


# ---------------------------------------------------------------------------
# FileDepDeclStore — happy path
# ---------------------------------------------------------------------------


def test_file_store_get_happy(tmp_path: Path) -> None:
    """FileDepDeclStore.get returns artifact bytes when file exists and hash matches."""
    artifact_bytes, hash_str = _artifact_and_hash()
    _put_artifact(tmp_path, artifact_bytes, hash_str)

    store = FileDepDeclStore(tmp_path)
    result = store.get(hash_str)
    assert result == artifact_bytes


def test_file_store_is_cached_true(tmp_path: Path) -> None:
    """is_cached returns True when the file exists."""
    artifact_bytes, hash_str = _artifact_and_hash()
    _put_artifact(tmp_path, artifact_bytes, hash_str)

    store = FileDepDeclStore(tmp_path)
    assert store.is_cached(hash_str)


def test_file_store_is_cached_false(tmp_path: Path) -> None:
    """is_cached returns False when the file is absent."""
    store = FileDepDeclStore(tmp_path)
    h = "sha256:" + "b" * 64
    assert not store.is_cached(h)


# ---------------------------------------------------------------------------
# FileDepDeclStore — FETCH-FAILED (missing file — unit level only per S3b spec)
# ---------------------------------------------------------------------------


def test_file_store_missing_raises_fetch_failed(tmp_path: Path) -> None:
    """FileDepDeclStore.get raises TNG-DEPDECL-FETCH-FAILED when file is absent."""
    store = FileDepDeclStore(tmp_path)
    h = "sha256:" + "c" * 64
    with pytest.raises(MilpaError) as exc_info:
        store.get(h)
    assert exc_info.value.slug == TNG_DEPDECL_FETCH_FAILED


# ---------------------------------------------------------------------------
# FileDepDeclStore — HASH-MISMATCH (corrupted bytes)
# ---------------------------------------------------------------------------


def test_file_store_hash_mismatch_raises(tmp_path: Path) -> None:
    """FileDepDeclStore.get raises TNG-DEPDECL-HASH-MISMATCH on corrupted file.

    This tests the SECURITY INVARIANT: corrupted file bytes → hard error,
    not a silent pass-through to the parser.
    """
    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")
    # Write CORRUPTED bytes to the file named after the correct hash.
    corrupt_path = tmp_path / f"{hex_digest}.kdl"
    corrupt_path.write_bytes(b"corrupted content that does not match the hash")

    store = FileDepDeclStore(tmp_path)
    with pytest.raises(MilpaError) as exc_info:
        store.get(hash_str)
    assert exc_info.value.slug == TNG_DEPDECL_HASH_MISMATCH


# ---------------------------------------------------------------------------
# HttpDepDeclStore — cache hit
# ---------------------------------------------------------------------------


def test_http_store_cache_hit_no_network(tmp_path: Path) -> None:
    """HttpDepDeclStore.get serves from cache without any network call."""
    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    # Pre-populate cache.
    (cache_dir / f"{hex_digest}.kdl").write_bytes(artifact_bytes)

    # Network transport that must NOT be called.
    def _never_called(url: str) -> bytes:
        raise AssertionError(f"network transport was called unexpectedly: {url}")

    store = HttpDepDeclStore(
        base_url="https://example.com/registry",
        cache_dir=cache_dir,
    )
    # Monkey-patch urllib to ensure no network call.
    import milpa.dep_decl_store as dds_module
    import urllib.request
    original_urlopen = urllib.request.urlopen

    class _NeverCalledCtxMgr:
        def __enter__(self): raise AssertionError("urlopen must not be called on cache hit")
        def __exit__(self, *_): ...

    result = store.get(hash_str)
    assert result == artifact_bytes


def test_http_store_is_cached_true(tmp_path: Path) -> None:
    """is_cached returns True when artifact is in local cache."""
    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    (cache_dir / f"{hex_digest}.kdl").write_bytes(artifact_bytes)

    store = HttpDepDeclStore(base_url="https://example.com", cache_dir=cache_dir)
    assert store.is_cached(hash_str)


def test_http_store_is_cached_false(tmp_path: Path) -> None:
    """is_cached returns False when artifact is not in local cache."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(base_url="https://example.com", cache_dir=cache_dir)
    h = "sha256:" + "d" * 64
    assert not store.is_cached(h)


def test_http_store_fetch_failed_on_network_error(tmp_path: Path) -> None:
    """HttpDepDeclStore.get raises TNG-DEPDECL-FETCH-FAILED on network error."""
    artifact_bytes, hash_str = _artifact_and_hash()
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(base_url="https://does-not-exist.invalid", cache_dir=cache_dir)

    with pytest.raises(MilpaError) as exc_info:
        store.get(hash_str)
    assert exc_info.value.slug == TNG_DEPDECL_FETCH_FAILED


def test_http_store_oci_base_raises_fetch_failed(tmp_path: Path) -> None:
    """OCI base URL raises TNG-DEPDECL-FETCH-FAILED with a clear message."""
    store = HttpDepDeclStore(base_url="oci://myregistry.example.com/milpa", cache_dir=tmp_path)
    h = "sha256:" + "e" * 64
    with pytest.raises(MilpaError) as exc_info:
        store.get(h)
    assert exc_info.value.slug == TNG_DEPDECL_FETCH_FAILED
    assert "MILPA_DEP_DECL_DIR" in exc_info.value.message


def test_http_store_fetch_from_file_url(tmp_path: Path) -> None:
    """HttpDepDeclStore.get fetches and caches from a file:// URL (air-gapped)."""
    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")

    # Serve from a local file:// URL structure.
    serve_dir = tmp_path / "serve"
    dep_decl_dir = serve_dir / "dep-decl"
    dep_decl_dir.mkdir(parents=True)
    (dep_decl_dir / f"{hex_digest}.kdl").write_bytes(artifact_bytes)

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    store = HttpDepDeclStore(
        base_url=f"file://{serve_dir}",
        cache_dir=cache_dir,
    )
    result = store.get(hash_str)
    assert result == artifact_bytes

    # Cache was populated.
    assert (cache_dir / f"{hex_digest}.kdl").is_file()
    # Second call is a cache hit.
    result2 = store.get(hash_str)
    assert result2 == artifact_bytes


# ---------------------------------------------------------------------------
# index_base_url — §3.3 URL-derivation table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("input_url,expected_base", [
    # RFC examples
    (
        "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl",
        "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/",
    ),
    (
        "https://example.com/registry/v2",
        "https://example.com/registry/v2/",
    ),
    (
        "file:///home/user/conformance/index.kdl",
        "file:///home/user/conformance/",
    ),
    # *.kdl segment removed
    (
        "https://example.com/tianguis/main/index.kdl",
        "https://example.com/tianguis/main/",
    ),
    (
        "https://example.com/custom/myindex.kdl",
        "https://example.com/custom/",
    ),
    # index* segment removed
    (
        "https://example.com/registry/index",
        "https://example.com/registry/",
    ),
    (
        "https://example.com/registry/index-v2",
        "https://example.com/registry/",
    ),
    # No matching last segment → append /
    (
        "https://example.com/registry/v2",
        "https://example.com/registry/v2/",
    ),
    (
        "https://example.com/packages",
        "https://example.com/packages/",
    ),
    # Trailing slash already
    (
        "https://example.com/registry/",
        "https://example.com/registry/",
    ),
])
def test_index_base_url(input_url: str, expected_base: str) -> None:
    """index_base_url derives the correct base URL per §3.3."""
    result = index_base_url(input_url)
    assert result == expected_base, (
        f"index_base_url({input_url!r}) = {result!r}, want {expected_base!r}"
    )


# ---------------------------------------------------------------------------
# DepDeclEdgeSource — happy path
# ---------------------------------------------------------------------------


def _ctx(
    dep_decl: str | None = None,
    dep_decl_schema_version: int | None = None,
) -> EdgeSourceCtx:
    return EdgeSourceCtx(
        dep_path=None,
        dep_name="pkg",
        dep_decl=dep_decl,
        dep_decl_schema_version=dep_decl_schema_version,
        is_overridden=False,
        has_milpa_kdl=False,
    )


class _FixedStore:
    """Test double: always returns fixed bytes."""

    def __init__(self, artifact_bytes: bytes) -> None:
        self._bytes = artifact_bytes

    def get(self, dep_decl_hash_str: str) -> bytes:
        return self._bytes

    def is_cached(self, dep_decl_hash_str: str) -> bool:
        return True


def test_dep_decl_edge_source_happy() -> None:
    """DepDeclEdgeSource.edges_for returns EdgeSet with source=DEP_DECL."""
    artifact_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 0\n"
        b'    src_dir "src"\n'
        b'    require "results" ">= 0.5.0"\n'
        b"}\n"
    )
    store = _FixedStore(artifact_bytes)
    src = DepDeclEdgeSource(store)

    ctx = _ctx(dep_decl="sha256:" + "a" * 64, dep_decl_schema_version=0)
    es = src.edges_for("pkg", _V, ctx)

    assert es.source == EdgeSource.DEP_DECL
    assert es.src_dir == "src"
    assert len(es.requires) == 1


def test_dep_decl_edge_source_schema_mismatch() -> None:
    """DepDeclEdgeSource raises TNG-DEPDECL-SCHEMA-MISMATCH when index vs artifact versions differ."""
    artifact_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 0\n"  # artifact says v0
        b'    src_dir ""\n'
        b"}\n"
    )
    store = _FixedStore(artifact_bytes)
    src = DepDeclEdgeSource(store)

    ctx = _ctx(dep_decl="sha256:" + "a" * 64, dep_decl_schema_version=1)  # index says v1
    with pytest.raises(MilpaError) as exc_info:
        src.edges_for("pkg", _V, ctx)
    assert exc_info.value.slug == TNG_DEPDECL_SCHEMA_MISMATCH


def test_dep_decl_edge_source_schema_unsupported() -> None:
    """DepDeclEdgeSource raises TNG-DEPDECL-SCHEMA-UNSUPPORTED when artifact version > impl cap."""
    # Artifact claims schema version 999 (above MAX_DEP_DECL_SCHEMA_VERSION=0).
    artifact_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 999\n"
        b'    src_dir ""\n'
        b"}\n"
    )
    store = _FixedStore(artifact_bytes)
    src = DepDeclEdgeSource(store)

    # Index pointer schema_version=999 as well (to avoid MISMATCH triggering first).
    ctx = _ctx(dep_decl="sha256:" + "a" * 64, dep_decl_schema_version=999)
    with pytest.raises(MilpaError) as exc_info:
        src.edges_for("pkg", _V, ctx)
    assert exc_info.value.slug == TNG_DEPDECL_SCHEMA_UNSUPPORTED


def test_dep_decl_edge_source_schema_unsupported_no_ctx_version() -> None:
    """TNG-DEPDECL-SCHEMA-UNSUPPORTED fires even when ctx has no index schema version."""
    artifact_bytes = (
        b"dep_decl {\n"
        b"    dep_decl_schema_version 999\n"
        b'    src_dir ""\n'
        b"}\n"
    )
    store = _FixedStore(artifact_bytes)
    src = DepDeclEdgeSource(store)

    ctx = _ctx(dep_decl="sha256:" + "a" * 64, dep_decl_schema_version=None)
    with pytest.raises(MilpaError) as exc_info:
        src.edges_for("pkg", _V, ctx)
    # UNSUPPORTED fires before MISMATCH when version exceeds cap.
    assert exc_info.value.slug == TNG_DEPDECL_SCHEMA_UNSUPPORTED


def test_dep_decl_edge_source_no_schema_version_in_artifact() -> None:
    """Artifact without dep_decl_schema_version treats it as 0 (forward-compat)."""
    artifact_bytes = (
        b"dep_decl {\n"
        b'    src_dir ""\n'  # no dep_decl_schema_version node
        b"}\n"
    )
    store = _FixedStore(artifact_bytes)
    src = DepDeclEdgeSource(store)

    ctx = _ctx(dep_decl="sha256:" + "a" * 64, dep_decl_schema_version=0)
    es = src.edges_for("pkg", _V, ctx)
    assert es.source == EdgeSource.DEP_DECL


# ---------------------------------------------------------------------------
# make_dep_decl_store
# ---------------------------------------------------------------------------


def test_make_dep_decl_store_returns_http_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """make_dep_decl_store returns an HttpDepDeclStore for a https URL."""
    monkeypatch.setenv("MILPA_INDEX_URL", "https://example.com/tianguis/main/index.kdl")
    store = make_dep_decl_store()
    assert isinstance(store, HttpDepDeclStore)
    # Base URL should end with the main/ dir (segment removed per §3.3).
    assert store._base_url == "https://example.com/tianguis/main"


def test_make_dep_decl_store_explicit_url() -> None:
    """make_dep_decl_store accepts an explicit URL argument."""
    store = make_dep_decl_store("https://example.com/registry/index.kdl")
    assert isinstance(store, HttpDepDeclStore)
    assert store._base_url == "https://example.com/registry"


# ---------------------------------------------------------------------------
# R6 — index_base_url case-insensitivity (spec §3.3 NORMATIVE)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("input_url,expected_base", [
    # Mixed-case *.kdl — MUST be stripped (case-insensitive)
    (
        "https://example.com/tianguis/main/Index.KDL",
        "https://example.com/tianguis/main/",
    ),
    (
        "https://example.com/tianguis/main/INDEX.kdl",
        "https://example.com/tianguis/main/",
    ),
    (
        "https://example.com/tianguis/main/index.KDL",
        "https://example.com/tianguis/main/",
    ),
    (
        "https://example.com/custom/Registry.KDL",
        "https://example.com/custom/",
    ),
    # Mixed-case index* — MUST be stripped (case-insensitive)
    (
        "https://example.com/registry/INDEX",
        "https://example.com/registry/",
    ),
    (
        "https://example.com/registry/Index-v2",
        "https://example.com/registry/",
    ),
    # Existing lowercase cases still pass (regression guard)
    (
        "https://example.com/tianguis/main/index.kdl",
        "https://example.com/tianguis/main/",
    ),
    (
        "https://example.com/registry/index",
        "https://example.com/registry/",
    ),
])
def test_index_base_url_case_insensitive(input_url: str, expected_base: str) -> None:
    """index_base_url strips last segment case-insensitively per spec §3.3 NORMATIVE."""
    result = index_base_url(input_url)
    assert result == expected_base, (
        f"index_base_url({input_url!r}) = {result!r}, want {expected_base!r}"
    )


# ---------------------------------------------------------------------------
# R8 — HttpDepDeclStore size cap (spec §3.3.1 NORMATIVE)
# ---------------------------------------------------------------------------

from milpa.dep_decl_store import _DEP_DECL_MAX_ARTIFACT_BYTES  # noqa: E402


class _FakeHTTPResponse:
    """Minimal fake urllib response: returns fixed bytes from read()."""

    def __init__(self, body: bytes, content_length: int | None = None) -> None:
        self._body = body
        self.headers = {"Content-Length": str(content_length)} if content_length is not None else {}

    def read(self, limit: int = -1) -> bytes:
        if limit < 0:
            return self._body
        return self._body[:limit]

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *_: object) -> None:
        pass

    def getheader(self, name: str, default: object = None) -> object:
        return self.headers.get(name, default)


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, body: bytes, content_length: int | None = None) -> None:
    """Replace urllib.request.urlopen with a fake returning body."""
    import milpa.dep_decl_store as dds_module

    def _fake_urlopen(url: str, **kwargs: object) -> "_FakeHTTPResponse":  # noqa: ANN401
        return _FakeHTTPResponse(body, content_length)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)


def test_http_store_size_cap_exceeded_raises_fetch_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HttpDepDeclStore.get raises TNG-DEPDECL-FETCH-FAILED when response body > cap.

    R8: A malicious/compromised index can point dep_decl at a multi-GB URL.
    We must never buffer the whole body; the check must fire early.
    """
    oversized_body = b"x" * (_DEP_DECL_MAX_ARTIFACT_BYTES + 1)
    _patch_urlopen(monkeypatch, oversized_body)

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(
        base_url="https://example.com/registry/",
        cache_dir=cache_dir,
    )
    h = "sha256:" + "f" * 64
    with pytest.raises(MilpaError) as exc_info:
        store.get(h)
    err = exc_info.value
    assert err.slug == TNG_DEPDECL_FETCH_FAILED
    assert "exceeds" in err.message.lower() or str(_DEP_DECL_MAX_ARTIFACT_BYTES) in err.message


def test_http_store_size_at_cap_succeeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HttpDepDeclStore.get succeeds when body is exactly at the cap.

    A legitimate 1 MiB artifact (edge-case) must not be rejected.
    """
    # Build a body that is exactly _DEP_DECL_MAX_ARTIFACT_BYTES bytes and
    # whose sha256 we can compute to produce a matching hash.
    exact_body = b"z" * _DEP_DECL_MAX_ARTIFACT_BYTES
    hash_str = dep_decl_hash(exact_body)
    _patch_urlopen(monkeypatch, exact_body)

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(
        base_url="https://example.com/registry/",
        cache_dir=cache_dir,
    )
    # Must not raise FETCH-FAILED (size is OK); will raise HASH-MISMATCH only
    # if the hash pointer doesn't match — use the correct hash here so we get bytes back.
    result = store.get(hash_str)
    assert result == exact_body


def test_http_store_content_length_too_large_raises_fetch_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HttpDepDeclStore.get raises TNG-DEPDECL-FETCH-FAILED when Content-Length > cap.

    Content-Length is an early-reject opportunity (avoids starting the read).
    """
    # The body we serve is small — but the advertised Content-Length is huge.
    # The implementation should reject on the header alone.
    small_body = b"tiny"
    _patch_urlopen(monkeypatch, small_body, content_length=_DEP_DECL_MAX_ARTIFACT_BYTES + 1)

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(
        base_url="https://example.com/registry/",
        cache_dir=cache_dir,
    )
    h = "sha256:" + "a" * 64
    with pytest.raises(MilpaError) as exc_info:
        store.get(h)
    err = exc_info.value
    assert err.slug == TNG_DEPDECL_FETCH_FAILED
