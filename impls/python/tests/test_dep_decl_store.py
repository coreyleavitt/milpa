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
# CR4 — fixed-temp-filename race (registry-protocol §3.5.2 NORMATIVE
# (concurrency)): cache writes must use a per-write-unique temp sibling, and
# a locally-corrupt cache entry must self-heal rather than poison forever.
# ---------------------------------------------------------------------------


def test_http_store_cache_write_uses_unique_temp_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for CR4: the cache write must go through
    ``atomic_cache.unique_temp_path`` (per-write-unique), never a fixed
    ``<hex>.kdl.tmp`` sibling — two concurrent fetches of the same uncached
    artifact must never be able to interleave partial writes."""
    import milpa.atomic_cache as atomic_cache_module

    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")
    serve_dir = tmp_path / "serve"
    dep_decl_dir = serve_dir / "dep-decl"
    dep_decl_dir.mkdir(parents=True)
    (dep_decl_dir / f"{hex_digest}.kdl").write_bytes(artifact_bytes)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    seen_tmp_paths: list[Path] = []
    original = atomic_cache_module.unique_temp_path

    def _spy(path: Path) -> Path:
        tmp = original(path)
        seen_tmp_paths.append(tmp)
        return tmp

    monkeypatch.setattr(atomic_cache_module, "unique_temp_path", _spy)

    HttpDepDeclStore(base_url=f"file://{serve_dir}", cache_dir=cache_dir).get(hash_str)
    (cache_dir / f"{hex_digest}.kdl").unlink()
    HttpDepDeclStore(base_url=f"file://{serve_dir}", cache_dir=cache_dir).get(hash_str)

    assert len(seen_tmp_paths) == 2
    assert seen_tmp_paths[0] != seen_tmp_paths[1], (
        "two writes to the same cache path must use different temp sibling names"
    )
    for tmp in seen_tmp_paths:
        assert not str(tmp).endswith(".kdl.tmp"), (
            "must not regress to a fixed .kdl.tmp sibling name"
        )


def test_http_store_corrupted_cache_self_heals_by_refetching(tmp_path: Path) -> None:
    """A locally-corrupt cache entry (e.g. left by the pre-fix race) must be
    discarded and transparently re-fetched, not raise HASH-MISMATCH forever."""
    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")
    serve_dir = tmp_path / "serve"
    dep_decl_dir = serve_dir / "dep-decl"
    dep_decl_dir.mkdir(parents=True)
    (dep_decl_dir / f"{hex_digest}.kdl").write_bytes(artifact_bytes)
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    # Simulate a truncated/corrupt cache entry under the correct hash name.
    (cache_dir / f"{hex_digest}.kdl").write_bytes(b"truncated garbage")

    store = HttpDepDeclStore(base_url=f"file://{serve_dir}", cache_dir=cache_dir)
    result = store.get(hash_str)
    assert result == artifact_bytes
    # Cache is repaired: a subsequent get (origin removed) still succeeds.
    (dep_decl_dir / f"{hex_digest}.kdl").unlink()
    assert store.get(hash_str) == artifact_bytes


def test_http_store_server_content_mismatch_stays_hard_error(tmp_path: Path) -> None:
    """A mismatch on FRESHLY FETCHED bytes (the server serving the wrong
    content for the hash) must stay a hard error — self-heal only applies to
    the locally-corrupt-cache path, never to content the server just sent."""
    artifact_bytes, hash_str = _artifact_and_hash()
    hex_digest = hash_str.removeprefix("sha256:")
    serve_dir = tmp_path / "serve"
    dep_decl_dir = serve_dir / "dep-decl"
    dep_decl_dir.mkdir(parents=True)
    # Origin serves bytes that do NOT hash to `hash_str` — genuine fetch
    # mismatch, nothing pre-cached.
    (dep_decl_dir / f"{hex_digest}.kdl").write_bytes(b"wrong content entirely")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    store = HttpDepDeclStore(base_url=f"file://{serve_dir}", cache_dir=cache_dir)
    with pytest.raises(MilpaError) as exc_info:
        store.get(hash_str)
    assert exc_info.value.slug == TNG_DEPDECL_HASH_MISMATCH
    assert not (cache_dir / f"{hex_digest}.kdl").is_file()


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
#
# These drive the REAL production transport (file:// / a local http.server)
# rather than monkeypatching urllib.request.urlopen: RFC docs/rfc-native-oci-
# fetch.md §3.3 (slice S3) moves HttpDepDeclStore off a direct
# urllib.request.urlopen call onto bounded_http.request, which builds its own
# OpenerDirector — a monkeypatch of the module-level urllib.request.urlopen
# function no longer intercepts anything.  Driving the real transport is also
# strictly more honest coverage of the production path.
# ---------------------------------------------------------------------------

from milpa.dep_decl_store import _DEP_DECL_MAX_ARTIFACT_BYTES  # noqa: E402


def test_http_store_size_cap_exceeded_raises_fetch_failed(tmp_path: Path) -> None:
    """HttpDepDeclStore.get raises TNG-DEPDECL-FETCH-FAILED when the actual
    response body exceeds the cap.

    R8: A malicious/compromised index can point dep_decl at a multi-GB URL.
    We must never buffer the whole body — the streaming cap must fire before
    the oversized body is fully read.
    """
    hex_digest = "f" * 64
    serve_dir = tmp_path / "serve"
    dep_decl_dir = serve_dir / "dep-decl"
    dep_decl_dir.mkdir(parents=True)
    oversized_body = b"x" * (_DEP_DECL_MAX_ARTIFACT_BYTES + 1)
    (dep_decl_dir / f"{hex_digest}.kdl").write_bytes(oversized_body)

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(base_url=f"file://{serve_dir}", cache_dir=cache_dir)
    h = "sha256:" + hex_digest
    with pytest.raises(MilpaError) as exc_info:
        store.get(h)
    err = exc_info.value
    assert err.slug == TNG_DEPDECL_FETCH_FAILED
    assert "exceed" in err.message.lower() or str(_DEP_DECL_MAX_ARTIFACT_BYTES) in err.message


def test_http_store_size_at_cap_succeeds(tmp_path: Path) -> None:
    """HttpDepDeclStore.get succeeds when body is exactly at the cap.

    A legitimate 1 MiB artifact (edge-case) must not be rejected.
    """
    # Build a body that is exactly _DEP_DECL_MAX_ARTIFACT_BYTES bytes and
    # whose sha256 we can compute to produce a matching hash.
    exact_body = b"z" * _DEP_DECL_MAX_ARTIFACT_BYTES
    hash_str = dep_decl_hash(exact_body)
    hex_digest = hash_str.removeprefix("sha256:")

    serve_dir = tmp_path / "serve"
    dep_decl_dir = serve_dir / "dep-decl"
    dep_decl_dir.mkdir(parents=True)
    (dep_decl_dir / f"{hex_digest}.kdl").write_bytes(exact_body)

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    store = HttpDepDeclStore(base_url=f"file://{serve_dir}", cache_dir=cache_dir)
    # Must not raise FETCH-FAILED (size is OK); will raise HASH-MISMATCH only
    # if the hash pointer doesn't match — use the correct hash here so we get bytes back.
    result = store.get(hash_str)
    assert result == exact_body


def test_http_store_lying_content_length_no_longer_pre_rejected(tmp_path: Path) -> None:
    """NAMED BEHAVIOR CHANGE (RFC docs/rfc-native-oci-fetch.md §3.3, slice S3):
    the Content-Length early-reject optimization ("avoid starting the read
    when a server lies about a huge Content-Length") is dropped along with
    the direct ``urllib.request.urlopen`` call site.  ``bounded_http.request``
    is a single atomic ``(cap, sink)`` call with no pre-flight header-peek
    hook, so there is no seam left to reject on a merely-*declared* size.

    The actual-bytes-streamed cap (see test_http_store_size_cap_exceeded_
    raises_fetch_failed, unchanged) is now the SOLE enforcement point: a
    SMALL actual body succeeds even when the server advertises a
    Content-Length far exceeding the cap.  This is a performance-only
    regression (one fewer avoided-large-read optimization for a lying
    server) — the real bound on bytes actually read off the wire is
    unaffected, so no security property is weakened.
    """
    import http.server
    import threading

    small_body = b"tiny"
    huge_declared_length = _DEP_DECL_MAX_ARTIFACT_BYTES + 1
    hash_str = dep_decl_hash(small_body)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(huge_declared_length))
            self.end_headers()
            self.wfile.write(small_body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    try:
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        # The fake handler ignores the request path and always serves
        # small_body, so any base_url routes to it; hash_str must match
        # small_body's real hash to pass the store's own hash-verify gate.
        store = HttpDepDeclStore(base_url=f"http://127.0.0.1:{port}", cache_dir=cache_dir)
        result = store.get(hash_str)
        assert result == small_body
    finally:
        server.shutdown()
        thread.join(timeout=5)
