"""Unit tests for entry_bundle_store.py (P3a, RFC per-entry-attestation.md §7).

Covers:
  - FileEntryBundleStore: get (happy) / hash-mismatch / missing-file (BUNDLE-MISSING)
  - HttpEntryBundleStore: cache-hit / cache-miss fetch (file:// transport) / not-found
  - entry_bundle_store_from_paths: priority table mirroring dep_decl_store_from_paths
  - _verify: one hash-verify site (SECURITY INVARIANT)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from milpa.entry_bundle_store import (
    FileEntryBundleStore,
    HttpEntryBundleStore,
    _verify,
    entry_bundle_store_from_paths,
)
from milpa.errors import (
    TNG_ENTRY_BUNDLE_MISSING,
    TNG_ENTRY_BUNDLE_PIN_MISMATCH,
    MilpaError,
)


def _bundle_and_pin() -> tuple[bytes, str]:
    bundle_bytes = b'{"dsseEnvelope": {"payload": "eyJ9"}}'
    pin = hashlib.sha256(bundle_bytes).hexdigest()
    return bundle_bytes, pin


def _put_bundle(dir: Path, bundle_bytes: bytes, pin: str) -> Path:
    path = dir / f"{pin}.bundle"
    path.write_bytes(bundle_bytes)
    return path


# ---------------------------------------------------------------------------
# _verify
# ---------------------------------------------------------------------------


def test_verify_accepts_matching_hash() -> None:
    bundle_bytes, pin = _bundle_and_pin()
    _verify(bundle_bytes, pin)  # no raise


def test_verify_rejects_mismatched_hash() -> None:
    bundle_bytes, pin = _bundle_and_pin()
    with pytest.raises(MilpaError) as exc_info:
        _verify(bundle_bytes, "0" * 64)
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH


# ---------------------------------------------------------------------------
# FileEntryBundleStore
# ---------------------------------------------------------------------------


def test_file_store_get_happy_path(tmp_path: Path) -> None:
    bundle_bytes, pin = _bundle_and_pin()
    _put_bundle(tmp_path, bundle_bytes, pin)

    store = FileEntryBundleStore(tmp_path)
    result = store.get(pin)
    assert result == bundle_bytes
    assert store.is_cached(pin)


def test_file_store_get_missing_raises_bundle_missing(tmp_path: Path) -> None:
    store = FileEntryBundleStore(tmp_path)
    with pytest.raises(MilpaError) as exc_info:
        store.get("a" * 64)
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_MISSING
    assert exc_info.value.context.get("cause") == "unfetchable"
    assert not store.is_cached("a" * 64)


def test_file_store_get_hash_mismatch_raises_pin_mismatch(tmp_path: Path) -> None:
    bundle_bytes, pin = _bundle_and_pin()
    # Store under a DIFFERENT pin than the actual hash — simulates corruption.
    wrong_pin = "b" * 64
    _put_bundle(tmp_path, bundle_bytes, wrong_pin)

    store = FileEntryBundleStore(tmp_path)
    with pytest.raises(MilpaError) as exc_info:
        store.get(wrong_pin)
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH


# ---------------------------------------------------------------------------
# HttpEntryBundleStore — file:// transport (no live network)
# ---------------------------------------------------------------------------


def test_http_store_fetches_and_caches_via_file_scheme(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    cache = tmp_path / "cache"
    bundle_bytes, pin = _bundle_and_pin()
    (origin / "attestation").mkdir()
    (origin / "attestation" / f"{pin}.bundle").write_bytes(bundle_bytes)

    store = HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache)
    result = store.get(pin)
    assert result == bundle_bytes
    # Cached after first fetch.
    assert store.is_cached(pin)
    assert (cache / f"{pin}.bundle").read_bytes() == bundle_bytes

    # Second get is a cache hit (no re-fetch needed — verified implicitly by
    # deleting the origin and confirming get() still succeeds).
    (origin / "attestation" / f"{pin}.bundle").unlink()
    result2 = store.get(pin)
    assert result2 == bundle_bytes


def test_http_store_not_found_raises_bundle_missing(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "attestation").mkdir()
    cache = tmp_path / "cache"

    store = HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache)
    with pytest.raises(MilpaError) as exc_info:
        store.get("c" * 64)
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_MISSING
    assert exc_info.value.context.get("cause") == "unfetchable"


# ---------------------------------------------------------------------------
# Size cap (mirrors dep_decl_store.py's R8) — driven against the REAL
# production transport (file:// / a local http.server), RFC docs/rfc-native-
# oci-fetch.md §3.3 slice S3.
# ---------------------------------------------------------------------------

from milpa.entry_bundle_store import _ENTRY_BUNDLE_MAX_ARTIFACT_BYTES  # noqa: E402


def test_http_store_size_cap_exceeded_raises_bundle_missing(tmp_path: Path) -> None:
    """HttpEntryBundleStore.get raises TNG-ENTRY-BUNDLE-MISSING when the
    actual response body exceeds the cap — never buffer the whole body."""
    pin = "f" * 64
    origin = tmp_path / "origin"
    (origin / "attestation").mkdir(parents=True)
    oversized_body = b"x" * (_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES + 1)
    (origin / "attestation" / f"{pin}.bundle").write_bytes(oversized_body)
    cache = tmp_path / "cache"

    store = HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache)
    with pytest.raises(MilpaError) as exc_info:
        store.get(pin)
    err = exc_info.value
    assert err.slug == TNG_ENTRY_BUNDLE_MISSING
    assert err.context.get("cause") == "unfetchable"
    assert "exceed" in err.message.lower() or str(_ENTRY_BUNDLE_MAX_ARTIFACT_BYTES) in err.message


def test_http_store_size_at_cap_succeeds(tmp_path: Path) -> None:
    """A legitimate bundle of exactly the cap size must not be rejected."""
    exact_body = b"z" * _ENTRY_BUNDLE_MAX_ARTIFACT_BYTES
    pin = hashlib.sha256(exact_body).hexdigest()
    origin = tmp_path / "origin"
    (origin / "attestation").mkdir(parents=True)
    (origin / "attestation" / f"{pin}.bundle").write_bytes(exact_body)
    cache = tmp_path / "cache"

    store = HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache)
    result = store.get(pin)
    assert result == exact_body


def test_http_store_lying_content_length_no_longer_pre_rejected(tmp_path: Path) -> None:
    """NAMED BEHAVIOR CHANGE (RFC docs/rfc-native-oci-fetch.md §3.3, slice S3):
    mirrors dep_decl_store.py's identical change.  The Content-Length
    early-reject optimization is dropped along with the direct
    ``urllib.request.urlopen`` call site — ``bounded_http.request`` has no
    pre-flight header-peek hook.  The actual-bytes-streamed cap (see
    test_http_store_size_cap_exceeded_raises_bundle_missing, unchanged) is
    now the sole enforcement point: a small actual body succeeds even when
    the server advertises a Content-Length far exceeding the cap.
    """
    import http.server
    import threading

    small_body = b"tiny"
    huge_declared_length = _ENTRY_BUNDLE_MAX_ARTIFACT_BYTES + 1
    pin = hashlib.sha256(small_body).hexdigest()

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
        cache = tmp_path / "cache"
        store = HttpEntryBundleStore(base_url=f"http://127.0.0.1:{port}", cache_dir=cache)
        result = store.get(pin)
        assert result == small_body
    finally:
        server.shutdown()
        thread.join(timeout=5)


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
    ``<pin>.bundle.tmp`` sibling — two concurrent fetches of the same
    uncached bundle must never be able to interleave partial writes."""
    import milpa.atomic_cache as atomic_cache_module

    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "attestation").mkdir()
    cache = tmp_path / "cache"
    bundle_bytes, pin = _bundle_and_pin()
    (origin / "attestation" / f"{pin}.bundle").write_bytes(bundle_bytes)

    seen_tmp_paths: list[Path] = []
    original = atomic_cache_module.unique_temp_path

    def _spy(path: Path) -> Path:
        tmp = original(path)
        seen_tmp_paths.append(tmp)
        return tmp

    monkeypatch.setattr(atomic_cache_module, "unique_temp_path", _spy)

    HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache).get(pin)
    (cache / f"{pin}.bundle").unlink()
    HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache).get(pin)

    assert len(seen_tmp_paths) == 2
    assert seen_tmp_paths[0] != seen_tmp_paths[1], (
        "two writes to the same cache path must use different temp sibling names"
    )
    for tmp in seen_tmp_paths:
        assert not str(tmp).endswith(".bundle.tmp"), (
            "must not regress to a fixed .bundle.tmp sibling name"
        )


def test_http_store_corrupted_cache_self_heals_by_refetching(tmp_path: Path) -> None:
    """A locally-corrupt cache entry (e.g. left by the pre-fix race) must be
    discarded and transparently re-fetched, not raise PIN-MISMATCH forever."""
    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "attestation").mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    bundle_bytes, pin = _bundle_and_pin()
    (origin / "attestation" / f"{pin}.bundle").write_bytes(bundle_bytes)
    # Simulate a truncated/corrupt cache entry under the correct pin.
    (cache / f"{pin}.bundle").write_bytes(b"truncated garbage")

    store = HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache)
    result = store.get(pin)
    assert result == bundle_bytes
    # Cache is repaired: a subsequent get (origin removed) still succeeds.
    (origin / "attestation" / f"{pin}.bundle").unlink()
    assert store.get(pin) == bundle_bytes


def test_http_store_server_content_mismatch_stays_hard_error(tmp_path: Path) -> None:
    """A mismatch on FRESHLY FETCHED bytes (the server serving the wrong
    content for the pin) must stay a hard error — self-heal only applies to
    the locally-corrupt-cache path, never to content the server just sent."""
    origin = tmp_path / "origin"
    origin.mkdir()
    (origin / "attestation").mkdir()
    cache = tmp_path / "cache"
    bundle_bytes, pin = _bundle_and_pin()
    # Origin serves bytes that do NOT hash to `pin` (server misconfiguration
    # / tampering) — nothing pre-cached, so this is a genuine fetch mismatch.
    (origin / "attestation" / f"{pin}.bundle").write_bytes(b"wrong content entirely")

    store = HttpEntryBundleStore(base_url=f"file://{origin}", cache_dir=cache)
    with pytest.raises(MilpaError) as exc_info:
        store.get(pin)
    assert exc_info.value.slug == TNG_ENTRY_BUNDLE_PIN_MISMATCH
    # Must NOT have cached the bad bytes.
    assert not store.is_cached(pin)


# ---------------------------------------------------------------------------
# entry_bundle_store_from_paths — priority table
# ---------------------------------------------------------------------------


def test_from_paths_no_index_returns_none(tmp_path: Path) -> None:
    assert entry_bundle_store_from_paths(tmp_path, "https://example.com/index.kdl", no_index=True) is None


def test_from_paths_dir_wins_over_url(tmp_path: Path) -> None:
    d = tmp_path / "bundles"
    d.mkdir()
    store = entry_bundle_store_from_paths(d, "https://example.com/index.kdl", no_index=False)
    assert isinstance(store, FileEntryBundleStore)


def test_from_paths_falls_back_to_http(tmp_path: Path) -> None:
    store = entry_bundle_store_from_paths(None, "https://example.com/registry/index.kdl", no_index=False)
    assert isinstance(store, HttpEntryBundleStore)


def test_from_paths_no_index_url_returns_none() -> None:
    assert entry_bundle_store_from_paths(None, None, no_index=False) is None
