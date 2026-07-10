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
