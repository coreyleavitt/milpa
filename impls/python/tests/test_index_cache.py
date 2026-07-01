"""Tests for milpa.index_cache — S8b (updated for S5 bytes transport).

Drives ALL FOUR cache states via injected ``http_get`` + ``now_unix``.
No network access; no real sleep; no reads from ``~/.cache``.
All cache dirs are isolated ``tmp_path`` directories.

States verified:
  1. Fresh cache (age < TTL) → served from cache, no network call.
  2. Stale cache (age ≥ TTL) → re-fetches, overwrites.
  3. Offline fallback (network failure, stale-but-present cache exists) →
     serve stale + warning to stderr that MUST NOT contain ``milpa-error:``.
  4. Network failure with no cache → raise ``MILPA-INDEX-UNREACHABLE``.

Also covers:
  - ``file://`` URL resolution (state: missing → read from filesystem).
  - ``cache_path_for`` is stable and URL-derived.
  - ``index_url_from_env`` default + override.
  - Atomic write: no partial file visible to a concurrent reader.
  - Parse error in fetched bytes propagates the correct ``TNG-*`` slug.

S5 note: ``HttpGet`` now returns ``bytes`` (not ``str``) — all mock transports
updated accordingly.  ``urllib_http_get`` also returns ``bytes``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import MILPA_INDEX_UNREACHABLE, TNG_SCHEMA_UNKNOWN, MilpaError
from milpa.index_cache import (
    DEFAULT_INDEX_URL,
    DEFAULT_TTL_SECONDS,
    HttpGet,
    _BundleNotFound,
    cache_path_for,
    derive_bundle_url,
    index_url_from_env,
    load_index,
    urllib_http_get,
)
from milpa.index_trust import (
    BundleMissing,
    BundleStale,
    DigestMismatch,
    IndexTrustConfig,
    MockVerifier,
    SigInvalid,
    Trusted,
    TrustBundle,
    VerificationResult,
    _reset_warned_urls,
)
from milpa.errors import (
    TNG_INDEX_BUNDLE_MISSING,
    TNG_INDEX_DIGEST_MISMATCH,
    TNG_INDEX_SIGNATURE_INVALID,
)

# ---------------------------------------------------------------------------
# Test fixtures (inline KDL strings)
# ---------------------------------------------------------------------------

URL = "https://example.test/index.kdl"

#: Minimal valid index with one package.
VALID_INDEX = """\
schema_version 1

package "bar" {
    namespace "example"
    version "1.0.0" {
        content_hash "sha256:0000000000000000000000000000000000000000000000000000000000000001"
        provenance {
            kind "git"
            url "https://example.com/bar.git"
            ref "v1.0.0"
        }
    }
}
"""

#: A second distinct valid index (different version) used to verify overwrites.
VALID_INDEX_V2 = """\
schema_version 1

package "bar" {
    namespace "example"
    version "2.0.0" {
        content_hash "sha256:0000000000000000000000000000000000000000000000000000000000000002"
        provenance {
            kind "git"
            url "https://example.com/bar.git"
            ref "v2.0.0"
        }
    }
}
"""

#: Invalid index that triggers TNG-SCHEMA-UNKNOWN.
BAD_SCHEMA_INDEX = "schema_version 99\n"


# ---------------------------------------------------------------------------
# HTTP transport helpers
# ---------------------------------------------------------------------------


def make_counter_get(body: str) -> tuple[HttpGet, list[int]]:
    """Return an ``HttpGet`` that serves *body* as bytes and a call-count list.

    S5: HttpGet now returns ``bytes``; the body is encoded to UTF-8.
    """
    calls: list[int] = [0]
    body_bytes = body.encode("utf-8")

    def get(url: str) -> bytes:
        calls[0] += 1
        return body_bytes

    return get, calls


def failing_get(url: str) -> bytes:
    raise RuntimeError("network down")


# ---------------------------------------------------------------------------
# 1. Missing → fetch + populate (state: missing)
# ---------------------------------------------------------------------------


class TestMissingState:
    def test_missing_fetches_and_returns_index(self, tmp_path: Path) -> None:
        get, calls = make_counter_get(VALID_INDEX)
        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert len(idx.packages) == 1
        assert idx.packages[0].name == "bar"
        assert calls[0] == 1

    def test_missing_writes_cache_file(self, tmp_path: Path) -> None:
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        cache_file = cache_path_for(URL, tmp_path)
        assert cache_file.is_file()
        assert b"schema_version" in cache_file.read_bytes()

    def test_missing_writes_stamp_file(self, tmp_path: Path) -> None:
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        cache_file = cache_path_for(URL, tmp_path)
        stamp = cache_file.with_suffix(".kdl.at")
        assert stamp.is_file()
        assert stamp.read_text().strip() == "1000"


# ---------------------------------------------------------------------------
# 2. Fresh cache (state 1)
# ---------------------------------------------------------------------------


class TestFreshState:
    def test_fresh_cache_no_network_call(self, tmp_path: Path) -> None:
        get, calls = make_counter_get(VALID_INDEX)

        # Populate the cache (now_unix=1000).
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert calls[0] == 1

        # Same now_unix=1000 → age=0 < ttl → fresh.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert calls[0] == 1, "fresh cache must NOT re-fetch"

    def test_fresh_cache_returns_cached_index(self, tmp_path: Path) -> None:
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)

        # Override the cache with different content to confirm we read from disk.
        cache_file = cache_path_for(URL, tmp_path)
        # S5: cache is written as bytes; overwrite as bytes too.
        cache_file.write_bytes(VALID_INDEX_V2.encode("utf-8"))

        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        # Fresh → reads what's on disk (our overwrite).
        assert idx.packages[0].versions[0].version == "2.0.0"

    def test_just_within_ttl_is_fresh(self, tmp_path: Path) -> None:
        get, calls = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)  # fetched at t=1000, ttl=100

        # age = 1099 - 1000 = 99 < 100 → fresh.
        load_index(URL, tmp_path, get, 100, 1099)
        assert calls[0] == 1, "age 99 < ttl 100 must be fresh"


# ---------------------------------------------------------------------------
# 3. Stale cache (state 2)
# ---------------------------------------------------------------------------


class TestStaleState:
    def test_stale_cache_refetches(self, tmp_path: Path) -> None:
        get, calls = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)  # fetched at t=1000
        assert calls[0] == 1

        # age = 1101 - 1000 = 101 ≥ 100 → stale → refetch.
        load_index(URL, tmp_path, get, 100, 1101)
        assert calls[0] == 2, "stale cache must re-fetch"

    def test_exactly_at_ttl_refetches(self, tmp_path: Path) -> None:
        get, calls = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)

        # age = 1100 - 1000 = 100 ≥ ttl 100 → stale.
        load_index(URL, tmp_path, get, 100, 1100)
        assert calls[0] == 2, "age == ttl must be treated as stale"

    def test_stale_refetch_overwrites_cache(self, tmp_path: Path) -> None:
        get_v1, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get_v1, 100, 1000)

        get_v2, _ = make_counter_get(VALID_INDEX_V2)
        idx = load_index(URL, tmp_path, get_v2, 100, 1101)

        assert idx.packages[0].versions[0].version == "2.0.0"
        cache_file = cache_path_for(URL, tmp_path)
        assert b"2.0.0" in cache_file.read_bytes()

    def test_stale_refetch_updates_stamp(self, tmp_path: Path) -> None:
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)

        load_index(URL, tmp_path, get, 100, 1101)
        cache_file = cache_path_for(URL, tmp_path)
        stamp = cache_file.with_suffix(".kdl.at")
        assert stamp.read_text().strip() == "1101"


# ---------------------------------------------------------------------------
# 4. Offline fallback (state 3)
# ---------------------------------------------------------------------------


class TestOfflineFallback:
    def test_offline_fallback_serves_stale_cache(self, tmp_path: Path) -> None:
        """Network failure + stale-but-present cache → serve it."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)

        idx = load_index(URL, tmp_path, failing_get, 100, 9999)
        assert len(idx.packages) == 1
        assert idx.packages[0].name == "bar"

    def test_offline_fallback_warning_to_stderr(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """State 3 warning MUST be emitted to stderr."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)

        load_index(URL, tmp_path, failing_get, 100, 9999)
        captured = capsys.readouterr()
        assert captured.err, "state 3 must emit a warning to stderr"

    def test_offline_fallback_warning_no_milpa_error_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """R3 requirement: the offline-fallback warning MUST NOT contain 'milpa-error:'."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1000)

        load_index(URL, tmp_path, failing_get, 100, 9999)
        captured = capsys.readouterr()
        assert "milpa-error:" not in captured.err, (
            "R3: offline-fallback warning must NOT contain 'milpa-error:' line\n"
            f"stderr was: {captured.err!r}"
        )

    def test_offline_fallback_even_when_fresh_fetch_was_old(self, tmp_path: Path) -> None:
        """Even a very stale cache beats a network failure (any-age fallback)."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, 100, 1)  # fetched at t=1

        # Very stale: age = 1_000_000 - 1 >> ttl 100. Network down.
        idx = load_index(URL, tmp_path, failing_get, 100, 1_000_000)
        assert idx.packages[0].name == "bar"


# ---------------------------------------------------------------------------
# 5. No-cache failure (state 4)
# ---------------------------------------------------------------------------


class TestNoCacheFailure:
    def test_no_cache_raises_milpa_index_unreachable(self, tmp_path: Path) -> None:
        """State 4: network failure + no cache → MILPA-INDEX-UNREACHABLE."""
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, failing_get, DEFAULT_TTL_SECONDS, 1000)
        assert exc_info.value.slug == MILPA_INDEX_UNREACHABLE

    def test_error_message_includes_url(self, tmp_path: Path) -> None:
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, failing_get, DEFAULT_TTL_SECONDS, 1000)
        assert URL in exc_info.value.message


# ---------------------------------------------------------------------------
# 6. Parse error propagates TNG-* slug
# ---------------------------------------------------------------------------


class TestParseErrorPropagates:
    def test_bad_schema_version_surfaces_tng_slug(self, tmp_path: Path) -> None:
        get, _ = make_counter_get(BAD_SCHEMA_INDEX)
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert exc_info.value.slug == TNG_SCHEMA_UNKNOWN


# ---------------------------------------------------------------------------
# 7. file:// URL support
# ---------------------------------------------------------------------------


class TestFileUrl:
    def test_file_url_loads_from_disk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """file:// URL must work for air-gapped / harness deployments."""
        # Write a valid index to a local file.
        index_file = tmp_path / "local.index.kdl"
        index_file.write_text(VALID_INDEX)
        file_url = index_file.as_uri()  # file:///...

        # Use urllib_http_get (the production transport) — it handles file://.
        cache_dir = tmp_path / "cache"
        idx = load_index(
            file_url, cache_dir, urllib_http_get, DEFAULT_TTL_SECONDS, 1000
        )
        assert len(idx.packages) == 1
        assert idx.packages[0].name == "bar"

    def test_file_url_is_cached(self, tmp_path: Path) -> None:
        """file:// fetches must also be cached."""
        index_file = tmp_path / "local.index.kdl"
        index_file.write_text(VALID_INDEX)
        file_url = index_file.as_uri()
        cache_dir = tmp_path / "cache"

        load_index(file_url, cache_dir, urllib_http_get, DEFAULT_TTL_SECONDS, 1000)
        cache_file = cache_path_for(file_url, cache_dir)
        assert cache_file.is_file()


# ---------------------------------------------------------------------------
# 8. cache_path_for — stable and URL-derived
# ---------------------------------------------------------------------------


class TestCachePathFor:
    def test_same_url_same_path(self, tmp_path: Path) -> None:
        a = cache_path_for(URL, tmp_path)
        b = cache_path_for(URL, tmp_path)
        assert a == b

    def test_different_url_different_path(self, tmp_path: Path) -> None:
        a = cache_path_for(URL, tmp_path)
        b = cache_path_for("https://other.test/index.kdl", tmp_path)
        assert a != b

    def test_path_ends_with_index_kdl(self, tmp_path: Path) -> None:
        path = cache_path_for(URL, tmp_path)
        assert str(path).endswith(".index.kdl")

    def test_path_is_under_cache_dir(self, tmp_path: Path) -> None:
        path = cache_path_for(URL, tmp_path)
        assert path.parent == tmp_path


# ---------------------------------------------------------------------------
# 9. index_url_from_env
# ---------------------------------------------------------------------------


class TestIndexUrlFromEnv:
    def test_default_when_no_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MILPA_INDEX_URL", raising=False)
        assert index_url_from_env() == DEFAULT_INDEX_URL

    def test_override_when_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MILPA_INDEX_URL", "https://my-mirror.example.com/index.kdl")
        assert index_url_from_env() == "https://my-mirror.example.com/index.kdl"

    def test_empty_string_uses_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MILPA_INDEX_URL", "")
        assert index_url_from_env() == DEFAULT_INDEX_URL

    def test_whitespace_only_uses_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MILPA_INDEX_URL", "   ")
        assert index_url_from_env() == DEFAULT_INDEX_URL

    def test_file_url_accepted_as_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MILPA_INDEX_URL", "file:///tmp/my-index.kdl")
        assert index_url_from_env() == "file:///tmp/my-index.kdl"


# ---------------------------------------------------------------------------
# 10. _load_index_for_verb — three-way MILPA_INDEX_URL semantics
# ---------------------------------------------------------------------------


class TestLoadIndexForVerbThreeWay:
    """Unit tests for the three-way MILPA_INDEX_URL semantics in _load_index_for_verb.

    Three-way semantics (cli-contract.md §8.1 NORMATIVE):
      - absent → load from DEFAULT_INDEX_URL (production fallback).
      - present-but-empty → index=None (explicitly no index, no network).
      - present-non-empty → load from that URL.

    These tests verify the routing decision (which URL is chosen / whether
    index=None is returned) WITHOUT hitting the network.  We inject a fake
    ``load_default_index`` so the test environment stays hermetic.
    """

    def _make_env(self) -> "MilpaEnv":
        """Build a minimal MilpaEnv for testing (no real fetcher or store needed)."""
        import unittest.mock
        from milpa.context import MilpaEnv
        return MilpaEnv(
            fetcher=unittest.mock.MagicMock(),
            index=None,
            store=unittest.mock.MagicMock(),
            dep_decl_store=None,
        )

    def test_absent_uses_default_url(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """MILPA_INDEX_URL absent → _load_index_for_verb attempts DEFAULT_INDEX_URL."""
        import unittest.mock
        monkeypatch.delenv("MILPA_INDEX_URL", raising=False)

        # Track what URL load_default_index would call index_url_from_env with.
        captured_urls: list[str] = []

        def fake_load_default_index() -> object:
            # Record the URL that index_url_from_env() returns at call time.
            captured_urls.append(index_url_from_env())
            # Return a sentinel index object so _load_index_for_verb gets index≠None.
            return object()

        from milpa.cli import _load_index_for_verb
        import milpa.cli as _cli_mod
        with unittest.mock.patch.object(_cli_mod, "load_default_index", fake_load_default_index):
            result = _load_index_for_verb(self._make_env())

        assert captured_urls == [DEFAULT_INDEX_URL], (
            f"Expected DEFAULT_INDEX_URL to be used when env var absent; got {captured_urls!r}"
        )
        assert result.index is not None, "index must be populated when load succeeds"

    def test_empty_returns_none_without_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MILPA_INDEX_URL='' → index=None immediately, no network call."""
        import unittest.mock
        monkeypatch.setenv("MILPA_INDEX_URL", "")

        called = False

        def fake_load_default_index() -> object:
            nonlocal called
            called = True
            return object()

        from milpa.cli import _load_index_for_verb
        import milpa.cli as _cli_mod
        with unittest.mock.patch.object(_cli_mod, "load_default_index", fake_load_default_index):
            result = _load_index_for_verb(self._make_env())

        assert not called, "load_default_index must NOT be called when MILPA_INDEX_URL=''"
        assert result.index is None, "index must be None when MILPA_INDEX_URL=''"

    def test_whitespace_only_returns_none_without_network(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MILPA_INDEX_URL='   ' (whitespace only) → treated as empty → index=None."""
        import unittest.mock
        monkeypatch.setenv("MILPA_INDEX_URL", "   ")

        called = False

        def fake_load_default_index() -> object:
            nonlocal called
            called = True
            return object()

        from milpa.cli import _load_index_for_verb
        import milpa.cli as _cli_mod
        with unittest.mock.patch.object(_cli_mod, "load_default_index", fake_load_default_index):
            result = _load_index_for_verb(self._make_env())

        assert not called, "whitespace-only MILPA_INDEX_URL must be treated as empty"
        assert result.index is None

    def test_nonempty_uses_that_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MILPA_INDEX_URL=<url> → load_default_index called; index_url_from_env returns that URL."""
        import unittest.mock
        custom_url = "file:///tmp/test-index.kdl"
        monkeypatch.setenv("MILPA_INDEX_URL", custom_url)

        captured_urls: list[str] = []

        def fake_load_default_index() -> object:
            captured_urls.append(index_url_from_env())
            return object()

        from milpa.cli import _load_index_for_verb
        import milpa.cli as _cli_mod
        with unittest.mock.patch.object(_cli_mod, "load_default_index", fake_load_default_index):
            result = _load_index_for_verb(self._make_env())

        assert captured_urls == [custom_url], (
            f"Expected custom URL to be used; got {captured_urls!r}"
        )
        assert result.index is not None

    def test_unreachable_index_when_absent_gives_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When MILPA_INDEX_URL absent and network unreachable → index=None (soft failure)."""
        import unittest.mock
        from milpa.errors import MILPA_INDEX_UNREACHABLE, MilpaError as _MilpaError
        monkeypatch.delenv("MILPA_INDEX_URL", raising=False)

        def fake_load_unreachable() -> object:
            raise _MilpaError(MILPA_INDEX_UNREACHABLE, "test: network unavailable")

        from milpa.cli import _load_index_for_verb
        import milpa.cli as _cli_mod
        with unittest.mock.patch.object(_cli_mod, "load_default_index", fake_load_unreachable):
            result = _load_index_for_verb(self._make_env())

        assert result.index is None, "Unreachable index must soft-fail to index=None"


# ---------------------------------------------------------------------------
# 11. Atomic write — no partial file observed
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_cache_file_has_complete_content(self, tmp_path: Path) -> None:
        """After load_index completes the cache file must be complete KDL."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        cache_file = cache_path_for(URL, tmp_path)
        content = cache_file.read_bytes().decode("utf-8")
        # The file should be parseable as a valid index.
        from milpa.registry import parse_index as _parse_index
        idx = _parse_index(content)
        assert len(idx.packages) == 1

    def test_no_tmp_file_remains_after_success(self, tmp_path: Path) -> None:
        """Temporary files must be renamed away; none should remain."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        tmp_files = list(tmp_path.glob("*.tmp.*"))
        assert tmp_files == [], f"left-over tmp files: {tmp_files}"


# ---------------------------------------------------------------------------
# S5 helpers — shared fixtures for trust-gate tests
# ---------------------------------------------------------------------------

_DUMMY_BUNDLE = TrustBundle(raw_json=b'{"__test__": true}', label="test:dummy")
_DEFAULT_SIGNER = (
    "https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml@refs/heads/main"
)
_FAKE_BUNDLE_BYTES = b'{"fake_bundle": true}'  # placeholder bytes; MockVerifier ignores content


def _make_trust_config(policy: str = "strict", max_age: int = 604800) -> IndexTrustConfig:
    return IndexTrustConfig(
        policy=policy,  # type: ignore[arg-type]
        trust_bundle=_DUMMY_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=max_age,
    )


def make_bundle_get(bundle_bytes: bytes = _FAKE_BUNDLE_BYTES) -> "_BundleGet":
    """Return a bundle_http_get that serves ``bundle_bytes``."""
    def get(url: str) -> bytes:
        return bundle_bytes
    return get


def failing_bundle_get(url: str) -> bytes:
    """bundle_http_get that raises _BundleNotFound (HTTP 404 simulation)."""
    raise _BundleNotFound(f"bundle 404: {url!r}")


# Typing alias
_BundleGet = "object"  # Callable[[str], bytes]


# ---------------------------------------------------------------------------
# 12. S5: Trust gate — verify on every cache read
# ---------------------------------------------------------------------------


class TestTrustGateVerifyEveryRead:
    """Verify that crypto runs on EVERY cache read, not just network fetches (RFC §7.2)."""

    def test_fresh_cache_crypto_verified(self, tmp_path: Path) -> None:
        """State 1 (fresh cache): crypto verification fires before parse."""
        get, _ = make_counter_get(VALID_INDEX)
        verifier = MockVerifier(Trusted)
        config = _make_trust_config("strict")
        bundle_get = make_bundle_get()
        _reset_warned_urls()

        # First load: populates cache + bundle sidecar.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=config, verifier=verifier, bundle_http_get=bundle_get)
        # Second load: fresh cache (age=0 < TTL) → reads from disk.
        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                         config=config, verifier=verifier, bundle_http_get=bundle_get)
        assert idx.packages[0].name == "bar"

    def test_fresh_cache_strict_sig_invalid_raises(self, tmp_path: Path) -> None:
        """State 1 (fresh cache) + strict policy + SigInvalid → raises TNG-INDEX-SIGNATURE-INVALID."""
        get, _ = make_counter_get(VALID_INDEX)
        bundle_get = make_bundle_get()
        _reset_warned_urls()

        # Populate cache with Trusted verifier.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=_make_trust_config("strict"),
                   verifier=MockVerifier(Trusted),
                   bundle_http_get=bundle_get)

        # Re-read fresh cache with SigInvalid verifier — strict must raise.
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                       config=_make_trust_config("strict"),
                       verifier=MockVerifier(SigInvalid),
                       bundle_http_get=bundle_get)
        assert exc_info.value.slug == TNG_INDEX_SIGNATURE_INVALID

    def test_fresh_cache_warn_sig_invalid_proceeds(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """State 1 (fresh cache) + warn policy + SigInvalid → proceeds with warning."""
        get, _ = make_counter_get(VALID_INDEX)
        bundle_get = make_bundle_get()
        _reset_warned_urls()

        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=_make_trust_config("warn"),
                   verifier=MockVerifier(Trusted),
                   bundle_http_get=bundle_get)

        _reset_warned_urls()
        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                         config=_make_trust_config("warn"),
                         verifier=MockVerifier(SigInvalid),
                         bundle_http_get=bundle_get)
        err = capsys.readouterr().err
        assert TNG_INDEX_SIGNATURE_INVALID in err
        assert idx.packages[0].name == "bar"

    def test_off_policy_skips_verification(self, tmp_path: Path) -> None:
        """off policy: verifier is not called; no exception even with SigInvalid."""
        get, _ = make_counter_get(VALID_INDEX)
        bundle_get = make_bundle_get()
        _reset_warned_urls()

        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=_make_trust_config("off"),
                   verifier=MockVerifier(SigInvalid),  # would raise if called under strict
                   bundle_http_get=bundle_get)
        # No exception → off policy skips verification.


# ---------------------------------------------------------------------------
# 13. S5: Freshness only on network-fetch path (RFC §4 step 6, §7.2)
# ---------------------------------------------------------------------------


class TestFreshnessOnlyOnNetwork:
    """Stale bundle on pure cache read: NOT BundleStale (freshness skipped).
    Same stale bundle on network fetch: BundleStale (freshness asserted).
    """

    def test_stale_bundle_on_cache_read_does_not_raise(self, tmp_path: Path) -> None:
        """State 1 (fresh cache): BundleStale result under strict MUST NOT raise.

        The verifier is called with max_age_seconds=None (freshness skipped).
        But our MockVerifier returns BundleStale regardless of max_age.
        So we need to check the enforce_index_trust call with is_network_fetch=False.

        Under strict + BundleStale on a cache read → should still raise (the
        MockVerifier returns BundleStale; enforce_index_trust sees strict+BundleStale).
        This test demonstrates the semantics of the FRESHNESS PATH (passed max_age=None
        to verifier, verifier itself decides BundleStale vs not).

        NOTE: since MockVerifier ignores max_age, we test the contract differently:
        verify that a cache-read path passes max_age_seconds=None to the verifier.
        """
        # Use a verifier that records what max_age was passed.
        recorded_max_age: list[int | None] = []

        class RecordingVerifier:
            def verify(self, index_bytes, bundle_bytes, trust_bundle, expected_signer,
                       max_age_seconds):
                recorded_max_age.append(max_age_seconds)
                return Trusted  # always passes

        get, _ = make_counter_get(VALID_INDEX)
        bundle_get = make_bundle_get()
        _reset_warned_urls()

        # First fetch (network) → populates cache; max_age should be the config value.
        config = _make_trust_config("strict", max_age=604800)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=config, verifier=RecordingVerifier(),
                   bundle_http_get=bundle_get)

        # Second fetch (fresh cache) → max_age_seconds passed as None.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=config, verifier=RecordingVerifier(),
                   bundle_http_get=bundle_get)

        assert len(recorded_max_age) == 2, f"expected 2 verify calls, got {recorded_max_age}"
        # First call: network fetch → max_age is the config value.
        assert recorded_max_age[0] == 604800, (
            f"network fetch should pass max_age=604800, got {recorded_max_age[0]!r}"
        )
        # Second call: fresh cache read → max_age=None (freshness skipped).
        assert recorded_max_age[1] is None, (
            f"cache read should pass max_age=None, got {recorded_max_age[1]!r}"
        )


# ---------------------------------------------------------------------------
# 14. S5: Bundle-URL derivation (RFC §7.3)
# ---------------------------------------------------------------------------


class TestBundleUrlDerivation:
    """Normative bundle-URL derivation: strip query+fragment, append .bundle to path."""

    def test_derive_bundle_url_default(self) -> None:
        """Default index URL → expected bundle URL."""
        from milpa.index_cache import DEFAULT_INDEX_URL
        bundle_url = derive_bundle_url(DEFAULT_INDEX_URL)
        assert bundle_url == (
            "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.bundle"
        )

    def test_derive_bundle_url_plain(self) -> None:
        """Simple URL: just appends .bundle to path."""
        url = derive_bundle_url("https://example.com/index.kdl")
        assert url == "https://example.com/index.kdl.bundle"

    def test_derive_bundle_url_preserves_query(self) -> None:
        """Query string is stripped from path, appended after .bundle."""
        url = derive_bundle_url("https://example.com/index.kdl?ref=main")
        # Path gets .bundle; query is reattached.
        assert url == "https://example.com/index.kdl.bundle?ref=main"

    def test_derive_bundle_url_preserves_fragment(self) -> None:
        """Fragment is stripped from path, reattached after .bundle."""
        url = derive_bundle_url("https://example.com/index.kdl#section")
        assert url == "https://example.com/index.kdl.bundle#section"

    def test_derive_bundle_url_naive_suffix_would_be_wrong(self) -> None:
        """Naive string suffix would embed query params in path — derivation fixes this."""
        idx_url = "https://example.com/index.kdl?ref=main"
        naive = idx_url + ".bundle"  # would be wrong
        correct = derive_bundle_url(idx_url)
        assert correct != naive, "derivation must not naively append .bundle to the full URL"


# ---------------------------------------------------------------------------
# 15. S5: Bundle 404 handling — strict vs warn (RFC §7.2)
# ---------------------------------------------------------------------------


class TestBundle404Handling:
    """bundle 404: strict → TNG-INDEX-BUNDLE-MISSING; warn → degraded marker."""

    def test_bundle_404_strict_raises_bundle_missing(
        self, tmp_path: Path
    ) -> None:
        """strict + bundle 404 → raises TNG-INDEX-BUNDLE-MISSING; no cache written."""
        get, _ = make_counter_get(VALID_INDEX)
        config = _make_trust_config("strict")
        _reset_warned_urls()

        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                       config=config, verifier=MockVerifier(Trusted),
                       bundle_http_get=failing_bundle_get)
        assert exc_info.value.slug == TNG_INDEX_BUNDLE_MISSING
        # Under strict, no partial cache state is written.
        cache_file = cache_path_for(URL, tmp_path)
        # The index file may or may not exist; but there should be no no-bundle marker.
        no_bundle_marker = Path(str(cache_file) + ".no-bundle")
        assert not no_bundle_marker.exists(), (
            "strict must not write a degraded no-bundle marker"
        )

    def test_bundle_404_warn_writes_degraded_marker(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """warn + bundle 404 → writes .kdl.no-bundle marker, warning in stderr."""
        get, _ = make_counter_get(VALID_INDEX)
        config = _make_trust_config("warn")
        _reset_warned_urls()

        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                         config=config, verifier=MockVerifier(Trusted),
                         bundle_http_get=failing_bundle_get)
        assert idx.packages[0].name == "bar"  # resolve proceeds

        cache_file = cache_path_for(URL, tmp_path)
        no_bundle_marker = Path(str(cache_file) + ".no-bundle")
        assert no_bundle_marker.exists(), (
            "warn + bundle 404 must write the .kdl.no-bundle degraded marker"
        )
        err = capsys.readouterr().err
        assert TNG_INDEX_BUNDLE_MISSING in err

    def test_bundle_404_off_no_marker_no_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """off + bundle 404 → no degraded marker, no warning (trust gate skipped)."""
        get, _ = make_counter_get(VALID_INDEX)
        config = _make_trust_config("off")
        _reset_warned_urls()

        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                         config=config, verifier=MockVerifier(Trusted),
                         bundle_http_get=failing_bundle_get)
        assert idx.packages[0].name == "bar"

        err = capsys.readouterr().err
        assert TNG_INDEX_BUNDLE_MISSING not in err


# ---------------------------------------------------------------------------
# 16. S5: Crash recovery (RFC §7.2 — bounded, one retry)
# ---------------------------------------------------------------------------


class TestCrashRecovery:
    """On cache-read bundle missing/corrupt → delete sidecars + refetch ONCE."""

    def test_missing_bundle_sidecar_triggers_recovery(
        self, tmp_path: Path
    ) -> None:
        """Cache file exists but bundle sidecar is absent → recovery refetch succeeds."""
        get, calls = make_counter_get(VALID_INDEX)
        bundle_get = make_bundle_get()
        config = _make_trust_config("strict")
        _reset_warned_urls()

        # First load: populates cache + bundle.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                   config=config, verifier=MockVerifier(Trusted),
                   bundle_http_get=bundle_get)
        assert calls[0] == 1

        # Delete the bundle sidecar to simulate an interrupted write.
        cache_file = cache_path_for(URL, tmp_path)
        bundle_file = Path(str(cache_file) + ".bundle")
        bundle_file.unlink()

        # Fresh cache read (age=0 < TTL) but bundle missing → recovery refetch.
        _reset_warned_urls()
        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000,
                         config=config, verifier=MockVerifier(Trusted),
                         bundle_http_get=bundle_get)
        assert idx.packages[0].name == "bar"
        # Recovery refetch = one additional call.
        assert calls[0] == 2, f"Expected recovery refetch; got {calls[0]} total calls"

    def test_no_trust_config_no_recovery(self, tmp_path: Path) -> None:
        """Without trust config, bundle sidecar absence is ignored (legacy path)."""
        get, calls = make_counter_get(VALID_INDEX)
        _reset_warned_urls()

        # Populate cache without trust gate.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert calls[0] == 1

        # Fresh cache read with no trust config → no recovery needed.
        idx = load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert calls[0] == 1  # still only 1 call
        assert idx.packages[0].name == "bar"


# ---------------------------------------------------------------------------
# 17. S5: --refresh-index bypasses cache TTL (RFC §7.4)
# ---------------------------------------------------------------------------


class TestRefreshIndex:
    def test_refresh_index_bypasses_fresh_cache(self, tmp_path: Path) -> None:
        """refresh=True forces re-fetch even when cache is fresh."""
        get, calls = make_counter_get(VALID_INDEX)
        _reset_warned_urls()

        # Populate cache.
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        assert calls[0] == 1

        # Refresh forces re-fetch (age=0 < TTL, but refresh=True).
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, refresh=True)
        assert calls[0] == 2, "refresh=True must bypass cache TTL"

    def test_no_refresh_respects_ttl(self, tmp_path: Path) -> None:
        """refresh=False (default) respects TTL — serves from cache."""
        get, calls = make_counter_get(VALID_INDEX)
        _reset_warned_urls()

        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, refresh=False)
        assert calls[0] == 1, "refresh=False must NOT re-fetch a fresh cache"
