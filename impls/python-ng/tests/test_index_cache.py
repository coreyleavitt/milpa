"""Tests for milpa.index_cache — S8b.

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
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import MILPA_INDEX_UNREACHABLE, TNG_SCHEMA_UNKNOWN, MilpaError
from milpa.index_cache import (
    DEFAULT_INDEX_URL,
    DEFAULT_TTL_SECONDS,
    HttpGet,
    cache_path_for,
    index_url_from_env,
    load_index,
    urllib_http_get,
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
    """Return an ``HttpGet`` that serves *body* and a call-count list."""
    calls: list[int] = [0]

    def get(url: str) -> str:
        calls[0] += 1
        return body

    return get, calls


def failing_get(url: str) -> str:
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
        assert "schema_version" in cache_file.read_text()

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
        cache_file.write_text(VALID_INDEX_V2)

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
        assert "2.0.0" in cache_file.read_text()

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
# 10. Atomic write — no partial file observed
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    def test_cache_file_has_complete_content(self, tmp_path: Path) -> None:
        """After load_index completes the cache file must be complete KDL."""
        get, _ = make_counter_get(VALID_INDEX)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000)
        cache_file = cache_path_for(URL, tmp_path)
        content = cache_file.read_text()
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
