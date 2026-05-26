"""`milpa.tianguis_client` — reads tianguis-shaped index.kdl as the
authoritative named-package registry.

Per tianguis #7. Tianguis-only model (no nim-lang fallback). The
vendor-en-absentia bot guarantees full nim-lang/packages coverage, so
falling back would either be redundant or actively wrong (e.g.,
re-fetching a denylisted package by URL bypasses the author's opt-out).
"""

from pathlib import Path

import pytest

from milpa.tianguis_client import parse_index


# ---------------------------------------------------------------------------
# Cycle 1 — tracer: parse a minimal index.kdl, lookup returns one version
# ---------------------------------------------------------------------------


MINIMAL_INDEX = """\
schema_version 1
package "nimkdl" {
    namespace "coreyleavitt"
    upstream (url)"https://github.com/coreyleavitt/nimkdl"
    version "0.1.4" {
        content_hash "sha256:1aaf2a95f53681c86f6dcd4c1267144401ba923f31afa42da3c5ae783dc7ab61"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "coreyleavitt/nimkdl"
            digest "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"
        }
        attestation "author-signed"
        signed_by "https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml"
        published_at "2026-05-26T04:49:44Z"
    }
}
"""


def test_lookup_returns_one_version_for_known_name():
    idx = parse_index(MINIMAL_INDEX)
    versions = idx.lookup("nimkdl")
    assert len(versions) == 1
    assert versions[0].version == "0.1.4"


# ---------------------------------------------------------------------------
# Cycle 2 — multi-version packages return versions in descending semver order.
# Order matters: resolver's default strategy is maxver, which expects the
# first element to be the newest.
# ---------------------------------------------------------------------------


MULTI_VERSION_INDEX = """\
schema_version 1
package "chronos" {
    namespace "status-im"
    upstream (url)"https://github.com/status-im/nim-chronos"
    version "0.2.0" {
        content_hash "sha256:aaa"
        attestation "milpa-vendored"
        signed_by "milpa-bot"
        published_at "2026-01-01T00:00:00Z"
    }
    version "1.0.0" {
        content_hash "sha256:bbb"
        attestation "milpa-vendored"
        signed_by "milpa-bot"
        published_at "2026-02-01T00:00:00Z"
    }
    version "0.10.3" {
        content_hash "sha256:ccc"
        attestation "milpa-vendored"
        signed_by "milpa-bot"
        published_at "2026-03-01T00:00:00Z"
    }
}
"""


def test_versions_returned_in_descending_semver_order():
    idx = parse_index(MULTI_VERSION_INDEX)
    versions = [v.version for v in idx.lookup("chronos")]
    assert versions == ["1.0.0", "0.10.3", "0.2.0"], (
        "versions must be ordered newest-first by semver — input order in "
        "the index file is incidental"
    )


# ---------------------------------------------------------------------------
# Cycle 3 — each version exposes its OCI provenance + content_hash.
# These are what the fetcher consumes; without them the registry is
# just a name→version-string map (useless for actually fetching).
# ---------------------------------------------------------------------------


def test_version_exposes_oci_provenance_and_content_hash():
    idx = parse_index(MINIMAL_INDEX)
    v = idx.lookup("nimkdl")[0]

    assert v.content_hash == "sha256:1aaf2a95f53681c86f6dcd4c1267144401ba923f31afa42da3c5ae783dc7ab61"

    assert len(v.provenances) == 1
    p = v.provenances[0]
    assert p.kind == "oci"
    assert p.registry == "ghcr.io"
    assert p.repository == "coreyleavitt/nimkdl"
    assert p.digest == "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"

    # Convenience: a canonical OCI ref string for the fetcher to use.
    assert p.oci_ref == (
        "ghcr.io/coreyleavitt/nimkdl@"
        "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"
    )


# ---------------------------------------------------------------------------
# Cycle 4 — fetch index.kdl from a URL into a cache dir, serve from cache.
# HTTP is injected so we don't touch the network in unit tests.
# ---------------------------------------------------------------------------


def test_load_index_fetches_from_url_and_writes_cache(tmp_path: Path):
    from milpa.tianguis_client import load_index

    calls: list[str] = []

    def fake_http_get(url: str) -> str:
        calls.append(url)
        return MINIMAL_INDEX

    idx = load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=fake_http_get,
    )

    # The HTTP layer was consulted once with the expected URL.
    assert calls == ["https://tianguis.dev/index.kdl"]
    # The Index was constructed and is queryable.
    assert idx.lookup("nimkdl")[0].version == "0.1.4"
    # The cache directory now holds the index file (callers will reuse it).
    cached_files = list(tmp_path.iterdir())
    assert len(cached_files) == 1
    assert cached_files[0].read_text().startswith("schema_version 1")


def test_load_index_serves_cache_when_present_without_network(tmp_path: Path):
    from milpa.tianguis_client import load_index

    # First call populates cache.
    def fetch_once(url: str) -> str:
        return MINIMAL_INDEX
    load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=fetch_once,
    )

    # Second call must not touch the network — exploding http_get
    # would expose a regression.
    def forbidden_http(url: str) -> str:
        raise AssertionError("network should not be touched when cache is fresh")
    idx = load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=forbidden_http,
    )
    assert idx.lookup("nimkdl")[0].version == "0.1.4"


# ---------------------------------------------------------------------------
# Cycle 5 — TTL: stale cache re-fetches. Fresh cache serves directly.
# Time is injected so tests don't depend on wall clock.
# ---------------------------------------------------------------------------


def test_stale_cache_triggers_refetch(tmp_path: Path):
    from milpa.tianguis_client import load_index

    fetched: list[str] = []
    def http(url: str) -> str:
        fetched.append(url)
        return MINIMAL_INDEX

    # Pretend "now" is t=0; cache TTL of 60 seconds.
    now = [0.0]
    load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=http,
        ttl_seconds=60,
        clock=lambda: now[0],
    )
    assert len(fetched) == 1  # first call populated cache

    # Jump past TTL — cache is stale, must re-fetch.
    now[0] = 120.0
    load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=http,
        ttl_seconds=60,
        clock=lambda: now[0],
    )
    assert len(fetched) == 2, "stale cache must trigger a re-fetch"


def test_fresh_cache_serves_without_refetch(tmp_path: Path):
    from milpa.tianguis_client import load_index

    fetched: list[str] = []
    def http(url: str) -> str:
        fetched.append(url)
        return MINIMAL_INDEX

    now = [0.0]
    load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path, http_get=http,
        ttl_seconds=60, clock=lambda: now[0],
    )
    # Move time forward but stay within TTL.
    now[0] = 30.0
    load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path, http_get=http,
        ttl_seconds=60, clock=lambda: now[0],
    )
    assert len(fetched) == 1, "fresh cache must NOT trigger re-fetch"


# ---------------------------------------------------------------------------
# Cycle 6 — offline: a transient network failure with a cache present
# falls back to the cache. Without a cache, the failure propagates
# (no silent "the registry is empty" behavior).
# ---------------------------------------------------------------------------


def test_offline_with_cache_falls_back_to_cache(tmp_path: Path):
    from milpa.tianguis_client import load_index

    # Populate the cache successfully on the first call.
    load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=lambda u: MINIMAL_INDEX,
        ttl_seconds=60, clock=lambda: 0.0,
    )

    # Time passes past TTL. Network is now down. Cache should serve.
    def offline(url: str) -> str:
        raise OSError("network unreachable")
    idx = load_index(
        url="https://tianguis.dev/index.kdl",
        cache_dir=tmp_path,
        http_get=offline,
        ttl_seconds=60, clock=lambda: 120.0,
    )
    assert idx.lookup("nimkdl")[0].version == "0.1.4"


def test_offline_without_cache_propagates_error(tmp_path: Path):
    from milpa.tianguis_client import load_index

    def offline(url: str) -> str:
        raise OSError("network unreachable")

    with pytest.raises(OSError, match="network unreachable"):
        load_index(
            url="https://tianguis.dev/index.kdl",
            cache_dir=tmp_path, http_get=offline,
            ttl_seconds=60, clock=lambda: 0.0,
        )


# ---------------------------------------------------------------------------
# Cycle 7 — resolve_named threads tianguis lookup through the existing
# VersionSet constraint matcher (single source of truth for "does
# version v satisfy constraint c?" across milpa, per the audit-for-
# duplication discipline).
# ---------------------------------------------------------------------------


def test_resolve_picks_highest_satisfying_version():
    from milpa.tianguis_client import parse_index, resolve_named

    idx = parse_index(MULTI_VERSION_INDEX)
    # chronos has 1.0.0, 0.10.3, 0.2.0; >= 0.5 admits 1.0.0 and 0.10.3;
    # maxver picks 1.0.0.
    resolved = resolve_named(idx, "chronos", ">= 0.5.0")
    assert resolved.version == "1.0.0"


def test_resolve_respects_upper_bound_constraint():
    from milpa.tianguis_client import parse_index, resolve_named

    idx = parse_index(MULTI_VERSION_INDEX)
    # Cap at < 1.0.0 → 0.10.3 wins (newest under the cap).
    resolved = resolve_named(idx, "chronos", "< 1.0.0")
    assert resolved.version == "0.10.3"


def test_resolve_unknown_package_errors_clearly():
    from milpa.tianguis_client import parse_index, resolve_named, TianguisError

    idx = parse_index(MINIMAL_INDEX)
    with pytest.raises(TianguisError, match="not in tianguis"):
        resolve_named(idx, "does-not-exist", None)


def test_resolve_no_satisfying_version_errors_clearly():
    from milpa.tianguis_client import parse_index, resolve_named, TianguisError

    idx = parse_index(MULTI_VERSION_INDEX)
    # All chronos versions are < 2.0.0; constraint demands >= 2.0.0.
    with pytest.raises(TianguisError, match="no version.*satisfies"):
        resolve_named(idx, "chronos", ">= 2.0.0")
