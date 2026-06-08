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
    versions = idx.lookup("coreyleavitt", "nimkdl")
    assert len(versions) == 1
    assert versions[0].version == "0.1.4"


# ---------------------------------------------------------------------------
# Cycle 2 — multi-version packages return versions in descending semver order.
# Order matters: resolver's default strategy is maxver, which expects the
# first element to be the newest.
# ---------------------------------------------------------------------------


def _git_prov(sha: str) -> str:
    return (
        '        provenance {\n'
        '            kind "git"\n'
        '            url "https://github.com/status-im/nim-chronos"\n'
        '            ref "HEAD"\n'
        f'            commit_sha "{sha}"\n'
        '        }\n'
    )


MULTI_VERSION_INDEX = """\
schema_version 1
package "chronos" {{
    namespace "status-im"
    upstream (url)"https://github.com/status-im/nim-chronos"
    version "0.2.0" {{
        content_hash "sha256:aaa"
{p_a}        attestation "milpa-vendored"
        signed_by "milpa-bot"
        published_at "2026-01-01T00:00:00Z"
    }}
    version "1.0.0" {{
        content_hash "sha256:bbb"
{p_b}        attestation "milpa-vendored"
        signed_by "milpa-bot"
        published_at "2026-02-01T00:00:00Z"
    }}
    version "0.10.3" {{
        content_hash "sha256:ccc"
{p_c}        attestation "milpa-vendored"
        signed_by "milpa-bot"
        published_at "2026-03-01T00:00:00Z"
    }}
}}
""".format(p_a=_git_prov("a" * 40), p_b=_git_prov("b" * 40), p_c=_git_prov("c" * 40))


def test_versions_returned_in_descending_semver_order():
    idx = parse_index(MULTI_VERSION_INDEX)
    versions = [v.version for v in idx.lookup("status-im", "chronos")]
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
    v = idx.lookup("coreyleavitt", "nimkdl")[0]

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
    assert idx.lookup("coreyleavitt", "nimkdl")[0].version == "0.1.4"
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
    assert idx.lookup("coreyleavitt", "nimkdl")[0].version == "0.1.4"


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
    assert idx.lookup("coreyleavitt", "nimkdl")[0].version == "0.1.4"


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


# ===========================================================================
# S1 (milpa#97) — provenance-agnostic index. The real index.kdl is
# 2613 git provenances + 1 oci; the reader must parse BOTH kinds into the
# fetcher Provenance vocabulary, dispatch-ready, with coded errors.
# ===========================================================================


MIXED_INDEX = """\
schema_version 1
package "results" {
    namespace "arnetheduck"
    upstream (url)"https://github.com/arnetheduck/nim-results"
    version "0.5.0" {
        content_hash "sha256:res050"
        provenance {
            kind "git"
            url "https://github.com/arnetheduck/nim-results"
            ref "HEAD"
            commit_sha "f3a2b1c9d8e7061524384950617283940a1b2c3d"
        }
        attestation "milpa-vendored"
    }
}
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
    }
}
"""


def test_git_provenance_parses_with_commit_sha():
    from milpa.tianguis_client import parse_index, resolve_named
    from milpa.fetchers.git import GitProvenance

    idx = parse_index(MIXED_INDEX)
    v = resolve_named(idx, "results", None)
    assert v.version == "0.5.0"
    assert len(v.provenances) == 1
    p = v.provenances[0]
    assert isinstance(p, GitProvenance)
    assert p.url == "https://github.com/arnetheduck/nim-results"
    assert p.ref == "HEAD"
    # commit_sha is the immutable pin the resolver fetches at (Invariant 2).
    assert p.commit_sha == "f3a2b1c9d8e7061524384950617283940a1b2c3d"


def test_git_url_with_url_type_annotation_parses():
    """Regression (milpa#97 S7): the live tianguis index annotates every
    URL `(url)"https://..."` (the milpa KDL url convention). The kdl lib
    parses that into a urllib ParseResult, not a str — `_scalar_child`
    must still recover the URL, or every git-vendored entry becomes
    unfetchable (empty url → `git clone ''`)."""
    from milpa.tianguis_client import parse_index, resolve_named
    from milpa.fetchers.git import GitProvenance

    text = """\
package "results" {
    version "0.5.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url (url)"https://github.com/arnetheduck/nim-results"
            ref "HEAD"
            commit_sha "f3a2b1c9d8e7061524384950617283940a1b2c3d"
        }
    }
}
"""
    idx = parse_index(text)
    p = resolve_named(idx, "results", None).provenances[0]
    assert isinstance(p, GitProvenance)
    assert p.url == "https://github.com/arnetheduck/nim-results"
    assert p.commit_sha == "f3a2b1c9d8e7061524384950617283940a1b2c3d"


def test_oci_provenance_still_parses_in_mixed_index():
    from milpa.tianguis_client import parse_index, resolve_named
    from milpa.fetchers.oci import OciProvenance

    idx = parse_index(MIXED_INDEX)
    v = resolve_named(idx, "nimkdl", None)
    p = v.provenances[0]
    assert isinstance(p, OciProvenance)
    assert p.registry == "ghcr.io"
    assert p.repository == "coreyleavitt/nimkdl"


def test_canonical_provenance_is_first_in_index_order():
    from milpa.tianguis_client import parse_index, resolve_named

    idx = parse_index(MIXED_INDEX)
    v = resolve_named(idx, "results", None)
    assert v.canonical_provenance is v.provenances[0]


def test_unknown_provenance_kind_is_skipped_not_fatal():
    from milpa.tianguis_client import parse_index, resolve_named
    from milpa.fetchers.git import GitProvenance

    idx = parse_index("""\
schema_version 1
package "x" {
    version "1.0.0" {
        content_hash "sha256:x"
        provenance {
            kind "ipfs"
            cid "bafy-future-transport"
        }
        provenance {
            kind "git"
            url "https://example.com/x"
            ref "HEAD"
            commit_sha "0000000000000000000000000000000000000000"
        }
    }
}
""")
    v = resolve_named(idx, "x", None)
    # The unknown ipfs kind is skipped; the git provenance survives.
    assert len(v.provenances) == 1
    assert isinstance(v.provenances[0], GitProvenance)


def test_schema_version_newer_than_known_raises_coded():
    from milpa.tianguis_client import parse_index, TianguisError

    with pytest.raises(TianguisError) as exc:
        parse_index("""\
schema_version 99
package "x" {
    version "1.0.0" {
        content_hash "sha256:x"
    }
}
""")
    assert exc.value.code == "TNG-SCHEMA-UNKNOWN"


def test_empty_provenance_version_raises_coded():
    from milpa.tianguis_client import parse_index, resolve_named, TianguisError

    idx = parse_index("""\
schema_version 1
package "x" {
    version "1.0.0" {
        content_hash "sha256:x"
    }
}
""")
    with pytest.raises(TianguisError) as exc:
        resolve_named(idx, "x", None)
    assert exc.value.code == "TNG-NO-PROVENANCE"


def test_unknown_package_error_carries_code():
    from milpa.tianguis_client import parse_index, resolve_named, TianguisError

    idx = parse_index(MIXED_INDEX)
    with pytest.raises(TianguisError) as exc:
        resolve_named(idx, "nonexistent", None)
    assert exc.value.code == "TNG-NOT-FOUND"


def test_no_satisfying_version_error_carries_code():
    from milpa.tianguis_client import parse_index, resolve_named, TianguisError

    idx = parse_index(MULTI_VERSION_INDEX)
    with pytest.raises(TianguisError) as exc:
        resolve_named(idx, "chronos", ">= 99.0.0")
    assert exc.value.code == "TNG-NO-SATISFYING-VERSION"


def test_unparseable_index_version_does_not_crash_sort():
    from milpa.tianguis_client import parse_index

    # A non-X.Y.Z tag ("nightly") mixed with clean semver. Parsing must
    # not crash on the heterogeneous sort, and the clean versions sort
    # ahead of the unparseable one.
    idx = parse_index("""\
schema_version 1
package "x" {
    version "nightly" {
        content_hash "sha256:n"
        provenance {
            kind "git"
            url "https://e.com/x"
            ref "HEAD"
            commit_sha "0000000000000000000000000000000000000000"
        }
    }
    version "1.2.0" {
        content_hash "sha256:a"
        provenance {
            kind "git"
            url "https://e.com/x"
            ref "HEAD"
            commit_sha "1111111111111111111111111111111111111111"
        }
    }
    version "1.10.0" {
        content_hash "sha256:b"
        provenance {
            kind "git"
            url "https://e.com/x"
            ref "HEAD"
            commit_sha "2222222222222222222222222222222222222222"
        }
    }
}
""")
    versions = [v.version for v in idx.lookup("", "x")]
    # Clean semver descending first, unparseable last (stable).
    assert versions == ["1.10.0", "1.2.0", "nightly"]


def test_unknown_error_code_is_rejected_at_construction():
    # The _TNG_CODES bijection guard: a typo'd code fails loudly.
    from milpa.tianguis_client import TianguisError

    with pytest.raises(AssertionError, match="unknown tianguis error code"):
        TianguisError(code="TNG-TYPO", message="nope")


def test_default_index_url_is_defined():
    from milpa.tianguis_client import DEFAULT_INDEX_URL

    assert DEFAULT_INDEX_URL.endswith("/index.kdl")


# ---------------------------------------------------------------------------
# L11 — duplicate-version warn and missing schema_version tolerated
# ---------------------------------------------------------------------------


def test_duplicate_version_does_not_crash_and_keeps_first_and_warns():
    """L11: a package declaring the same version string twice must (a) not
    crash, (b) keep the first occurrence (len == 1), (c) emit a warning."""
    import warnings
    from milpa.tianguis_client import parse_index

    text = """\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:first"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "main"
        }
    }
    version "1.0.0" {
        content_hash "sha256:second"
        provenance {
            kind "git"
            url "https://example.com/foo-mirror"
            ref "main"
        }
    }
}
"""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        idx = parse_index(text)

    versions = idx.lookup("", "foo")
    # (b) exactly one entry — first occurrence kept
    assert len(versions) == 1, (
        "duplicate version must be dropped, not accumulated"
    )
    # (a) no crash — reached here
    # (c) at least one warning mentioning the duplicate
    assert any("1.0.0" in str(warning.message) for warning in w), (
        "duplicate version must emit a warning naming the version"
    )


def test_parse_index_without_schema_version_does_not_raise():
    """L11: an index with no schema_version node must parse without error
    (forward/back-compat — both older and draft indexes may omit it)."""
    from milpa.tianguis_client import parse_index

    # Deliberately omit schema_version — must not raise.
    idx = parse_index("""\
package "foo" {
    version "1.0.0" {
        content_hash "sha256:abc"
        provenance {
            kind "git"
            url "https://example.com/foo"
            ref "main"
        }
    }
}
"""
    )
    assert idx.lookup("", "foo")[0].version == "1.0.0"


# ===========================================================================
# P1.2 — parse_index tuple-key + namespace + AmbiguousName (tianguis #32)
# ===========================================================================

# ---------------------------------------------------------------------------
# (0) TNG-AMBIGUOUS-NAME is registered in _TNG_CODES
# ---------------------------------------------------------------------------


def test_tng_ambiguous_name_is_in_codes():
    """TNG-AMBIGUOUS-NAME must appear in _TNG_CODES so TianguisError
    construction with this code doesn't AssertionError."""
    from milpa.tianguis_client import _TNG_CODES
    assert "TNG-AMBIGUOUS-NAME" in _TNG_CODES, (
        "TNG-AMBIGUOUS-NAME must be registered in _TNG_CODES before any "
        "raise site can use it"
    )


# ---------------------------------------------------------------------------
# (a/b) Package.namespace field + (namespace, name) store key
# ---------------------------------------------------------------------------

NIMKDL_COLLISION_INDEX = """\
schema_version 1
package "nimkdl" {
    namespace "greenm01"
    upstream (url)"https://github.com/greenm01/nimkdl"
    version "0.3.0" {
        content_hash "sha256:aaa0000000000000000000000000000000000000000000000000000000000000"
        provenance {
            kind "git"
            url "https://github.com/greenm01/nimkdl"
            ref "HEAD"
            commit_sha "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    }
}
package "nimkdl" {
    namespace "coreyleavitt"
    upstream (url)"https://github.com/coreyleavitt/nimkdl"
    version "0.1.4" {
        content_hash "sha256:bbb0000000000000000000000000000000000000000000000000000000000000"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "coreyleavitt/nimkdl"
            digest "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"
        }
    }
}
"""


def test_package_has_namespace_field():
    """(a) Package dataclass must carry a `namespace` field populated from
    the index block."""
    idx = parse_index(MINIMAL_INDEX)
    pkgs = list(idx._packages.values())
    assert len(pkgs) == 1
    pkg = pkgs[0]
    assert hasattr(pkg, "namespace"), "Package must have a namespace field"
    assert pkg.namespace == "coreyleavitt"


def test_collision_index_parses_to_two_packages_not_one():
    """(b) Two `nimkdl` blocks under different namespaces must produce 2
    distinct entries — not a silent drop of the second."""
    idx = parse_index(NIMKDL_COLLISION_INDEX)
    assert len(idx._packages) == 2, (
        "collision pair must produce 2 package entries, not 1 — "
        "bare-name keying silently drops one"
    )


# ---------------------------------------------------------------------------
# (c) lookup(ns, name) + lookup_bare typed union
# ---------------------------------------------------------------------------


def test_lookup_by_namespace_and_name_returns_correct_package():
    """(c) lookup(namespace, name) returns the one matching Package's
    versions; a qualified lookup with the wrong namespace returns []."""
    idx = parse_index(NIMKDL_COLLISION_INDEX)
    versions = idx.lookup("coreyleavitt", "nimkdl")
    assert len(versions) == 1
    assert versions[0].version == "0.1.4"

    versions_other = idx.lookup("greenm01", "nimkdl")
    assert len(versions_other) == 1
    assert versions_other[0].version == "0.3.0"


def test_lookup_bare_returns_package_when_name_is_unique():
    """(c) lookup_bare on a unique name returns the Package directly
    (not AmbiguousName, not None)."""
    from milpa.tianguis_client import AmbiguousName

    idx = parse_index(MINIMAL_INDEX)
    result = idx.lookup_bare("nimkdl")
    assert not isinstance(result, AmbiguousName), (
        "lookup_bare on a unique name must return the Package, not AmbiguousName"
    )
    assert result is not None
    # It should be a Package — check it has versions
    assert len(result.versions) == 1


def test_lookup_bare_returns_ambiguous_name_on_collision_not_raises():
    """(c) lookup_bare on a name collision returns AmbiguousName (typed
    result, does NOT raise). Rationale: the multi-version provider in
    P3.2/#100 enumerates candidates while backtracking — a raise inside
    the registry primitive would be a hard stop mid-solve."""
    from milpa.tianguis_client import AmbiguousName

    idx = parse_index(NIMKDL_COLLISION_INDEX)
    result = idx.lookup_bare("nimkdl")
    assert isinstance(result, AmbiguousName), (
        "lookup_bare on a collision pair must return AmbiguousName, not raise"
    )
    assert result.name == "nimkdl"
    assert set(result.namespaces) == {"greenm01", "coreyleavitt"}


# ---------------------------------------------------------------------------
# (d) resolve_named raises TNG-AMBIGUOUS-NAME at the policy layer
# ---------------------------------------------------------------------------


def test_resolve_named_raises_ambiguous_on_collision():
    """(d) resolve_named calls lookup_bare; on an AmbiguousName result it
    raises TianguisError(code='TNG-AMBIGUOUS-NAME'). The raise lives here
    (policy layer), NOT in the registry primitive."""
    from milpa.tianguis_client import resolve_named, TianguisError

    idx = parse_index(NIMKDL_COLLISION_INDEX)
    with pytest.raises(TianguisError) as exc:
        resolve_named(idx, "nimkdl", None)
    assert exc.value.code == "TNG-AMBIGUOUS-NAME"
    # Message names the competing namespaces so the error is actionable.
    assert "greenm01" in str(exc.value) or "coreyleavitt" in str(exc.value)


# ===========================================================================
# P3.2 — multi-version named-dep provider (resolve_named_all)
# ===========================================================================
#
# `resolve_named` keeps its single-maxver contract (used by existing callers
# in tests).  `resolve_named_all` is the new entry point that returns ALL
# satisfying IndexVersions so the resolver can build a multi-candidate set.
# ---------------------------------------------------------------------------


def test_resolve_named_all_returns_all_satisfying_versions():
    """P3.2 gate 1: a named dep with N satisfying index versions yields all N
    IndexVersions, not just the highest one. The solver can then choose and
    backtrack among them."""
    from milpa.tianguis_client import parse_index, resolve_named_all

    idx = parse_index(MULTI_VERSION_INDEX)
    # chronos has 1.0.0, 0.10.3, 0.2.0; >= 0.5 admits 1.0.0 and 0.10.3
    versions = resolve_named_all(idx, "chronos", ">= 0.5.0")
    assert len(versions) == 2
    version_strs = [v.version for v in versions]
    assert "1.0.0" in version_strs
    assert "0.10.3" in version_strs


def test_resolve_named_all_returns_all_when_no_constraint():
    """resolve_named_all with constraint=None returns every parseable version."""
    from milpa.tianguis_client import parse_index, resolve_named_all

    idx = parse_index(MULTI_VERSION_INDEX)
    versions = resolve_named_all(idx, "chronos", None)
    assert len(versions) == 3
    version_strs = [v.version for v in versions]
    assert "1.0.0" in version_strs
    assert "0.10.3" in version_strs
    assert "0.2.0" in version_strs


def test_resolve_named_all_raises_not_found_for_unknown_name():
    """resolve_named_all raises TNG-NOT-FOUND for a name not in the index."""
    from milpa.tianguis_client import parse_index, resolve_named_all, TianguisError

    idx = parse_index(MINIMAL_INDEX)
    with pytest.raises(TianguisError) as exc:
        resolve_named_all(idx, "ghost", None)
    assert exc.value.code == "TNG-NOT-FOUND"


def test_resolve_named_all_raises_no_satisfying_version_when_none_match():
    """resolve_named_all raises TNG-NO-SATISFYING-VERSION when no version
    satisfies the constraint (all parseable versions are excluded)."""
    from milpa.tianguis_client import parse_index, resolve_named_all, TianguisError

    idx = parse_index(MULTI_VERSION_INDEX)
    with pytest.raises(TianguisError) as exc:
        resolve_named_all(idx, "chronos", ">= 99.0.0")
    assert exc.value.code == "TNG-NO-SATISFYING-VERSION"


def test_resolve_named_all_raises_ambiguous_on_name_collision():
    """resolve_named_all raises TNG-AMBIGUOUS-NAME when a bare name matches
    multiple namespaces (same policy layer as resolve_named)."""
    from milpa.tianguis_client import parse_index, resolve_named_all, TianguisError

    idx = parse_index(NIMKDL_COLLISION_INDEX)
    with pytest.raises(TianguisError) as exc:
        resolve_named_all(idx, "nimkdl", None)
    assert exc.value.code == "TNG-AMBIGUOUS-NAME"


def test_resolve_named_all_versions_are_ordered_descending_by_semver():
    """The returned list is ordered newest-first (descending semver) — the
    provider registers them in this order so maxver still picks index 0."""
    from milpa.tianguis_client import parse_index, resolve_named_all

    idx = parse_index(MULTI_VERSION_INDEX)
    versions = resolve_named_all(idx, "chronos", None)
    version_strs = [v.version for v in versions]
    # Descending: 1.0.0 > 0.10.3 > 0.2.0
    from milpa.solver import parse_version
    parsed = [parse_version(s) for s in version_strs]
    assert parsed == sorted(parsed, reverse=True)


# ---------------------------------------------------------------------------
# M12 regression: resolve_named_all skips provenance-less versions
# ---------------------------------------------------------------------------


def test_resolve_named_all_skips_provenance_less_versions_and_returns_older():
    """M12: when the newest satisfying version has no provenance, it must be
    skipped (with a warning) rather than raising TNG-NO-PROVENANCE mid-loop.
    An older version with provenance is the correct result.

    Previously the function raised immediately on the first provenance-less
    version, blocking older valid satisfying versions from being considered."""
    import warnings
    from milpa.tianguis_client import parse_index, resolve_named_all

    idx = parse_index("""\
schema_version 1
package "foo" {
    version "2.0.0" {
        content_hash "sha256:aaa0000000000000000000000000000000000000000000000000000000000000"
    }
    version "1.0.0" {
        content_hash "sha256:bbb0000000000000000000000000000000000000000000000000000000000000"
        provenance {
            kind "git"
            url "https://example.com/foo.git"
            ref "v1.0.0"
            commit_sha "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    }
}
""")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = resolve_named_all(idx, "foo", None)

    # Must resolve to the older version with provenance, not raise.
    assert len(result) == 1, f"expected 1 result, got {len(result)}: {result}"
    assert result[0].version == "1.0.0", (
        f"M12 regression: expected 1.0.0 (provenance-less 2.0.0 skipped), "
        f"got {result[0].version!r}"
    )
    # A warning must have been emitted for the skipped provenance-less version.
    warn_messages = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
    assert any("2.0.0" in m or "provenance" in m.lower() for m in warn_messages), (
        f"expected a UserWarning mentioning '2.0.0' or 'provenance', got: {warn_messages}"
    )


def test_resolve_named_all_raises_if_all_satisfying_have_no_provenance():
    """M12: when ALL satisfying versions lack provenance, TNG-NO-PROVENANCE
    must still be raised (no valid fallback exists)."""
    import warnings
    from milpa.tianguis_client import TianguisError, parse_index, resolve_named_all

    idx = parse_index("""\
schema_version 1
package "foo" {
    version "1.0.0" {
        content_hash "sha256:ccc0000000000000000000000000000000000000000000000000000000000000"
    }
}
""")
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        with pytest.raises(TianguisError) as exc:
            resolve_named_all(idx, "foo", None)
    assert exc.value.code == "TNG-NO-PROVENANCE"
