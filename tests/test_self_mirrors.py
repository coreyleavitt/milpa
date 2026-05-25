"""Self-mirrors: package-declared mirrors propagate to consumers (#79).

A package's `milpa.kdl` declares URLs where IT is hosted via a
top-level `mirrors { mirror (url)"..." }` block. The resolver harvests
these when fetching transitively and uses them as fall-back
candidates alongside consumer-declared dep-mirrors.

Identity verification (#37 + #82) provides the safety net: hostile
self-mirrors serving different bytes are rejected at fetch time.

Also: this cycle aligns URL emission across milpa.kdl + milpa.lock
to use KDL's (url) type annotation consistently.
"""

import pytest

from milpa.manifest import Manifest, UrlDep, parse_manifest


def test_parser_accepts_mirror_with_url_annotation_in_dep_block():
    """Cycle 1: parser accepts `mirror (url)"X"` form on dep blocks
    (kdl-py converts the value to a ParseResult; we normalize to str)."""
    text = '''name "test"
kind "library"
deps {
    chronos git=(url)"https://github.com/x/chronos.git" ref="main" {
        mirror (url)"https://gitlab.com/x/chronos.git"
        mirror "https://legacy.example.com/x/chronos.git"
    }
}
'''
    manifest = parse_manifest(text)
    dep = manifest.deps[0]
    assert isinstance(dep, UrlDep)
    # Both forms (annotated + plain) normalize to plain strings
    assert dep.mirrors == (
        "https://gitlab.com/x/chronos.git",
        "https://legacy.example.com/x/chronos.git",
    )


def test_format_manifest_emits_mirror_with_url_annotation():
    """format_manifest's canonical output uses `mirror (url)"X"` for
    every dep mirror. Round-trip is structurally stable."""
    from milpa.manifest import format_manifest

    original = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="chronos",
            git="https://github.com/x/chronos.git", ref="main",
            mirrors=(
                "https://gitlab.com/x/chronos.git",
                "https://mirror.example.com/x/chronos.git",
            ),
        ),),
    )
    text = format_manifest(original)
    # Canonical form: (url) on every mirror URL
    assert 'mirror (url)"https://gitlab.com/x/chronos.git"' in text
    assert 'mirror (url)"https://mirror.example.com/x/chronos.git"' in text
    # Round-trip preserves structure
    reparsed = parse_manifest(text)
    assert reparsed == original


# ---------------------------------------------------------------------------
# Part B — top-level self-mirrors
# ---------------------------------------------------------------------------


def test_parser_accepts_top_level_mirrors_block():
    """Tracer (Part B): a top-level `mirrors { mirror (url)"X" }`
    block populates Manifest.self_mirrors."""
    text = '''name "chronos"
kind "library"
mirrors {
    mirror (url)"https://gitlab.com/x/chronos.git"
    mirror (url)"https://mirror.example.com/x/chronos.git"
}
'''
    manifest = parse_manifest(text)
    assert manifest.self_mirrors == (
        "https://gitlab.com/x/chronos.git",
        "https://mirror.example.com/x/chronos.git",
    )


def test_format_manifest_round_trips_top_level_mirrors_block():
    """format → parse preserves self_mirrors; idempotence (no diff
    on second emission). Empty self_mirrors → no block."""
    from milpa.manifest import format_manifest

    original = Manifest(
        kind="library", name="chronos", deps=(),
        self_mirrors=(
            "https://gitlab.com/x/chronos.git",
            "https://mirror.example.com/x/chronos.git",
        ),
    )
    text1 = format_manifest(original)
    assert "mirrors {" in text1
    assert 'mirror (url)"https://gitlab.com/x/chronos.git"' in text1
    reparsed = parse_manifest(text1)
    assert reparsed == original
    # Idempotence
    text2 = format_manifest(reparsed)
    assert text1 == text2

    # Empty self_mirrors → no block emitted
    empty = Manifest(kind="library", name="proj", deps=())
    text_empty = format_manifest(empty)
    assert "mirrors {" not in text_empty


# ---------------------------------------------------------------------------
# Part B (resolver) — harvest self-mirrors from transitive milpa.kdl
# ---------------------------------------------------------------------------


class _MilpaKdlFetcher:
    """Test fetcher that writes a milpa.kdl per-URL into the dest."""
    def __init__(self, milpa_kdl_by_url): self.by_url = milpa_kdl_by_url; self.calls = []
    def can_handle(self, p):
        from milpa.fetchers.git import GitProvenance
        return isinstance(p, GitProvenance)
    def fetch(self, name, p, *, dest):
        from milpa.fetchers.git import GitReceipt
        self.calls.append(p.url)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        if p.url in self.by_url:
            (dest / "milpa.kdl").write_text(self.by_url[p.url])
        return GitReceipt(commit_sha="abc")


def test_resolver_harvests_self_mirrors_from_transitive_milpa_kdl(tmp_path):
    """After resolution, a dep whose milpa.kdl declared self-mirrors
    carries them in its ResolvedDep.self_mirrors field."""
    from milpa.fetchers import FetcherRegistry
    from milpa.profile import Profile
    from milpa.resolver import resolve

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="chronos",
            git="https://primary.example.com/chronos.git", ref="main",
        ),),
    )

    fetcher_impl = _MilpaKdlFetcher(milpa_kdl_by_url={
        "https://primary.example.com/chronos.git": '''name "chronos"
kind "library"
mirrors {
    mirror (url)"https://gitlab.com/x/chronos.git"
    mirror (url)"https://mirror.example.com/x/chronos.git"
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps", registry={},
        fetcher=registry, list_tags=lambda url: [],
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )

    chronos = next(d for d in graph.deps if d.name == "chronos")
    assert chronos.self_mirrors == (
        "https://gitlab.com/x/chronos.git",
        "https://mirror.example.com/x/chronos.git",
    )


def test_lockfile_round_trips_self_mirrors():
    """LockedDep.self_mirrors records harvested set; KDL emission +
    parse preserves them. Empty self_mirrors → no line emitted."""
    from milpa.lockfile import (
        GitProvenanceRecord, LockedDep, Lockfile,
        format_lockfile, parse_lockfile,
    )

    original = Lockfile(deps=(
        LockedDep(
            name="chronos", identity="sha256:" + "a" * 64,
            version="0.0.1", src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://primary/chronos.git", ref="main",
                commit_sha="abc",
            ),),
            self_mirrors=(
                "https://gitlab.com/x/chronos.git",
                "https://mirror.example.com/x/chronos.git",
            ),
        ),
        LockedDep(
            name="bare", identity="sha256:" + "b" * 64,
            version="0.0.1", src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://x/bare.git", ref="main", commit_sha="d",
            ),),
            # No self_mirrors — should not appear in text
        ),
    ))
    text = format_lockfile(original)
    assert 'self_mirrors (url)"https://gitlab.com/x/chronos.git"' in text
    reparsed = parse_lockfile(text)
    assert reparsed == original


def test_lockfile_cached_self_mirrors_used_as_fallback_on_primary_failure(tmp_path):
    """Subsequent resolve scenario: prior lockfile records X's
    self-mirrors. On this resolve, primary URL fails; the lockfile-
    cached self-mirror is tried as fall-back."""
    from milpa.fetchers import FetcherRegistry, FetchError
    from milpa.fetchers.git import GitProvenance, GitReceipt
    from milpa.lockfile import (
        GitProvenanceRecord, LockedDep, Lockfile,
    )
    from milpa.profile import Profile
    from milpa.resolver import resolve

    PRIMARY = "https://primary.example.com/chronos.git"
    SELF_MIRROR = "https://gitlab.com/x/chronos.git"

    class PartialFetcher:
        def __init__(self): self.attempted = []
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            self.attempted.append(p.url)
            if p.url == PRIMARY:
                raise FetchError(f"primary {p.url} is down")
            # Mirror succeeds
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    fetcher_impl = PartialFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="chronos", git=PRIMARY, ref="main",
        ),),
    )
    prior_lockfile = Lockfile(deps=(
        LockedDep(
            name="chronos", identity=None, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url=PRIMARY, ref="main", commit_sha="abc",
            ),),
            self_mirrors=(SELF_MIRROR,),
        ),
    ))

    # No identity pin so the mirror's bytes are accepted on first fetch
    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps", registry={},
        fetcher=registry, list_tags=lambda url: [],
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
        prior_lockfile=prior_lockfile,
    )
    # Both URLs were attempted; mirror succeeded
    assert PRIMARY in fetcher_impl.attempted
    assert SELF_MIRROR in fetcher_impl.attempted
    assert "chronos" in {d.name for d in graph.deps}


def test_hostile_self_mirror_rejected_by_identity_verification(tmp_path):
    """Safety net: a hostile self-mirror serving different bytes is
    rejected by fetch_any's expected_identity check (#82). Even though
    primary failed and we fell through to the self-mirror, the
    mismatched bytes can't masquerade as the locked dep."""
    from milpa.fetchers import FetcherRegistry, FetchError
    from milpa.fetchers.git import GitProvenance, GitReceipt
    from milpa.lockfile import (
        GitProvenanceRecord, LockedDep, Lockfile,
    )
    from milpa.profile import Profile
    from milpa.resolver import resolve

    PRIMARY = "https://primary.example.com/chronos.git"
    HOSTILE = "https://hostile.example.com/chronos.git"
    locked_identity = "sha256:" + "a" * 64  # pin to bogus value

    class HostileFetcher:
        def __init__(self): self.attempted = []
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            self.attempted.append(p.url)
            if p.url == PRIMARY:
                raise FetchError(f"primary down")
            # Hostile mirror: returns DIFFERENT bytes than what's pinned
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('# hostile bytes\n')
            (dest / "evil").write_text("malicious content")
            return GitReceipt(commit_sha="evil")

    fetcher_impl = HostileFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(name="chronos", git=PRIMARY, ref="main"),),
    )
    prior_lockfile = Lockfile(deps=(
        LockedDep(
            name="chronos", identity=locked_identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url=PRIMARY, ref="main", commit_sha="abc",
            ),),
            self_mirrors=(HOSTILE,),
        ),
    ))

    with pytest.raises(Exception) as exc:
        resolve(
            top_manifest, deps_dir=tmp_path / "_deps", registry={},
            fetcher=registry, list_tags=lambda url: [],
            profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
            prior_lockfile=prior_lockfile,
        )
    # Both URLs attempted, both rejected (primary down, mirror identity-mismatch)
    assert PRIMARY in fetcher_impl.attempted
    assert HOSTILE in fetcher_impl.attempted
    msg = str(exc.value).lower()
    assert "identity" in msg or "all" in msg
