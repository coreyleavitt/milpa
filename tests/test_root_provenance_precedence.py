"""Root-only provenance-override precedence (§ Provenance precedence).

When the ROOT manifest and a TRANSITIVE dep declare different provenance for
the SAME package name, the ROOT's declaration wins and the transitive
provenance is suppressed (not fetched).  Only the top-level project being
built can redirect a dep's source; an intermediate library cannot.

Semantics under test:
 1. Root authority: root deps/dev-deps/overrides win over any transitive
    provenance for the same name.
 2. Transitive overrides {} blocks are ignored (security: intermediate dep
    cannot redirect another dep's source).
 3. Non-root disagreement: two transitives declare different provenance for
    the same name → conflict error (RES-PROVENANCE-CONFLICT) if different
    identity, unify if same identity.
 4. Workspace: a member's root-authority declaration wins over a transitive
    provenance for the same name.
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.fetchers.local import LocalFetcher
from milpa.manifest import LocalDep, Manifest, NamedDep, Override, UrlDep
from milpa.resolver import ResolverError, resolve, resolve_workspace
from milpa.workspace import LoadedMember, Workspace


# ---------------------------------------------------------------------------
# Test harness — tracking fetcher
# ---------------------------------------------------------------------------


@dataclass
class TrackingFetcher:
    """Fetcher that records every (name, url, ref) fetch call.

    Maps (url, ref) → (sha, nimble_text) for git fetches.  Also accepts
    local-path fetches (always writes a minimal .nimble)."""

    by_url_ref: dict[tuple[str, str], tuple[str, str]]
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((name, p.url, p.ref))
        sha, nimble_text = self.by_url_ref[(p.url, p.ref)]
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(nimble_text)
        return GitReceipt(commit_sha=sha)


def _reg(fake, *, with_local: bool = False):
    r = FetcherRegistry()
    if with_local:
        r.register(LocalFetcher())
    r.register(fake)
    return r


def _urls_fetched(fake: TrackingFetcher) -> list[str]:
    return [url for _name, url, _ref in fake.calls]


# ---------------------------------------------------------------------------
# Test 1 (CORE): root local dep wins over transitive git dep of same name
# ---------------------------------------------------------------------------


def test_root_local_dep_wins_over_transitive_git_dep(tmp_path):
    """Root manifest declares `proptest local="..."`.
    A transitive dep (via its nimble) declares `proptest git="https://..."`.

    Expected:
    - proptest resolves to the local (root) provenance.
    - The transitive git URL is NEVER fetched.
    - proptest appears exactly once in the graph.
    """
    # Build a fake local source tree for proptest.
    proptest_local = tmp_path / "proptest"
    proptest_local.mkdir()
    (proptest_local / "proptest.nimble").write_text('srcDir = "src"\n')

    # mylib.git transitively requires proptest via git.
    proptest_git_url = "https://example.com/proptest.git"
    fake = TrackingFetcher(
        by_url_ref={
            ("https://example.com/mylib.git", "main"): (
                "mylib-sha",
                f'srcDir = "src"\nrequires "{proptest_git_url}#main"\n',
            ),
            # proptest via git MUST NOT be fetched — not in by_url_ref
            # so an attempt would raise KeyError.
        }
    )

    manifest = Manifest(
        kind="library",
        name="proj",
        deps=(
            LocalDep(name="proptest", path="../proptest"),
            UrlDep(name="mylib", git="https://example.com/mylib.git", ref="main"),
        ),
    )

    project_dir = tmp_path / "project"
    project_dir.mkdir()

    graph = resolve(
        manifest,
        deps_dir=project_dir / "_deps",
        fetcher=_reg(fake, with_local=True),
    )

    # proptest appears exactly once
    proptest_entries = [d for d in graph.deps if d.name == "proptest"]
    assert len(proptest_entries) == 1, (
        f"proptest must appear exactly once; got {len(proptest_entries)} "
        f"(all deps: {[d.name for d in graph.deps]})"
    )

    # proptest resolves to local provenance (source starts with "local:")
    proptest_dep = proptest_entries[0]
    assert proptest_dep.source.startswith("local:"), (
        f"proptest must resolve to local provenance; got source={proptest_dep.source!r}"
    )

    # The git URL was NEVER fetched
    assert proptest_git_url not in _urls_fetched(fake), (
        f"proptest git URL must never be fetched; fetcher calls: {fake.calls}"
    )


# ---------------------------------------------------------------------------
# Test 2: transitive overrides {} block is ignored (security)
# ---------------------------------------------------------------------------


def test_transitive_override_block_is_ignored(tmp_path):
    """A transitive dep's milpa.kdl declares an overrides {} block that
    would redirect `results` to a different URL.  That override MUST be
    ignored — only the root's overrides apply.

    The root does NOT override results.  The transitive override from mylib's
    milpa.kdl MUST NOT affect how results is resolved.
    """
    from tests.test_transitive_milpa_kdl import MilpaKdlFetcher

    results_canonical_url = "https://example.com/results.git"
    results_malicious_url = "https://evil.example.com/results.git"

    fetcher_impl = MilpaKdlFetcher({
        "https://example.com/mylib.git": f'''name "mylib"
kind "library"
deps {{
    results git=(url)"{results_canonical_url}" ref="main"
}}
overrides {{
    pkg "results" git=(url)"{results_malicious_url}" ref="hacked"
}}
''',
        results_canonical_url: 'name "results"\nkind "library"\n',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    manifest = Manifest(
        kind="library",
        name="proj",
        deps=(
            UrlDep(name="mylib", git="https://example.com/mylib.git", ref="main"),
        ),
    )

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
    )

    # results must be present (the canonical URL was in the transitive dep)
    results_entries = [d for d in graph.deps if d.name == "results"]
    assert len(results_entries) == 1

    # results must resolve to the canonical URL, NOT the malicious one
    results_dep = results_entries[0]
    assert results_malicious_url not in results_dep.source, (
        f"results must NOT resolve to the malicious override URL; "
        f"got source={results_dep.source!r}"
    )
    # The malicious URL was never fetched
    assert results_malicious_url not in fetcher_impl.fetched, (
        f"malicious results URL must not be fetched; fetched={fetcher_impl.fetched}"
    )


# ---------------------------------------------------------------------------
# Test 3a: non-root disagreement, different identity → conflict error
# ---------------------------------------------------------------------------


def test_non_root_disagreement_different_provenance_raises_conflict(tmp_path):
    """Two transitive deps (a and b) both declare a dep on `shared` (same
    package name), but from different git URLs (different provenance →
    different identity since they write different nimble contents).

    `a` requires `shared` from `shared-fork-a.git` (ref v1).
    `b` requires `shared` from `shared-fork-b.git` (ref v1).
    Both deps name the package `shared` (derived via _name_from_url from
    a URL whose last segment is "shared").

    Root does NOT declare `shared`.  This is a provenance conflict: the
    resolver cannot unambiguously choose between two different source trees
    for the same package name.

    Expected: ResolverError with code RES-PROVENANCE-CONFLICT.
    """
    # Both URLs derive the name "shared" via _name_from_url (last segment).
    shared_url_fork_a = "https://example.com/forks/shared.git"
    shared_url_fork_b = "https://other.example.com/forks/shared.git"

    fake = TrackingFetcher(
        by_url_ref={
            ("https://example.com/a.git", "main"): (
                "a-sha",
                f'srcDir = "src"\nrequires "{shared_url_fork_a}#v1"\n',
            ),
            ("https://example.com/b.git", "main"): (
                "b-sha",
                f'srcDir = "src"\nrequires "{shared_url_fork_b}#v1"\n',
            ),
            (shared_url_fork_a, "v1"): ("shared-a-sha", 'srcDir = "src-a"\n'),
            (shared_url_fork_b, "v1"): ("shared-b-sha", 'srcDir = "src-b"\n'),
        }
    )

    manifest = Manifest(
        kind="library",
        name="proj",
        deps=(
            UrlDep(name="a", git="https://example.com/a.git", ref="main"),
            UrlDep(name="b", git="https://example.com/b.git", ref="main"),
        ),
    )

    with pytest.raises(ResolverError) as exc_info:
        resolve(
            manifest,
            deps_dir=tmp_path / "_deps",
            fetcher=_reg(fake),
        )

    assert exc_info.value.code == "RES-PROVENANCE-CONFLICT", (
        f"expected RES-PROVENANCE-CONFLICT, got {exc_info.value.code!r}: "
        f"{exc_info.value}"
    )
    # The error message should name the conflicted package
    assert "shared" in str(exc_info.value).lower(), (
        f"error should mention 'shared'; got: {exc_info.value}"
    )


# ---------------------------------------------------------------------------
# Test 3b: non-root disagreement, SAME identity → unifies fine (no error)
# ---------------------------------------------------------------------------


def test_non_root_disagreement_same_provenance_unifies(tmp_path):
    """Two transitive deps declare the SAME git URL+ref for `shared`.
    This is a simple mirror/duplicate — the resolver deduplicates cleanly
    (same provenance key → transport-level dedup, no conflict raised).
    """
    shared_url = "https://example.com/shared.git"
    shared_nimble = 'srcDir = "src"\n'

    fake = TrackingFetcher(
        by_url_ref={
            ("https://example.com/a.git", "main"): (
                "a-sha",
                f'srcDir = "src"\nrequires "{shared_url}#v1"\n',
            ),
            ("https://example.com/b.git", "main"): (
                "b-sha",
                f'srcDir = "src"\nrequires "{shared_url}#v1"\n',
            ),
            (shared_url, "v1"): ("shared-sha", shared_nimble),
        }
    )

    manifest = Manifest(
        kind="library",
        name="proj",
        deps=(
            UrlDep(name="a", git="https://example.com/a.git", ref="main"),
            UrlDep(name="b", git="https://example.com/b.git", ref="main"),
        ),
    )

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=_reg(fake),
    )

    # shared appears exactly once (same (url, ref) → transport-level dedup)
    shared_entries = [d for d in graph.deps if d.name == "shared"]
    assert len(shared_entries) == 1, (
        f"shared should appear exactly once; got {len(shared_entries)}"
    )
    # Both a and b are in the graph
    names = {d.name for d in graph.deps}
    assert "a" in names
    assert "b" in names


# ---------------------------------------------------------------------------
# Test 4: workspace — member root-authority declaration wins over transitive
# ---------------------------------------------------------------------------


def test_workspace_member_root_authority_wins_over_transitive(tmp_path):
    """A workspace member declares `proptest git="https://our-fork/..."`.
    A transitive dep of another member declares `proptest git="https://upstream/..."`.

    Expected:
    - proptest resolves to the member's (root-authority) provenance.
    - The upstream URL is NOT fetched.
    - proptest appears exactly once in the graph.
    """
    our_fork_url = "https://our-fork.example.com/proptest.git"
    upstream_url = "https://upstream.example.com/proptest.git"

    # member A directly declares proptest from our fork
    # member B has a transitive dep that wants proptest from upstream
    fake = TrackingFetcher(
        by_url_ref={
            (our_fork_url, "our-branch"): ("fork-sha", 'srcDir = "src"\n'),
            ("https://example.com/mylib.git", "main"): (
                "mylib-sha",
                f'srcDir = "src"\nrequires "{upstream_url}#main"\n',
            ),
            # upstream proptest MUST NOT be fetched
        }
    )

    member_a_dir = tmp_path / "a"
    member_a_dir.mkdir()
    (member_a_dir / "a.nimble").write_text('srcDir = "src"\n')

    member_b_dir = tmp_path / "b"
    member_b_dir.mkdir()
    (member_b_dir / "b.nimble").write_text('srcDir = "src"\n')

    member_a_manifest = Manifest(
        kind="library", name="a",
        deps=(
            UrlDep(name="proptest", git=our_fork_url, ref="our-branch"),
        ),
    )
    member_b_manifest = Manifest(
        kind="library", name="b",
        deps=(
            UrlDep(name="mylib", git="https://example.com/mylib.git", ref="main"),
        ),
    )

    ws = Workspace(
        root=tmp_path,
        members=(
            LoadedMember(
                name="a",
                path="a",
                directory=member_a_dir,
                manifest=member_a_manifest,
            ),
            LoadedMember(
                name="b",
                path="b",
                directory=member_b_dir,
                manifest=member_b_manifest,
            ),
        ),
    )

    graph = resolve_workspace(
        ws,
        deps_dir=tmp_path / "_deps",
        fetcher=_reg(fake),
    )

    # proptest appears exactly once
    proptest_entries = [d for d in graph.deps if d.name == "proptest"]
    assert len(proptest_entries) == 1, (
        f"proptest must appear exactly once; got {len(proptest_entries)} "
        f"(all deps: {[d.name for d in graph.deps]})"
    )

    # proptest resolves to the fork (our root-authority) provenance
    proptest_dep = proptest_entries[0]
    assert our_fork_url in proptest_dep.source, (
        f"proptest must resolve to our fork URL; got source={proptest_dep.source!r}"
    )

    # The upstream URL was NEVER fetched
    assert upstream_url not in _urls_fetched(fake), (
        f"upstream proptest URL must not be fetched; fetcher calls: {fake.calls}"
    )
