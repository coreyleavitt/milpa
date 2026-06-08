"""Named-dep resolution through the tianguis index (milpa#97, S4).

These pin the behaviors the registry→index swap introduces on the
resolver's named path:

  - a named dep resolves to the index-pinned git provenance + records it
    typed (not a `registry:` source string);
  - the index `content_hash` is the post-fetch identity gate (Invariant
    1 / R2) — matching bytes pass, mismatched bytes are rejected;
  - a `v`-prefixed index version resolves (the old `int(split)` path
    crashed on it); a genuinely unparseable version surfaces a coded
    TianguisError, never a Python crash;
  - a name absent from the index is a hard TNG-NOT-FOUND (no fallback).
"""

from dataclasses import dataclass, field

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.lockfile import GitProvenanceRecord, from_graph
from milpa.manifest import Manifest, NamedDep
from milpa.resolver import resolve
from milpa.tianguis_client import TianguisError
from tests.indexkdl import make_index


@dataclass
class _Fake:
    """Writes a fixed nimble; records the (url, ref) it was asked for."""
    nimble: str = 'srcDir = "src"\n'
    sha: str = "deadbeef"
    calls: list = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((p.url, p.ref, p.commit_sha))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(self.nimble)
        return GitReceipt(commit_sha=self.sha)


def _reg(fake):
    r = FetcherRegistry()
    r.register(fake)
    return r


def test_named_dep_resolves_to_typed_git_provenance(tmp_path):
    fake = _Fake()
    # Use a valid 40-hex commit_sha (H2 validation now enforced at parse time)
    pin_sha = "cafef00dcafef00dcafef00dcafef00dcafef00d"
    index = make_index([
        {"name": "foo", "version": "1.2.3",
         "url": "https://example.com/foo.git", "ref": "v1.2.3",
         "commit_sha": pin_sha},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=">= 1.0.0"),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
    )
    foo = next(d for d in graph.deps if d.name == "foo")
    assert foo.version == (1, 2, 3)
    assert foo.source == "https://example.com/foo.git"
    assert foo.ref == "v1.2.3"
    assert foo.sha == "deadbeef"            # from the receipt, not the index
    # The fetcher was asked to honor the index's immutable commit_sha pin.
    assert fake.calls == [("https://example.com/foo.git", "v1.2.3", pin_sha)]
    # Lockfile reconstructs a git record by TYPE (no source-string parse).
    locked = from_graph(graph).deps
    rec = next(d for d in locked if d.name == "foo").provenances[0]
    assert isinstance(rec, GitProvenanceRecord)
    assert rec.url == "https://example.com/foo.git"
    assert rec.ref == "v1.2.3"
    assert rec.commit_sha == "deadbeef"


def test_named_dep_v_prefixed_version_resolves(tmp_path):
    """A `v`-prefixed index version (`v2.0.0`) resolves — the old
    `int(version.split('.')[0])` path crashed on the `v`."""
    fake = _Fake()
    index = make_index([
        {"name": "foo", "version": "v2.0.0",
         "url": "https://example.com/foo.git", "ref": "v2.0.0"},
    ])
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
    )
    assert next(d for d in graph.deps if d.name == "foo").version == (2, 0, 0)


def test_named_dep_unparseable_version_raises_coded_error(tmp_path):
    """An index whose only version is unparseable surfaces a coded
    TianguisError — never a bare Python ValueError.

    The unparseable version is filtered inside tianguis_client.resolve_named
    (L2: the TNG-BAD-VERSION arm in _process_named is unreachable); the
    error that fires is TNG-NO-SATISFYING-VERSION."""
    fake = _Fake()
    # 1.2.3.4 (four components) is not a clean X.Y.Z; it's the lone version.
    index = make_index([
        {"name": "foo", "version": "1.2.3.4",
         "url": "https://example.com/foo.git", "ref": "main"},
    ])
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    with pytest.raises(TianguisError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
        )
    assert exc.value.code == "TNG-NO-SATISFYING-VERSION"


def test_named_dep_identity_gate_passes_on_matching_hash(tmp_path):
    """R2: when the index records the content_hash the fetched tree
    actually hashes to, the identity gate passes."""
    fake = _Fake()
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    # First resolve with the gate OFF to learn the real recomputed hash.
    probe = resolve(
        manifest, deps_dir=tmp_path / "_probe",
        index=make_index([
            {"name": "foo", "version": "1.0.0",
             "url": "https://example.com/foo.git", "ref": "v1.0.0"},
        ]),
        fetcher=_reg(_Fake()),
    )
    real_hash = next(d for d in probe.deps if d.name == "foo").identity
    assert real_hash and real_hash.startswith("sha256:")

    # Now the index claims that exact hash → gate passes.
    index = make_index([
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": real_hash},
    ])
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
    )
    assert next(d for d in graph.deps if d.name == "foo").identity == real_hash


def test_named_dep_identity_gate_rejects_mismatched_hash(tmp_path):
    """A hostile forge serving bytes that don't hash to the index's
    content_hash is rejected at fetch time (Invariant 1)."""
    from milpa.fetchers import FetchError
    fake = _Fake()
    index = make_index([
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": "sha256:" + "0" * 64},
    ])
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="foo", constraint=None),),
    )
    with pytest.raises(FetchError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=_reg(fake),
        )
    assert "identity" in str(exc.value).lower()


def test_named_dep_absent_from_index_raises_not_found(tmp_path):
    """No nim-lang fallback: a name not in the index is a hard error."""
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="ghost", constraint=None),),
    )
    with pytest.raises(TianguisError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps",
            index=make_index([]), fetcher=_reg(_Fake()),
        )
    assert exc.value.code == "TNG-NOT-FOUND"


def test_named_dep_without_index_raises_clear_resolver_error(tmp_path):
    """M7: when a manifest has named deps and index=None is passed, the
    error is a clear ResolverError — not a misleading TNG-NOT-FOUND."""
    from milpa.resolver import ResolverError
    manifest = Manifest(
        kind="library", name="proj", deps=(NamedDep(name="results", constraint=None),),
    )
    with pytest.raises(ResolverError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps",
            index=None, fetcher=_reg(_Fake()),
        )
    assert "index" in str(exc.value).lower()
    assert "results" in str(exc.value)


# ---------------------------------------------------------------------------
# M8 — OCI named-dep path through the resolver in-process
# ---------------------------------------------------------------------------
# The chain parse_index → resolve_named → _process_named →
# fetch_any(OciProvenance) → from_graph → OciProvenanceRecord had been
# covered only by the gated live integration test. These tests close that gap
# with a fake OciFetcher injected via FetcherRegistry (no oras invocation).
# ---------------------------------------------------------------------------


@dataclass
class _FakeOci:
    """Fake OciFetcher: writes a fixed source tree and records calls.
    The content_hash produced must be pre-computed and passed to make_index
    so the identity gate passes (use fake_content_hash(name) for that)."""
    nimble: str = 'srcDir = "src"\n'
    calls: list = field(default_factory=list)

    def can_handle(self, p):
        from milpa.fetchers.oci import OciProvenance
        return isinstance(p, OciProvenance)

    def fetch(self, name, p, *, dest):
        from milpa.fetchers.oci import OciProvenance, OciReceipt
        assert isinstance(p, OciProvenance)
        self.calls.append((p.registry, p.repository, p.digest))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(self.nimble)
        return OciReceipt(oci_digest=p.digest)


def test_oci_named_dep_resolves_end_to_end(tmp_path):
    """M8: a named dep whose canonical provenance is OciProvenance resolves
    end-to-end through the resolver. The resulting ResolvedDep carries an
    OciProvenance; from_graph emits an OciProvenanceRecord with matching
    registry/repository/digest."""
    from milpa.lockfile import OciProvenanceRecord
    from milpa.fetchers.oci import OciProvenance
    from tests.indexkdl import fake_content_hash

    digest = "sha256:" + "e" * 64
    name = "nimkdl"
    ch = fake_content_hash(name)

    oci_fake = _FakeOci()
    r = FetcherRegistry()
    r.register(oci_fake)

    index = make_index([{
        "name": name,
        "kind": "oci",
        "registry": "ghcr.io",
        "repository": "user/nimkdl",
        "digest": digest,
        "content_hash": ch,
        "version": "0.2.0",
    }])

    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name=name, constraint=None),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=r,
    )

    dep = next(d for d in graph.deps if d.name == name)
    # Typed OCI provenance carried on the resolved dep.
    assert isinstance(dep.provenance, OciProvenance)
    assert dep.provenance.registry == "ghcr.io"
    assert dep.provenance.repository == "user/nimkdl"
    assert dep.provenance.digest == digest
    # source display string for OCI (milpa#97).
    assert dep.source == "oci:ghcr.io/user/nimkdl"

    # from_graph must emit an OciProvenanceRecord (not GitProvenanceRecord).
    from milpa.lockfile import from_graph
    locked_dep = next(
        d for d in from_graph(graph).deps if d.name == name
    )
    rec = locked_dep.provenances[0]
    assert isinstance(rec, OciProvenanceRecord)
    assert rec.registry == "ghcr.io"
    assert rec.repository == "user/nimkdl"
    assert rec.digest == digest

    # The fake OCI fetcher was called exactly once with the right coordinates.
    assert oci_fake.calls == [("ghcr.io", "user/nimkdl", digest)]


# ===========================================================================
# P3.2 — multi-version named-dep provider
# ===========================================================================
#
# These tests drive the two-phase architecture:
#   Phase A: enumerate all satisfying IndexVersions as stub candidates (no
#            fetch yet) — the provider now sees N versions, not 1.
#   Phase B: fetch only the solver-selected version, then parse its nimble
#            for transitives.
#   Fixpoint: if Phase B reveals new named deps, re-enumerate and re-solve.
#
# Regression guard: existing single-version tests continue to pass unmodified.
# ===========================================================================


@dataclass
class _FakeVersioned:
    """Fake fetcher that can serve multiple distinct versions.

    `versions` maps version_str → nimble_text.  `sha` is uniform.
    `calls` records (url, ref, commit_sha) for assertion.
    """
    versions: dict  # version_str → nimble_text
    sha: str = "deadbeef" * 5  # 40 chars
    calls: list = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((p.url, p.ref, p.commit_sha))
        dest.mkdir(parents=True, exist_ok=True)
        # The ref encodes the version for this fake: the index uses ref=vX.Y.Z
        # so we map ref → nimble.  Fall back to a default empty nimble.
        nimble_text = self.versions.get(p.ref, 'srcDir = "src"\n')
        (dest / f"{name}.nimble").write_text(nimble_text)
        return GitReceipt(commit_sha=self.sha)


def _reg_versioned(fake):
    r = FetcherRegistry()
    r.register(fake)
    return r


# ---------------------------------------------------------------------------
# Gate 1: N satisfying index versions → N candidates (provider sees all N)
# ---------------------------------------------------------------------------


def test_multi_version_named_dep_all_candidates_registered(tmp_path):
    """P3.2 gate 1: a named dep with N satisfying index versions must register
    all N candidates in the provider. The solver should see N versions, not 1.

    We verify indirectly: if only 1 version is registered, the solver cannot
    backtrack when that version's deps create a conflict. With N registered,
    the solver can pick the highest and succeed without backtracking for simple
    cases, but the candidate set exists.

    Direct invariant: the graph contains `foo` at the HIGHEST satisfying
    version (maxver strategy picks index 0 = newest), and only one `foo`
    entry exists in the graph (PubGrub still selects exactly ONE).
    """
    # Index has foo at 2.0.0 and 1.0.0, both satisfying >= 1.0.0
    # The content_hash must be pre-computed for each version's fetched tree.
    from tests.indexkdl import fake_content_hash
    nimble_200 = 'srcDir = "src"\n'
    nimble_100 = 'srcDir = "src"\n'
    ch_200 = fake_content_hash("foo", nimble_200)
    ch_100 = fake_content_hash("foo", nimble_100)

    fake = _FakeVersioned(
        versions={"v2.0.0": nimble_200, "v1.0.0": nimble_100},
        sha="a" * 40,
    )
    index = make_index([
        {"name": "foo", "version": "2.0.0",
         "url": "https://example.com/foo.git", "ref": "v2.0.0",
         "content_hash": ch_200},
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": ch_100},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=">= 1.0.0"),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index,
        fetcher=_reg_versioned(fake),
    )
    # Exactly one `foo` in the graph (PubGrub selects one version)
    foo_deps = [d for d in graph.deps if d.name == "foo"]
    assert len(foo_deps) == 1
    # maxver picks the highest: 2.0.0
    assert foo_deps[0].version == (2, 0, 0)
    # Only one fetch call was made — Phase B fetches only the winner
    assert len(fake.calls) == 1


# ---------------------------------------------------------------------------
# Gate 2: backtracking — single-constraint conflict forces lower version
# ---------------------------------------------------------------------------


def test_backtracking_picks_lower_version_when_higher_conflicts(tmp_path):
    """P3.2 gate 2: when the highest satisfying version's deps are
    unsatisfiable (conflict), the solver must backtrack and pick the next
    lower version.

    Setup:
      - `foo` has versions 2.0.0 and 1.0.0
      - `foo 2.0.0` requires `bar >= 2.0.0` (bar only has 1.0.0 → conflict)
      - `foo 1.0.0` has no transitive deps → resolves cleanly

    Without P3.2's multi-candidate set, the solver would try only 2.0.0 and
    fail with an unsatisfiable error. With P3.2, it backtracks to 1.0.0.
    """
    from milpa.solver import SolverError
    from tests.indexkdl import fake_content_hash

    # bar has only 1.0.0
    bar_nimble = 'srcDir = "src"\n'
    bar_ch = fake_content_hash("bar", bar_nimble)

    # foo 2.0.0 requires bar >= 2.0.0 (conflict — bar only has 1.0.0)
    foo200_nimble = 'requires "bar >= 2.0.0"\nsrcDir = "src"\n'
    # foo 1.0.0 has no deps
    foo100_nimble = 'srcDir = "src"\n'

    foo200_ch = fake_content_hash("foo", foo200_nimble)
    foo100_ch = fake_content_hash("foo", foo100_nimble)

    @dataclass
    class _FakeMulti:
        """Fake that serves different nimble content per (name, ref) pair."""
        calls: list = field(default_factory=list)
        sha: str = "b" * 40

        def can_handle(self, p):
            return isinstance(p, GitProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append((name, p.ref))
            dest.mkdir(parents=True, exist_ok=True)
            content = {
                ("foo", "v2.0.0"): foo200_nimble,
                ("foo", "v1.0.0"): foo100_nimble,
                ("bar", "v1.0.0"): bar_nimble,
            }.get((name, p.ref), 'srcDir = "src"\n')
            (dest / f"{name}.nimble").write_text(content)
            return GitReceipt(commit_sha=self.sha)

    fake = _FakeMulti()
    r = FetcherRegistry()
    r.register(fake)

    index = make_index([
        {"name": "foo", "version": "2.0.0",
         "url": "https://example.com/foo.git", "ref": "v2.0.0",
         "content_hash": foo200_ch},
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": foo100_ch},
        {"name": "bar", "version": "1.0.0",
         "url": "https://example.com/bar.git", "ref": "v1.0.0",
         "content_hash": bar_ch},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(
            NamedDep(name="foo", constraint=">= 1.0.0"),
            NamedDep(name="bar", constraint=">= 1.0.0"),
        ),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=r,
    )
    # foo resolved to 1.0.0 (2.0.0 was tried and caused a conflict)
    foo_dep = next(d for d in graph.deps if d.name == "foo")
    assert foo_dep.version == (1, 0, 0), (
        f"expected foo 1.0.0 (backtracked from 2.0.0), got {foo_dep.version}"
    )
    bar_dep = next(d for d in graph.deps if d.name == "bar")
    assert bar_dep.version == (1, 0, 0)


# ---------------------------------------------------------------------------
# Gate 3: TNG-AMBIGUOUS-NAME still raised for bare-name collision
# ---------------------------------------------------------------------------


def test_ambiguous_bare_name_still_raises(tmp_path):
    """P3.2 gate 3: a bare-name collision (two namespaces, one name) must
    still surface TNG-AMBIGUOUS-NAME — the multi-version path does not
    accidentally silence this error."""
    from milpa.tianguis_client import TianguisError

    # Two packages sharing the bare name "nimkdl"
    from milpa.tianguis_client import parse_index
    index = parse_index("""\
schema_version 1
package "nimkdl" {
    namespace "greenm01"
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
    version "0.1.4" {
        content_hash "sha256:bbb0000000000000000000000000000000000000000000000000000000000000"
        provenance {
            kind "git"
            url "https://github.com/coreyleavitt/nimkdl"
            ref "HEAD"
            commit_sha "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
    }
}
""")
    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="nimkdl", constraint=None),),
    )
    with pytest.raises(TianguisError) as exc:
        resolve(
            manifest, deps_dir=tmp_path / "_deps", index=index,
            fetcher=_reg_versioned(_FakeVersioned({})),
        )
    assert exc.value.code == "TNG-AMBIGUOUS-NAME"


# ===========================================================================
# P3.3 — strategy + backtracking for named deps
# ===========================================================================
#
# These validate the three remaining behaviors from P3.3:
#
#   S1: SEMVER through the full resolve() stack picks the highest version
#       within the same major as the constraint's lower bound.
#
#   S2: Diamond conflict over a named dep forces backtracking. Two deps share
#       a common named dep; only one version of the shared dep satisfies both.
#
#   S3: SEMVER + prerelease opt-in — a >=1.0.0 constraint excludes 1.0.0-rc
#       from the candidate set, so SEMVER never surfaces the pre-release
#       version that opt-in already filtered out.
#
# P3.2 already pins MAXVER and MINVER (test_resolve_named_dep_strategy_applies_to_index_versions
# in test_resolver.py) and single-constraint backtracking (test_backtracking_picks_lower_version_when_higher_conflicts).
# P3.3 extends coverage with the SEMVER path and a true diamond.
# ===========================================================================


# ---------------------------------------------------------------------------
# S1: SEMVER through the full resolve() stack
# ---------------------------------------------------------------------------


def test_semver_strategy_picks_highest_within_same_major(tmp_path):
    """P3.3 S1: SEMVER picks the highest satisfying version within the same
    major as the constraint's lower bound, not the global max.

    Setup: foo has versions 0.9.0, 1.0.0, 1.1.0, 2.0.0. Constraint >= 1.0.0.
    - MAXVER would pick 2.0.0 (global highest).
    - SEMVER picks 1.1.0 (highest within major=1, the lower-bound major).
    """
    from milpa.solver import Strategy
    from tests.indexkdl import fake_content_hash

    nimble = 'srcDir = "src"\n'
    index = make_index([
        {"name": "foo", "version": "0.9.0",
         "url": "https://example.com/foo.git", "ref": "v0.9.0",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "1.1.0",
         "url": "https://example.com/foo.git", "ref": "v1.1.0",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "2.0.0",
         "url": "https://example.com/foo.git", "ref": "v2.0.0",
         "content_hash": fake_content_hash("foo", nimble)},
    ])

    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=">= 1.0.0"),),
    )

    fake = _FakeVersioned(
        versions={
            "v1.1.0": nimble,  # the expected SEMVER winner
        },
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index,
        fetcher=_reg_versioned(fake), strategy=Strategy.SEMVER,
    )
    foo_dep = next(d for d in graph.deps if d.name == "foo")
    assert foo_dep.version == (1, 1, 0), (
        f"SEMVER should pick 1.1.0 (highest in major=1), got {foo_dep.version}"
    )
    assert foo_dep.ref == "v1.1.0"


# ---------------------------------------------------------------------------
# S2: Diamond conflict over a named dep forces backtracking
# ---------------------------------------------------------------------------


def test_diamond_conflict_named_dep_backtracks(tmp_path):
    """P3.3 S2: a diamond dep conflict forces backtracking to a compatible version.

    Diamond shape: baz is constrained from two paths — the manifest root and
    a transitive dep from foo.

    Graph:
      root → foo (>= 1.0.0), baz (>= 1.0.0)
      foo 2.0.0 → baz (>= 3.0.0)   ← conflict: baz max is 2.5.0
      foo 1.0.0 → no transitive deps
      baz: versions 1.5.0 and 2.5.0

    MAXVER picks foo 2.0.0 first. Its transitive dep baz >= 3.0.0, combined
    with the root's baz >= 1.0.0, leaves baz >= 3.0.0. No baz candidate
    satisfies that. The solver backtracks to foo 1.0.0. Now baz only has
    the root constraint baz >= 1.0.0, and MAXVER picks baz 2.5.0.

    Note: this shape is compatible with the teaching-clean one-level
    backtracking solver. A multi-path diamond that also constrains baz
    from an independent named dep (e.g. bar) would require multi-level
    backjumping (deferred to #28 / P3.5).
    """
    from tests.indexkdl import fake_content_hash

    baz_nimble = 'srcDir = "src"\n'
    baz150_ch = fake_content_hash("baz", baz_nimble)
    baz250_ch = fake_content_hash("baz", baz_nimble)

    foo200_nimble = 'requires "baz >= 3.0.0"\nsrcDir = "src"\n'
    foo100_nimble = 'srcDir = "src"\n'
    foo200_ch = fake_content_hash("foo", foo200_nimble)
    foo100_ch = fake_content_hash("foo", foo100_nimble)

    @dataclass
    class _FakeDiamond:
        calls: list = field(default_factory=list)
        sha: str = "c" * 40

        def can_handle(self, p):
            return isinstance(p, GitProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append((name, p.ref))
            dest.mkdir(parents=True, exist_ok=True)
            content = {
                ("foo", "v2.0.0"): foo200_nimble,
                ("foo", "v1.0.0"): foo100_nimble,
                ("baz", "v1.5.0"): baz_nimble,
                ("baz", "v2.5.0"): baz_nimble,
            }.get((name, p.ref), 'srcDir = "src"\n')
            (dest / f"{name}.nimble").write_text(content)
            return GitReceipt(commit_sha=self.sha)

    fake = _FakeDiamond()
    r = FetcherRegistry()
    r.register(fake)

    index = make_index([
        {"name": "foo", "version": "2.0.0",
         "url": "https://example.com/foo.git", "ref": "v2.0.0",
         "content_hash": foo200_ch},
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": foo100_ch},
        {"name": "baz", "version": "1.5.0",
         "url": "https://example.com/baz.git", "ref": "v1.5.0",
         "content_hash": baz150_ch},
        {"name": "baz", "version": "2.5.0",
         "url": "https://example.com/baz.git", "ref": "v2.5.0",
         "content_hash": baz250_ch},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(
            NamedDep(name="foo", constraint=">= 1.0.0"),
            NamedDep(name="baz", constraint=">= 1.0.0"),
        ),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=r,
    )
    foo_dep = next(d for d in graph.deps if d.name == "foo")
    assert foo_dep.version == (1, 0, 0), (
        f"foo should backtrack to 1.0.0 (diamond conflict: foo 2.0.0 requires "
        f"baz >= 3.0.0 which has no candidate), got {foo_dep.version}"
    )
    baz_dep = next(d for d in graph.deps if d.name == "baz")
    assert baz_dep.version == (2, 5, 0), (
        f"baz should be 2.5.0 (MAXVER from root constraint >= 1.0.0 after "
        f"foo backtracked), got {baz_dep.version}"
    )


# ---------------------------------------------------------------------------
# S3: SEMVER + prerelease opt-in — excluded prerelease is never surfaced
# ---------------------------------------------------------------------------


def test_semver_strategy_with_prerelease_opt_in_excludes_prerelease(tmp_path):
    """P3.3 S3: a >=1.0.0 constraint excludes 1.0.0-rc.1 via P3.1b's
    prerelease opt-in (1.0.0-rc.1 < 1.0.0 so it doesn't satisfy >= 1.0.0).
    SEMVER then picks the highest stable version within major=1 from the
    remaining candidates.

    This pins the SEMVER + prerelease-opt-in interaction: the pre-release
    version that opt-in excluded must not appear in the resolved output.

    Setup: foo has 0.9.0-beta, 1.0.0-rc.1, 1.0.0, 1.1.0. Constraint >= 1.0.0.
    - Opt-in excludes: 0.9.0-beta (< 1.0.0), 1.0.0-rc.1 (< 1.0.0).
    - Satisfying: 1.0.0, 1.1.0.
    - SEMVER: same_major=1 → picks 1.1.0 (max).
    """
    from milpa.solver import Strategy
    from tests.indexkdl import fake_content_hash

    nimble = 'srcDir = "src"\n'

    index = make_index([
        {"name": "foo", "version": "0.9.0-beta",
         "url": "https://example.com/foo.git", "ref": "v0.9.0-beta",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "1.0.0-rc.1",
         "url": "https://example.com/foo.git", "ref": "v1.0.0-rc.1",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": fake_content_hash("foo", nimble)},
        {"name": "foo", "version": "1.1.0",
         "url": "https://example.com/foo.git", "ref": "v1.1.0",
         "content_hash": fake_content_hash("foo", nimble)},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=">= 1.0.0"),),
    )

    fake = _FakeVersioned(
        versions={"v1.1.0": nimble},  # only the expected winner needs serving
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index,
        fetcher=_reg_versioned(fake), strategy=Strategy.SEMVER,
    )
    foo_dep = next(d for d in graph.deps if d.name == "foo")
    assert foo_dep.version == (1, 1, 0), (
        f"SEMVER should pick 1.1.0 (prerelease excluded by >= 1.0.0 opt-in), "
        f"got {foo_dep.version}"
    )
    assert foo_dep.ref == "v1.1.0", (
        f"expected ref v1.1.0, got {foo_dep.ref}"
    )


# ===========================================================================
# H4 — URL transitive deps from a Phase-B named dep are not dropped
# ===========================================================================


def test_named_dep_url_transitive_appears_in_resolved_graph(tmp_path):
    """H4: a named dep whose .nimble declares a URL require must produce
    that URL dep in the resolved graph. Previously _materialize_stub put
    the URL dep in dep_terms but never enrolled it with the provider,
    so the solver raised a spurious no-versions SolverError.

    Setup:
      - manifest requires named dep `foo` (in the index)
      - `foo`'s nimble requires `https://github.com/x/bar.git` (URL)
      - `bar` is a git URL dep, not in the index
      - resolve() must succeed and bar must appear in the graph
    """
    from tests.indexkdl import fake_content_hash
    from milpa.fetchers.git import GitProvenance, GitReceipt

    bar_nimble = 'srcDir = "src"\n'
    foo_nimble = 'requires "https://github.com/x/bar.git"\nsrcDir = "src"\n'

    foo_ch = fake_content_hash("foo", foo_nimble)

    @dataclass
    class _FakeMultiUrl:
        calls: list = field(default_factory=list)
        sha: str = "c" * 40

        def can_handle(self, p):
            return isinstance(p, GitProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append((name, p.url, p.ref))
            dest.mkdir(parents=True, exist_ok=True)
            content = bar_nimble if name == "bar" else foo_nimble
            (dest / f"{name}.nimble").write_text(content)
            return GitReceipt(commit_sha=self.sha)

    fake = _FakeMultiUrl()
    r = FetcherRegistry()
    r.register(fake)

    index = make_index([
        {"name": "foo", "version": "1.0.0",
         "url": "https://example.com/foo.git", "ref": "v1.0.0",
         "content_hash": foo_ch},
    ])
    manifest = Manifest(
        kind="library", name="proj",
        deps=(NamedDep(name="foo", constraint=None),),
    )
    graph = resolve(
        manifest, deps_dir=tmp_path / "_deps", index=index, fetcher=r,
    )
    names = {d.name for d in graph.deps}
    assert "foo" in names, f"foo missing from graph: {names}"
    assert "bar" in names, (
        f"H4 regression: bar (URL transitive from named dep foo) "
        f"missing from resolved graph: {names}"
    )
