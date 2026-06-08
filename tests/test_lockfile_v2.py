"""Lockfile schema — structured identity + multi-provenance (#33).

The lockfile uses an explicit `identity` field (multihash-encoded per
#34) and one-or-more `provenance { ... }` blocks per dep. Each block
carries a `kind` discriminator + kind-specific fields.

Multi-provenance (multiple `provenance` blocks per dep) is forward-
compat plumbing for Phase D #37 (where `milpa add` will append
provenances and the resolver will record mirrors). #33 ships the
schema; #37 lights up the application.

Schema version stays at 1 while we iterate pre-1.0. Once real
consumers exist we will bump and grow proper migration support.

See docs/rfc-content-addressed-identity.md §Proposed model.
"""

from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
    format_lockfile,
    parse_lockfile,
)


_HASH = "sha256:" + "a" * 64


def test_format_lockfile_emits_version_and_provenance_block():
    """Tracer: a LockedDep with a single GitProvenanceRecord produces
    a lockfile carrying `version 1`, an `identity` field, and a
    `provenance { kind "git" url "..." ref "..." commit_sha "..." }`
    block."""
    L = Lockfile(
        deps=(LockedDep(
            name="chronos",
            identity=_HASH,
            version="0.5.0",
            src_dir="src",
            requires=(),
            provenances=(GitProvenanceRecord(
                url="https://github.com/x/chronos.git",
                ref="feat/contextvars",
                commit_sha="906608aaaaaaaaaa",
            ),),
        ),),
        strategy="maxver",
    )
    text = format_lockfile(L)

    assert "version 1" in text
    assert f'identity "{_HASH}"' in text
    assert "provenance {" in text
    assert 'kind "git"' in text
    assert 'url "https://github.com/x/chronos.git"' in text
    assert 'ref "feat/contextvars"' in text
    assert 'commit_sha "906608aaaaaaaaaa"' in text


def test_parse_lockfile_reads_structured_git_provenance():
    """A lockfile parses into LockedDep with structured provenances."""
    text = '''version 1

dep "chronos" {
    identity "''' + _HASH + '''"
    version "0.5.0"
    src_dir "src"
    requires
    provenance {
        kind "git"
        url "https://github.com/x/chronos.git"
        ref "feat/contextvars"
        commit_sha "906608aaaaaaaaaa"
    }
}
'''
    lockfile = parse_lockfile(text)
    assert lockfile.version == 1
    assert len(lockfile.deps) == 1
    dep = lockfile.deps[0]
    assert dep.name == "chronos"
    assert dep.identity == _HASH
    assert len(dep.provenances) == 1
    p = dep.provenances[0]
    assert isinstance(p, GitProvenanceRecord)
    assert p.url == "https://github.com/x/chronos.git"
    assert p.ref == "feat/contextvars"
    assert p.commit_sha == "906608aaaaaaaaaa"


def test_lockfile_round_trips_byte_identical():
    """format → parse → format produces the same text."""
    L = Lockfile(
        deps=(LockedDep(
            name="chronos",
            identity=_HASH,
            version="0.5.0",
            src_dir="src",
            requires=("results",),
            provenances=(GitProvenanceRecord(
                url="https://github.com/x/chronos.git",
                ref="main",
                commit_sha="abc",
            ),),
        ),),
        strategy="maxver",
    )
    text1 = format_lockfile(L)
    parsed = parse_lockfile(text1)
    text2 = format_lockfile(parsed)
    assert text1 == text2
    assert parsed == L


def test_multiple_provenance_blocks_round_trip():
    """A LockedDep with two provenances (e.g., upstream + mirror)
    round-trips both. Plumbing for Phase D #37."""
    L = Lockfile(
        deps=(LockedDep(
            name="chronos",
            identity=_HASH,
            version="0.5.0",
            src_dir="src",
            requires=(),
            provenances=(
                GitProvenanceRecord(
                    url="https://upstream/chronos.git",
                    ref="main",
                    commit_sha="up123",
                ),
                GitProvenanceRecord(
                    url="https://mirror/chronos.git",
                    ref="main",
                    commit_sha="up123",
                ),
            ),
        ),),
        strategy="maxver",
    )
    text = format_lockfile(L)
    assert text.count("provenance {") == 2
    parsed = parse_lockfile(text)
    assert parsed == L


def test_each_provenance_kind_round_trips():
    """All five kinds (git, tarball, local, member, registry)
    serialize and parse correctly."""
    from milpa.lockfile import (
        LocalProvenanceRecord,
        MemberProvenanceRecord,
        RegistryProvenanceRecord,
        TarballProvenanceRecord,
    )
    L = Lockfile(
        deps=(
            LockedDep(
                name="a-git", identity=_HASH, version="0.0.1", src_dir="",
                requires=(),
                provenances=(GitProvenanceRecord(
                    url="https://example.com/a.git", ref="v1", commit_sha="g1",
                ),),
            ),
            LockedDep(
                name="b-tarball", identity=_HASH, version="0.0.1", src_dir="",
                requires=(),
                provenances=(TarballProvenanceRecord(
                    url="https://example.com/b.tar.gz", sha256="abc",
                ),),
            ),
            LockedDep(
                name="c-local", identity=_HASH, version="0.0.1", src_dir="",
                requires=(),
                provenances=(LocalProvenanceRecord(path="../c"),),
            ),
            LockedDep(
                name="d-member", identity=_HASH, version="0.0.1", src_dir="",
                requires=(),
                provenances=(MemberProvenanceRecord(name="d-member"),),
            ),
            LockedDep(
                name="e-registry", identity=_HASH, version="0.0.1", src_dir="",
                requires=(),
                provenances=(RegistryProvenanceRecord(
                    name="e-registry", tag="v1.0.0", commit_sha="r1",
                ),),
            ),
        ),
        strategy="maxver",
    )
    text = format_lockfile(L)
    parsed = parse_lockfile(text)
    assert parsed == L


def test_from_graph_builds_correct_provenance_variant():
    """from_graph dispatches on a None-provenance ResolvedDep's source
    prefix to choose the right ProvenanceRecord variant. (milpa#97: named
    deps now carry a typed provenance and never emit a `registry:` source
    string, so that arm is gone — git is the bare-source catch-all.)"""
    from milpa.lockfile import (
        from_graph,
    )
    from milpa.resolver import ResolvedDep, ResolvedGraph

    def _rd(name, source, **kw):
        return ResolvedDep(
            name=name, source=source,
            ref=kw.get("ref"), sha=kw.get("sha"),
            version=(0, 0, 1), identity=_HASH, src_dir="", requires=(),
        )

    graph = ResolvedGraph(deps=(
        _rd("g", "https://x/g.git", ref="main", sha="abc"),
        _rd("t", "tarball:https://x/t.tar.gz"),
        _rd("l", "local:../l"),
        _rd("m", "member:m"),
    ))
    lockfile = from_graph(graph)
    kinds = {d.name: type(d.provenances[0]).__name__ for d in lockfile.deps}
    assert kinds == {
        "g": "GitProvenanceRecord",
        "t": "TarballProvenanceRecord",
        "l": "LocalProvenanceRecord",
        "m": "MemberProvenanceRecord",
    }


def test_typed_provenance_reconstructs_same_record_as_source_string():
    """S2.7 (milpa#97 / Option A): git typed dispatch matches source-string.
    Tarball diverges intentionally when expected_sha256 is set — the typed
    path preserves it; the source-string fallback has no sha256 to preserve.
    Only verify git identity here; tarball sha256 preservation is tested
    separately in test_tarball_provenance_sha256_round_trips."""
    from milpa.lockfile import from_graph
    from milpa.resolver import ResolvedDep, ResolvedGraph
    from milpa.fetchers.git import GitProvenance

    def _rd(name, source, provenance, **kw):
        return ResolvedDep(
            name=name, source=source,
            ref=kw.get("ref"), sha=kw.get("sha"),
            version=(0, 0, 1), identity=_HASH, src_dir="", requires=(),
            provenance=provenance,
        )

    # git: typed dispatch and source-string fallback must agree.
    typed_g = ResolvedGraph(deps=(
        _rd("g", "https://x/g.git",
            GitProvenance(url="https://x/g.git", ref="main"),
            ref="main", sha="abc"),
    ))
    untyped_g = ResolvedGraph(deps=(
        _rd("g", "https://x/g.git", None, ref="main", sha="abc"),
    ))
    lt = {d.name: d.provenances[0] for d in from_graph(typed_g).deps}
    lu = {d.name: d.provenances[0] for d in from_graph(untyped_g).deps}
    assert lt == lu


# ---------------------------------------------------------------------------
# S3 (milpa#97) — OCI provenance record: write→parse round-trip + the
# legacy registry read-compat path.
# ---------------------------------------------------------------------------


def test_oci_provenance_record_round_trips():
    from milpa.lockfile import OciProvenanceRecord

    lf = Lockfile(version=1, strategy="maxver", deps=(
        LockedDep(
            name="nimkdl", identity=_HASH, version="0.1.4", src_dir="src",
            requires=(),
            provenances=(OciProvenanceRecord(
                registry="ghcr.io",
                repository="coreyleavitt/nimkdl",
                digest="sha256:deadbeef",
            ),),
        ),
    ))
    parsed = parse_lockfile(format_lockfile(lf))
    p = parsed.deps[0].provenances[0]
    assert isinstance(p, OciProvenanceRecord)
    assert p.registry == "ghcr.io"
    assert p.repository == "coreyleavitt/nimkdl"
    assert p.digest == "sha256:deadbeef"


def test_from_graph_oci_provenance_builds_oci_record():
    """M8 (focused unit): a ResolvedDep carrying OciProvenance produces an
    OciProvenanceRecord from from_graph — complementing the existing git +
    tarball typed-dispatch test."""
    from milpa.fetchers.oci import OciProvenance
    from milpa.lockfile import OciProvenanceRecord, from_graph
    from milpa.resolver import ResolvedDep, ResolvedGraph

    digest = "sha256:" + "a" * 64
    dep = ResolvedDep(
        name="nimkdl",
        source="oci:ghcr.io/coreyleavitt/nimkdl",
        ref=None,
        sha=None,
        version=(0, 1, 4),
        identity=_HASH,
        src_dir="src",
        requires=(),
        provenance=OciProvenance(
            registry="ghcr.io",
            repository="coreyleavitt/nimkdl",
            digest=digest,
        ),
    )
    lockfile = from_graph(ResolvedGraph(deps=(dep,)))
    rec = lockfile.deps[0].provenances[0]
    assert isinstance(rec, OciProvenanceRecord)
    assert rec.registry == "ghcr.io"
    assert rec.repository == "coreyleavitt/nimkdl"
    assert rec.digest == digest


def test_legacy_registry_record_still_parses():
    from milpa.lockfile import RegistryProvenanceRecord

    text = """\
// generated by milpa; reproducible build snapshot
version 1
strategy "maxver"

dep "foo" {
    identity "%s"
    version "1.2.0"
    src_dir ""
    requires
    provenance {
        kind "registry"
        name "foo"
        tag "v1.2.0"
        commit_sha "abc123"
    }
}
""" % _HASH
    parsed = parse_lockfile(text)
    p = parsed.deps[0].provenances[0]
    assert isinstance(p, RegistryProvenanceRecord)
    assert p.name == "foo"
    assert p.tag == "v1.2.0"


# ---------------------------------------------------------------------------
# RD3 — unknown typed provenance raises ValueError (programmer-error trap)
# ---------------------------------------------------------------------------


def test_rd3_unknown_provenance_type_raises_value_error():
    """_provenance_from_resolved must raise ValueError for an unexpected
    typed Provenance subclass. This pins the programmer-error trap so a
    future refactor can't silently make the else-arm unreachable without
    a red test.

    Uses a trivial stub subclass — only needs to satisfy the type check.
    """
    import pytest
    from dataclasses import dataclass

    from milpa.fetchers.types import Provenance
    from milpa.lockfile import from_graph
    from milpa.resolver import ResolvedDep, ResolvedGraph

    @dataclass(frozen=True)
    class _StubProvenance(Provenance):
        """Unknown transport — not git, tarball, or OCI."""

    dep = ResolvedDep(
        name="mystery",
        source="unknown://example.com/mystery",
        ref=None,
        sha=None,
        version=(1, 0, 0),
        identity=_HASH,
        src_dir="",
        requires=(),
        provenance=_StubProvenance(),
    )
    with pytest.raises(ValueError, match="unexpected typed provenance"):
        from_graph(ResolvedGraph(deps=(dep,)))


# ---------------------------------------------------------------------------
# M11 regression: TarballProvenance.expected_sha256 round-trips
# ---------------------------------------------------------------------------

def test_tarball_provenance_sha256_round_trips():
    """M11: a TarballProvenance with expected_sha256 set must survive the
    from_graph → format_lockfile → parse_lockfile round-trip. Previously
    _provenance_from_resolved wrote sha256=None unconditionally."""
    from milpa.fetchers.tarball import TarballProvenance
    from milpa.lockfile import TarballProvenanceRecord, format_lockfile, from_graph, parse_lockfile
    from milpa.resolver import ResolvedDep, ResolvedGraph

    sha = "sha256:" + "b" * 64
    dep = ResolvedDep(
        name="archive",
        source="tarball:https://example.com/archive.tar.gz",
        ref=None,
        sha=None,
        version=(1, 2, 3),
        identity=_HASH,
        src_dir="",
        requires=(),
        provenance=TarballProvenance(
            url="https://example.com/archive.tar.gz",
            expected_sha256=sha,
        ),
    )
    lockfile = from_graph(ResolvedGraph(deps=(dep,)))
    rec = lockfile.deps[0].provenances[0]
    assert isinstance(rec, TarballProvenanceRecord)
    assert rec.sha256 == sha, (
        f"M11 regression: expected_sha256 {sha!r} was not preserved; got {rec.sha256!r}"
    )

    # format → parse round-trip preserves the sha256
    text = format_lockfile(lockfile)
    parsed = parse_lockfile(text)
    rec2 = parsed.deps[0].provenances[0]
    assert isinstance(rec2, TarballProvenanceRecord)
    assert rec2.sha256 == sha, (
        f"round-trip dropped sha256: expected {sha!r}, got {rec2.sha256!r}"
    )
