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
    """from_graph dispatches on ResolvedDep.source prefix to choose
    the right ProvenanceRecord variant."""
    from milpa.lockfile import (
        from_graph,
    )
    from milpa.resolver import ResolvedDep, ResolvedGraph

    def _rd(name, source, **kw):
        return ResolvedDep(
            name=name, source=source,
            ref=kw.get("ref"), tag=kw.get("tag"), sha=kw.get("sha"),
            version=(0, 0, 1), identity=_HASH, src_dir="", requires=(),
        )

    graph = ResolvedGraph(deps=(
        _rd("g", "https://x/g.git", ref="main", sha="abc"),
        _rd("t", "tarball:https://x/t.tar.gz"),
        _rd("l", "local:../l"),
        _rd("m", "member:m"),
        _rd("r", "registry:r", tag="v1", sha="r1"),
    ))
    lockfile = from_graph(graph)
    kinds = {d.name: type(d.provenances[0]).__name__ for d in lockfile.deps}
    assert kinds == {
        "g": "GitProvenanceRecord",
        "t": "TarballProvenanceRecord",
        "l": "LocalProvenanceRecord",
        "m": "MemberProvenanceRecord",
        "r": "RegistryProvenanceRecord",
    }
