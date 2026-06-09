"""Emission determinism — the spec's single canonical ordering rule.

Every emitted ordering (nim.cfg --path lines, lockfile `requires`
arguments, lockfile dep entries) is lexicographic by dep name. This is
the rule a from-scratch implementation must reproduce byte-for-byte;
see resolver-semantics.md §4.4 and lockfile-schema.md §3.4.

Also covers the `milpa` predicate's version source (MILPA_TARGET_MILPA
env override + default to milpa.__version__).
"""

from milpa import __version__
from milpa.fetchers.git import GitProvenance
from milpa.lockfile import format_lockfile, from_graph
from milpa.nimcfg import format_nimcfg
from milpa.profile import Profile
from milpa.resolver import ResolvedDep, ResolvedGraph


def _dep(name, requires=()):
    return ResolvedDep(
        name=name,
        source=f"git:https://example.com/{name}.git",
        ref="v1.0.0",
        sha="a" * 40,
        version=(1, 0, 0),
        identity=f"sha256:{'0' * 64}",
        src_dir="src",
        requires=tuple(requires),
        provenance=GitProvenance(
            url=f"https://example.com/{name}.git", ref="v1.0.0",
            commit_sha="a" * 40,
        ),
    )


def test_nimcfg_path_order_is_lexicographic_not_insertion():
    # Graph deps deliberately out of alphabetical order.
    graph = ResolvedGraph(deps=(_dep("Z"), _dep("X"), _dep("Y")))
    out = format_nimcfg(graph)
    paths = [ln for ln in out.splitlines() if ln.startswith("--path:")]
    assert paths == [
        '--path:"_deps/X/src"',
        '--path:"_deps/Y/src"',
        '--path:"_deps/Z/src"',
    ]


def test_lockfile_requires_args_are_sorted():
    # requires given in non-sorted (BFS-arrival-like) order.
    graph = ResolvedGraph(
        deps=(_dep("A", requires=("zeta", "alpha", "mu")), _dep("alpha"),
              _dep("mu"), _dep("zeta")),
    )
    text = format_lockfile(from_graph(graph))
    req_line = next(ln for ln in text.splitlines() if ln.strip().startswith("requires "))
    assert req_line.strip() == 'requires "alpha" "mu" "zeta"'


def test_lockfile_dep_entries_are_sorted():
    graph = ResolvedGraph(deps=(_dep("zeta"), _dep("alpha"), _dep("mu")))
    text = format_lockfile(from_graph(graph))
    names = [ln.split('"')[1] for ln in text.splitlines() if ln.startswith('dep "')]
    assert names == ["alpha", "mu", "zeta"]


def test_profile_milpa_defaults_to_own_version(monkeypatch):
    monkeypatch.delenv("MILPA_TARGET_MILPA", raising=False)
    p = Profile.from_environment(nim_version_query=lambda: "2.0.0")
    assert p.milpa == __version__


def test_profile_milpa_env_override(monkeypatch):
    monkeypatch.setenv("MILPA_TARGET_MILPA", "9.9.9")
    p = Profile.from_environment(nim_version_query=lambda: "2.0.0")
    assert p.milpa == "9.9.9"
