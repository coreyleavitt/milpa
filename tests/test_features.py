"""Per-dep features / optional deps (#23).

Cabal-inspired declarative feature system, reusing #26's `when` block
machinery for dep gating. Cross-graph union semantics from cargo:
any consumer's `true` on a flag turns it on for that dep across the
whole resolution.

Manifest grammar:
  flags {
      json default=true description="JSON support"
      postgres default=false {
          defines "MYLIB_HAS_POSTGRES"
      }
  }

  deps {
      core git="..." ref="main"
      when flag="json" {
          serde git="..." ref="main"
      }
  }

Consumer requests:
  mylib git="..." ref="main" {
      flag "postgres"          # turn on (default false)
      flag "json" false        # explicit off (overrides default true)
  }
"""

import pytest

from milpa.manifest import (
    FlagDecl,
    Manifest,
    parse_manifest,
)


def test_parser_accepts_top_level_flags_block():
    """Tracer: a `flags { ... }` block at top level produces
    Manifest.flags as a tuple of FlagDecl(name, default, description,
    defines)."""
    text = '''name "mylib"
kind "library"
flags {
    json default=true description="JSON support"
    postgres default=false description="Postgres bindings" {
        defines "MYLIB_HAS_POSTGRES" "USE_LIBPQ"
    }
    plain
}
'''
    manifest = parse_manifest(text)
    flags_by_name = {f.name: f for f in manifest.flags}

    assert "json" in flags_by_name
    assert flags_by_name["json"].default is True
    assert flags_by_name["json"].description == "JSON support"
    assert flags_by_name["json"].defines == ()

    assert "postgres" in flags_by_name
    assert flags_by_name["postgres"].default is False
    assert flags_by_name["postgres"].description == "Postgres bindings"
    assert flags_by_name["postgres"].defines == (
        "MYLIB_HAS_POSTGRES", "USE_LIBPQ",
    )

    # Minimal declaration: bare name, defaults applied
    assert "plain" in flags_by_name
    assert flags_by_name["plain"].default is False     # default-default
    assert flags_by_name["plain"].description == ""
    assert flags_by_name["plain"].defines == ()


def test_when_flag_predicate_gates_deps_in_block():
    """`when flag="X" { ... }` is a new predicate dimension; the
    wrapped deps carry a Predicate(name="flag", values=("X",)) just
    like #26's platform/arch predicates."""
    from milpa.manifest import Predicate, UrlDep

    text = '''name "mylib"
kind "library"
flags {
    json default=true
}
deps {
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
}
'''
    manifest = parse_manifest(text)
    assert len(manifest.deps) == 1
    dep = manifest.deps[0]
    assert isinstance(dep, UrlDep)
    assert dep.name == "serde"
    # Predicate inherited from the when block: flag=json
    assert any(
        p.name == "flag" and p.values == ("json",) and not p.negated
        for p in dep.predicates
    ), f"missing flag predicate: {dep.predicates}"


def test_consumer_flag_requests_are_parsed_on_dep():
    """A consumer dep declaration: `flag "X"` enables, `flag "X" false`
    explicitly disables. Both produce FlagRequest entries on the dep."""
    from milpa.manifest import FlagRequest, UrlDep

    text = '''name "app"
kind "application"
deps {
    mylib git=(url)"https://example.com/mylib.git" ref="main" {
        flag "postgres"
        flag "json" false
    }
}
'''
    manifest = parse_manifest(text)
    dep = manifest.deps[0]
    assert isinstance(dep, UrlDep)
    assert dep.flag_requests == (
        FlagRequest(name="postgres", enabled=True),
        FlagRequest(name="json", enabled=False),
    )


def test_format_manifest_round_trips_flags_and_requests():
    """A Manifest with FlagDecls + FlagRequests → format → parse →
    structurally identical."""
    from milpa.manifest import (
        FlagDecl, FlagRequest, UrlDep, format_manifest,
    )

    original = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
            flag_requests=(
                FlagRequest(name="postgres", enabled=True),
                FlagRequest(name="json", enabled=False),
            ),
        ),),
        flags=(
            FlagDecl(name="json", default=True, description="JSON"),
            FlagDecl(name="postgres", default=False, description="",
                     defines=("MYLIB_HAS_PG",)),
        ),
    )
    text = format_manifest(original)
    # Sanity: text mentions the constructs
    assert "flags {" in text
    assert "json" in text
    assert 'flag "postgres"' in text
    assert 'flag "json" false' in text
    reparsed = parse_manifest(text)
    assert reparsed == original


# ---------------------------------------------------------------------------
# Part B — Resolver respects flag-gated deps
# ---------------------------------------------------------------------------


class StubFetcher:
    def __init__(self): self.fetched = []
    def can_handle(self, p):
        from milpa.fetchers.git import GitProvenance
        return isinstance(p, GitProvenance)
    def fetch(self, name, p, *, dest):
        from milpa.fetchers.git import GitReceipt
        self.fetched.append(name)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        return GitReceipt(commit_sha="abc")


def test_top_level_default_true_flag_includes_gated_dep(tmp_path):
    """Tracer (Part B): top-level manifest declares `json` flag with
    default=true. A `when flag="json"` block holds a dep. With the
    flag default-active, the gated dep is included in the graph."""
    from milpa.fetchers import FetcherRegistry
    from milpa.profile import Profile
    from milpa.resolver import resolve

    text = '''name "mylib"
kind "library"
flags {
    json default=true
}
deps {
    core git=(url)"https://example.com/core.git" ref="main"
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
}
'''
    manifest = parse_manifest(text)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    assert "core" in names
    assert "serde" in names


def test_default_false_flag_excludes_gated_dep(tmp_path):
    """Flag declared with default=false → gated dep is NOT in the
    resolved graph (and never fetched)."""
    from milpa.fetchers import FetcherRegistry
    from milpa.profile import Profile
    from milpa.resolver import resolve

    text = '''name "mylib"
kind "library"
flags {
    postgres default=false
}
deps {
    core git=(url)"https://example.com/core.git" ref="main"
    when flag="postgres" {
        pg git=(url)"https://example.com/pg.git" ref="main"
    }
}
'''
    manifest = parse_manifest(text)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    assert "core" in names
    assert "pg" not in names
    assert "pg" not in fetcher_impl.fetched


# ---------------------------------------------------------------------------
# Part C — Lockfile + nim.cfg integration
# ---------------------------------------------------------------------------


def test_lockfile_round_trips_active_flags():
    """LockedDep.active_flags records computed flag state per dep
    and round-trips through KDL serialization."""
    from milpa.lockfile import (
        GitProvenanceRecord, LockedDep, Lockfile,
        format_lockfile, parse_lockfile,
    )

    original = Lockfile(deps=(
        LockedDep(
            name="mylib", identity="sha256:" + "a" * 64, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://example.com/mylib.git", ref="main",
                commit_sha="abc",
            ),),
            active_flags=("json", "postgres"),
        ),
        # A dep with no active flags — round-trips without an empty
        # active_flags noise line.
        LockedDep(
            name="core", identity="sha256:" + "b" * 64, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://example.com/core.git", ref="main",
                commit_sha="def",
            ),),
        ),
    ))
    text = format_lockfile(original)
    assert 'active_flags "json" "postgres"' in text
    reparsed = parse_lockfile(text)
    assert reparsed == original


def test_nim_cfg_emits_define_for_each_active_flag_using_convention():
    """Default convention: `-d:<dep_name>_<flag_name>` per active
    flag. No explicit defines map → use the convention."""
    from milpa.nimcfg import format_nimcfg
    from milpa.resolver import ResolvedDep, ResolvedGraph

    graph = ResolvedGraph(deps=(
        ResolvedDep(
            name="mylib", source="https://x", ref="main",
            sha="abc", version=(0, 0, 1), identity=None,
            src_dir="", requires=(),
            active_flags=("json", "postgres"),
        ),
        ResolvedDep(
            name="other", source="https://x", ref="main",
            sha="def", version=(0, 0, 1), identity=None,
            src_dir="", requires=(),
            # No active flags — no -d: lines
        ),
    ))
    text = format_nimcfg(graph)
    assert "-d:mylib_json" in text
    assert "-d:mylib_postgres" in text
    # No spurious -d: for the flagless dep
    assert "-d:other_" not in text


def test_nim_cfg_emits_explicit_defines_when_provided(tmp_path):
    """When a ResolvedDep carries flag_defines, those override the
    convention emission for the corresponding flag."""
    from milpa.nimcfg import format_nimcfg
    from milpa.resolver import ResolvedDep, ResolvedGraph

    graph = ResolvedGraph(deps=(
        ResolvedDep(
            name="mylib", source="https://x", ref="main",
            sha="abc", version=(0, 0, 1), identity=None,
            src_dir="", requires=(),
            active_flags=("postgres", "json"),
            flag_defines=(
                ("postgres", ("MYLIB_HAS_PG", "USE_LIBPQ")),
                # json uses convention (not in flag_defines)
            ),
        ),
    ))
    text = format_nimcfg(graph)
    # postgres → explicit
    assert "-d:MYLIB_HAS_PG" in text
    assert "-d:USE_LIBPQ" in text
    # postgres did NOT get the convention emission
    assert "-d:mylib_postgres" not in text
    # json still uses convention
    assert "-d:mylib_json" in text
