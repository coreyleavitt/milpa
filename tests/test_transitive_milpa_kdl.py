"""Resolver parses transitive deps' milpa.kdl manifests (#90).

When a fetched dep ships a milpa.kdl alongside its .nimble (or
without one), the resolver prefers the milpa.kdl for its declarations:
the manifest's `deps { ... }` block defines transitive deps; `flags`
and `when flag=X` blocks gate them; FlagDecl.defines carries through
to nim.cfg emission.

This unlocks the full cargo-style feature propagation pipeline from
#23, which today only works at the top-level manifest.
"""

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.manifest import Manifest, UrlDep
from milpa.profile import Profile
from milpa.resolver import resolve
from tests.indexkdl import make_index


class MilpaKdlFetcher:
    """Test fetcher that writes a milpa.kdl into the fetched dep's dest
    based on a fixture map { url → milpa.kdl text }. Falls back to a
    minimal .nimble if no milpa.kdl is registered for the URL."""

    def __init__(self, milpa_kdl_by_url: dict[str, str]):
        self.milpa_kdl_by_url = milpa_kdl_by_url
        self.fetched: list[str] = []

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.fetched.append(name)
        dest.mkdir(parents=True, exist_ok=True)
        # Always write a minimal .nimble so the legacy path doesn't fail
        # if milpa.kdl isn't present.
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        if p.url in self.milpa_kdl_by_url:
            (dest / "milpa.kdl").write_text(self.milpa_kdl_by_url[p.url])
        return GitReceipt(commit_sha="abc")


def test_resolver_parses_transitive_dep_milpa_kdl_for_its_deps(tmp_path):
    """Tracer: top-level has one dep (mylib). mylib's milpa.kdl
    declares a transitive UrlDep (chronos). The resolver should
    fetch chronos as a transitive — meaning it parsed mylib's
    milpa.kdl rather than just its (deps-less) .nimble."""
    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
        ),),
    )

    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/mylib.git": '''name "mylib"
kind "library"
deps {
    chronos git=(url)"https://example.com/chronos.git" ref="main"
}
''',
        # chronos has no transitive deps; fetcher will give it a
        # bare .nimble.
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )

    names = {d.name for d in graph.deps}
    assert "mylib" in names
    assert "chronos" in names, (
        f"chronos should be pulled in via mylib's milpa.kdl; got {names}"
    )
    # Fetcher was invoked for chronos
    assert "chronos" in fetcher_impl.fetched


def test_milpa_kdl_wins_precedence_over_nimble(tmp_path):
    """When both files are present, milpa.kdl is authoritative.
    The fetcher gives mylib both files: .nimble says `requires "results"`,
    milpa.kdl says `deps { chronos ... }`. Only chronos should appear."""

    class PrecedenceFetcher:
        def __init__(self): self.fetched = []
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            self.fetched.append(name)
            dest.mkdir(parents=True, exist_ok=True)
            if name == "mylib":
                (dest / "mylib.nimble").write_text(
                    'srcDir = "src"\n'
                    'requires "results"\n'   # nimble path would add this
                )
                (dest / "milpa.kdl").write_text(
                    'name "mylib"\n'
                    'kind "library"\n'
                    'deps {\n'
                    '    chronos git=(url)"https://example.com/chronos.git" ref="main"\n'
                    '}\n'
                )
            else:
                (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    fetcher_impl = PrecedenceFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
        ),),
    )
    graph = resolve(
        top_manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    # milpa.kdl's chronos wins
    assert "chronos" in names
    # .nimble's `requires "results"` is ignored (milpa.kdl took over)
    assert "results" not in names
    assert "results" not in fetcher_impl.fetched


def test_consumer_flag_request_activates_transitive_when_block(tmp_path):
    """Top-level requests `flag "json"` on mylib. mylib's milpa.kdl
    declares flag json + gates serde behind it. serde should be in
    the graph."""
    from milpa.manifest import FlagRequest

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
            flag_requests=(FlagRequest(name="json", enabled=True),),
        ),),
    )

    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/mylib.git": '''name "mylib"
kind "library"
flags {
    json default=false
}
deps {
    core git=(url)"https://example.com/core.git" ref="main"
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    assert "mylib" in names
    assert "core" in names
    assert "serde" in names, (
        f"serde should be activated by consumer's flag request; got {names}"
    )


def test_default_false_transitive_flag_excludes_gated_dep_without_request(tmp_path):
    """Sharper probe: same mylib, but NO consumer flag request and
    flag's default=false. serde MUST NOT be in the graph."""
    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
            # NO flag_requests
        ),),
    )
    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/mylib.git": '''name "mylib"
kind "library"
flags {
    json default=false
}
deps {
    core git=(url)"https://example.com/core.git" ref="main"
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    assert "core" in names
    assert "serde" not in names, (
        f"serde should NOT be included (flag json default=false, no request); got {names}"
    )
    assert "serde" not in fetcher_impl.fetched


def test_default_true_transitive_flag_includes_gated_dep(tmp_path):
    """Default-true flag → gated dep included even without explicit
    consumer request."""
    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
        ),),
    )
    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/mylib.git": '''name "mylib"
kind "library"
flags {
    json default=true
}
deps {
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "serde" in {d.name for d in graph.deps}


def test_cross_graph_union_of_flag_requests_from_multiple_consumers(tmp_path):
    """Two consumers (top-level + C) both depend on D with DIFFERENT
    flag requests on D. The final active set on D is the UNION.

    Top-level → requests flag "json" on D.
    Top-level → C.
    C        → requests flag "stream" on D.
    D has flags { json, stream } (both default false); gates serde
    under json, futures under stream.
    Expected: both serde and futures in the graph (D got both flags)."""
    from milpa.manifest import FlagRequest

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(
            UrlDep(
                name="D", git="https://example.com/D.git", ref="main",
                flag_requests=(FlagRequest(name="json", enabled=True),),
            ),
            UrlDep(
                name="C", git="https://example.com/C.git", ref="main",
            ),
        ),
    )

    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/C.git": '''name "C"
kind "library"
deps {
    D git=(url)"https://example.com/D.git" ref="main" {
        flag "stream"
    }
}
''',
        "https://example.com/D.git": '''name "D"
kind "library"
flags {
    json default=false
    stream default=false
}
deps {
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
    when flag="stream" {
        futures git=(url)"https://example.com/futures.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    assert "D" in names
    assert "C" in names
    # Union of flag requests on D → BOTH gated transitives included
    assert "serde" in names, (
        f"serde should be included (top requested json on D); got {names}"
    )
    assert "futures" in names, (
        f"futures should be included (C requested stream on D — UNION); got {names}"
    )


def test_false_request_does_not_override_another_consumers_true(tmp_path):
    """Additive semantics: any true wins. Consumer C says
    `flag "json" false` on D; top-level says `flag "json" true`.
    The graph still has json active for D."""
    from milpa.manifest import FlagRequest

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(
            UrlDep(
                name="D", git="https://example.com/D.git", ref="main",
                flag_requests=(FlagRequest(name="json", enabled=True),),
            ),
            UrlDep(
                name="C", git="https://example.com/C.git", ref="main",
            ),
        ),
    )

    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/C.git": '''name "C"
kind "library"
deps {
    D git=(url)"https://example.com/D.git" ref="main" {
        flag "json" false
    }
}
''',
        "https://example.com/D.git": '''name "D"
kind "library"
flags {
    json default=false
}
deps {
    when flag="json" {
        serde git=(url)"https://example.com/serde.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    # Top-level's true wins despite C's false
    assert "serde" in names


def test_flag_defines_flow_through_to_nim_cfg(tmp_path):
    """A transitive dep declares a flag with explicit `defines`.
    After resolution, nim.cfg emits the explicit -d: lines, not the
    convention `-d:<dep>_<flag>`."""
    from milpa.manifest import FlagRequest
    from milpa.nimcfg import format_nimcfg

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
            flag_requests=(FlagRequest(name="postgres", enabled=True),),
        ),),
    )
    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/mylib.git": '''name "mylib"
kind "library"
flags {
    postgres default=false {
        defines "MYLIB_HAS_PG" "USE_LIBPQ"
    }
    plain default=false
}
deps {
    when flag="postgres" {
        pg-client git=(url)"https://example.com/pg.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )

    # The mylib dep in the graph carries active_flags + flag_defines
    mylib = next(d for d in graph.deps if d.name == "mylib")
    assert "postgres" in mylib.active_flags
    # nim.cfg emits the explicit defines
    text = format_nimcfg(graph)
    assert "-d:MYLIB_HAS_PG" in text
    assert "-d:USE_LIBPQ" in text
    # ... and NOT the convention name for `postgres`
    assert "-d:mylib_postgres" not in text


def test_three_level_cascade_of_flag_propagation_terminates(tmp_path):
    """Multi-level milpa.kdl chain:
      top → A (flag X) → B (flag Y) → C
    A's flag X gates B; B's flag Y gates C. Activating X via top
    cascades through both levels."""
    from milpa.manifest import FlagRequest

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="A", git="https://example.com/A.git", ref="main",
            flag_requests=(FlagRequest(name="X", enabled=True),),
        ),),
    )

    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/A.git": '''name "A"
kind "library"
flags {
    X default=false
}
deps {
    when flag="X" {
        B git=(url)"https://example.com/B.git" ref="main" {
            flag "Y"
        }
    }
}
''',
        "https://example.com/B.git": '''name "B"
kind "library"
flags {
    Y default=false
}
deps {
    when flag="Y" {
        C git=(url)"https://example.com/C.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    # All three levels included via the cascade
    assert "A" in names
    assert "B" in names, f"B should be activated by top→A's X; got {names}"
    assert "C" in names, f"C should be activated by A→B's Y; got {names}"


def test_parse_error_when_flag_predicate_references_undeclared_flag():
    """`when flag="undeclared"` in a manifest's own deps block must
    be a parse error (typo protection)."""
    from milpa.manifest import ManifestError, parse_manifest

    text = '''name "proj"
kind "library"
flags {
    json default=false
}
deps {
    when flag="jsno" {
        serde git=(url)"https://x/serde.git" ref="main"
    }
}
'''
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value)
    assert "jsno" in msg
    assert "flag" in msg.lower()
    # Suggests the user check declared flags
    assert "declared" in msg.lower() or "undeclared" in msg.lower() or "unknown" in msg.lower()


def test_consumer_request_for_unknown_flag_is_silently_ignored(tmp_path):
    """Consumer requests a flag the dep doesn't declare → no error.
    Resolution proceeds; the unknown request is ignored. This lets
    consumers tolerate upstream renaming a flag without breaking."""
    from milpa.manifest import FlagRequest

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
            flag_requests=(
                FlagRequest(name="stale", enabled=True),   # NOT declared by mylib
                FlagRequest(name="json", enabled=True),    # declared
            ),
        ),),
    )
    fetcher_impl = MilpaKdlFetcher(milpa_kdl_by_url={
        "https://example.com/mylib.git": '''name "mylib"
kind "library"
flags {
    json default=false
}
deps {
    when flag="json" {
        serde git=(url)"https://x/serde.git" ref="main"
    }
}
''',
    })
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # Should not raise — unknown flag silently ignored
    graph = resolve(
        top_manifest, deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    # json was honored
    assert "serde" in names


def test_transitive_milpa_kdl_named_dep_without_constraint_does_not_crash(tmp_path):
    """Regression: _extract_from_milpa_kdl called VersionSet.all() (line 1210)
    when a transitive milpa.kdl contained a bare NamedDep (constraint=None).
    That classmethod does not exist — the correct name is VersionSet.full().
    The AttributeError fires only via this transitive milpa.kdl path; a
    top-level NamedDep goes through a different code path and doesn't hit it.

    Setup: top → mylib (UrlDep), mylib has a milpa.kdl that declares
    results as a bare NamedDep (no constraint).  The tianguis index has
    one version of results.  Resolution must succeed (not raise
    AttributeError) and results must appear in the graph."""
    index = make_index([
        {"name": "results", "version": "0.3.0",
         "url": "https://example.com/results.git", "ref": "v0.3.0"},
    ])

    class MilpaKdlWithNamedDepFetcher:
        def __init__(self): self.fetched = []
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            self.fetched.append(name)
            dest.mkdir(parents=True, exist_ok=True)
            if name == "mylib":
                (dest / "milpa.kdl").write_text(
                    'name "mylib"\n'
                    'kind "library"\n'
                    'deps {\n'
                    '    results\n'   # bare NamedDep — no constraint
                    '}\n'
                )
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    fetcher_impl = MilpaKdlWithNamedDepFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    top_manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="mylib",
            git="https://example.com/mylib.git", ref="main",
        ),),
    )

    # Before the fix this raises:
    #   AttributeError: type object 'VersionSet' has no attribute 'all'
    graph = resolve(
        top_manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        index=index,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in graph.deps}
    assert "mylib" in names
    assert "results" in names, (
        f"results (bare NamedDep from transitive milpa.kdl) should be in graph; got {names}"
    )
