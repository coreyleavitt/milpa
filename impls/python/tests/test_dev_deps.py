"""dev-deps feature tests (TDD slice).

Covers:
  1. Parse dev-deps block → Manifest.dev_deps populated (named + git forms).
  2. Round-trip: present stays present, absent stays absent (byte-clean).
  3. Root resolution INCLUDES root dev-dep in graph; a transitive dep's own
     dev-deps do NOT enter the graph.
  4. when-conditional dev-dep is profile-filtered.
  5. Workspace member's dev-dep IS included; transitive dep of member still
     has its dev-deps excluded.
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.manifest import (
    Manifest, ManifestError, NamedDep, Predicate, UrlDep,
    format_manifest, parse_manifest,
)
from milpa.profile import Profile
from milpa.resolver import resolve, resolve_workspace
from tests.indexkdl import make_index


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeFetcher:
    """Writes a synthetic file tree per (url, ref) and records calls."""
    by_url_ref: dict[tuple[str, str], tuple[str, str | None]]
    """mapping (url, ref) → (sha, milpa_kdl_text | None)

    When milpa_kdl_text is not None the fetcher writes milpa.kdl in the
    dest dir; otherwise it writes a minimal <name>.nimble."""
    calls: list = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((name, p.url, p.ref))
        sha, manifest_text = self.by_url_ref[(p.url, p.ref)]
        dest.mkdir(parents=True, exist_ok=True)
        if manifest_text is not None:
            (dest / "milpa.kdl").write_text(manifest_text)
        else:
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        return GitReceipt(commit_sha=sha)


def _reg(fake):
    r = FetcherRegistry()
    r.register(fake)
    return r


# ---------------------------------------------------------------------------
# 1. Parse: dev-deps block populates Manifest.dev_deps
# ---------------------------------------------------------------------------

def test_parse_dev_deps_named_and_git():
    text = """
name "mylib"
deps {
    foo git=(url)"https://example.com/foo.git" ref="main"
}
dev-deps {
    bar git=(url)"https://example.com/bar.git" ref="v1"
    testutil
}
kind "library"
"""
    m = parse_manifest(text)
    assert len(m.dev_deps) == 2
    bar = m.dev_deps[0]
    assert isinstance(bar, UrlDep)
    assert bar.name == "bar"
    assert bar.git == "https://example.com/bar.git"
    assert bar.ref == "v1"
    tu = m.dev_deps[1]
    assert isinstance(tu, NamedDep)
    assert tu.name == "testutil"
    assert tu.constraint is None


def test_parse_dev_deps_absent_gives_empty_tuple():
    text = """
name "mylib"
deps {
    foo git=(url)"https://example.com/foo.git" ref="main"
}
kind "library"
"""
    m = parse_manifest(text)
    assert m.dev_deps == ()


def test_parse_dev_deps_only_no_regular_deps():
    text = """
name "mylib"
dev-deps {
    bar git=(url)"https://example.com/bar.git" ref="main"
}
kind "library"
"""
    m = parse_manifest(text)
    assert m.deps == ()
    assert len(m.dev_deps) == 1
    assert m.dev_deps[0].name == "bar"


def test_parse_dev_deps_duplicate_raises():
    text = """
name "mylib"
dev-deps {
    bar git=(url)"https://example.com/bar.git" ref="main"
    bar git=(url)"https://example.com/bar2.git" ref="v1"
}
kind "library"
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.code == "MAN-DEP-DUPLICATE"
    assert "bar" in str(exc.value)


def test_parse_dev_deps_missing_ref_raises_coded_error():
    text = """
name "mylib"
dev-deps {
    bar git=(url)"https://example.com/bar.git"
}
kind "library"
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.code == "MAN-DEP-REF-MISSING"


def test_parse_dev_deps_malformed_uses_man_dep_codes():
    """Malformed dev-dep reuses MAN-DEP-* codes — no new error codes."""
    text = """
name "mylib"
dev-deps {
    bar git=(url)"https://example.com/bar.git" ref="main" unknown_prop="x"
}
kind "library"
"""
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert exc.value.code == "MAN-DEP-UNKNOWN-PROPS"


# ---------------------------------------------------------------------------
# 2. Round-trip: format_manifest ↔ parse_manifest
# ---------------------------------------------------------------------------

def test_round_trip_dev_deps_present_survives():
    text = """
name "mylib"
dev-deps {
    bar git=(url)"https://example.com/bar.git" ref="v1"
    testutil
}
kind "library"
"""
    m = parse_manifest(text)
    text2 = format_manifest(m)
    m2 = parse_manifest(text2)
    assert m2.dev_deps == m.dev_deps


def test_round_trip_absent_dev_deps_stays_absent():
    text = """
name "mylib"
deps {
    foo git=(url)"https://example.com/foo.git" ref="main"
}
kind "library"
"""
    m = parse_manifest(text)
    formatted = format_manifest(m)
    assert "dev-deps" not in formatted
    m2 = parse_manifest(formatted)
    assert m2.dev_deps == ()


def test_format_manifest_emits_dev_deps_block():
    """format_manifest emits a dev-deps block when dev_deps is non-empty."""
    m = parse_manifest("""
name "mylib"
dev-deps {
    bar git=(url)"https://example.com/bar.git" ref="v1"
}
kind "library"
""")
    out = format_manifest(m)
    assert "dev-deps {" in out
    assert "bar" in out


# ---------------------------------------------------------------------------
# 3. Resolver: root dev-dep in graph; transitive dep's dev-deps excluded
# ---------------------------------------------------------------------------

def test_root_dev_dep_appears_in_resolved_graph(tmp_path):
    """Root package's dev-dep D is resolved and appears in the graph.
    Transitive package A (regular dep) declares its own dev-dep E;
    E must NOT appear in the graph."""
    # A's milpa.kdl: has a regular dep chain but also dev-deps E
    a_milpa_kdl = """\
name "a"
dev-deps {
    e git=(url)"https://example.com/e.git" ref="main"
}
kind "library"
"""
    # D has no transitive deps
    d_milpa_kdl = """\
name "d"
kind "library"
"""

    fake = FakeFetcher({
        # regular dep A  (has dev-deps: e)
        ("https://example.com/a.git", "main"): ("sha-a", a_milpa_kdl),
        # dev dep D (no transitive deps)
        ("https://example.com/d.git", "main"): ("sha-d", d_milpa_kdl),
        # E should never be fetched; if it is, the test must fail
    })
    manifest = Manifest(
        kind="library",
        name="root",
        deps=(UrlDep(name="a", git="https://example.com/a.git", ref="main"),),
        dev_deps=(UrlDep(name="d", git="https://example.com/d.git", ref="main"),),
    )
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=_reg(fake),
    )
    names = {d.name for d in graph.deps}
    assert "a" in names, "regular dep A must be resolved"
    assert "d" in names, "root dev-dep D must be resolved"
    assert "e" not in names, "transitive dep A's dev-dep E must NOT enter the graph"


def test_transitive_dep_dev_deps_excluded(tmp_path):
    """A's milpa.kdl dev-deps are silently ignored during transitive traversal."""
    a_milpa_kdl = """\
name "a"
dev-deps {
    e git=(url)"https://example.com/e.git" ref="main"
    f git=(url)"https://example.com/f.git" ref="v2"
}
kind "library"
"""
    fake = FakeFetcher({
        ("https://example.com/a.git", "main"): ("sha-a", a_milpa_kdl),
        # e and f must never be fetched
    })
    manifest = Manifest(
        kind="library",
        name="root",
        deps=(UrlDep(name="a", git="https://example.com/a.git", ref="main"),),
    )
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=_reg(fake),
    )
    names = {d.name for d in graph.deps}
    assert "a" in names
    assert "e" not in names
    assert "f" not in names
    # e and f must never have been fetched
    fetch_names = {c[0] for c in fake.calls}
    assert "e" not in fetch_names
    assert "f" not in fetch_names


def test_dev_dep_in_lockfile_and_nimcfg(tmp_path):
    """Root dev-dep appears in the lockfile and nim.cfg (on the nim.cfg path)."""
    from milpa.lockfile import from_graph, format_lockfile
    from milpa.nimcfg import format_nimcfg

    d_milpa_kdl = """\
name "d"
src_dir "src"
kind "library"
"""
    fake = FakeFetcher({
        ("https://example.com/d.git", "main"): ("sha-d", d_milpa_kdl),
    })
    manifest = Manifest(
        kind="library",
        name="root",
        deps=(),
        dev_deps=(UrlDep(name="d", git="https://example.com/d.git", ref="main"),),
    )
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=_reg(fake),
    )
    lockfile_text = format_lockfile(from_graph(graph))
    nimcfg_text = format_nimcfg(graph, deps_dir=Path("_deps"))
    assert "d" in lockfile_text
    assert "_deps/d/src" in nimcfg_text


# ---------------------------------------------------------------------------
# 4. when-conditional dev-dep is profile-filtered
# ---------------------------------------------------------------------------

def test_conditional_dev_dep_filtered_by_profile(tmp_path):
    """A dev-dep gated on platform=linux is excluded on macosx."""
    d_milpa_kdl = """\
name "d"
kind "library"
"""
    fake = FakeFetcher({
        ("https://example.com/d.git", "main"): ("sha-d", d_milpa_kdl),
    })
    manifest_text = """
name "root"
dev-deps {
    d git=(url)"https://example.com/d.git" ref="main" platform="linux"
}
kind "library"
"""
    manifest = parse_manifest(manifest_text)
    # On linux: d should appear
    linux_profile = Profile(platform="linux", arch="x64", nim="2.0.0", milpa="1.0.0")
    graph_linux = resolve(
        manifest,
        deps_dir=tmp_path / "_deps_linux",
        fetcher=_reg(fake),
        profile=linux_profile,
    )
    assert any(d.name == "d" for d in graph_linux.deps)

    # On macosx: d should NOT appear
    mac_profile = Profile(platform="macosx", arch="x64", nim="2.0.0", milpa="1.0.0")
    graph_mac = resolve(
        manifest,
        deps_dir=tmp_path / "_deps_mac",
        fetcher=_reg(FakeFetcher({
            ("https://example.com/d.git", "main"): ("sha-d", d_milpa_kdl),
        })),
        profile=mac_profile,
    )
    assert not any(d.name == "d" for d in graph_mac.deps)


# ---------------------------------------------------------------------------
# 5. Workspace member dev-deps: included for member, excluded for transitives
# ---------------------------------------------------------------------------

def test_workspace_member_dev_dep_included(tmp_path):
    """A workspace member's own dev-dep appears in the workspace resolution;
    a transitive external dep's dev-deps are still excluded."""
    from milpa.workspace import LoadedMember, Workspace

    # member 'pkg' has dev-dep 'testlib' and regular dep 'extdep'
    # extdep has dev-dep 'ignoreme' in its milpa.kdl — must NOT enter graph
    extdep_milpa_kdl = """\
name "extdep"
dev-deps {
    ignoreme git=(url)"https://example.com/ignoreme.git" ref="main"
}
kind "library"
"""
    testlib_milpa_kdl = """\
name "testlib"
kind "library"
"""

    fake = FakeFetcher({
        ("https://example.com/extdep.git", "main"): ("sha-ext", extdep_milpa_kdl),
        ("https://example.com/testlib.git", "main"): ("sha-tl", testlib_milpa_kdl),
    })

    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "milpa.kdl").write_text("""\
name "pkg"
deps {
    extdep git=(url)"https://example.com/extdep.git" ref="main"
}
dev-deps {
    testlib git=(url)"https://example.com/testlib.git" ref="main"
}
kind "library"
""")

    from milpa.manifest import load_manifest
    pkg_manifest = load_manifest(pkg_dir / "milpa.kdl")
    workspace = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="pkg",
            path="pkg",
            directory=pkg_dir,
            manifest=pkg_manifest,
        ),),
        overrides=(),
    )
    graph = resolve_workspace(
        workspace,
        deps_dir=tmp_path / "_deps",
        fetcher=_reg(fake),
    )
    names = {d.name for d in graph.deps}
    assert "extdep" in names, "regular external dep must be resolved"
    assert "testlib" in names, "member's own dev-dep must be resolved"
    assert "ignoreme" not in names, "transitive dep's dev-dep must be excluded"
