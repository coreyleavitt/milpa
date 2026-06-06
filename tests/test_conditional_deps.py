"""Conditional deps via typed predicate props (#26).

Per-dep predicates on a UrlDep node express compile-time / target
gating. The resolver evaluates them against a Profile (host or
overridden via env) and excludes deps whose predicates don't match.

Forms shipped:
  Inline props on the dep:
      pywin32 git=(url)"..." ref="main" platform="windows"
      uvloop  git=(url)"..." ref="main" platform=(not)"windows"
      modern  git=(url)"..." ref="main" nim=">=2.0"

  `when` block (factoring helper):
      when platform="windows" {
          winapi git="..." ref="main"
      }

Predicate set: platform, arch, nim, milpa.
Negation: (not) type annotation on the value.
OR / set membership: filed as #88 (child-node syntax).

Conditional .nimble `when` block handling is the closing cycle.
"""

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.manifest import Manifest, UrlDep, parse_manifest
from milpa.profile import Profile
from milpa.resolver import resolve


class StubFetcher:
    def __init__(self):
        self.fetched: list[str] = []
    def can_handle(self, p): return isinstance(p, GitProvenance)
    def fetch(self, name, p, *, dest):
        self.fetched.append(name)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        return GitReceipt(commit_sha="abc")


def test_inline_platform_predicate_excludes_dep_when_profile_mismatches(tmp_path):
    """Tracer: pywin32 platform='windows' is NOT fetched / resolved when
    the resolver runs against a Linux profile. foo (no predicate) is
    always included."""
    text = '''name "proj"
kind "library"
deps {
    foo git=(url)"https://example.com/foo.git" ref="main"
    pywin32 git=(url)"https://example.com/pywin32.git" ref="main" platform="windows"
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
    assert "foo" in names
    assert "pywin32" not in names
    # pywin32 was never fetched
    assert "pywin32" not in fetcher_impl.fetched


def test_multiple_predicates_on_one_dep_and_together(tmp_path):
    """A dep with platform AND arch predicates is included only when
    BOTH match the profile. Profile platform=linux arch=arm64; dep
    requires platform=linux arch=amd64 → excluded."""
    text = '''name "proj"
kind "library"
deps {
    foo git=(url)"https://example.com/foo.git" ref="main" platform="linux" arch="amd64"
}
'''
    manifest = parse_manifest(text)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # Profile matches platform but not arch
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="arm64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "foo" not in {d.name for d in graph.deps}

    # Profile matches both
    graph2 = resolve(
        manifest,
        deps_dir=tmp_path / "_deps2",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "foo" in {d.name for d in graph2.deps}


def test_not_type_annotation_negates_predicate(tmp_path):
    """platform=(not)"windows" → included on non-windows, excluded on windows."""
    text = '''name "proj"
kind "library"
deps {
    uvloop git=(url)"https://example.com/uvloop.git" ref="main" platform=(not)"windows"
}
'''
    manifest = parse_manifest(text)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # On linux: included (linux != windows, negated → satisfied)
    graph_linux = resolve(
        manifest,
        deps_dir=tmp_path / "linux_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "uvloop" in {d.name for d in graph_linux.deps}

    # On windows: excluded (windows = windows, negated → not satisfied)
    graph_win = resolve(
        manifest,
        deps_dir=tmp_path / "win_deps",
        fetcher=registry,
        profile=Profile(platform="windows", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "uvloop" not in {d.name for d in graph_win.deps}


def test_nim_predicate_supports_constraint_strings(tmp_path):
    """nim=">=2.0" matches profile nim=2.0.4, but not nim=1.6.20."""
    text = '''name "proj"
kind "library"
deps {
    modern git=(url)"https://example.com/modern.git" ref="main" nim=">=2.0"
}
'''
    manifest = parse_manifest(text)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # nim 2.0.4 → constraint satisfied
    graph_new = resolve(
        manifest,
        deps_dir=tmp_path / "new",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.4", milpa="0.1.0"),
    )
    assert "modern" in {d.name for d in graph_new.deps}

    # nim 1.6.20 → constraint NOT satisfied
    graph_old = resolve(
        manifest,
        deps_dir=tmp_path / "old",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="1.6.20", milpa="0.1.0"),
    )
    assert "modern" not in {d.name for d in graph_old.deps}


def test_format_manifest_round_trips_predicates():
    """A Manifest with predicate-bearing UrlDeps → format → parse →
    structurally identical."""
    from milpa.manifest import Predicate, format_manifest

    original = Manifest(
        kind="library", name="proj",
        deps=(
            UrlDep(
                name="pywin32",
                git="https://example.com/pywin32.git", ref="main",
                predicates=(Predicate(name="platform", values=("windows",)),),
            ),
            UrlDep(
                name="uvloop",
                git="https://example.com/uvloop.git", ref="main",
                predicates=(Predicate(name="platform", values=("windows",), negated=True),),
            ),
            UrlDep(
                name="modern",
                git="https://example.com/modern.git", ref="main",
                predicates=(Predicate(name="nim", values=(">=2.0",)),),
            ),
        ),
    )
    text = format_manifest(original)
    assert 'platform="windows"' in text
    assert 'platform=(not)"windows"' in text
    assert 'nim=">=2.0"' in text
    reparsed = parse_manifest(text)
    assert reparsed == original


def test_when_block_distributes_predicates_to_child_deps(tmp_path):
    """A `when` block applies its predicates to every dep declared
    inside. Two deps share a single condition declaration."""
    text = '''name "proj"
kind "library"
deps {
    when platform="windows" {
        winapi git=(url)"https://example.com/winapi.git" ref="main"
        wincred git=(url)"https://example.com/wincred.git" ref="main"
    }
}
'''
    manifest = parse_manifest(text)

    # Both deps have inherited the platform=windows predicate
    assert len(manifest.deps) == 2
    for d in manifest.deps:
        assert any(
            p.name == "platform" and "windows" in p.values and not p.negated
            for p in d.predicates
        ), f"{d.name} missing inherited predicate"

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # On linux: both excluded
    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert graph.deps == ()


def test_when_block_and_inline_predicates_compose_with_and(tmp_path):
    """A dep inside a when block carries BOTH the block's predicates
    and its own. Effective condition is the conjunction."""
    text = '''name "proj"
kind "library"
deps {
    when platform="windows" {
        modern_winapi git=(url)"https://example.com/x.git" ref="main" nim=">=2.0"
    }
}
'''
    manifest = parse_manifest(text)
    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # Windows + nim 2.0+ → included
    g = resolve(
        manifest, deps_dir=tmp_path / "a",
        fetcher=registry,
        profile=Profile(platform="windows", arch="amd64", nim="2.0.4", milpa="0.1.0"),
    )
    assert "modern_winapi" in {d.name for d in g.deps}

    # Windows + nim 1.6 → excluded (nim mismatch)
    g = resolve(
        manifest, deps_dir=tmp_path / "b",
        fetcher=registry,
        profile=Profile(platform="windows", arch="amd64", nim="1.6.20", milpa="0.1.0"),
    )
    assert "modern_winapi" not in {d.name for d in g.deps}

    # Linux + nim 2.0+ → excluded (platform mismatch)
    g = resolve(
        manifest, deps_dir=tmp_path / "c",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.4", milpa="0.1.0"),
    )
    assert "modern_winapi" not in {d.name for d in g.deps}


# ---------------------------------------------------------------------------
# #88 — OR / set membership via child-node syntax
# ---------------------------------------------------------------------------


def test_child_node_with_multiple_positional_args_is_OR(tmp_path):
    """Tracer (#88): a child node with multiple positional args means
    'predicate satisfied if profile matches ANY value'."""
    text = '''name "proj"
kind "library"
deps {
    cross git=(url)"https://example.com/cross.git" ref="main" {
        platform "linux" "macosx"
    }
}
'''
    manifest = parse_manifest(text)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # On linux: included
    g_lin = resolve(
        manifest, deps_dir=tmp_path / "lin",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" in {d.name for d in g_lin.deps}

    # On macosx: included
    g_mac = resolve(
        manifest, deps_dir=tmp_path / "mac",
        fetcher=registry,
        profile=Profile(platform="macosx", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" in {d.name for d in g_mac.deps}

    # On windows: excluded
    g_win = resolve(
        manifest, deps_dir=tmp_path / "win",
        fetcher=registry,
        profile=Profile(platform="windows", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" not in {d.name for d in g_win.deps}


def test_single_arg_child_node_equivalent_to_inline():
    """A single-arg child node produces the same Predicate value as
    the inline form: { platform "x" } ≡ platform="x"."""
    text_inline = '''name "proj"
kind "library"
deps {
    a git=(url)"https://x/a.git" ref="main" platform="windows"
}
'''
    text_child = '''name "proj"
kind "library"
deps {
    a git=(url)"https://x/a.git" ref="main" {
        platform "windows"
    }
}
'''
    m_inline = parse_manifest(text_inline)
    m_child = parse_manifest(text_child)
    # Predicates are structurally equal
    assert m_inline.deps[0].predicates == m_child.deps[0].predicates


def test_all_negated_args_in_child_node_mean_match_none(tmp_path):
    """{ platform (not)"windows" (not)"linux" } = profile must NOT
    be windows AND NOT be linux."""
    text = '''name "proj"
kind "library"
deps {
    a git=(url)"https://x/a.git" ref="main" {
        platform (not)"windows" (not)"linux"
    }
}
'''
    manifest = parse_manifest(text)
    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # On macosx: included (not windows AND not linux → True)
    g = resolve(
        manifest, deps_dir=tmp_path / "mac",
        fetcher=registry,
        profile=Profile(platform="macosx", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "a" in {d.name for d in g.deps}

    # On windows: excluded
    g = resolve(
        manifest, deps_dir=tmp_path / "win",
        fetcher=registry,
        profile=Profile(platform="windows", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "a" not in {d.name for d in g.deps}

    # On linux: excluded
    g = resolve(
        manifest, deps_dir=tmp_path / "lin",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "a" not in {d.name for d in g.deps}


def test_mixed_negation_in_child_node_is_rejected():
    """{ platform "windows" (not)"linux" } is ambiguous — reject."""
    text = '''name "proj"
kind "library"
deps {
    bad git=(url)"https://x/a.git" ref="main" {
        platform "windows" (not)"linux"
    }
}
'''
    from milpa.manifest import ManifestError
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    assert "negation" in str(exc.value).lower() or "mixed" in str(exc.value).lower() or "(not)" in str(exc.value)


def test_multiple_distinct_child_predicates_compose_with_and(tmp_path):
    """{ platform "a" "b"  arch "amd64" } = (platform∈{a,b}) AND (arch=amd64)."""
    text = '''name "proj"
kind "library"
deps {
    cross git=(url)"https://x/c.git" ref="main" {
        platform "linux" "macosx"
        arch "amd64"
    }
}
'''
    manifest = parse_manifest(text)
    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # linux + amd64 → included
    g = resolve(
        manifest, deps_dir=tmp_path / "a",
        fetcher=registry,
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" in {d.name for d in g.deps}

    # macosx + amd64 → included
    g = resolve(
        manifest, deps_dir=tmp_path / "b",
        fetcher=registry,
        profile=Profile(platform="macosx", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" in {d.name for d in g.deps}

    # linux + arm64 → excluded (arch mismatch)
    g = resolve(
        manifest, deps_dir=tmp_path / "c",
        fetcher=registry,
        profile=Profile(platform="linux", arch="arm64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" not in {d.name for d in g.deps}

    # windows + amd64 → excluded (platform mismatch)
    g = resolve(
        manifest, deps_dir=tmp_path / "d",
        fetcher=registry,
        profile=Profile(platform="windows", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    assert "cross" not in {d.name for d in g.deps}


def test_inline_and_child_node_form_for_same_predicate_is_rejected():
    """`platform="x"` inline AND `{ platform "y" }` child on the same
    dep is ambiguous — reject with a clear error naming the predicate."""
    text = '''name "proj"
kind "library"
deps {
    bad git=(url)"https://x/a.git" ref="main" platform="windows" {
        platform "linux"
    }
}
'''
    from milpa.manifest import ManifestError
    with pytest.raises(ManifestError) as exc:
        parse_manifest(text)
    msg = str(exc.value)
    assert "platform" in msg
    assert "both" in msg.lower() or "pick one" in msg.lower()


def test_format_manifest_emits_canonical_form_for_multi_value_predicates():
    """A multi-value Predicate round-trips as a child node; a
    single-value Predicate round-trips as inline. format∘parse∘format
    is byte-identical (idempotence)."""
    from milpa.manifest import Predicate, format_manifest

    # Construct in canonical (sorted-by-name) order so equality holds
    # against the reparsed form.
    original = Manifest(
        kind="library", name="proj",
        deps=(
            UrlDep(
                name="cross",
                git="https://x/c.git", ref="main",
                predicates=(
                    Predicate(name="arch", values=("amd64",)),
                    Predicate(name="platform", values=("linux", "macosx")),
                ),
            ),
        ),
    )
    text1 = format_manifest(original)
    # Multi-value as child node
    assert 'platform "linux" "macosx"' in text1
    # Single-value as inline
    assert 'arch="amd64"' in text1

    # Round-trip preserves the structure
    reparsed = parse_manifest(text1)
    assert reparsed == original

    # Second emission byte-identical (idempotence)
    text2 = format_manifest(reparsed)
    assert text1 == text2
