"""Manifest dep-mirrors grammar (#37 Part B).

A UrlDep may declare additional mirror URLs inside its node body:

    deps {
        chronos git=(url)"https://github.com/x/chronos.git" ref="main" {
            mirror "https://gitlab.com/x/chronos.git"
            mirror "oci://registry.example.com/chronos"
        }
    }

Mirrors are fall-back fetch targets, tried after the primary `git`
URL fails. Order matters — first declared, first tried.
"""

import pytest

from milpa.manifest import (
    Manifest,
    UrlDep,
    format_manifest,
    parse_manifest,
)


def test_parse_manifest_reads_mirror_lines_in_url_dep_block():
    """A `dep { mirror "..." }` block produces UrlDep.mirrors."""
    text = '''name "test"
deps {
    chronos git=(url)"https://github.com/x/chronos.git" ref="main" {
        mirror "https://gitlab.com/x/chronos.git"
        mirror "https://mirror.example.com/x/chronos.git"
    }
}
kind "library"
'''
    m = parse_manifest(text)
    assert len(m.deps) == 1
    dep = m.deps[0]
    assert isinstance(dep, UrlDep)
    assert dep.name == "chronos"
    assert dep.git == "https://github.com/x/chronos.git"
    assert dep.ref == "main"
    assert dep.mirrors == (
        "https://gitlab.com/x/chronos.git",
        "https://mirror.example.com/x/chronos.git",
    )


def test_format_manifest_emits_mirrors_and_round_trips():
    """A Manifest with UrlDep mirrors → format → parse yields an
    equal Manifest (mirror order preserved)."""
    original = Manifest(
        kind="library",
        name="proj",
        deps=(UrlDep(
            name="chronos",
            git="https://github.com/x/chronos.git",
            ref="main",
            mirrors=(
                "https://gitlab.com/x/chronos.git",
                "https://mirror.example.com/x/chronos.git",
            ),
        ),),
    )
    text = format_manifest(original)
    assert 'mirror (url)"https://gitlab.com/x/chronos.git"' in text
    assert 'mirror (url)"https://mirror.example.com/x/chronos.git"' in text
    reparsed = parse_manifest(text)
    assert reparsed == original


def test_format_manifest_no_mirror_block_when_dep_has_no_mirrors():
    """A bare UrlDep (no mirrors) must not emit an empty block."""
    m = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(name="x", git="https://example.com/x.git", ref="main"),),
    )
    text = format_manifest(m)
    assert "mirror" not in text
    assert "{" not in text.split("deps {")[1].split("}")[0]


# ---------------------------------------------------------------------------
# Resolver integration: mirrors get tried on primary failure
# ---------------------------------------------------------------------------


def test_resolver_falls_through_to_manifest_mirror_when_primary_url_fails(tmp_path):
    """When a UrlDep has mirrors and the primary URL fails to fetch,
    the resolver tries each mirror in order and uses the first that
    succeeds. End-to-end via resolve() with a fake fetcher."""
    from milpa.fetchers import (
        FetcherRegistry,
        FetchError,
        Provenance,
        ProvenanceReceipt,
    )
    from milpa.fetchers.git import GitProvenance, GitReceipt
    from milpa.resolver import resolve

    primary_url = "https://primary.example.com/x.git"
    mirror_url = "https://mirror.example.com/x.git"

    class MirrorAwareFetcher:
        """Fakes primary failure + mirror success for the test URL pair."""

        def __init__(self):
            self.calls: list[str] = []

        def can_handle(self, p):
            return isinstance(p, GitProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append(p.url)
            if p.url == primary_url:
                raise FetchError(f"synthetic primary failure for {p.url}")
            # Mirror: succeed
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="mirror-sha")

    fetcher_impl = MirrorAwareFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    manifest = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(
            name="x", git=primary_url, ref="main",
            mirrors=(mirror_url,),
        ),),
    )

    graph = resolve(
        manifest,
        deps_dir=tmp_path / "_deps",
        fetcher=registry,
    )

    # Both URLs attempted, in order
    assert fetcher_impl.calls == [primary_url, mirror_url]
    # Resolution succeeded with mirror's bytes
    assert len(graph.deps) == 1
    assert graph.deps[0].name == "x"
    assert graph.deps[0].sha == "mirror-sha"
