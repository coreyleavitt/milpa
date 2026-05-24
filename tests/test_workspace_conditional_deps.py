"""Workspace per-member predicate filtering (#89).

#26 shipped predicates for single-package manifests. resolve_workspace
accepts a `profile` kwarg but didn't filter member-declared deps
until this cycle. Members declaring `pywin32 platform="windows"` are
now excluded on Linux profile during workspace resolution.
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.manifest import Manifest, UrlDep, Predicate
from milpa.profile import Profile
from milpa.resolver import ResolvedGraph, resolve_workspace
from milpa.workspace import LoadedMember, Workspace


class StubFetcher:
    def __init__(self):
        self.fetched: list[str] = []
    def can_handle(self, p): return isinstance(p, GitProvenance)
    def fetch(self, name, p, *, dest):
        self.fetched.append(name)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        return GitReceipt(commit_sha="abc")


def test_workspace_member_conditional_dep_filtered_by_profile(tmp_path):
    """A workspace member declares `pywin32 platform="windows"`. Under
    a Linux profile, the conditional dep is excluded from resolution —
    not fetched, not in the graph."""
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "fresco.nim").write_text("# fresco\n")

    member_manifest = Manifest(
        kind="library", name="fresco",
        deps=(UrlDep(
            name="pywin32",
            git="https://example.com/pywin32.git", ref="main",
            predicates=(Predicate(name="platform", values=("windows",)),),
        ),),
    )

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="fresco", path="fresco",
            directory=member_dir, manifest=member_manifest,
        ),),
    )

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    graph = resolve_workspace(
        ws,
        deps_dir=tmp_path / "_deps",
        registry={},
        fetcher=registry,
        list_tags=lambda url: [],
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )

    names = {d.name for d in graph.deps}
    # Member itself present
    assert "fresco" in names
    # Conditional dep excluded
    assert "pywin32" not in names
    # Fetcher was never invoked
    assert "pywin32" not in fetcher_impl.fetched


def test_workspace_member_when_block_end_to_end_via_kdl(tmp_path):
    """A workspace member's milpa.kdl uses a `when` block. Parse it
    from KDL text (covering the full grammar path) and verify the
    block's predicate distributes correctly under the workspace
    resolver."""
    from milpa.manifest import parse_manifest

    member_dir = tmp_path / "member"
    member_dir.mkdir()
    (member_dir / "member.nim").write_text("# member\n")

    kdl_text = '''name "member"
kind "library"
deps {
    when platform="windows" {
        winapi git=(url)"https://example.com/winapi.git" ref="main"
    }
    cross git=(url)"https://example.com/cross.git" ref="main"
}
'''
    member_manifest = parse_manifest(kdl_text)

    ws = Workspace(
        root=tmp_path,
        members=(LoadedMember(
            name="member", path="member",
            directory=member_dir, manifest=member_manifest,
        ),),
    )

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # On linux: winapi excluded, cross included
    g_lin = resolve_workspace(
        ws, deps_dir=tmp_path / "lin_deps", registry={},
        fetcher=registry, list_tags=lambda url: [],
        profile=Profile(platform="linux", arch="amd64", nim="2.0.0", milpa="0.1.0"),
    )
    names = {d.name for d in g_lin.deps}
    assert "member" in names
    assert "cross" in names
    assert "winapi" not in names
