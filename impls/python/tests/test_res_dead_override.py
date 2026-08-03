"""RES-DEAD-OVERRIDE (S5b Part 2 — ``rfc-origin-as-identity.md`` §10 item 12
/ B10): a root ``overrides {}`` entry naming a dep absent from the resolved
graph is dead config that silently does nothing without this diagnostic.

``tests/test_m6_m7_override_warnings.py`` already covers the ORIGINAL
(pre-slug) "M6" behavior for a standalone resolve. This file:

  (a) re-asserts the dead-override warning fires and names the target,
      now under the ``RES-DEAD-OVERRIDE`` slug (``milpa.errors``);
  (b) re-asserts an override that redirects an ACTUALLY-consumed dep never
      warns;
  (c) makes the "non-fatal" clause explicit: resolution still returns a
      valid, usable ``ResolvedGraph`` alongside the warning, for both a
      standalone resolve AND the workspace path (``resolve_workspace`` — a
      real pre-existing gap this slice closes: the workspace resolver had
      NO equivalent check before S5b).
"""

from __future__ import annotations

import warnings
from pathlib import Path

from milpa.errors import RES_DEAD_OVERRIDE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_mocked_env(tmp_path: Path, url: str, kdl: str, sha: str):
    from milpa.context import MilpaEnv
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.cas import CAStore

    mocked_dir = tmp_path / "mocked-fetches"
    key = url_key(url, "main")
    d = mocked_dir / key
    (d / "content").mkdir(parents=True)
    (d / "content" / "milpa.kdl").write_text(kdl, encoding="utf-8")
    (d / "sha").write_text(sha, encoding="utf-8")

    store = CAStore(tmp_path / "cas")
    reg = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(reg, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def test_dead_override_warns_under_slug_and_names_target(tmp_path: Path) -> None:
    """(a) An override for a name no dep uses emits a warning naming it —
    the RES-DEAD-OVERRIDE slug is defined + documented (bijection lint), even
    though (mirroring RES-REGISTRY-SHADOW's warn-only path) the slug string
    itself is not embedded in the message text."""
    from milpa.context import ResolveParams
    from milpa.manifest import parse_manifest
    from milpa.resolver import resolve

    lib_a_kdl = 'name "lib-a"\nkind "library"\n'
    env = _build_mocked_env(tmp_path, "https://example.com/lib-a.git", lib_a_kdl, "aaaa" * 10)

    root_kdl = (
        'name "myapp"\nkind "application"\n'
        'deps {\n'
        '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
        '}\n'
        'overrides {\n'
        '    pkg "ghost-dep" git=(url)"https://example.com/fork.git" ref="main"\n'
        '}\n'
    )
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        graph = resolve(manifest, deps_dir, env, ResolveParams())

    assert RES_DEAD_OVERRIDE, "slug constant must exist (bijection lint)"
    dead_warnings = [
        str(x.message) for x in w
        if issubclass(x.category, UserWarning) and "ghost-dep" in str(x.message)
    ]
    assert dead_warnings, f"expected a dead-override warning naming 'ghost-dep'; got: {[str(x.message) for x in w]}"
    # (c, standalone half) non-fatal: resolution still succeeds with a usable graph.
    assert any(d.name == "lib-a" for d in graph.deps)


def test_consumed_override_no_dead_warning(tmp_path: Path) -> None:
    """(b) An override that redirects a dep ACTUALLY present in the graph
    must never emit the dead-override warning."""
    from milpa.context import ResolveParams
    from milpa.manifest import parse_manifest
    from milpa.resolver import resolve

    lib_a_kdl = 'name "lib-a"\nkind "library"\n'
    lib_fork_kdl = 'name "lib-a"\nkind "library"\n'
    env = _build_mocked_env(
        tmp_path, "https://example.com/lib-a-fork.git", lib_fork_kdl, "ffff" * 10
    )

    root_kdl = (
        'name "myapp"\nkind "application"\n'
        'deps {\n'
        '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
        '}\n'
        'overrides {\n'
        '    pkg "lib-a" git=(url)"https://example.com/lib-a-fork.git" ref="main"\n'
        '}\n'
    )
    manifest = parse_manifest(root_kdl)
    deps_dir = tmp_path / "_deps"

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        graph = resolve(manifest, deps_dir, env, ResolveParams())

    dead_warnings = [
        str(x.message) for x in w
        if issubclass(x.category, UserWarning) and "typo" in str(x.message).lower()
    ]
    assert not dead_warnings, f"no dead-override warning expected; got: {dead_warnings}"
    assert any(d.name == "lib-a" for d in graph.deps)


def test_dead_override_workspace_warns_and_resolution_still_succeeds(tmp_path: Path) -> None:
    """(a)+(c) for the WORKSPACE path (`resolve_workspace`) — a real gap
    closed by this slice: before S5b, only the standalone `resolve()` had
    this check; a workspace-root override naming no resolved dep silently
    no-op'd with zero diagnostic."""
    from milpa.context import MilpaEnv, ResolveParams
    from milpa.cas import CAStore
    from milpa.fetchers.mocked import mocked_registry, url_key
    from milpa.fetchers.cas_admitting import CasAdmittingFetcher
    from milpa.resolver import resolve_workspace
    from milpa.workspace import load_workspace

    ws_root = tmp_path / "ws"
    member_dir = ws_root / "member-a"
    member_dir.mkdir(parents=True)

    (ws_root / "milpa.kdl").write_text(
        "workspace {\n"
        '    member "member-a"\n'
        "}\n"
        "overrides {\n"
        '    pkg "ghost-dep" git=(url)"https://example.com/fork.git" ref="main"\n'
        "}\n",
        encoding="utf-8",
    )
    (member_dir / "milpa.kdl").write_text(
        'name "member-a"\nkind "library"\n',
        encoding="utf-8",
    )

    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    store = CAStore(tmp_path / "cas")
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    env = MilpaEnv(fetcher=fetcher, index=None, store=store)

    workspace = load_workspace(ws_root)
    deps_dir = ws_root / "_deps"

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        graph = resolve_workspace(workspace, deps_dir, env, ResolveParams())

    dead_warnings = [
        str(x.message) for x in w
        if issubclass(x.category, UserWarning) and "ghost-dep" in str(x.message)
    ]
    assert dead_warnings, (
        f"expected a workspace dead-override warning naming 'ghost-dep'; "
        f"got: {[str(x.message) for x in w]}"
    )
    # Non-fatal: the workspace still resolves to a usable graph.
    assert any(d.name == "member-a" for d in graph.deps)
