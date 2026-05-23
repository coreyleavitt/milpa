"""Workspace discovery + structural validation tests (W2 / #74).

Discovery is the mechanical walk-up of `find_workspace_root` — returns
the nearest workspace milpa.kdl ancestor. Validation lives in
`load_workspace` — once a candidate root exists, all the structural
checks (members exist, no nesting, names unique, etc.) run before
returning a usable Workspace value.

`workspace_containing` composes the two for the CLI use case: am I
in a workspace, and is this directory legitimately a member?

See docs/comparison-vs-nimble-atlas.md for the cargo-style framing.
"""

from pathlib import Path

import pytest

from milpa.workspace import (
    LoadedMember, Workspace, WorkspaceError,
    find_workspace_root, load_workspace, workspace_containing,
)


def test_find_workspace_root_returns_dir_when_start_is_the_root(tmp_path):
    """Tracer: a workspace milpa.kdl in start_dir → find_workspace_root
    returns start_dir."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )
    assert find_workspace_root(tmp_path) == tmp_path


def test_find_workspace_root_walks_up_from_subdir(tmp_path):
    """A workspace milpa.kdl at <root>; start_dir is <root>/fresco/.
    find_workspace_root must walk up and find <root>."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()

    assert find_workspace_root(member_dir) == tmp_path


def _make_workspace_fixture(tmp_path: Path, members: dict[str, str]) -> Path:
    """Build a workspace directory at tmp_path with the given members.
    `members` maps relative member path → that member's name."""
    member_lines = "\n".join(f'    member "{path}"' for path in members)
    (tmp_path / "milpa.kdl").write_text(
        f'workspace {{\n{member_lines}\n}}\n'
    )
    for path, name in members.items():
        d = tmp_path / path
        d.mkdir(parents=True, exist_ok=True)
        (d / "milpa.kdl").write_text(
            f'name "{name}"\nkind "library"\n'
        )
    return tmp_path


def test_load_workspace_happy_path_one_member(tmp_path):
    """A workspace with one member loads into a Workspace with one
    LoadedMember carrying name, path, directory, and the member's
    parsed Manifest."""
    root = _make_workspace_fixture(tmp_path, {"fresco": "fresco"})

    ws = load_workspace(root)

    assert isinstance(ws, Workspace)
    assert ws.root == root
    assert len(ws.members) == 1
    m = ws.members[0]
    assert isinstance(m, LoadedMember)
    assert m.name == "fresco"
    assert m.path == "fresco"
    assert m.directory == root / "fresco"
    assert m.manifest.name == "fresco"
    assert m.manifest.kind == "library"


def test_load_workspace_raises_when_member_dir_missing(tmp_path):
    """A declared member whose directory doesn't exist on disk →
    WorkspaceError naming the member path."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "ghost"\n'
        '}\n'
    )
    # No tmp_path/ghost/ on disk.

    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert "ghost" in str(exc.value)


def test_load_workspace_raises_when_member_has_no_milpa_kdl(tmp_path):
    """A member directory exists but contains no milpa.kdl →
    WorkspaceError pointing to the missing manifest path."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "empty"\n'
        '}\n'
    )
    (tmp_path / "empty").mkdir()  # directory but no milpa.kdl

    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    msg = str(exc.value)
    assert "empty" in msg
    assert "milpa.kdl" in msg


def test_load_workspace_raises_on_nested_workspace(tmp_path):
    """A member's milpa.kdl declares its own workspace { ... } block →
    WorkspaceError. Workspaces do not nest."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "outer-member"\n'
        '}\n'
    )
    nested = tmp_path / "outer-member"
    nested.mkdir()
    (nested / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "inner"\n'
        '}\n'
    )

    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    msg = str(exc.value).lower()
    assert "outer-member" in msg
    assert "nest" in msg or "workspace" in msg


def test_load_workspace_raises_on_duplicate_member_names(tmp_path):
    """Two member directories whose manifests both claim the same
    `name` → WorkspaceError naming the collision. Members must be
    uniquely identifiable for the resolver's `member "..."` lookup."""
    root = _make_workspace_fixture(tmp_path, {"a": "shared", "b": "shared"})

    with pytest.raises(WorkspaceError) as exc:
        load_workspace(root)
    msg = str(exc.value)
    assert "shared" in msg
    assert "a" in msg
    assert "b" in msg


def test_load_workspace_rejects_member_dot(tmp_path):
    """`member "."` is structurally incoherent under virtual-workspace-
    only — the root milpa.kdl is a workspace declaration and cannot
    also be parsed as a package. Reject explicitly with guidance to
    put the package at a subdirectory."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "."\n'
        '}\n'
    )
    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    msg = str(exc.value).lower()
    # The message should make the recovery path clear
    assert '"."' in str(exc.value) or "member '.'" in msg
    assert "subdirectory" in msg or "virtual-workspace" in msg


def test_load_workspace_parses_workspace_level_overrides(tmp_path):
    """A workspace milpa.kdl with overrides { pkg ... } block →
    Workspace.overrides populated. Resolver-side application is W5;
    W2 closes the silent-drop gap from W1's _WORKSPACE_TOP_LEVEL."""
    from milpa.manifest import Override
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
        'overrides {\n'
        '    pkg "chronos" git=(url)"https://my-fork/chronos.git" ref="my-fix"\n'
        '}\n'
    )
    (tmp_path / "fresco").mkdir()
    (tmp_path / "fresco" / "milpa.kdl").write_text(
        'name "fresco"\nkind "library"\n'
    )

    ws = load_workspace(tmp_path)
    assert ws.overrides == (
        Override(
            name="chronos",
            git="https://my-fork/chronos.git",
            ref="my-fix",
        ),
    )


def test_load_workspace_warns_on_orphan_milpa_kdl_at_depth_1(tmp_path, capsys):
    """A direct subdirectory of the workspace root containing a
    milpa.kdl but NOT declared as a member → printed warning. Catches
    the 'forgot to register new package' mistake without preventing
    the load."""
    root = _make_workspace_fixture(tmp_path, {"fresco": "fresco"})
    # Plant an orphan package alongside `fresco/`:
    orphan = root / "ghost-pkg"
    orphan.mkdir()
    (orphan / "milpa.kdl").write_text('name "ghost"\nkind "library"\n')

    ws = load_workspace(root)
    # The workspace still loads successfully (warning is non-fatal)
    assert len(ws.members) == 1

    err = capsys.readouterr().err
    assert "warning" in err.lower()
    assert "ghost-pkg" in err


def test_workspace_containing_returns_workspace_for_member_dir(tmp_path):
    """High-level dispatcher: start_dir IS a declared member's
    directory → returns the loaded Workspace."""
    root = _make_workspace_fixture(tmp_path, {"fresco": "fresco"})
    ws = workspace_containing(root / "fresco")
    assert ws is not None
    assert ws.root == root
    assert ws.members[0].name == "fresco"


def test_workspace_containing_returns_workspace_for_root_dir(tmp_path):
    """Running from the workspace root itself also resolves to the
    Workspace — the root is implicitly a valid 'inside-workspace'
    location."""
    root = _make_workspace_fixture(tmp_path, {"fresco": "fresco"})
    ws = workspace_containing(root)
    assert ws is not None
    assert ws.root == root


def test_workspace_containing_returns_none_for_non_member_subdir(tmp_path, capsys):
    """A subdirectory under workspace root that isn't a declared
    member → None. Guards against the 'random workspace above
    accidentally claims me' scenario."""
    root = _make_workspace_fixture(tmp_path, {"fresco": "fresco"})
    # Create a dir under root that's NOT a member.
    stray = root / "random-stuff"
    stray.mkdir()

    # Discard any orphan-scan warnings from load_workspace
    capsys.readouterr()
    assert workspace_containing(stray) is None


def test_find_workspace_root_returns_none_when_no_workspace_above(tmp_path):
    """A directory with no workspace milpa.kdl in any ancestor →
    find_workspace_root returns None. Walking terminates at the
    filesystem root without finding anything."""
    # tmp_path is a fresh temp dir with no milpa.kdl above it
    # (the test environment guarantees this).
    nested = tmp_path / "deep" / "nested" / "dir"
    nested.mkdir(parents=True)
    assert find_workspace_root(nested) is None


def test_find_workspace_root_walks_past_package_milpa_kdls(tmp_path):
    """A member's own (package) milpa.kdl must NOT terminate discovery
    — otherwise calling find_workspace_root from inside a member dir
    would stop at the member's manifest and never find the workspace
    above. Package manifests are transparent to discovery."""
    # Workspace at <root>:
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )
    # Member at <root>/fresco/ with its OWN milpa.kdl (a package):
    member_dir = tmp_path / "fresco"
    member_dir.mkdir()
    (member_dir / "milpa.kdl").write_text(
        'name "fresco"\n'
        'kind "library"\n'
    )

    # From inside the member dir: discovery must walk past the package
    # manifest to find the workspace at the parent.
    assert find_workspace_root(member_dir) == tmp_path
