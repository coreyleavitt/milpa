"""B7 (resolution-semantics RFC §3 Axis B / final Axis-B slice): thread
``prior`` through the remaining resolve-triggering verbs that hardcoded
``prior=None`` — ``add`` (both the standalone-package path
``_cmd_add_git`` and the member-dir path ``_cmd_add_from_member_dir``),
``workspace add-member``, and ``workspace remove-member``.

Before this slice, each of these verbs re-resolved with NO prior-lock
preference, so adding one dep (or a workspace member) would newest-wins
bump every OTHER already-locked dep that happened to have a newer
version available in the index — reproducing #192 through a door the
original incident never hit.

Pattern mirrors ``test_b4_upgrade.py``: real mocked-git transport + a real
file:// tianguis index with two versions per package, so the "would move
under a fresh/newest-wins resolve" claim is genuinely exercised (not just
asserted) — establish a lock against a v1-only index, then swap the index
to also carry v2 before invoking the verb under test.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import (
    cmd_add,
    cmd_fetch,
    cmd_workspace_add_member,
    cmd_workspace_remove_member,
)
from milpa.context import MilpaEnv
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import Lockfile, load_lockfile
from milpa.version import Strategy

# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_b4_upgrade.py's local helpers)
# ---------------------------------------------------------------------------


def _make_git_mock(
    mocked_dir: Path, url: str, ref: str, *, sha: str, nim_name: str, marker: str
) -> None:
    d = mocked_dir / url_key(url, ref)
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{nim_name}.nim").write_text(f"# {nim_name} {marker}\n", encoding="utf-8")
    (d / f"{nim_name}.nimble").write_text(
        '# Package\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n', encoding="utf-8"
    )
    (d / "sha").write_text(sha, encoding="utf-8")


def _content_hash_for(mocked_dir: Path, url: str, ref: str, name: str) -> str:
    key_dir = mocked_dir / url_key(url, ref)
    with tempfile.TemporaryDirectory() as td:
        dest = Path(td)
        content = key_dir / "content"
        for src in content.rglob("*"):
            if src.is_file():
                rel = src.relative_to(content)
                tgt = dest / rel
                tgt.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, tgt)
        nimble_src = key_dir / f"{name}.nimble"
        if nimble_src.is_file():
            shutil.copy2(nimble_src, dest / f"{name}.nimble")
        return compute_content_hash(dest)


def _stage_two_versions(mocked_dir: Path, name: str, *, sha_prefix: str) -> tuple[str, str]:
    url = f"https://example.com/{name}.git"
    _make_git_mock(mocked_dir, url, "v1.0.0", sha=f"{sha_prefix}1" * 20, nim_name=name, marker="v1")
    _make_git_mock(mocked_dir, url, "v2.0.0", sha=f"{sha_prefix}2" * 20, nim_name=name, marker="v2")
    h1 = _content_hash_for(mocked_dir, url, "v1.0.0", name)
    h2 = _content_hash_for(mocked_dir, url, "v2.0.0", name)
    return h1, h2


def _stage_new_dep(mocked_dir: Path, name: str, *, sha: str) -> None:
    """A single-version git dep used as the NEWLY ADDED dep (no index entry —
    ``milpa add --git`` fetches directly, it never goes through the index).

    Writes an explicit ``version = "1.0.0"`` in the .nimble so the added dep's
    resolved version is deterministic (Axis A: ``.nimble version`` labels the
    candidate) rather than falling back to the version-unknown sentinel."""
    url = f"https://example.com/{name}.git"
    d = mocked_dir / url_key(url, "main")
    content = d / "content"
    content.mkdir(parents=True)
    (content / f"{name}.nim").write_text(f"# {name} v1\n", encoding="utf-8")
    (d / f"{name}.nimble").write_text(
        '# Package\nversion = "1.0.0"\nauthor = "e"\ndescription = "d"\nlicense = "MIT"\n',
        encoding="utf-8",
    )
    (d / "sha").write_text(sha, encoding="utf-8")


def _index_kdl(hashes: dict[str, tuple[str, str]], *, include_v2: bool) -> str:
    def pkg_block(name: str, h1: str, h2: str) -> str:
        v2_block = (
            f"""    version "2.0.0" {{
        content_hash "{h2}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v2.0.0"
            commit_sha "{'b' * 40}"
        }}
    }}
"""
            if include_v2
            else ""
        )
        return f"""\
package "{name}" {{
    version "1.0.0" {{
        content_hash "{h1}"
        provenance {{
            kind "git"
            url "https://example.com/{name}.git"
            ref "v1.0.0"
            commit_sha "{'a' * 40}"
        }}
    }}
{v2_block}}}
"""

    return "schema_version 1\n" + "".join(
        pkg_block(name, h1, h2) for name, (h1, h2) in hashes.items()
    )


def _mocked_env(mocked_dir: Path, tmp_store: Path) -> MilpaEnv:
    store = CAStore(root=tmp_store)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _versions(lock: Lockfile) -> dict[str, str]:
    return {d.name: d.version for d in lock.deps}


@pytest.fixture()
def _env_isolation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate index-cache + trust env vars (mirrors test_b4_upgrade.py's
    ``_upgrade_setup``)."""
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
    monkeypatch.setenv("MILPA_CACHE_DIR", str(cache_dir))
    monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
    monkeypatch.delenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", raising=False)
    monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)


# ---------------------------------------------------------------------------
# 1. cmd_add (standalone package) — _cmd_add_git
# ---------------------------------------------------------------------------


def test_add_leaves_existing_deps_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _env_isolation
) -> None:
    """``milpa add baz --git ...`` resolves baz while foo/bar — already
    locked at 1.0.0 — stay pinned even though the index now also offers
    2.0.0 for both (would newest-wins-bump them pre-B7)."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    foo_hashes = _stage_two_versions(mocked_dir, "foo", sha_prefix="1")
    bar_hashes = _stage_two_versions(mocked_dir, "bar", sha_prefix="2")
    hashes = {"foo": foo_hashes, "bar": bar_hashes}

    index_v1 = tmp_path / "index-v1.kdl"
    index_v1.write_text(_index_kdl(hashes, include_v2=False), encoding="utf-8")
    index_v1v2 = tmp_path / "index-v1v2.kdl"
    index_v1v2.write_text(_index_kdl(hashes, include_v2=True), encoding="utf-8")

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project_dir.joinpath("milpa.kdl").write_text(
        'name "myapp"\nkind "application"\nindex-trust "off"\ndeps {\n    foo\n    bar\n}\n',
        encoding="utf-8",
    )

    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1}")
    env = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    assert _versions(load_lockfile(project_dir / "milpa.lock")) == {
        "foo": "1.0.0",
        "bar": "1.0.0",
    }

    # A newer version of both got published.
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2}")
    # The dep being ADDED via --git (never index-resolved).
    _stage_new_dep(mocked_dir, "baz", sha="c" * 40)

    env2 = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_add(
        project_dir,
        env2,
        dep_name="baz",
        git_url="https://example.com/baz.git",
        mirror_url=None,
        ref="main",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    lock = load_lockfile(project_dir / "milpa.lock")
    versions = _versions(lock)
    assert versions["baz"] == "1.0.0", "the newly added dep resolves"
    assert versions["foo"] == "1.0.0", "B7: unrelated locked dep must NOT move"
    assert versions["bar"] == "1.0.0", "B7: unrelated locked dep must NOT move"
    kdl_text = (project_dir / "milpa.kdl").read_text(encoding="utf-8")
    assert "baz" in kdl_text


# ---------------------------------------------------------------------------
# 2. cmd_add (member-dir) — _cmd_add_from_member_dir
# ---------------------------------------------------------------------------


def test_add_from_member_dir_leaves_other_members_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _env_isolation
) -> None:
    """``milpa add`` invoked from a workspace MEMBER dir re-resolves the
    WHOLE shared workspace graph; B7: other members' already-locked deps
    (foo, in member-a) must stay pinned when a new dep is added to
    member-b, even though foo's index now also offers 2.0.0."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    foo_hashes = _stage_two_versions(mocked_dir, "foo", sha_prefix="1")
    hashes = {"foo": foo_hashes}

    index_v1 = tmp_path / "index-v1.kdl"
    index_v1.write_text(_index_kdl(hashes, include_v2=False), encoding="utf-8")
    index_v1v2 = tmp_path / "index-v1v2.kdl"
    index_v1v2.write_text(_index_kdl(hashes, include_v2=True), encoding="utf-8")

    root = tmp_path / "ws"
    root.mkdir()
    root.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "member-a"\n    member "member-b"\n}\nindex-trust "off"\n',
        encoding="utf-8",
    )
    member_a = root / "member-a"
    member_a.mkdir()
    member_a.joinpath("milpa.kdl").write_text(
        'name "liba"\nkind "library"\ndeps {\n    foo\n}\n',
        encoding="utf-8",
    )
    member_b = root / "member-b"
    member_b.mkdir()
    member_b.joinpath("milpa.kdl").write_text(
        'name "libb"\nkind "library"\n', encoding="utf-8"
    )

    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1}")
    env = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_fetch(root, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    assert load_lockfile(root / "milpa.lock").deps
    assert _versions(load_lockfile(root / "milpa.lock"))["foo"] == "1.0.0"

    # foo's index now also offers 2.0.0.
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2}")
    _stage_new_dep(mocked_dir, "baz", sha="c" * 40)

    env2 = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_add(
        member_b,
        env2,
        dep_name="baz",
        git_url="https://example.com/baz.git",
        mirror_url=None,
        ref="main",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    lock = load_lockfile(root / "milpa.lock")
    versions = _versions(lock)
    assert versions["baz"] == "1.0.0"
    assert versions["foo"] == "1.0.0", "B7: member-a's dep must NOT move"
    # No member-local lock written (D5 correctness point, unrelated to B7
    # but a cheap sanity check that this is still the right code path).
    assert not (member_b / "milpa.lock").exists()


# ---------------------------------------------------------------------------
# 3. cmd_workspace_add_member
# ---------------------------------------------------------------------------


def test_workspace_add_member_leaves_other_members_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _env_isolation
) -> None:
    """Adding a new member to the workspace re-resolves the shared graph;
    B7: the EXISTING member's already-locked dep (foo) stays pinned even
    though the index now also offers 2.0.0."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    foo_hashes = _stage_two_versions(mocked_dir, "foo", sha_prefix="1")
    bar_hashes = _stage_two_versions(mocked_dir, "bar", sha_prefix="2")
    hashes = {"foo": foo_hashes, "bar": bar_hashes}

    index_v1 = tmp_path / "index-v1.kdl"
    index_v1.write_text(_index_kdl({"foo": foo_hashes}, include_v2=False), encoding="utf-8")
    index_v1v2 = tmp_path / "index-v1v2.kdl"
    index_v1v2.write_text(_index_kdl(hashes, include_v2=True), encoding="utf-8")

    root = tmp_path / "ws"
    root.mkdir()
    root.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "member-a"\n}\nindex-trust "off"\n', encoding="utf-8"
    )
    member_a = root / "member-a"
    member_a.mkdir()
    member_a.joinpath("milpa.kdl").write_text(
        'name "liba"\nkind "library"\ndeps {\n    foo\n}\n',
        encoding="utf-8",
    )
    # member-c is the NEW member being added — declared on disk now, added
    # to the workspace manifest by the verb under test.
    member_c = root / "member-c"
    member_c.mkdir()
    member_c.joinpath("milpa.kdl").write_text(
        'name "libc"\nkind "library"\ndeps {\n    bar\n}\n', encoding="utf-8"
    )

    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1}")
    env = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_fetch(root, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    assert _versions(load_lockfile(root / "milpa.lock"))["foo"] == "1.0.0"

    # foo's index now also offers 2.0.0; bar (member-c's own dep) is new.
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2}")
    env2 = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_workspace_add_member(
        root, env2, member_path="member-c", strategy=Strategy.MAXVER, max_parallel=4
    )
    assert rc == 0

    lock = load_lockfile(root / "milpa.lock")
    versions = _versions(lock)
    assert versions["foo"] == "1.0.0", "B7: member-a's dep must NOT move"
    assert "bar" in versions, "member-c's own dep resolves"
    text = (root / "milpa.kdl").read_text(encoding="utf-8")
    assert "member-c" in text


# ---------------------------------------------------------------------------
# 4. cmd_workspace_remove_member
# ---------------------------------------------------------------------------


def test_workspace_remove_member_leaves_remaining_members_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _env_isolation
) -> None:
    """Removing a member re-resolves the shared graph minimally; B7: the
    REMAINING member's already-locked dep (foo) stays pinned even though
    the index now also offers 2.0.0."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    foo_hashes = _stage_two_versions(mocked_dir, "foo", sha_prefix="1")
    bar_hashes = _stage_two_versions(mocked_dir, "bar", sha_prefix="2")
    hashes = {"foo": foo_hashes, "bar": bar_hashes}

    index_v1 = tmp_path / "index-v1.kdl"
    index_v1.write_text(_index_kdl(hashes, include_v2=False), encoding="utf-8")
    index_v1v2 = tmp_path / "index-v1v2.kdl"
    index_v1v2.write_text(_index_kdl(hashes, include_v2=True), encoding="utf-8")

    root = tmp_path / "ws"
    root.mkdir()
    root.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "member-a"\n    member "member-b"\n}\nindex-trust "off"\n',
        encoding="utf-8",
    )
    member_a = root / "member-a"
    member_a.mkdir()
    member_a.joinpath("milpa.kdl").write_text(
        'name "liba"\nkind "library"\ndeps {\n    foo\n}\n',
        encoding="utf-8",
    )
    member_b = root / "member-b"
    member_b.mkdir()
    member_b.joinpath("milpa.kdl").write_text(
        'name "libb"\nkind "library"\ndeps {\n    bar\n}\n', encoding="utf-8"
    )

    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1}")
    env = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_fetch(root, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    baseline = _versions(load_lockfile(root / "milpa.lock"))
    assert baseline["foo"] == "1.0.0"
    assert baseline["bar"] == "1.0.0"

    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2}")
    env2 = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_workspace_remove_member(
        root, env2, name_or_path="member-b", strategy=Strategy.MAXVER, max_parallel=4
    )
    assert rc == 0

    lock = load_lockfile(root / "milpa.lock")
    versions = _versions(lock)
    assert "bar" not in versions, "member-b's dep is gone"
    assert versions["foo"] == "1.0.0", "B7: member-a's dep must NOT move"
    text = (root / "milpa.kdl").read_text(encoding="utf-8")
    assert "member-b" not in text
