"""S5b (``docs/rfc-origin-as-identity.md`` §10 item 12): CLI-wide
``solver_var``/``from_solver_var`` audit + mutation-verb behavioral coverage.

The audit swept all ``solver_var``/``from_solver_var`` call sites (~66 total,
9 clustered in ``cli.py``'s ``cmd_remove``, S5-rekey RFC §4.4.1) and found ONE
genuine conflation bug: ``cmd_remove`` computed a ``DepKey.solver_var()``-
joined string (``"ns1::bar"``) and compared it directly against the prior
lockfile's ``LockedDep.name`` / the freshly resolved graph's
``ResolvedDep.name`` — but both store a qualified dep as two SEPARATE fields
(bare ``name`` + separate ``namespace``), never joined with ``::``
(``DepKey.solver_var()``'s own docstring: "SOLVER-INTERNAL ONLY... MUST NOT
be written to disk, the lockfile, or _deps/ paths"). The joined string never
equals the bare lockfile ``name``, so:

  - the alias→canonical lookup against the prior lockfile silently failed
    for a qualified dep (fell through to "no alias" every time);
  - the "alias still required transitively" vs. "alias removed" branch
    (D-update-remove Phase D item 5) always took the wrong path for a
    qualified dep with a recorded alias.

Fixed in ``cli.cmd_remove`` by matching on a structural ``DepKey(name,
namespace)`` tuple throughout — never a joined string — mirroring the
pattern ``frozen.py``'s ``_check_source_id_preconditions`` already used
correctly (``DepKey(name=locked.name, namespace=locked.namespace)``).

This file covers:
  1. End-to-end ``add``/``remove``/``update`` over ONE manifest mixing a
     ``git=`` dep, a namespace-qualified named dep, and a bare named dep —
     proving the mutation verbs survive the S5-rekey solver-variable change
     without conflating a qualified dep's lockfile identity with its
     solver key.
  2. A focused regression test for the alias-warning conflation bug itself.

No mocking of milpa's own logic: real mocked-git-fetches + a real file://
tianguis index, same infra as ``test_b4_upgrade.py``/``test_c2_lowest_direct.py``.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import cmd_add, cmd_fetch, cmd_remove, cmd_update
from milpa.context import MilpaEnv
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import Lockfile, load_lockfile
from milpa.version import Strategy

# ---------------------------------------------------------------------------
# Fixture helpers (mirrors test_b4_upgrade.py / test_c2_lowest_direct.py)
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


def _pkg_block(name: str, *, namespace: str | None, h1: str, h2: str | None) -> str:
    ns_line = f'    namespace "{namespace}"\n' if namespace is not None else ""
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
        if h2 is not None
        else ""
    )
    return f"""\
package "{name}" {{
{ns_line}    version "1.0.0" {{
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


def _mocked_env(mocked_dir: Path, tmp_store: Path) -> MilpaEnv:
    store = CAStore(root=tmp_store)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


_ROOT_KDL = (
    'name "myapp"\nkind "application"\nindex-trust "off"\n'
    "deps {\n"
    '    gitdep git=(url)"https://example.com/gitdep.git" ref="main"\n'
    '    qual namespace="ns1"\n'
    "    bare1\n"
    "}\n"
)


@pytest.fixture()
def _mixed_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A project with a git dep, a namespace-qualified named dep ("qual" in
    "ns1"), and a bare named dep ("bare1"). Returns
    (mocked_dir, index_v1_path, index_v1v2_path)."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()

    # git dep content.
    _make_git_mock(
        mocked_dir, "https://example.com/gitdep.git", "main",
        sha="1" * 40, nim_name="gitdep", marker="main",
    )

    # qual (namespace "ns1") — two versions, so the update test can prove a
    # real re-resolve moves the pin.
    _make_git_mock(
        mocked_dir, "https://example.com/qual.git", "v1.0.0",
        sha="2" * 40, nim_name="qual", marker="v1",
    )
    _make_git_mock(
        mocked_dir, "https://example.com/qual.git", "v2.0.0",
        sha="3" * 40, nim_name="qual", marker="v2",
    )
    qual_h1 = _content_hash_for(mocked_dir, "https://example.com/qual.git", "v1.0.0", "qual")
    qual_h2 = _content_hash_for(mocked_dir, "https://example.com/qual.git", "v2.0.0", "qual")

    # bare1 (no namespace) — single version.
    _make_git_mock(
        mocked_dir, "https://example.com/bare1.git", "v1.0.0",
        sha="4" * 40, nim_name="bare1", marker="v1",
    )
    bare1_h1 = _content_hash_for(mocked_dir, "https://example.com/bare1.git", "v1.0.0", "bare1")

    index_v1_path = tmp_path / "index-v1.kdl"
    index_v1_path.write_text(
        "schema_version 1\n"
        + _pkg_block("qual", namespace="ns1", h1=qual_h1, h2=None)
        + _pkg_block("bare1", namespace=None, h1=bare1_h1, h2=None),
        encoding="utf-8",
    )
    index_v1v2_path = tmp_path / "index-v1v2.kdl"
    index_v1v2_path.write_text(
        "schema_version 1\n"
        + _pkg_block("qual", namespace="ns1", h1=qual_h1, h2=qual_h2)
        + _pkg_block("bare1", namespace=None, h1=bare1_h1, h2=None),
        encoding="utf-8",
    )

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
    monkeypatch.setenv("MILPA_CACHE_DIR", str(cache_dir))
    monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
    monkeypatch.delenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", raising=False)
    monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

    return mocked_dir, index_v1_path, index_v1v2_path


def _bootstrap(
    tmp_path: Path, mocked_dir: Path, index_v1_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """A fresh project directory, resolved once against the v1-only index —
    gitdep, ns1::qual@1.0.0, bare1@1.0.0."""
    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    (project_dir / "milpa.kdl").write_text(_ROOT_KDL, encoding="utf-8")
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1_path}")
    env = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0, "bootstrap fetch must succeed"
    lock = load_lockfile(project_dir / "milpa.lock")
    by_key = {(d.name, d.namespace): d.version for d in lock.deps}
    assert by_key == {
        ("gitdep", None): "0.0.0",
        ("qual", "ns1"): "1.0.0",
        ("bare1", None): "1.0.0",
    }, f"unexpected bootstrap lock contents: {by_key}"
    return project_dir


def _lock_keys(lock: Lockfile) -> set[tuple[str, str | None]]:
    return {(d.name, d.namespace) for d in lock.deps}


# ---------------------------------------------------------------------------
# add: new git dep added alongside the mixed set
# ---------------------------------------------------------------------------


def test_add_git_dep_preserves_mixed_lockfile(
    tmp_path: Path, _mixed_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    mocked_dir, index_v1_path, _index_v1v2_path = _mixed_setup
    project_dir = _bootstrap(tmp_path, mocked_dir, index_v1_path, monkeypatch)

    _make_git_mock(
        mocked_dir, "https://example.com/gitdep2.git", "main",
        sha="5" * 40, nim_name="gitdep2", marker="main",
    )
    env = _mocked_env(mocked_dir, project_dir / "cas")

    rc = cmd_add(
        project_dir,
        env,
        dep_name="gitdep2",
        git_url="https://example.com/gitdep2.git",
        mirror_url=None,
        ref="main",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    kdl_text = (project_dir / "milpa.kdl").read_text()
    assert "gitdep2" in kdl_text

    lock = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock) == {
        ("gitdep", None), ("gitdep2", None), ("qual", "ns1"), ("bare1", None),
    }
    # The pre-existing mixed deps are untouched (B2 minimal-change).
    versions = {(d.name, d.namespace): d.version for d in lock.deps}
    assert versions[("qual", "ns1")] == "1.0.0"
    assert versions[("bare1", None)] == "1.0.0"


# ---------------------------------------------------------------------------
# remove: qualified named dep removed via slash-shorthand
# ---------------------------------------------------------------------------


def test_remove_qualified_dep_from_mixed_project(
    tmp_path: Path, _mixed_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    mocked_dir, index_v1_path, _index_v1v2_path = _mixed_setup
    project_dir = _bootstrap(tmp_path, mocked_dir, index_v1_path, monkeypatch)
    env = _mocked_env(mocked_dir, project_dir / "cas")

    rc = cmd_remove(
        project_dir,
        env,
        dep_name="ns1/qual",  # slash-shorthand — exercises the fixed cli.py:4152-4182 path
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    kdl_text = (project_dir / "milpa.kdl").read_text()
    assert "qual" not in kdl_text

    lock = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock) == {("gitdep", None), ("bare1", None)}


def test_remove_bare_dep_from_mixed_project_keeps_qualified(
    tmp_path: Path, _mixed_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the BARE dep must not disturb the qualified dep's identity —
    the conflation bug (joined string vs. bare-name lockfile field) risked
    exactly this kind of cross-talk."""
    mocked_dir, index_v1_path, _index_v1v2_path = _mixed_setup
    project_dir = _bootstrap(tmp_path, mocked_dir, index_v1_path, monkeypatch)
    env = _mocked_env(mocked_dir, project_dir / "cas")

    rc = cmd_remove(
        project_dir,
        env,
        dep_name="bare1",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    lock = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock) == {("gitdep", None), ("qual", "ns1")}
    versions = {(d.name, d.namespace): d.version for d in lock.deps}
    assert versions[("qual", "ns1")] == "1.0.0"


# ---------------------------------------------------------------------------
# update: scoped update of the qualified dep moves its version
# ---------------------------------------------------------------------------


def test_update_scoped_qualified_dep_moves_version(
    tmp_path: Path, _mixed_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    mocked_dir, index_v1_path, index_v1v2_path = _mixed_setup
    project_dir = _bootstrap(tmp_path, mocked_dir, index_v1_path, monkeypatch)
    env = _mocked_env(mocked_dir, project_dir / "cas")

    # Newer version now available.
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2_path}")

    # The lockfile's own on-disk dep-arg for a qualified dep is the BARE name
    # (lockfile-schema.md §3.9 — never `::`-joined); `cmd_update`'s scoped
    # lookup is bare-name-keyed (`resolve_alias_to_canonical`/`strip_dep_pin`
    # both match on `LockedDep.name` alone), so the CLI arg is the bare name.
    rc = cmd_update(
        project_dir,
        env,
        dep_name="qual",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    lock = load_lockfile(project_dir / "milpa.lock")
    versions = {(d.name, d.namespace): d.version for d in lock.deps}
    assert versions[("qual", "ns1")] == "2.0.0", (
        f"scoped update must move qual to the newer version; got {versions}"
    )
    # bare1 stayed pinned (scoped update touches only the named dep).
    assert versions[("bare1", None)] == "1.0.0"
    assert versions[("gitdep", None)] == "0.0.0"


def test_update_all_resolves_mixed_project_green(
    tmp_path: Path, _mixed_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bare ``update`` (no arg) drops all pins and re-resolves the WHOLE
    mixed graph — the base case every scoped verb builds on."""
    mocked_dir, index_v1_path, _index_v1v2_path = _mixed_setup
    project_dir = _bootstrap(tmp_path, mocked_dir, index_v1_path, monkeypatch)
    env = _mocked_env(mocked_dir, project_dir / "cas")

    rc = cmd_update(
        project_dir,
        env,
        dep_name=None,
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0
    lock = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock) == {("gitdep", None), ("qual", "ns1"), ("bare1", None)}


# ---------------------------------------------------------------------------
# Focused regression: the alias-warning conflation bug itself
# ---------------------------------------------------------------------------


def test_remove_qualified_dep_alias_warning_not_conflated(tmp_path: Path) -> None:
    """DR-5 (Phase D item 5) for a NAMESPACE-QUALIFIED dep: before the S5b
    fix, `cmd_remove` computed the joined solver_var string ("ns1::bar") and
    compared it against `LockedDep.name` (bare "bar") — which never matches,
    so the alias-still-required/alias-removed warning silently never fired
    for a qualified dep with a recorded alias. Constructing the LockedDep
    directly (bypassing a full resolve) isolates exactly this comparison."""
    from milpa.lockfile import GitProvenanceRecord, LockedDep, write_lockfile

    primary_url = "https://example.com/bar.git"
    ref = "main"
    sha = "abcdef1234567890abcdef1234567890abcdef12"
    identity = "dag-sha256:a1e5adf673db945ef4fd8def4ab5e0c753c2c831323907fd894712d2c46c4ba3"

    (tmp_path / "milpa.kdl").write_text(
        'name "myapp"\nkind "application"\n'
        'deps {\n    bar namespace="ns1"\n}\n'
    )

    dep = LockedDep(
        name="bar",
        namespace="ns1",
        identity=identity,
        version="1.0.0",
        src_dir="",
        requires=(),
        provenances=(GitProvenanceRecord(url=primary_url, ref=ref, commit_sha=sha, origin="observed"),),
        aliases=("bar-alias",),
    )
    write_lockfile(Lockfile(deps=(dep,), strategy="maxver"), tmp_path / "milpa.lock")

    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    env = _mocked_env(mocked_dir, tmp_path / "cas")

    import sys
    from io import StringIO
    old_stderr = sys.stderr
    sys.stderr = StringIO()
    try:
        rc = cmd_remove(
            tmp_path,
            env,
            dep_name="ns1/bar",
            strategy=Strategy.MAXVER,
            max_parallel=4,
        )
    finally:
        stderr_out = sys.stderr.getvalue()
        sys.stderr = old_stderr

    assert rc == 0, f"remove of a qualified dep with an alias must succeed; stderr={stderr_out!r}"
    assert "bar-alias" in stderr_out, (
        f"expected the alias-removal warning to mention 'bar-alias' for a "
        f"qualified dep (the conflation bug swallowed this silently); "
        f"got stderr: {stderr_out!r}"
    )
    kdl_text = (tmp_path / "milpa.kdl").read_text()
    assert "bar" not in kdl_text
