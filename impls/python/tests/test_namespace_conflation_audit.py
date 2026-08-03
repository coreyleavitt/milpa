"""Namespace-conflation audit (P3/P4/P5): three verified findings, all in
``cli.py``, all pre-existing gaps in the earlier S5b namespace-conflation
audit (``test_s5b_mutation_verb_audit.py``) that only covered the
STANDALONE ``cmd_remove``/``cmd_update`` paths.

  P3 (High): ``_cmd_remove_from_member_dir`` matched by BARE ``d.name``, so
    ``milpa remove foo`` run from a workspace-member dir deleted BOTH
    ``foo namespace="ns1"`` and ``foo namespace="ns2"``. Fixed by making the
    member-dir path share ``cmd_remove``'s structured ``DepKey`` matching
    (``_resolve_remove_target``/``_dep_identity_key`` in ``cli.py``).

  P4 (High — SILENT DATA LOSS): ``resolve_alias_to_canonical`` /
    ``_strip_pins_for_upgrade`` / ``lockfile.strip_dep_pin`` matched only
    bare ``name``, so ``milpa update foo`` with two namespaced ``foo``
    locked deps silently deleted the sibling's entire lockfile entry (see
    the unit-level regression coverage already added to
    ``test_b4_upgrade.py::TestStripPinsForUpgrade`` and
    ``test_lockfile.py::TestStripDepPin`` for the mechanism itself). This
    file adds the end-to-end ``cmd_update`` proof against a real
    (mocked-git + file:// index) two-namespace resolve.

  P5 (Medium): ``_verify_dep_decl_pins`` used ``index.lookup_bare`` even for
    a namespace-qualified locked dep, so an ``AmbiguousName`` result (a
    DIFFERENT namespace publishing a same-bare-name package) was treated
    like not-found, producing a false ``LOCK-DEPDECL-PIN-MISSING``. Fixed by
    dispatching to ``index.lookup_qualified`` whenever ``dep.namespace`` is
    present.

No mocking of milpa's own logic for P3/P4: real mocked-git-fetches + a real
file:// tianguis index, same infra as ``test_b4_upgrade.py`` /
``test_s5b_mutation_verb_audit.py``. P5 constructs a real ``Index`` value
directly (registry.py's own dataclasses) since it only needs to exercise
``_verify_dep_decl_pins``'s dispatch, not a full resolve.
"""

from __future__ import annotations

import tempfile
import shutil
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import cmd_fetch, cmd_remove, cmd_update
from milpa.context import MilpaEnv
from milpa.errors import LOCK_DEPDECL_PIN_MISSING, MAN_REMOVE_DEP_ABSENT
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import LockedDep, load_lockfile
from milpa.registry import Index, IndexVersion, Package
from milpa.version import Strategy

# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_b4_upgrade.py / test_s5b_mutation_verb_audit.py)
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


def _mocked_env(mocked_dir: Path, tmp_store: Path) -> MilpaEnv:
    store = CAStore(root=tmp_store)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _lock_keys(lock) -> set[tuple[str, str | None]]:
    return {(d.name, d.namespace) for d in lock.deps}


@pytest.fixture()
def _two_namespace_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A real (mocked-git + file:// index) fixture with TWO packages that
    share the bare name "foo" under different namespaces ("ns1"/"ns2") —
    the exact shape both P3 and P4 need."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()

    _make_git_mock(
        mocked_dir, "https://example.com/foo-ns1.git", "v1.0.0",
        sha="1" * 40, nim_name="foo", marker="ns1",
    )
    _make_git_mock(
        mocked_dir, "https://example.com/foo-ns2.git", "v1.0.0",
        sha="2" * 40, nim_name="foo", marker="ns2",
    )
    h_ns1 = _content_hash_for(mocked_dir, "https://example.com/foo-ns1.git", "v1.0.0", "foo")
    h_ns2 = _content_hash_for(mocked_dir, "https://example.com/foo-ns2.git", "v1.0.0", "foo")

    def _pkg(namespace: str, url: str, commit_prefix: str, h: str) -> str:
        return f"""\
package "foo" {{
    namespace "{namespace}"
    version "1.0.0" {{
        content_hash "{h}"
        provenance {{
            kind "git"
            url "{url}"
            ref "v1.0.0"
            commit_sha "{commit_prefix * 40}"
        }}
    }}
}}
"""

    index_path = tmp_path / "index.kdl"
    index_path.write_text(
        "schema_version 1\n"
        + _pkg("ns1", "https://example.com/foo-ns1.git", "a", h_ns1)
        + _pkg("ns2", "https://example.com/foo-ns2.git", "b", h_ns2),
        encoding="utf-8",
    )

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
    monkeypatch.setenv("MILPA_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_path}")
    monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
    monkeypatch.delenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", raising=False)
    monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

    return mocked_dir


# ---------------------------------------------------------------------------
# P3: milpa remove <bare-name> from a workspace MEMBER dir must not conflate
# two same-bare-name deps in different namespaces.
# ---------------------------------------------------------------------------


def test_remove_bare_ambiguous_name_from_member_dir_errors_instead_of_deleting_both(
    tmp_path: Path, _two_namespace_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before the P3 fix: `_cmd_remove_from_member_dir` matched by bare
    `d.name`, so `milpa remove foo` (ambiguous — matches BOTH namespaces)
    would find `"foo"` in the bare-name existence set and delete BOTH
    `foo namespace="ns1"` and `foo namespace="ns2"` from the member's
    manifest and the shared lockfile. After the fix, a bare ambiguous name
    matches neither structured DepKey, so the pre-flight guard reports
    MAN-REMOVE-DEP-ABSENT and nothing is touched."""
    mocked_dir = _two_namespace_setup

    root = tmp_path / "ws"
    root.mkdir()
    root.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "member-a"\n}\nindex-trust "off"\n', encoding="utf-8"
    )
    member_a = root / "member-a"
    member_a.mkdir()
    member_a.joinpath("milpa.kdl").write_text(
        'name "liba"\nkind "library"\n'
        'deps {\n    foo namespace="ns1"\n    foo namespace="ns2"\n}\n',
        encoding="utf-8",
    )

    env = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_fetch(root, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    lock = load_lockfile(root / "milpa.lock")
    assert _lock_keys(lock) == {("foo", "ns1"), ("foo", "ns2"), ("liba", None)}

    env2 = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_remove(
        member_a,
        env2,
        dep_name="foo",  # bare, ambiguous — must NOT delete anything
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 1, "an ambiguous bare name must be refused, not silently resolved"

    # Both entries must survive completely untouched.
    lock_after = load_lockfile(root / "milpa.lock")
    assert _lock_keys(lock_after) == {("foo", "ns1"), ("foo", "ns2"), ("liba", None)}
    member_kdl_after = member_a.joinpath("milpa.kdl").read_text(encoding="utf-8")
    assert 'namespace="ns1"' in member_kdl_after
    assert 'namespace="ns2"' in member_kdl_after


def test_remove_qualified_name_from_member_dir_removes_only_that_namespace(
    tmp_path: Path, _two_namespace_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`milpa remove ns1/foo` from a member dir removes ONLY the ns1 entry;
    the ns2 sibling (same bare name) stays declared and locked."""
    mocked_dir = _two_namespace_setup

    root = tmp_path / "ws"
    root.mkdir()
    root.joinpath("milpa.kdl").write_text(
        'workspace {\n    member "member-a"\n}\nindex-trust "off"\n', encoding="utf-8"
    )
    member_a = root / "member-a"
    member_a.mkdir()
    member_a.joinpath("milpa.kdl").write_text(
        'name "liba"\nkind "library"\n'
        'deps {\n    foo namespace="ns1"\n    foo namespace="ns2"\n}\n',
        encoding="utf-8",
    )

    env = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_fetch(root, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0

    env2 = _mocked_env(mocked_dir, root / "cas")
    rc = cmd_remove(
        member_a,
        env2,
        dep_name="ns1/foo",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    lock_after = load_lockfile(root / "milpa.lock")
    assert _lock_keys(lock_after) == {("foo", "ns2"), ("liba", None)}
    member_kdl_after = member_a.joinpath("milpa.kdl").read_text(encoding="utf-8")
    assert 'namespace="ns1"' not in member_kdl_after
    assert 'namespace="ns2"' in member_kdl_after


# ---------------------------------------------------------------------------
# P4: milpa update <ns/name> must strip only that namespace's pin, and a
# bare ambiguous name must error rather than silently delete the sibling.
# ---------------------------------------------------------------------------


def test_update_qualified_name_strips_only_that_namespace_end_to_end(
    tmp_path: Path, _two_namespace_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`milpa update ns1/foo` re-resolves ns1's entry; ns2's entry (same
    bare name, different namespace) must survive bit-for-bit — this is the
    end-to-end proof of the fix behind test_b4_upgrade.py's unit coverage."""
    mocked_dir = _two_namespace_setup

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project_dir.joinpath("milpa.kdl").write_text(
        'name "myapp"\nkind "application"\nindex-trust "off"\n'
        'deps {\n    foo namespace="ns1"\n    foo namespace="ns2"\n}\n',
        encoding="utf-8",
    )

    env = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    lock_before = load_lockfile(project_dir / "milpa.lock")
    ns2_before = next(d for d in lock_before.deps if d.namespace == "ns2")
    assert _lock_keys(lock_before) == {("foo", "ns1"), ("foo", "ns2")}

    env2 = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_update(
        project_dir,
        env2,
        dep_name="ns1/foo",
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 0

    lock_after = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock_after) == {("foo", "ns1"), ("foo", "ns2")}, (
        "the ns2 sibling must NOT be deleted by a scoped update of ns1"
    )
    ns2_after = next(d for d in lock_after.deps if d.namespace == "ns2")
    assert ns2_after.identity == ns2_before.identity, (
        "ns2's entry must be completely untouched by `update ns1/foo`"
    )


def test_update_bare_ambiguous_name_errors_instead_of_deleting_sibling(
    tmp_path: Path, _two_namespace_setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`milpa update foo` (bare, ambiguous between ns1/ns2) must fail
    loudly rather than silently deleting one of the two locked entries —
    the exact SILENT DATA LOSS finding (P4)."""
    mocked_dir = _two_namespace_setup

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    project_dir.joinpath("milpa.kdl").write_text(
        'name "myapp"\nkind "application"\nindex-trust "off"\n'
        'deps {\n    foo namespace="ns1"\n    foo namespace="ns2"\n}\n',
        encoding="utf-8",
    )

    env = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    lock_before = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock_before) == {("foo", "ns1"), ("foo", "ns2")}

    env2 = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_update(
        project_dir,
        env2,
        dep_name="foo",  # bare, ambiguous
        strategy=Strategy.MAXVER,
        max_parallel=4,
    )
    assert rc == 1

    # Neither entry may have been touched/deleted.
    lock_after = load_lockfile(project_dir / "milpa.lock")
    assert _lock_keys(lock_after) == {("foo", "ns1"), ("foo", "ns2")}
    assert lock_after == lock_before


# ---------------------------------------------------------------------------
# P5: `verify`'s dep_decl pin check must use the namespace-qualified lookup
# for a namespaced locked dep, never `lookup_bare` (which returns
# AmbiguousName the moment a different namespace shares the bare name).
# ---------------------------------------------------------------------------


def test_verify_dep_decl_pins_namespaced_dep_not_conflated_by_bare_ambiguity_live(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same scenario as above, driving the REAL function (patching
    `load_default_index` + forcing the online branch), asserting rc == 0
    (no false PIN-MISSING) for the namespaced dep."""
    import milpa.cli as cli_mod

    matching_dep_decl = "sha256:" + "a" * 64
    other_dep_decl = "sha256:" + "b" * 64

    index = Index(
        packages=[
            Package(
                name="foo",
                namespace="ns1",
                versions=(
                    IndexVersion(version="1.0.0", dep_decl=matching_dep_decl),
                ),
            ),
            Package(
                name="foo",
                namespace="ns2",
                versions=(
                    IndexVersion(version="1.0.0", dep_decl=other_dep_decl),
                ),
            ),
        ]
    )
    monkeypatch.setattr(cli_mod, "load_default_index", lambda: index)
    monkeypatch.setenv("MILPA_INDEX_URL", "file:///dummy-index.kdl")

    pinned_dep = LockedDep(
        name="foo",
        namespace="ns1",
        identity="dag-sha256:" + "c" * 64,
        version="1.0.0",
        src_dir="",
        requires=(),
        provenances=(),
        dep_decl=matching_dep_decl,
    )

    env = MilpaEnv(fetcher=object(), index=None, store=object(), dep_decl_store=object())  # type: ignore[arg-type]

    rc = cli_mod._verify_dep_decl_pins([pinned_dep], env=env, strict=False)
    assert rc == 0, (
        "a namespace-qualified pin must verify OK even when a DIFFERENT "
        "namespace shares the bare name (must not false-positive PIN-MISSING)"
    )


def test_verify_dep_decl_pins_bare_dep_ambiguous_still_reports_pin_missing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Regression guard for the OTHER direction: an actually un-namespaced
    (bare) locked dep whose bare name IS ambiguous in the index must still
    report LOCK-DEPDECL-PIN-MISSING — the fix must not blanket-suppress the
    ambiguous-name-is-unresolvable case, only the namespaced-dep case."""
    import milpa.cli as cli_mod

    index = Index(
        packages=[
            Package(
                name="foo", namespace="ns1",
                versions=(IndexVersion(version="1.0.0", dep_decl="sha256:" + "a" * 64),),
            ),
            Package(
                name="foo", namespace="ns2",
                versions=(IndexVersion(version="1.0.0", dep_decl="sha256:" + "b" * 64),),
            ),
        ]
    )
    monkeypatch.setattr(cli_mod, "load_default_index", lambda: index)
    monkeypatch.setenv("MILPA_INDEX_URL", "file:///dummy-index.kdl")

    pinned_dep = LockedDep(
        name="foo",
        namespace=None,  # bare — genuinely ambiguous against this index
        identity="dag-sha256:" + "c" * 64,
        version="1.0.0",
        src_dir="",
        requires=(),
        provenances=(),
        dep_decl="sha256:" + "a" * 64,
    )
    env = MilpaEnv(fetcher=object(), index=None, store=object(), dep_decl_store=object())  # type: ignore[arg-type]

    rc = cli_mod._verify_dep_decl_pins([pinned_dep], env=env, strict=False)
    assert rc == 1
    out = capsys.readouterr()
    assert LOCK_DEPDECL_PIN_MISSING in out.err
