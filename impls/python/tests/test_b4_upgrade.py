"""B4 (resolution-semantics RFC §3 Axis B / D-B3): ``--upgrade [<dep>...]``
on ``fetch``/``lock``, implemented as DELEGATION to the exact strip-pin
mechanism ``milpa update``/``milpa update <dep>`` already uses (the shared
``_strip_pins_for_upgrade`` helper in ``milpa.cli``), plus
``CLI-LOCKED-UPGRADE-CONFLICT``.

Scenarios:
  1. ``_strip_pins_for_upgrade`` unit tests (the shared mechanism itself).
  2. Bare ``--upgrade`` re-resolves newest-wins for the WHOLE graph (a dep
     with a newer available version moves off its locked version) — via
     direct ``cmd_fetch``/``cmd_lock`` calls against a real multi-version
     file:// index (B2's preference only ever bites a named/index dep).
  3. ``--upgrade <dep>`` moves ONLY that dep; an unrelated dep stays
     locked even though a newer version exists — contrasted with a plain
     re-fetch (upgrade absent), which keeps ALL deps locked.
  4. Delegation equivalence: ``--upgrade``/``--upgrade <dep>`` on
     ``fetch``/``lock`` produce the SAME resolved versions as
     ``update``/``update <dep>`` from the same starting lock — this is the
     D-B3 guarantee, asserted directly (not just "both happen to work").
  5. ``--locked`` + ``--upgrade`` together -> ``CLI-LOCKED-UPGRADE-CONFLICT``
     (via the real argparse/``main()`` layer, since the mutual-exclusion
     check lives in ``main()``'s dispatch, before any verb runs).
  6. ``--upgrade`` (like ``--locked``) bypasses the implicit frozen
     fast-path — otherwise it would be silently defeated on an
     already-in-sync project.

No mocking of milpa's own logic: real mocked-git-fetches + a real
in-memory/file:// tianguis index, same infra as
``test_b2_prior_lock_preference.py`` / ``test_cli_mutation.py``.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import (
    _strip_pins_for_upgrade,
    cmd_fetch,
    cmd_lock,
    cmd_update,
)
from milpa.context import MilpaEnv
from milpa.errors import (
    LOCK_DEP_AMBIGUOUS_NAME,
    LOCK_DEP_NOT_FOUND,
    LOCK_FILE_NOT_FOUND,
    MilpaError,
)
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.identity import compute_content_hash
from milpa.lockfile import Lockfile, LockedDep, load_lockfile
from milpa.version import Strategy

# ---------------------------------------------------------------------------
# Part 1 — _strip_pins_for_upgrade unit tests (the shared mechanism itself)
# ---------------------------------------------------------------------------


def _lock_with(names_versions: dict[str, str]) -> Lockfile:
    deps = tuple(
        LockedDep(
            name=name,
            namespace=None,
            identity=f"sha256:{'0' * 63}{i}",
            version=version,
            src_dir="",
            requires=(),
            provenances=(),
            active_flags=(),
            aliases=(f"{name}-alias",),
        )
        for i, (name, version) in enumerate(names_versions.items())
    )
    return Lockfile(version=1, strategy="maxver", deps=deps)


def _lock_with_ns(entries: "list[tuple[str, str | None, str]]") -> Lockfile:
    """Build a Lockfile from ``(name, namespace, version)`` triples — for
    exercising namespace-qualified matching (P4, namespace-conflation audit)."""
    deps = tuple(
        LockedDep(
            name=name,
            namespace=namespace,
            identity=f"sha256:{'0' * 63}{i}",
            version=version,
            src_dir="",
            requires=(),
            provenances=(),
            active_flags=(),
        )
        for i, (name, namespace, version) in enumerate(entries)
    )
    return Lockfile(version=1, strategy="maxver", deps=deps)


class TestStripPinsForUpgrade:
    """Pure unit tests for the ONE shared helper both `update` and
    `--upgrade` delegate to (D-B3)."""

    def test_empty_dep_names_drops_all_pins(self) -> None:
        prior = _lock_with({"foo": "1.0.0", "bar": "2.0.0"})
        assert _strip_pins_for_upgrade(prior, ()) is None

    def test_empty_dep_names_with_no_prior_still_none(self) -> None:
        # Bare upgrade/update never needs a prior lock to exist at all.
        assert _strip_pins_for_upgrade(None, ()) is None

    def test_named_strips_only_that_dep(self) -> None:
        prior = _lock_with({"foo": "1.0.0", "bar": "2.0.0"})
        result = _strip_pins_for_upgrade(prior, ("foo",))
        assert result is not None
        foo = next(d for d in result.deps if d.name == "foo")
        bar = next(d for d in result.deps if d.name == "bar")
        assert foo.identity is None  # pin stripped
        assert bar.identity == prior.deps[1].identity  # untouched

    def test_multiple_names_strip_each_in_sequence(self) -> None:
        prior = _lock_with({"foo": "1.0.0", "bar": "2.0.0", "baz": "3.0.0"})
        result = _strip_pins_for_upgrade(prior, ("foo", "bar"))
        assert result is not None
        by_name = {d.name: d for d in result.deps}
        assert by_name["foo"].identity is None
        assert by_name["bar"].identity is None
        assert by_name["baz"].identity == prior.deps[2].identity

    def test_alias_resolves_to_canonical(self) -> None:
        prior = _lock_with({"foo": "1.0.0"})
        result = _strip_pins_for_upgrade(prior, ("foo-alias",))
        assert result is not None
        assert result.deps[0].identity is None

    def test_named_with_no_prior_raises_lock_file_not_found(self) -> None:
        with pytest.raises(MilpaError) as exc_info:
            _strip_pins_for_upgrade(None, ("foo",))
        assert exc_info.value.slug == LOCK_FILE_NOT_FOUND

    def test_named_not_in_lock_raises_lock_dep_not_found(self) -> None:
        prior = _lock_with({"foo": "1.0.0"})
        with pytest.raises(MilpaError) as exc_info:
            _strip_pins_for_upgrade(prior, ("nonexistent",))
        assert exc_info.value.slug == LOCK_DEP_NOT_FOUND

    # -----------------------------------------------------------------
    # P4 (namespace-conflation audit, SILENT DATA LOSS finding): a bare
    # name matching locked deps in 2+ distinct namespaces used to resolve
    # via `resolve_alias_to_canonical`/`strip_dep_pin` matching on bare
    # `name` alone — `update foo` would strip ONE namespaced dep's pin
    # and, because `strip_dep_pin` rebuilt `new_deps` with a
    # `d.name != canonical_name` filter, SILENTLY DELETE the sibling's
    # entire lockfile entry. These pin the fixed, namespace-aware
    # behavior: a `ns/name` ref strips only that one entry and leaves
    # every same-bare-name sibling in another namespace fully intact.
    # -----------------------------------------------------------------

    def test_qualified_ref_strips_only_that_namespace_preserves_sibling(self) -> None:
        prior = _lock_with_ns(
            [("foo", "ns1", "1.0.0"), ("foo", "ns2", "1.0.0")]
        )
        ns2_before = next(d for d in prior.deps if d.namespace == "ns2")

        result = _strip_pins_for_upgrade(prior, ("ns1/foo",))

        assert result is not None
        assert len(result.deps) == 2, "the ns2 sibling must not be deleted"
        ns1_after = next(d for d in result.deps if d.namespace == "ns1")
        ns2_after = next(d for d in result.deps if d.namespace == "ns2")
        assert ns1_after.identity is None, "ns1's pin was stripped"
        assert ns2_after == ns2_before, "ns2's entry must be completely untouched"
        assert ns2_after.identity is not None, "ns2 must keep its own pin"

    def test_bare_name_ambiguous_across_namespaces_raises(self) -> None:
        """A BARE name (no `ns/` prefix) that matches 2+ distinct
        namespaces must raise LOCK_DEP_AMBIGUOUS_NAME rather than
        silently picking one and deleting the other."""
        prior = _lock_with_ns(
            [("foo", "ns1", "1.0.0"), ("foo", "ns2", "1.0.0")]
        )
        with pytest.raises(MilpaError) as exc_info:
            _strip_pins_for_upgrade(prior, ("foo",))
        assert exc_info.value.slug == LOCK_DEP_AMBIGUOUS_NAME
        # Neither entry may have been mutated — the function must raise
        # BEFORE performing any strip.
        assert prior.deps[0].identity is not None
        assert prior.deps[1].identity is not None

    def test_qualified_ref_not_found_raises_lock_dep_not_found(self) -> None:
        prior = _lock_with_ns([("foo", "ns1", "1.0.0")])
        with pytest.raises(MilpaError) as exc_info:
            _strip_pins_for_upgrade(prior, ("ns2/foo",))
        assert exc_info.value.slug == LOCK_DEP_NOT_FOUND

    def test_bare_name_unambiguous_when_only_one_namespace_present(self) -> None:
        """A bare name that matches exactly ONE locked dep (even if that
        dep IS namespaced) is unambiguous — no error, exactly like an
        un-namespaced dep."""
        prior = _lock_with_ns(
            [("foo", "ns1", "1.0.0"), ("bar", None, "2.0.0")]
        )
        result = _strip_pins_for_upgrade(prior, ("foo",))
        assert result is not None
        foo = next(d for d in result.deps if d.name == "foo")
        bar = next(d for d in result.deps if d.name == "bar")
        assert foo.identity is None
        assert bar.identity is not None


# ---------------------------------------------------------------------------
# Part 2 — real multi-version resolution behaviors, via direct cmd_* calls
# against a real file:// index (mirrors test_b2_prior_lock_preference.py's
# staging + test_cli_mutation.py's file:// index CLI pattern — cmd_fetch/
# cmd_update always reload the index from MILPA_INDEX_URL, discarding
# whatever MilpaEnv.index the caller constructed, so a real file:// index is
# required even for a "direct call", not just a full main(argv) run).
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


_ROOT_KDL = (
    'name "myapp"\nkind "application"\nindex-trust "off"\n'
    "deps {\n    foo\n    bar\n}\n"
)


def _mocked_env(mocked_dir: Path, tmp_store: Path) -> MilpaEnv:
    store = CAStore(root=tmp_store)
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


@pytest.fixture()
def _upgrade_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Two named deps (foo, bar), each with real v1.0.0/v2.0.0 mocked git
    content. Returns (mocked_dir, index_v1_path, index_v1v2_path)."""
    mocked_dir = tmp_path / "mocked-fetches"
    mocked_dir.mkdir()
    foo_hashes = _stage_two_versions(mocked_dir, "foo", sha_prefix="1")
    bar_hashes = _stage_two_versions(mocked_dir, "bar", sha_prefix="2")
    hashes = {"foo": foo_hashes, "bar": bar_hashes}

    index_v1_path = tmp_path / "index-v1.kdl"
    index_v1_path.write_text(_index_kdl(hashes, include_v2=False), encoding="utf-8")
    index_v1v2_path = tmp_path / "index-v1v2.kdl"
    index_v1v2_path.write_text(_index_kdl(hashes, include_v2=True), encoding="utf-8")

    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache_dir))
    monkeypatch.setenv("MILPA_CACHE_DIR", str(cache_dir))
    monkeypatch.delenv("MILPA_INDEX_TRUST", raising=False)
    monkeypatch.delenv("MILPA_INDEX_TRUST_MOCK_VERIFIER", raising=False)
    monkeypatch.delenv("MILPA_INDEX_HISTORY", raising=False)

    return mocked_dir, index_v1_path, index_v1v2_path


def _versions(lock: Lockfile) -> dict[str, str]:
    return {d.name: d.version for d in lock.deps}


def _make_locked_project(
    tmp_path: Path, name: str, mocked_dir: Path, index_v1_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """A fresh project directory, resolved once against the v1-only index
    (so both foo/bar lock to 1.0.0 — the only candidate at that point)."""
    project_dir = tmp_path / name
    project_dir.mkdir()
    (project_dir / "milpa.kdl").write_text(_ROOT_KDL, encoding="utf-8")
    monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1_path}")
    env = _mocked_env(mocked_dir, project_dir / "cas")
    rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
    assert rc == 0
    lock = load_lockfile(project_dir / "milpa.lock")
    assert _versions(lock) == {"foo": "1.0.0", "bar": "1.0.0"}
    return project_dir


class TestBareUpgradeMovesWholeGraph:
    def test_bare_upgrade_pulls_newest_everywhere(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _upgrade_setup
    ) -> None:
        mocked_dir, index_v1_path, index_v1v2_path = _upgrade_setup
        project_dir = _make_locked_project(
            tmp_path, "proj", mocked_dir, index_v1_path, monkeypatch
        )

        # A newer version got published (index now carries 1.0.0 AND 2.0.0).
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2_path}")

        # Plain re-fetch (no --upgrade): minimal-change keeps both locked.
        env = _mocked_env(mocked_dir, project_dir / "cas")
        rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
        assert rc == 0
        assert _versions(load_lockfile(project_dir / "milpa.lock")) == {
            "foo": "1.0.0",
            "bar": "1.0.0",
        }

        # Bare --upgrade: opts out GLOBALLY -> both move to the newest.
        rc = cmd_fetch(
            project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False, upgrade=()
        )
        assert rc == 0
        assert _versions(load_lockfile(project_dir / "milpa.lock")) == {
            "foo": "2.0.0",
            "bar": "2.0.0",
        }


class TestScopedUpgradeMovesOnlyNamedDep:
    def test_upgrade_one_dep_leaves_the_other_locked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _upgrade_setup
    ) -> None:
        mocked_dir, index_v1_path, index_v1v2_path = _upgrade_setup
        project_dir = _make_locked_project(
            tmp_path, "proj", mocked_dir, index_v1_path, monkeypatch
        )
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2_path}")
        env = _mocked_env(mocked_dir, project_dir / "cas")

        rc = cmd_fetch(
            project_dir,
            env,
            strategy=Strategy.MAXVER,
            max_parallel=4,
            frozen=False,
            upgrade=("foo",),
        )
        assert rc == 0
        versions = _versions(load_lockfile(project_dir / "milpa.lock"))
        assert versions["foo"] == "2.0.0"  # opted out -> newest
        assert versions["bar"] == "1.0.0"  # untouched -> stays locked


class TestUpgradeDelegationEquivalence:
    """The D-B3 guarantee: --upgrade on fetch/lock produces the SAME
    resolved versions as update/update <dep> from the same starting lock —
    asserted directly, both bare and scoped, on both fetch and lock."""

    def _two_identical_locked_projects(
        self, tmp_path: Path, mocked_dir: Path, index_v1_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[Path, Path]:
        a = _make_locked_project(tmp_path, "a", mocked_dir, index_v1_path, monkeypatch)
        b = _make_locked_project(tmp_path, "b", mocked_dir, index_v1_path, monkeypatch)
        return a, b

    def test_bare_upgrade_equals_bare_update(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _upgrade_setup
    ) -> None:
        mocked_dir, index_v1_path, index_v1v2_path = _upgrade_setup
        proj_a, proj_b = self._two_identical_locked_projects(
            tmp_path, mocked_dir, index_v1_path, monkeypatch
        )
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2_path}")

        env_a = _mocked_env(mocked_dir, proj_a / "cas")
        rc = cmd_fetch(
            proj_a, env_a, strategy=Strategy.MAXVER, max_parallel=4, frozen=False, upgrade=()
        )
        assert rc == 0

        env_b = _mocked_env(mocked_dir, proj_b / "cas")
        rc = cmd_update(proj_b, env_b, dep_name=None, strategy=Strategy.MAXVER, max_parallel=4)
        assert rc == 0

        lock_a = load_lockfile(proj_a / "milpa.lock")
        lock_b = load_lockfile(proj_b / "milpa.lock")
        assert _versions(lock_a) == _versions(lock_b) == {"foo": "2.0.0", "bar": "2.0.0"}
        assert {d.name: d.identity for d in lock_a.deps} == {
            d.name: d.identity for d in lock_b.deps
        }

    def test_scoped_upgrade_equals_scoped_update(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _upgrade_setup
    ) -> None:
        mocked_dir, index_v1_path, index_v1v2_path = _upgrade_setup
        proj_a, proj_b = self._two_identical_locked_projects(
            tmp_path, mocked_dir, index_v1_path, monkeypatch
        )
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2_path}")

        env_a = _mocked_env(mocked_dir, proj_a / "cas")
        rc = cmd_fetch(
            proj_a,
            env_a,
            strategy=Strategy.MAXVER,
            max_parallel=4,
            frozen=False,
            upgrade=("foo",),
        )
        assert rc == 0

        env_b = _mocked_env(mocked_dir, proj_b / "cas")
        rc = cmd_update(proj_b, env_b, dep_name="foo", strategy=Strategy.MAXVER, max_parallel=4)
        assert rc == 0

        lock_a = load_lockfile(proj_a / "milpa.lock")
        lock_b = load_lockfile(proj_b / "milpa.lock")
        assert _versions(lock_a) == _versions(lock_b) == {"foo": "2.0.0", "bar": "1.0.0"}
        assert {d.name: d.identity for d in lock_a.deps} == {
            d.name: d.identity for d in lock_b.deps
        }

    def test_upgrade_on_lock_verb_equals_update(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _upgrade_setup
    ) -> None:
        """Same equivalence, but via the `lock` verb (not just `fetch`) —
        `cmd_lock` shares the same upgrade-threading shape."""
        mocked_dir, index_v1_path, index_v1v2_path = _upgrade_setup
        proj_a, proj_b = self._two_identical_locked_projects(
            tmp_path, mocked_dir, index_v1_path, monkeypatch
        )
        monkeypatch.setenv("MILPA_INDEX_URL", f"file://{index_v1v2_path}")

        env_a = _mocked_env(mocked_dir, proj_a / "cas")
        rc = cmd_lock(proj_a, env_a, strategy=Strategy.MAXVER, max_parallel=4, upgrade=("bar",))
        assert rc == 0

        env_b = _mocked_env(mocked_dir, proj_b / "cas")
        rc = cmd_update(proj_b, env_b, dep_name="bar", strategy=Strategy.MAXVER, max_parallel=4)
        assert rc == 0

        lock_a = load_lockfile(proj_a / "milpa.lock")
        lock_b = load_lockfile(proj_b / "milpa.lock")
        assert _versions(lock_a) == _versions(lock_b) == {"foo": "1.0.0", "bar": "2.0.0"}


# ---------------------------------------------------------------------------
# Part 3 — CLI-LOCKED-UPGRADE-CONFLICT, via the real main() dispatch (the
# mutual-exclusion check lives there, before any verb runs — no manifest
# or fetch infra needed at all).
# ---------------------------------------------------------------------------


def _run_main(argv: list[str]) -> tuple[int, str]:
    from milpa.cli import main

    old_env = os.environ.copy()
    try:
        os.environ["MILPA_INDEX_URL"] = ""  # no-index; irrelevant, check fires first
        err = io.StringIO()
        import contextlib

        with contextlib.redirect_stderr(err):
            rc = main(argv)
        return rc, err.getvalue()
    finally:
        os.environ.clear()
        os.environ.update(old_env)


class TestCliLockedUpgradeConflict:
    def test_fetch_locked_and_bare_upgrade_conflict(self, tmp_path: Path) -> None:
        rc, err = _run_main(["-C", str(tmp_path), "fetch", "--locked", "--upgrade"])
        assert rc == 1
        assert "milpa-error: CLI-LOCKED-UPGRADE-CONFLICT" in err

    def test_fetch_locked_and_scoped_upgrade_conflict(self, tmp_path: Path) -> None:
        rc, err = _run_main(["-C", str(tmp_path), "fetch", "--locked", "--upgrade", "foo"])
        assert rc == 1
        assert "milpa-error: CLI-LOCKED-UPGRADE-CONFLICT" in err

    def test_lock_locked_and_upgrade_conflict(self, tmp_path: Path) -> None:
        rc, err = _run_main(["-C", str(tmp_path), "lock", "--locked", "--upgrade"])
        assert rc == 1
        assert "milpa-error: CLI-LOCKED-UPGRADE-CONFLICT" in err


# ---------------------------------------------------------------------------
# Part 4 — --upgrade bypasses the implicit frozen fast-path (mirrors B3's
# equivalent proof for --locked): otherwise an up-to-date project would
# silently take the no-solve reconstruction path and --upgrade would have
# zero effect.
# ---------------------------------------------------------------------------


def _make_single_version_git_mock(mocked_dir: Path, ref: str) -> None:
    _make_git_mock(
        mocked_dir,
        "https://example.com/foo.git",
        ref,
        sha="a" * 40,
        nim_name="foo",
        marker=ref,
    )


class TestUpgradeBypassesFrozenFastPath:
    def test_bare_fetch_takes_frozen_path_but_upgrade_does_not(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mocked_dir = tmp_path / "mocked-fetches"
        mocked_dir.mkdir()
        _make_single_version_git_mock(mocked_dir, "v1.0.0")
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        (project_dir / "milpa.kdl").write_text(
            'name "myapp"\nkind "application"\n'
            'deps {\n    foo git=(url)"https://example.com/foo.git" ref="v1.0.0"\n}\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("MILPA_INDEX_URL", "")
        env = _mocked_env(mocked_dir, project_dir / "cas")

        rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
        assert rc == 0
        capsys.readouterr()  # discard first-run output

        # Second bare fetch: CAS + lock both present -> silent frozen fast-path.
        rc = cmd_fetch(project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False)
        assert rc == 0
        out = capsys.readouterr()
        assert "(frozen)" in out.err

        # fetch --upgrade: MUST NOT take the frozen fast-path even though
        # nothing else changed — otherwise --upgrade would have no effect.
        rc = cmd_fetch(
            project_dir, env, strategy=Strategy.MAXVER, max_parallel=4, frozen=False, upgrade=()
        )
        assert rc == 0
        out = capsys.readouterr()
        assert "(frozen)" not in out.err
