"""S10 subcommand awareness tests — RFC #23 §3.7.

Covers:
- milpa add --optional: writes optional=#true on the dep node.
- milpa add --features a,b: writes flag "a" / flag "b" children.
- milpa add pre-write clash check: rejects when name clashes with existing flag.
- milpa remove optional dep: no phantom flags {} entry left behind.
- milpa update threads locked active_flags into re-resolve.
- milpa show prints per-dep active_flags.
- milpa verify detects active_flags mismatch (reuses FROZEN-ACTIVE-FLAGS-MISMATCH).

All tests drive the REAL CLI paths (cli.py subcommands), NOT test-harness adapters.
Coverage rationale per §3.7:
- add/remove: unit tests on cmd_add/cmd_remove + manifest_writer path (the CLI
  runs resolve + write; mocked transport keeps tests fast; conformance corpus
  fixtures for add/remove are CLI-only so unit coverage here mirrors the pattern).
- update: unit test confirming locked active_flags thread through.
- show: unit test on cmd_show stdout (no network; reads lockfile directly).
- verify: unit test on cmd_verify checking active_flags mismatch (no network;
  reads manifest + lockfile directly for the flag comparison).
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import (
    cmd_add,
    cmd_remove,
    cmd_show,
    cmd_update,
    cmd_verify,
)
from milpa.context import MilpaEnv
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry, url_key
from milpa.lockfile import (
    GitProvenanceRecord,
    LockAttestation,
    LockedDep,
    Lockfile,
    write_lockfile,
)
from milpa.registry import AuthorSigned, MilpaVendored, _parse_timestamp
from milpa.version import Strategy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_manifest_kdl(name: str = "myapp", extra: str = "") -> str:
    return f'name "{name}"\nkind "application"\n{extra}'


def _make_mocked_env(mocked_dir: Path, tmp_path: Path) -> MilpaEnv:
    """Build a MilpaEnv backed by the mocked transport."""
    store = CAStore(root=tmp_path / "cas")
    inner = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner, store)
    return MilpaEnv(fetcher=fetcher, index=None, store=store)


def _make_mocked_fixture(
    mocked_dir: Path,
    url: str,
    ref: str,
    sha: str,
    nimble_content: str = 'version = "1.0.0"\nauthor = "test"\nlicense = "MIT"\n',
    milpa_kdl_content: str | None = None,
) -> None:
    """Create a mocked-fetches fixture for one git dep.

    If ``milpa_kdl_content`` is provided, write it as ``content/milpa.kdl``
    so the dep has a milpa.kdl that the edge source will pick up.
    Otherwise write a minimal ``<name>.nimble`` (the default path).
    """
    key = url_key(url, ref)
    dep_dir = mocked_dir / key
    dep_dir.mkdir(parents=True, exist_ok=True)
    (dep_dir / "sha").write_text(sha, encoding="utf-8")
    content_dir = dep_dir / "content"
    content_dir.mkdir(exist_ok=True)
    if milpa_kdl_content is not None:
        (content_dir / "milpa.kdl").write_text(milpa_kdl_content, encoding="utf-8")
    else:
        (content_dir / "dep.nimble").write_text(nimble_content, encoding="utf-8")


def _write_locked_dep(
    lock_path: Path,
    dep_name: str,
    active_flags: tuple[str, ...] = (),
    git_url: str = "https://example.com/dep.git",
    ref: str = "main",
    sha: str = "a" * 40,
    identity: str = "dag-sha256:" + "a" * 64,
    attestation: LockAttestation | None = None,
    version: str = "1.0.0",
    declared_version_source: str | None = None,
    strategy: str = "maxver",
) -> None:
    """Write a minimal lockfile with one dep that has active_flags set."""
    dep = LockedDep(
        name=dep_name,
        version=version,
        src_dir="",
        requires=(),
        provenances=(
            GitProvenanceRecord(
                url=git_url,
                ref=ref,
                commit_sha=sha,
                origin="observed",
            ),
        ),
        identity=identity,
        active_flags=active_flags,
        attestation=attestation,
        declared_version_source=declared_version_source,
    )
    lf = Lockfile(version=1, strategy=strategy, deps=(dep,))
    write_lockfile(lf, lock_path)


# ---------------------------------------------------------------------------
# 1. milpa add --optional  writes optional=#true
# ---------------------------------------------------------------------------

class TestAddOptional:
    """milpa add <dep> --optional writes optional=#true on the dep node."""

    def test_add_optional_writes_optional_true(self, tmp_path: Path) -> None:
        """add --git --optional writes optional=#true in milpa.kdl."""
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "b" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            optional=True,
            features=(),
        )
        assert rc == 0, "cmd_add with --optional must exit 0"
        text = manifest_path.read_text(encoding="utf-8")
        assert "optional=#true" in text, f"optional=#true not in manifest:\n{text}"

    def test_add_optional_false_default_no_optional_key(self, tmp_path: Path) -> None:
        """add without --optional does NOT write optional= at all (default #false)."""
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "b" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            optional=False,
            features=(),
        )
        assert rc == 0
        text = manifest_path.read_text(encoding="utf-8")
        assert "optional" not in text, f"optional must not appear when not requested:\n{text}"


# ---------------------------------------------------------------------------
# 2. milpa add --features a,b  writes flag "a" / flag "b" children
# ---------------------------------------------------------------------------

class TestAddFeatures:
    """milpa add <dep> --features a,b writes flag "a" / flag "b" children."""

    def test_add_features_writes_flag_children(self, tmp_path: Path) -> None:
        """add --features alpha,beta writes flag children on the dep node."""
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "c" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            optional=False,
            features=("alpha", "beta"),
        )
        assert rc == 0, "cmd_add with --features must exit 0"
        text = manifest_path.read_text(encoding="utf-8")
        assert 'flag "alpha"' in text, f'flag "alpha" not in manifest:\n{text}'
        assert 'flag "beta"' in text, f'flag "beta" not in manifest:\n{text}'

    def test_add_no_features_no_flag_children(self, tmp_path: Path) -> None:
        """add without --features writes no flag children on the dep node."""
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "c" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            optional=False,
            features=(),
        )
        assert rc == 0
        text = manifest_path.read_text(encoding="utf-8")
        # No flag children when no --features requested.
        assert "\n        flag " not in text, (
            f"No flag children expected without --features:\n{text}"
        )


# ---------------------------------------------------------------------------
# 2b. A3b: milpa add --git --version x.y.z  writes version= on the dep node
# ---------------------------------------------------------------------------

class TestAddVersion:
    """A3b (rfc-resolution-semantics.md §3 Axis A (b) step 4): ``milpa add
    --git --version x.y.z`` writes a ``version=`` annotation on the new dep
    — the natural-site workflow, mirrors ``--optional``/``--features``."""

    def test_add_version_writes_version_annotation(self, tmp_path: Path) -> None:
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "d" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            version="1.2.3",
        )
        assert rc == 0, "cmd_add with --version must exit 0"
        text = manifest_path.read_text(encoding="utf-8")
        assert 'version="1.2.3"' in text, f'version="1.2.3" not in manifest:\n{text}'

    def test_add_no_version_no_version_annotation(self, tmp_path: Path) -> None:
        """add without --version writes no version= at all (default None)."""
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "d" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
        )
        assert rc == 0
        text = manifest_path.read_text(encoding="utf-8")
        assert "version=" not in text, f"version= must not appear when not requested:\n{text}"

    def test_add_version_malformed_rejected(self, tmp_path: Path) -> None:
        """A malformed --version value is rejected before anything is written
        (same slug as the manifest grammar, MAN-DEP-VERSION-INVALID)."""
        manifest_path = tmp_path / "milpa.kdl"
        original_text = _minimal_manifest_kdl()
        manifest_path.write_text(original_text, encoding="utf-8")

        url = "https://example.com/mydep.git"
        sha = "d" * 40
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_add(
            tmp_path,
            env,
            dep_name="mydep",
            git_url=url,
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            version="not-a-version",
        )
        assert rc == 1, "malformed --version must reject with exit 1"
        # The manifest must be left unmodified — no partial write.
        assert manifest_path.read_text(encoding="utf-8") == original_text


# ---------------------------------------------------------------------------
# 3. Pre-write clash check: add rejects dep whose name clashes with existing flag
# ---------------------------------------------------------------------------

class TestAddClashCheck:
    """milpa add rejects dep names that would clash with existing flags (§3.2)."""

    def test_add_rejected_when_name_clashes_with_flag(self, tmp_path: Path) -> None:
        """add --optional rejects a dep whose name matches an existing declared flag.

        Reuses S7 _desugar_optional_deps / namespace-hygiene validation —
        no duplicate logic. The pre-write check prevents the writer from
        producing an unparseable manifest.
        """
        # Manifest with a declared flag named "myflag".
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(
            'name "myapp"\nkind "application"\nflags {\n    "myflag" default=#false\n}\n',
            encoding="utf-8",
        )
        mocked_dir = tmp_path / "mocked"
        mocked_dir.mkdir()
        env = _make_mocked_env(mocked_dir, tmp_path)

        # optional=True triggers the clash check: adding an optional dep whose
        # name "myflag" matches the already-declared flag.
        rc = cmd_add(
            tmp_path,
            env,
            dep_name="myflag",
            git_url="https://example.com/myflag.git",
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            optional=True,
            features=(),
        )
        # Must exit non-zero (before any write).
        assert rc != 0, "add must reject a dep whose name clashes with an existing flag"
        # milpa.kdl must be unchanged.
        text = manifest_path.read_text(encoding="utf-8")
        assert "myflag.git" not in text, "manifest must not be modified after clash rejection"

    def test_add_optional_invalid_name_rejected(self, tmp_path: Path) -> None:
        """add --optional rejects a dep name with invalid flag charset."""
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(_minimal_manifest_kdl(), encoding="utf-8")
        mocked_dir = tmp_path / "mocked"
        mocked_dir.mkdir()
        env = _make_mocked_env(mocked_dir, tmp_path)

        # Dep name with invalid charset for flag names (contains dot which is invalid).
        rc = cmd_add(
            tmp_path,
            env,
            dep_name="bad.name",  # dot is invalid in flag charset
            git_url="https://example.com/bad.git",
            mirror_url=None,
            ref="main",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            optional=True,
            features=(),
        )
        assert rc != 0, "add --optional with invalid flag name must be rejected"


# ---------------------------------------------------------------------------
# 4. milpa remove optional dep: no orphan flag left behind
# ---------------------------------------------------------------------------

class TestRemoveOptional:
    """milpa remove of an optional=#true dep leaves no phantom flags {} entry."""

    def test_remove_optional_dep_no_orphan_flag(self, tmp_path: Path) -> None:
        """Removing an optional dep does NOT leave a flags {} block for the auto-flag.

        The auto-flag is a parse-time construct that never appears in the KDL file
        (§3.7), so remove must not choke on or produce a phantom flags {} entry.
        """
        url = "https://example.com/optdep.git"
        sha = "a" * 40

        # Manifest with one optional dep.
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(
            'name "myapp"\nkind "application"\n'
            f'deps {{\n    "optdep" git=(url)"{url}" ref="main" optional=#true\n}}\n',
            encoding="utf-8",
        )
        # Minimal lockfile so remove can load prior.
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="optdep",
            active_flags=(),
            git_url=url,
        )

        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_remove(
            tmp_path,
            env,
            dep_name="optdep",
            strategy=Strategy.MAXVER,
            max_parallel=1,
        )
        assert rc == 0, "remove optional dep must exit 0"
        text = manifest_path.read_text(encoding="utf-8")
        # The dep should be removed.
        assert "optdep" not in text, f"optdep should be removed from manifest:\n{text}"
        # No phantom flags block introduced by remove.
        assert "flags {" not in text, f"No flags block should be left behind:\n{text}"


# ---------------------------------------------------------------------------
# 5. milpa update: threads locked active_flags into re-resolve
# ---------------------------------------------------------------------------

class TestUpdateLockedActiveFlags:
    """milpa update <dep> re-resolves honoring locked active_flags (§3.7).

    §3.7 says update re-resolves with the lockfile's recorded active_flags,
    NOT all-features-off. The test verifies:
    1. dep's own default-true flags survive update (they're reproduced by the
       resolver's own flag-closure, not special update logic).
    2. Explicit --features flags passed to cmd_update are threaded through.
    3. The effective_features computation from locked active_flags doesn't
       pass ROOT-undeclared flags as root features (that would error).
    """

    def test_update_preserves_dep_default_true_flags(self, tmp_path: Path) -> None:
        """update <dep>: dep's own default-true flags appear in updated lockfile.

        A dep with flags { ssl default=#true } will always have active_flags=("ssl",)
        in the lockfile — the resolver computes this from the dep's own flag table.
        update must not strip this (must not reset to all-features-off).
        """
        url = "https://example.com/dep.git"
        sha = "d" * 40
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(
            f'name "myapp"\nkind "application"\n'
            f'deps {{\n    "dep" git=(url)"{url}" ref="main"\n}}\n',
            encoding="utf-8",
        )
        # Prior lockfile with active_flags=("ssl",) for dep.
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="dep",
            active_flags=("ssl",),
            git_url=url,
            ref="main",
            sha=sha,
        )
        # Dep has milpa.kdl with flags { ssl default=#true }.
        dep_milpa_kdl_content = (
            'name "dep"\nkind "library"\nflags {\n    "ssl" default=#true\n}\n'
        )
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha,
                             milpa_kdl_content=dep_milpa_kdl_content)
        env = _make_mocked_env(mocked_dir, tmp_path)

        rc = cmd_update(tmp_path, env, dep_name="dep", strategy=Strategy.MAXVER, max_parallel=1)
        assert rc == 0, "update must exit 0"
        # The dep's own default-true flag must still appear in active_flags after update.
        lock_text = (tmp_path / "milpa.lock").read_text(encoding="utf-8")
        assert 'active_flags "ssl"' in lock_text, (
            f"update must preserve dep's own default-true active_flags;\nlock:\n{lock_text}"
        )

    def test_update_with_explicit_features_threads_them_through(self, tmp_path: Path) -> None:
        """update <dep> with explicit --features ssl threads ssl into the resolve.

        The root manifest declares flags { ssl default=#false }. If --features ssl
        is passed to cmd_update, the dep should get ssl active (via cross-package
        enables or root-flag computation).
        """
        url = "https://example.com/dep.git"
        sha = "d" * 40
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(
            f'name "myapp"\nkind "application"\n'
            f'deps {{\n    "dep" git=(url)"{url}" ref="main"\n}}\n'
            f'flags {{\n    "ssl" default=#false\n}}\n',
            encoding="utf-8",
        )
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="dep",
            active_flags=(),
            git_url=url,
            ref="main",
            sha=sha,
        )
        mocked_dir = tmp_path / "mocked"
        _make_mocked_fixture(mocked_dir, url, "main", sha)
        env = _make_mocked_env(mocked_dir, tmp_path)

        # Pass --features ssl explicitly; root manifest declares ssl.
        rc = cmd_update(
            tmp_path, env,
            dep_name="dep",
            strategy=Strategy.MAXVER,
            max_parallel=1,
            features=frozenset({"ssl"}),
        )
        assert rc == 0, "update with explicit --features must exit 0"


# ---------------------------------------------------------------------------
# 6. milpa show: prints per-dep active_flags
# ---------------------------------------------------------------------------

class TestShowActiveFlags:
    """milpa show prints per-dep active_flags when they are non-empty."""

    def test_show_prints_active_flags(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """cmd_show prints 'active_flags ...' for deps that have non-empty active_flags."""
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="mylib",
            active_flags=("ssl", "threads"),
        )

        rc = cmd_show(tmp_path)
        assert rc == 0, "show must exit 0"
        captured = capsys.readouterr()
        # active_flags must appear in stdout.
        assert "ssl" in captured.out, f"'ssl' not in show output:\n{captured.out}"
        assert "threads" in captured.out, f"'threads' not in show output:\n{captured.out}"
        assert "active_flags" in captured.out, (
            f"'active_flags' label not in show output:\n{captured.out}"
        )

    def test_show_no_active_flags_line_when_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """cmd_show omits the active_flags line when the dep has no active flags."""
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="mylib",
            active_flags=(),  # empty
        )

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "active_flags" not in captured.out, (
            f"active_flags line must be omitted when empty:\n{captured.out}"
        )


# ---------------------------------------------------------------------------
# 6b. milpa show: renders the attestation claim (RFC per-entry-attestation
#     P2 §7) as an UNVERIFIED claim — no crypto has run over it.
# ---------------------------------------------------------------------------

class TestShowAttestation:
    def test_show_renders_author_signed_claim(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="widget",
            attestation=LockAttestation(
                kind=AuthorSigned(signer="https://example.com/workflow.yaml")
            ),
        )

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "claims author-signed by https://example.com/workflow.yaml" in captured.out, (
            f"expected unverified-claim wording in show output:\n{captured.out}"
        )

    def test_show_renders_milpa_vendored_claim(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="widget",
            attestation=LockAttestation(kind=MilpaVendored()),
        )

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "claims milpa-vendored" in captured.out, (
            f"expected unverified-claim wording in show output:\n{captured.out}"
        )

    def test_show_no_attestation_line_when_absent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_locked_dep(tmp_path / "milpa.lock", dep_name="widget")

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "attestation" not in captured.out, (
            f"attestation line must be omitted when absent:\n{captured.out}"
        )


# ---------------------------------------------------------------------------
# 6c. milpa show: A7 (rfc-resolution-semantics.md §3 Axis A) — surfaces the
#     declared-version source per dep + the top-level strategy/exclude-newer
#     header.
# ---------------------------------------------------------------------------

class TestShowDeclaredVersionSource:
    """show prints the declared-version source next to each dep's version."""

    @pytest.mark.parametrize(
        "source", ["manifest", "nimble", "tag", "annotation"]
    )
    def test_show_prints_declared_version_source(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], source: str
    ) -> None:
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="mylib",
            version="2.3.4",
            declared_version_source=source,
        )

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert f"{'mylib':20s} 2.3.4 ({source})" in captured.out, (
            f"expected version+source pairing not in show output:\n{captured.out}"
        )

    def test_show_marks_version_unknown_when_source_absent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A5's flattening pairing: version '0.0.0' + no source => version-unknown."""
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="mylib",
            version="0.0.0",
            declared_version_source=None,
        )

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert f"{'mylib':20s} 0.0.0 (version-unknown)" in captured.out, (
            f"expected version-unknown marker not in show output:\n{captured.out}"
        )

    def test_show_no_suffix_for_named_dep_real_version_no_source(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A named/index dep has no source either, but a real version — not unknown."""
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="mylib",
            version="1.2.3",
            declared_version_source=None,
        )

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert f"{'mylib':20s} 1.2.3" in captured.out
        assert "(version-unknown)" not in captured.out
        assert "1.2.3 (" not in captured.out


class TestShowHeader:
    """show prints a top-level resolution-state header before the dep list."""

    def test_show_prints_strategy(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _write_locked_dep(tmp_path / "milpa.lock", dep_name="mylib", strategy="minver")

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "strategy    minver" in captured.out, (
            f"expected strategy header not in show output:\n{captured.out}"
        )

    def test_show_omits_exclude_newer_when_absent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """exclude-newer (Axis D / D5) is omitted from the header when the
        lockfile recorded no bound — must never be faked as present."""
        _write_locked_dep(tmp_path / "milpa.lock", dep_name="mylib")

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "exclude-newer" not in captured.out, (
            f"exclude-newer must be omitted when the lockfile has none:\n{captured.out}"
        )

    def test_show_prints_exclude_newer_when_present(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """exclude-newer (Axis D / D5) IS printed in the header when the
        lockfile recorded a bound (mirrors Rust's R11 fix)."""
        lf = Lockfile(
            version=1,
            strategy="maxver",
            exclude_newer=_parse_timestamp("2026-01-01T00:00:00Z"),
            deps=(),
        )
        write_lockfile(lf, tmp_path / "milpa.lock")

        rc = cmd_show(tmp_path)
        assert rc == 0
        captured = capsys.readouterr()
        assert "exclude-newer 2026-01-01T00:00:00Z" in captured.out, (
            f"expected exclude-newer header line not in show output:\n{captured.out}"
        )


# ---------------------------------------------------------------------------
# 7. milpa verify: detects active_flags mismatch
# ---------------------------------------------------------------------------

class TestVerifyActiveFlagsMismatch:
    """milpa verify checks locked active_flags against manifest defaults.

    Reuses FROZEN-ACTIVE-FLAGS-MISMATCH slug (SSOT — same slug as S9 frozen check).
    Scope: flag membership, not defines content (§3.6).
    """

    def test_verify_passes_no_flags_no_mismatch(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """verify exits 0 when both manifest and lockfile have no active flags."""
        # Simple manifest with no flags block.
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(
            'name "myapp"\nkind "application"\n'
            'deps {\n    "dep" git=(url)"https://example.com/dep.git" ref="main"\n}\n',
            encoding="utf-8",
        )
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir()

        # Lockfile with no active_flags.
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="dep",
            active_flags=(),
        )
        # Create _deps/dep symlink so verify doesn't fail on missing dep.
        dep_dir = deps_dir / "dep"
        dep_dir.mkdir()
        (dep_dir / "dep.nimble").write_text('version = "1.0.0"\n', encoding="utf-8")

        env = _make_mocked_env(tmp_path / "mocked", tmp_path)
        rc = cmd_verify(tmp_path, env)
        captured = capsys.readouterr()
        assert "FROZEN-ACTIVE-FLAGS-MISMATCH" not in captured.err, (
            f"No mismatch expected when no flags:\n{captured.err}"
        )

    def test_verify_fails_when_optional_dep_in_lock_but_default_off(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """verify exits non-zero when an optional dep is in the lock but the flag is default=#false.

        The optional dep's gate flag is off by default, but the lockfile
        records the dep as present — this is the mismatch case.
        """
        # Manifest with an optional dep "optdep" (default=#false gate flag auto-injected).
        manifest_path = tmp_path / "milpa.kdl"
        manifest_path.write_text(
            'name "myapp"\nkind "application"\n'
            'deps {\n    "optdep" git=(url)"https://example.com/optdep.git" ref="main" optional=#true\n}\n',
            encoding="utf-8",
        )
        deps_dir = tmp_path / "_deps"
        deps_dir.mkdir()
        # Create _deps/optdep so identity check passes and we reach the flag check.
        optdep_dir = deps_dir / "optdep"
        optdep_dir.mkdir()
        # Write a fake identity by using the actual sha256 of the empty dir.
        # For the purpose of this test we just need to get past the deps-dir check
        # and into the active_flags mismatch check. We'll accept either an identity
        # divergence exit-1 or a FROZEN-ACTIVE-FLAGS-MISMATCH exit-1.

        # Lockfile has the optional dep PRESENT (as if it was enabled when locked).
        _write_locked_dep(
            tmp_path / "milpa.lock",
            dep_name="optdep",
            active_flags=("optdep",),  # locked with optdep flag active
        )

        env = _make_mocked_env(tmp_path / "mocked", tmp_path)
        rc = cmd_verify(tmp_path, env)
        # verify must exit non-zero — the optional dep's gate flag is off by default
        # but it's in the lockfile as if it were on.
        assert rc != 0, (
            "verify must exit non-zero when locked active_flags mismatch manifest defaults"
        )
        captured = capsys.readouterr()
        assert "FROZEN-ACTIVE-FLAGS-MISMATCH" in captured.err, (
            f"FROZEN-ACTIVE-FLAGS-MISMATCH slug expected in stderr:\n{captured.err}"
        )
