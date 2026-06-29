"""In-process conformance adapter — spec/conformance-fixtures.md §4.4.

Drives the shared ``conformance/spec-v1/`` corpus in-process (mirrors the Rust
runner in ``impls/rust/crates/milpa-conformance/``).  This is slice 9a-pre.

Design
------
The adapter is the **machinery** slice, not a "fixture green" slice.  At this
stage ``resolve`` and ``resolve_frozen`` raise ``NotImplementedError``, so
success-class resolve/frozen fixtures cannot pass yet.  They are collected but
parked as ``xfail`` (expected failure) so the suite stays GREEN while reporting
the expected failure mode rather than silently skipping them.

Architecture
------------
1. **Fixture discovery**: walk ``conformance/spec-v1/fixture-*/`` (two-level
   ``spec-v*/fixture-*`` scan — mirrors the Rust ``discover`` function).

2. **parents[N] corpus-path assertion (RED test)**: the path to ``conformance/``
   is computed via ``Path(__file__).parents[N]`` where N is derived from the
   test file's position relative to the repo root.  The test ASSERTS the
   resolved path is non-empty.  A wrong depth → 0 fixtures → vacuous green;
   the non-empty assertion is the RED guard.

3. **Dispatch**: per-fixture ``cmd`` selector:
   - absent / ``resolve`` → single-package or workspace resolve (live path)
   - ``frozen``           → single-package or workspace frozen path
   - ``parse-lockfile``   → parse-only (lockfile parse boundary)
   - ``add``/``remove``/``update``/``show``/``--version`` → CLI-only (skip)

4. **MilpaEnv construction**: ``mocked_registry(mocked_dir)`` wrapped in
   ``CasAdmittingFetcher``, a tmp ``CAStore``, and a per-fixture ``ResolveParams``
   + ``Profile`` (from the fixture's optional ``env`` file — no live
   ``nim --version``).

5. **Parking mechanism**: resolve-path and frozen-path fixtures that are not
   yet green (because the resolver raises ``NotImplementedError``) are marked
   ``xfail``.  Once a resolver slice lands, those fixtures move to
   ``expected_pass`` and the ``xfail`` decorator is dropped.  The list of
   parked fixtures is maintained here; an ``xfail`` that unexpectedly passes
   causes a test failure (strict mode).

   The partition mirrors the Rust ``known_failing.txt`` policy:
   - ``NOT_YET_WIRED``: resolver not yet implemented (9b+/9d/9e);
     marked xfail(strict=False) — they'll green when resolver lands.
   - ``CLI_ONLY_SKIPPED``: mutation/liveness verb fixtures; marked skip
     (not xfail — they are the black-box CLI harness's responsibility, not
     an in-process-adapter concern).

Spec authority: spec/conformance-fixtures.md, RFC §4.4/§4.5.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Literal

import pytest

# ---------------------------------------------------------------------------
# Harness imports — stdlib-only; no milpa import at module level.
# The harness package lives at the repo root (parents[3] from this test file).
# ---------------------------------------------------------------------------
_REPO_ROOT_FOR_HARNESS = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT_FOR_HARNESS) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_FOR_HARNESS))

from harness.assertions import (  # noqa: E402
    apply_lock_placeholders,
    compare_certificate_json,
    normalize_deps_structure,
)
from harness.inputs import (  # noqa: E402
    env_flag,
    parse_cli_features,
    read_env_file,
    resolve_project_dir,
)

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import SOLVE_CONFLICT, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.local import LocalFetcher
from milpa.fetchers.mocked import (
    MockedGitFetcher,
    MockedOciFetcher,
    MockedTarballFetcher,
    mocked_registry,
)
from milpa.fetchers.types import FetcherRegistry
from milpa.lockfile import Lockfile, parse_lockfile
from milpa.manifest import (
    Manifest,
    WorkspaceManifest,
    parse_workspace_or_manifest,
)
from milpa.profile import Profile
from milpa.resolver import resolve, resolve_workspace
from milpa.solver import SolverError, certificate_to_json
from milpa.version import Strategy
from milpa.workspace import load_workspace

# ---------------------------------------------------------------------------
# Corpus path — parents[N] depth assertion
# ---------------------------------------------------------------------------

# This test file lives at:
#   impls/python/tests/test_conformance.py
# parents[0] = impls/python/tests/
# parents[1] = impls/python/
# parents[2] = impls/
# parents[3] = <repo_root>/
# The corpus lives at <repo_root>/conformance/
_THIS_FILE = Path(__file__)
_REPO_ROOT = _THIS_FILE.parents[3]  # 3 levels up from this test file
_CORPUS_ROOT = _REPO_ROOT / "conformance"


# ---------------------------------------------------------------------------
# Fixture descriptor
# ---------------------------------------------------------------------------

# CLI-only verb selectors: handled exclusively by the black-box CLI harness.
# clean (S11c): workspace clean exercises filesystem-state post-cmd; the
# in-process Target does not model _deps/ / nim.cfg removal.
_CLI_ONLY_VERBS = frozenset({"add", "remove", "update", "show", "--version", "workspace", "clean"})

# CLI-level filesystem-discovery guard fixtures: these error codes are raised by
# the CLI's file-discovery layer (load_or_discover_manifest, frozen lockfile guard)
# before any resolver logic runs.  The in-process adapter always reads milpa.kdl
# directly from the fixture dir — it cannot model "no milpa.kdl found" or "no
# milpa.lock found" without the CLI's filesystem-scanning entry points.
# Covered by the black-box CLI harness for all three impls; skipped here.
_CLI_DISCOVERY_GUARD_NAMES: frozenset[str] = frozenset({
    # MAN-NO-MANIFEST: fixture has no milpa.kdl; CLI's load_or_discover_manifest
    # raises MAN-NO-MANIFEST; the in-process adapter returns E2E-MANIFEST-UNREADABLE.
    "fixture-153-man-no-manifest",
    # MAN-NIMBLE-AMBIGUOUS: fixture has two *.nimble files, no milpa.kdl;
    # CLI's load_or_discover_manifest raises MAN-NIMBLE-AMBIGUOUS; adapter returns
    # E2E-MANIFEST-UNREADABLE on the missing milpa.kdl.
    "fixture-154-man-nimble-ambiguous",
    # FROZEN-NO-LOCKFILE: cmd:frozen but no milpa.lock; CLI guard checks existence
    # before calling resolve_frozen; the in-process adapter returns E2E-LOCKFILE-UNREADABLE.
    "fixture-156-frozen-no-lockfile",
    # (fixture-288 un-parked: the adapter is now project-dir-aware (§2.8.1), so it
    # loads the workspace from <fixture>/workspace-root and raises
    # WS-MEMBER-PATH-ESCAPE like the CLI — rfc-conformance-parity Slice 3.)
})


class FixtureCmd(str):
    """The resolved command selector from the fixture's ``cmd`` file."""
    ...


class Fixture:
    """A discovered conformance fixture."""

    def __init__(self, fixture_id: str, fixture_dir: Path) -> None:
        self.id = fixture_id          # e.g. "spec-v1/fixture-003-single-url-dep"
        self.dir = fixture_dir        # absolute path to the fixture directory
        # Parse the cmd file once; derive both self.cmd and self.no_index from
        # the same text (L6: avoid reading the file twice).
        cmd_file = fixture_dir / "cmd"
        if cmd_file.exists():
            _cmd_text = cmd_file.read_text(encoding="utf-8")
        else:
            _cmd_text = ""
        self.cmd: str = self._parse_cmd(_cmd_text)
        self.no_index: bool = "--no-index" in _cmd_text.split()
        self.expected_error: str | None = self._read_expected_error()

    @staticmethod
    def _parse_cmd(text: str) -> str:
        """Derive the cmd selector from the raw cmd file text (or empty string).

        The first whitespace-separated token is the selector; absent or
        ``resolve`` → ``"resolve"``.
        """
        stripped = text.strip()
        head = stripped.split()[0] if stripped else ""
        if not head or head == "resolve":
            return "resolve"
        return head

    def _read_expected_error(self) -> str | None:
        error_file = self.dir / "expected" / "error"
        if not error_file.exists():
            return None
        return error_file.read_text(encoding="utf-8").strip()

    @property
    def is_success(self) -> bool:
        return self.expected_error is None

    @property
    def is_cli_only(self) -> bool:
        return self.cmd in _CLI_ONLY_VERBS

    def __repr__(self) -> str:
        return f"Fixture({self.id!r}, cmd={self.cmd!r})"


# ---------------------------------------------------------------------------
# Fixture discovery (mirrors Rust discover() in fixture.rs)
# ---------------------------------------------------------------------------


def _discover_fixtures(corpus_root: Path) -> list[Fixture]:
    """Discover every spec-v<N>/fixture-* directory under ``corpus_root``.

    Sorted for deterministic ordering.  Non-matching entries are ignored.
    """
    fixtures: list[Fixture] = []
    if not corpus_root.is_dir():
        return fixtures

    # Two-level scan: spec-v* group dirs, then fixture-* dirs within each.
    group_dirs = sorted(
        p for p in corpus_root.iterdir()
        if p.is_dir() and p.name.startswith("spec-v")
    )
    for group in group_dirs:
        fixture_dirs = sorted(
            p for p in group.iterdir()
            if p.is_dir() and p.name.startswith("fixture-")
        )
        for fixture_dir in fixture_dirs:
            fixture_id = f"{group.name}/{fixture_dir.name}"
            fixtures.append(Fixture(fixture_id, fixture_dir))

    return fixtures


# ---------------------------------------------------------------------------
# Profile construction from fixture env file (conformance-fixtures.md §2.8)
# ---------------------------------------------------------------------------


_PROFILE_TARGET_KEYS = frozenset(
    {
        "MILPA_TARGET_PLATFORM",
        "MILPA_TARGET_ARCH",
        "MILPA_TARGET_NIM",
        "MILPA_TARGET_MILPA",
    }
)


def _fixture_profile(fixture_dir: Path) -> Profile | None:
    """Build a ``Profile`` from the fixture's optional ``env`` file.

    Returns ``None`` when no ``MILPA_TARGET_*`` axis is present — even if
    an ``env`` file exists for other keys such as ``MILPA_CLI_FEATURES``.
    This mirrors the Rust runner's ``fixture_profile`` (runner.rs ~861-885):
    an absent profile means predicate filtering is disabled (resolver-semantics
    §470); host-defaulting belongs to the CLI, not the host-independent corpus
    runner.
    """
    env_vars = read_env_file(fixture_dir)
    if not env_vars:
        return None

    # Mirror the Rust runner: return None when no MILPA_TARGET_* axis is set.
    # An env file carrying only MILPA_CLI_FEATURES (or other non-target keys)
    # must yield None so that resolver-semantics §470 "absent profile ⇒
    # platform filtering disabled" is exercised, not a host-defaulted Profile.
    if not _PROFILE_TARGET_KEYS.intersection(env_vars):
        return None

    # Use Profile.partial(...) so that only axes explicitly set in the fixture's
    # env file are non-None.  This mirrors the Rust runner (runner.rs:891-914)
    # which builds Profile { platform: Option<String>, … } directly from the env
    # vars — missing axes remain None (partial profile semantics, §3.C).
    # Profile.from_environment() must NOT be used here because it host-defaults
    # every absent axis, making partial-profile fixtures host-dependent.
    return Profile.partial(
        platform=env_vars.get("MILPA_TARGET_PLATFORM") or None,
        arch=env_vars.get("MILPA_TARGET_ARCH") or None,
        nim=env_vars.get("MILPA_TARGET_NIM") or None,
        milpa=env_vars.get("MILPA_TARGET_MILPA") or None,
    )


def _fixture_require_attested_metadata(fixture_dir: Path) -> bool:
    """Return True when MILPA_REQUIRE_ATTESTED_METADATA is set in the fixture env file.

    Mirrors the Rust runner's fixture_require_attested_metadata() function.
    Delegates to ``read_env_file`` (the canonical env-file parser from
    harness/inputs.py) and ``env_flag`` (the canonical boolean-flag interpreter).
    """
    env = read_env_file(fixture_dir)
    return env_flag(env, "MILPA_REQUIRE_ATTESTED_METADATA")


def _fixture_cli_features(fixture_dir: Path) -> frozenset[str]:
    """Return the ``--features`` flag set from the fixture env file.

    Reads ``MILPA_CLI_FEATURES`` (comma-separated flag names).
    S9: mirrors CLI's _parse_features(args.features).

    Delegates to ``parse_cli_features`` from harness/inputs.py —
    the SINGLE DEFINITION of fixture feature-flag semantics (M1 unification).
    """
    return parse_cli_features(read_env_file(fixture_dir))


def _fixture_no_default_features(fixture_dir: Path) -> bool:
    """Return True when MILPA_NO_DEFAULT_FEATURES is set in the fixture env file.

    S9: mirrors CLI's --no-default-features.
    Delegates to ``env_flag`` from harness/inputs.py (M1 unification).
    """
    return env_flag(read_env_file(fixture_dir), "MILPA_NO_DEFAULT_FEATURES")


def _fixture_all_features(fixture_dir: Path) -> bool:
    """Return True when MILPA_ALL_FEATURES is set in the fixture env file.

    S9: mirrors CLI's --all-features.
    Delegates to ``env_flag`` from harness/inputs.py (M1 unification).
    """
    return env_flag(read_env_file(fixture_dir), "MILPA_ALL_FEATURES")


# ---------------------------------------------------------------------------
# MilpaEnv construction for in-process conformance
# ---------------------------------------------------------------------------


def _build_env(fixture_dir: Path, tmp_dir: Path, no_index: bool = False) -> MilpaEnv:
    """Build a ``MilpaEnv`` for the fixture's in-process run.

    Uses ``mocked_registry(mocked_dir)`` wrapped in ``CasAdmittingFetcher``,
    plus a fixture-local ``CAStore`` rooted at ``tmp_dir/.cas``.

    The ``index`` field is loaded from ``fixture_dir/index.kdl`` when present
    (required for named-dep fixtures, slice 9b-3a+).  ``None`` when absent
    (URL-only and error fixtures do not need an index).

    ``no_index`` mirrors the CLI ``--no-index`` flag (cli-contract §2.6): when
    set, the index and dep_decl_store are suppressed (``None``) even if
    ``index.kdl`` is present — the flag overrides a configured index.
    """
    from milpa.registry import parse_index

    cas_root = tmp_dir / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)

    # Build a FetcherRegistry with the REAL LocalFetcher (not mocked).
    # Local deps are filesystem-native — the fixture already contains the source
    # tree on disk, and the real LocalFetcher symlinks to it without any network.
    # Git and tarball transports are mocked via mocked-fetches/ for hermeticity.
    mocked_dir = fixture_dir / "mocked-fetches"
    inner_registry = FetcherRegistry()
    inner_registry.register(MockedGitFetcher(mocked_dir))
    inner_registry.register(MockedTarballFetcher(mocked_dir))
    inner_registry.register(LocalFetcher())
    inner_registry.register(MockedOciFetcher(mocked_dir))
    fetcher = CasAdmittingFetcher(inner_registry, store)

    index_path = fixture_dir / "index.kdl"
    index = None
    if not no_index and index_path.exists():
        # Let MilpaError propagate — TNG-* parse errors from index.kdl must
        # surface as the fixture's expected error (not be swallowed).
        # Non-MilpaError exceptions (e.g. KDL syntax error not yet typed)
        # are still silently ignored so the adapter stays robust for
        # structurally-invalid KDL (which would produce MAN-KDL-SYNTAX anyway).
        try:
            index = parse_index(index_path.read_text(encoding="utf-8"))
        except MilpaError:
            raise
        except Exception:
            index = None

    # S3b: when the fixture ships a ``dep-decl/`` artifact dir, build a
    # ``FileDepDeclStore`` over it — the in-process mirror of the harness
    # injecting ``MILPA_DEP_DECL_DIR`` (S3a, conformance-fixtures.md §2.11).
    # Delegates to ``dep_decl_store_from_paths`` — the SINGLE priority definition
    # shared with the CLI (H1 unification: one function, two call sites).
    from milpa.dep_decl_store import dep_decl_store_from_paths

    dep_decl_dir = fixture_dir / "dep-decl"
    index_path_for_decl = fixture_dir / "index.kdl"
    # Derive the index URL for the dep-decl store: file:// when index.kdl exists,
    # None when absent (dep_decl_store_from_paths → None in that branch).
    index_url_for_decl = (
        f"file://{index_path_for_decl.resolve()}"
        if index_path_for_decl.exists()
        else None
    )
    dep_decl_store = dep_decl_store_from_paths(
        dep_decl_dir=dep_decl_dir if dep_decl_dir.is_dir() else None,
        index_url=index_url_for_decl,
        no_index=no_index,
    )

    return MilpaEnv(
        fetcher=fetcher,
        index=index,
        store=store,
        dep_decl_store=dep_decl_store,
        no_index=no_index,
    )


# ---------------------------------------------------------------------------
# Prior lockfile loading (conformance-fixtures.md §2.9)
# ---------------------------------------------------------------------------


def _load_prior_lockfile(fixture_dir: Path) -> Lockfile | None:
    """Load the fixture's ``milpa.lock`` as a prior (§8 pin reuse input).

    Returns ``None`` when absent or unparseable — a soft preference, not a
    hard requirement (resolver-semantics.md §8).
    """
    lock_path = fixture_dir / "milpa.lock"
    if not lock_path.exists():
        return None
    try:
        return parse_lockfile(lock_path.read_text(encoding="utf-8"))
    except (MilpaError, Exception):
        return None


# ---------------------------------------------------------------------------
# Certificate JSON comparison (cli-contract.md §2.5 / conformance-fixtures §2.7.3)
# ---------------------------------------------------------------------------
# compare_certificate_json is imported from harness.assertions at the top of
# this module (H2 unification).  The single definition lives there; using it
# here prevents the in-process adapter and the black-box harness from drifting.


# ---------------------------------------------------------------------------
# H-infra: git-protocol fixture tier
# ---------------------------------------------------------------------------
# H-infra builds local bare repos at test time, runs the REAL GitFetcher against
# file:// URLs, and asserts content_hash matches expected/content_hash.
# This is a distinct tier from the static corpus (MockedGitFetcher, no git
# invocations) and from MILPA_INTEGRATION_TESTS=1 (real network): it uses real
# git against generated repos with no network access.
#
# Fixture schema (git-protocol.json):
#   {
#     "repos": [
#       {
#         "name": "<repo-name>",
#         "files": {"<relpath>": "<content>", ...},
#         "ref": "<branch-name>"
#       }
#     ],
#     "fetch": {
#       "dep_name": "<dep-name>",
#       "repo_name": "<repo-name to clone from>",
#       "ref": "<ref to fetch>",
#       "commit_sha": null | "<40-hex-sha>"
#     }
#   }
#
# The runner generates each repo under a tempdir, runs the REAL GitFetcher
# (GitProvenance → GitFetcher.fetch()), and asserts:
#   compute_content_hash(dest) == expected/content_hash (stripped)
#
# Determinism: content_hash is over the materialized source tree (file relpaths
# + bytes), NOT git pack objects.  Same declared file content committed by both
# impls → identical hash across git versions and impls.
#
# Auto-inserted files by git (COMMIT_EDITMSG, index, pack files) live under
# .git/ and are excluded by identity.md §1.4 — they cannot pollute the hash.


def _make_git_protocol_repo(
    tmpdir: Path,
    repo_spec: dict,  # type: ignore[type-arg]
) -> tuple[Path, list]:  # type: ignore[type-arg]
    """Build a local git repo from a git-protocol.json repo spec.

    Returns ``(repo_path, [commit_sha_0, commit_sha_1, ...])``.

    Two forms are supported:

    *Single-commit form* (backward-compat): ``repo_spec["files"]`` is a
    ``{relpath: content}`` mapping.  One commit is produced; the returned list
    has one element.

    *Multi-commit form* (H4): ``repo_spec["commits"]`` is a list of
    ``{"files": {relpath: content}}`` dicts applied sequentially.  Each dict
    is committed on top of the previous; files not mentioned in a later commit
    survive (no auto-deletion).  The returned list has one SHA per commit in
    oldest-first order.

    *Symlinks* (H3d): ``repo_spec["symlinks"]`` is a ``{link_path: target}``
    mapping of filesystem symlinks to commit alongside ``files``.  Symlinks are
    created on disk before ``git add`` so git picks them up as mode-120000
    blobs (committed symlinks), exactly as the H3b/H3c invariant tests do.
    The ``target`` value is the raw link-target string (may be relative or
    absolute, safe or escaping — the generator commits whatever the fixture
    declares; containment-checking is the fetcher's job, not the generator's).

    git user identity is overridden via ``-c`` flags (the fixture repo is
    disposable and not constrained by the global config policy).
    """
    import os as _os

    name = repo_spec["name"]
    ref = repo_spec.get("ref", "main")

    repo_dir = tmpdir / name
    repo_dir.mkdir(parents=True, exist_ok=True)

    def _git(args: list) -> None:  # type: ignore[type-arg]
        result = subprocess.run(
            ["git", "-C", str(repo_dir),
             "-c", "user.email=milpa-hinfra@test.milpa",
             "-c", "user.name=Milpa H-infra",
             "-c", "core.autocrlf=false",
             ] + args,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git {args[0]!r} failed in {repo_dir}:\n"
                f"  stdout: {result.stdout.strip()}\n"
                f"  stderr: {result.stderr.strip()}"
            )

    def _head_sha() -> str:
        return subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    # init — without -c user.* (git init ignores them cleanly in some versions)
    subprocess.run(
        ["git", "-C", str(repo_dir), "init", "-b", ref, "-q"],
        capture_output=True, check=True,
    )

    # Normalise to a list of commit specs regardless of form.
    if "commits" in repo_spec:
        # Multi-commit form: list of {"files": {...}} dicts.
        commit_specs: list = repo_spec["commits"]
    else:
        # Single-commit (backward-compat): wrap the top-level "files" dict.
        # The top-level "symlinks" map, if present, goes into this single commit.
        commit_specs = [{"files": repo_spec.get("files", {}), "symlinks": repo_spec.get("symlinks", {})}]

    commit_shas: list = []
    for i, commit_spec in enumerate(commit_specs):
        files: dict = commit_spec.get("files", {})
        for relpath, content in files.items():
            target = repo_dir / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        # H3d: symlinks support — create on-disk symlinks so git commits them
        # as mode-120000 blobs.  The target string is committed verbatim
        # (escaping or safe — containment is the fetcher's responsibility).
        symlinks: dict = commit_spec.get("symlinks", {})
        for link_path, link_target in symlinks.items():
            link_on_disk = repo_dir / link_path
            link_on_disk.parent.mkdir(parents=True, exist_ok=True)
            # Remove stale symlink/file if present (idempotent re-generation).
            if link_on_disk.exists() or link_on_disk.is_symlink():
                link_on_disk.unlink()
            _os.symlink(link_target, link_on_disk)
        _git(["add", "."])
        msg = f"H-infra commit {i}" if i > 0 else "H-infra initial commit"
        _git(["commit", "-q", "-m", msg])
        commit_shas.append(_head_sha())

    # Optional: create an orphan tip commit and force-reset the branch to it.
    # This simulates a force-push that makes earlier commits unreachable from
    # any ref — so a ``git clone`` of this repo will NOT fetch those commits.
    # Used by H4 to produce a non-tip commit that is absent after a plain clone,
    # exposing the Rust FETCH-GIT-COMMIT-ABSENT bug before the 4-step fix.
    orphan_tip: dict | None = repo_spec.get("orphan_tip")
    if orphan_tip is not None:
        # Create an orphan branch, commit the orphan files, then force-reset
        # the target ref to that orphan commit so it becomes the branch tip.
        orphan_branch = "__milpa_hinfra_orphan__"
        _git(["checkout", "--orphan", orphan_branch])
        _git(["rm", "-rf", "."])
        orphan_files: dict = orphan_tip.get("files", {})
        for relpath, content in orphan_files.items():
            target = repo_dir / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        _git(["add", "."])
        _git(["commit", "-q", "-m", "H-infra orphan tip (simulates force-push)"])
        orphan_sha = _head_sha()
        # Force-reset the target ref to the orphan commit
        _git(["branch", "-f", ref, orphan_sha])
        # Return to a detached HEAD so `git clone` clones the ref correctly
        _git(["checkout", "--detach", "HEAD"])

    return repo_dir, commit_shas


def _execute_git_protocol_fixture(
    fixture: "Fixture",
    tmp_dir: Path,
) -> tuple[Literal["pass", "fail", "skip"], str]:
    """Execute a git-protocol fixture end-to-end using the REAL GitFetcher.

    H-infra flow:
    1. Parse ``git-protocol.json``.
    2. Generate each declared repo under a tempdir via ``_make_git_protocol_repo``.
    3. Build a ``file://`` URL for the target repo.
    4. Invoke the REAL ``GitFetcher`` (not MockedGitFetcher) via ``FetcherRegistry``.
    5. Compare ``compute_content_hash(dest)`` to ``expected/content_hash``.

    The content_hash assertion is the proof that H-infra exercises the REAL
    fetcher against a REAL git repo: MockedGitFetcher stages bytes verbatim
    without any git invocation, so it could never fail this assertion for
    transport-dependent reasons (object-store vs smudge divergence, submodule
    omission, etc.).
    """
    from milpa.fetchers.git import GitFetcher, GitProvenance
    from milpa.fetchers.types import FetcherRegistry
    from milpa.identity import compute_content_hash

    fixture_dir = fixture.dir
    spec_path = fixture_dir / "git-protocol.json"
    try:
        spec_text = spec_path.read_text(encoding="utf-8")
    except OSError as e:
        return ("fail", f"git-protocol.json missing or unreadable: {e}")
    try:
        spec = json.loads(spec_text)
    except json.JSONDecodeError as e:
        return ("fail", f"git-protocol.json parse error: {e}")

    # Read expected outcome: either a content_hash (success) or an error slug.
    # Error-class fixtures (expected/error file) assert the fetcher raises the
    # named slug; success-class fixtures assert content_hash matches.
    expected_error_path = fixture_dir / "expected" / "error"
    expected_hash_path = fixture_dir / "expected" / "content_hash"
    expected_error: str | None = None
    expected_hash: str = ""
    if expected_error_path.exists():
        expected_error = expected_error_path.read_text(encoding="utf-8").strip()
    else:
        try:
            expected_hash = expected_hash_path.read_text(encoding="utf-8").strip()
        except OSError as e:
            return ("fail", f"expected/content_hash missing or unreadable: {e}")

    repos_spec: list = spec.get("repos", [])
    fetch_spec: dict = spec.get("fetch", {})

    # Generate repos in a sub-tempdir (separate from tmp_dir for clarity)
    repos_tmpdir = tmp_dir / "git-repos"
    repos_tmpdir.mkdir(parents=True, exist_ok=True)

    repo_paths: dict = {}
    repo_commit_shas: dict = {}  # name -> [sha_0, sha_1, ...]
    try:
        for repo_spec in repos_spec:
            repo_dir, commit_shas = _make_git_protocol_repo(repos_tmpdir, repo_spec)
            repo_paths[repo_spec["name"]] = repo_dir
            repo_commit_shas[repo_spec["name"]] = commit_shas
    except RuntimeError as e:
        return ("fail", f"git repo generation failed: {e}")

    # Resolve the target repo
    repo_name = fetch_spec.get("repo_name", "")
    if repo_name not in repo_paths:
        return ("fail", f"fetch.repo_name {repo_name!r} not found in repos")

    target_repo = repo_paths[repo_name]
    # Use file:// URL so GitFetcher exercises the real git clone protocol path
    file_url = f"file://{target_repo.resolve()}"
    dep_name = fetch_spec.get("dep_name", "smoke")
    ref = fetch_spec.get("ref", "main")
    commit_sha = fetch_spec.get("commit_sha")  # may be None or "@repo:<n>:commit:<i>"

    # H4: resolve "@repo:<name>:commit:<index>" references to the actual SHA
    # captured during repo generation.  This is the mechanism that lets a fixture
    # pin a non-tip commit without knowing its SHA statically.
    if isinstance(commit_sha, str) and commit_sha.startswith("@repo:"):
        parts = commit_sha.split(":")
        # Expected format: @repo:<repo_name>:commit:<index>
        if len(parts) == 4 and parts[2] == "commit":
            ref_repo_name = parts[1]
            try:
                commit_index = int(parts[3])
            except ValueError:
                return ("fail", f"commit SHA reference {commit_sha!r}: index must be an integer")
            sha_list = repo_commit_shas.get(ref_repo_name)
            if sha_list is None:
                return ("fail", f"commit SHA reference {commit_sha!r}: repo {ref_repo_name!r} not found")
            if commit_index < 0 or commit_index >= len(sha_list):
                return ("fail", f"commit SHA reference {commit_sha!r}: index {commit_index} out of range (repo has {len(sha_list)} commits)")
            commit_sha = sha_list[commit_index]
        else:
            return ("fail", f"commit SHA reference {commit_sha!r}: expected format @repo:<name>:commit:<index>")

    dest = tmp_dir / "_deps" / dep_name
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Run the REAL GitFetcher.
    # H3d: error-class fixtures (EXTRACT-SYMLINK-ESCAPE, FETCH-GIT-LFS-POINTER)
    # expect the fetcher to raise a MilpaError with the declared slug.
    from milpa.errors import MilpaError as _MilpaError

    registry = FetcherRegistry()
    registry.register(GitFetcher())
    try:
        result = registry.fetch(
            dep_name,
            GitProvenance(url=file_url, ref=ref, commit_sha=commit_sha),
            dest=dest,
        )
    except _MilpaError as e:
        if expected_error is not None:
            if e.slug == expected_error:
                return ("pass", "")
            else:
                return ("fail", f"expected error {expected_error!r}, got {e.slug!r}: {e}")
        return ("fail", f"GitFetcher.fetch raised unexpected error {e.slug!r}: {e}")
    except Exception as e:
        if expected_error is not None:
            return ("fail", f"expected error {expected_error!r}, got unexpected exception: {e}")
        return ("fail", f"GitFetcher.fetch failed: {e}")

    # Fetcher succeeded — if we expected an error, that's a failure.
    if expected_error is not None:
        return ("fail", f"expected error {expected_error!r} but GitFetcher.fetch succeeded")

    # Compute content_hash of the materialized tree
    try:
        got_hash = compute_content_hash(dest)
    except Exception as e:
        return ("fail", f"compute_content_hash failed: {e}")

    if got_hash != expected_hash:
        return (
            "fail",
            f"content_hash mismatch:\n"
            f"  expected: {expected_hash}\n"
            f"  actual:   {got_hash}\n"
            f"  (GitFetcher used file:// URL: {file_url!r})",
        )

    return ("pass", "")


# ---------------------------------------------------------------------------
# H-infra: hash fixture tier (cmd=hash)
# ---------------------------------------------------------------------------
# The ``hash`` fixture type exercises the A0 ``milpa hash`` subcommand path:
#
#   parse_source_spec(tokens) → Provenance
#   → env.fetcher.inner.fetch() → FetchResult
#   → print(result.identity)
#
# Fixture schema: ``git-protocol.json`` (same as the git-protocol tier) for
# repo setup; ``expected/stdout`` carries the expected stdout line
# (``sha256:<64hex>`` for git/tarball sources, empty for local/editable).
#
# The runner asserts ``result.identity`` (set by the REAL GitFetcher) matches
# ``expected/stdout``, which is exactly what ``cmd_hash`` prints.  Calling
# ``result.identity`` directly (rather than capturing ``print()``) avoids
# stdout-redirect complexity while still pinning the same value.


def _execute_hash_fixture(
    fixture: "Fixture",
    tmp_dir: Path,
) -> tuple[Literal["pass", "fail", "skip"], str]:
    """Execute a ``hash`` fixture by running the REAL GitFetcher and checking identity.

    Mirrors the ``milpa hash`` A0-cmd path: fetch via the inner registry (no
    CAS admission), then assert ``result.identity`` matches ``expected/stdout``.
    """
    from milpa.fetchers.git import GitFetcher, GitProvenance
    from milpa.fetchers.types import FetcherRegistry

    fixture_dir = fixture.dir
    spec_path = fixture_dir / "git-protocol.json"
    try:
        spec_text = spec_path.read_text(encoding="utf-8")
    except OSError as e:
        return ("fail", f"git-protocol.json missing or unreadable: {e}")
    try:
        spec = json.loads(spec_text)
    except json.JSONDecodeError as e:
        return ("fail", f"git-protocol.json parse error: {e}")

    # Read expected stdout (the sha256 identity line or empty for local sources).
    expected_stdout_path = fixture_dir / "expected" / "stdout"
    try:
        expected_stdout = expected_stdout_path.read_text(encoding="utf-8").strip()
    except OSError as e:
        return ("fail", f"expected/stdout missing or unreadable: {e}")

    repos_spec: list = spec.get("repos", [])
    fetch_spec: dict = spec.get("fetch", {})

    # Generate repos in a sub-tempdir (reuses _make_git_protocol_repo infrastructure)
    repos_tmpdir = tmp_dir / "git-repos"
    repos_tmpdir.mkdir(parents=True, exist_ok=True)

    repo_paths: dict = {}
    repo_commit_shas: dict = {}
    try:
        for repo_spec in repos_spec:
            repo_dir, commit_shas = _make_git_protocol_repo(repos_tmpdir, repo_spec)
            repo_paths[repo_spec["name"]] = repo_dir
            repo_commit_shas[repo_spec["name"]] = commit_shas
    except RuntimeError as e:
        return ("fail", f"git repo generation failed: {e}")

    repo_name = fetch_spec.get("repo_name", "")
    if repo_name not in repo_paths:
        return ("fail", f"fetch.repo_name {repo_name!r} not found in repos")

    target_repo = repo_paths[repo_name]
    file_url = f"file://{target_repo.resolve()}"
    dep_name = fetch_spec.get("dep_name", "smoke")
    ref = fetch_spec.get("ref", "main")
    commit_sha = fetch_spec.get("commit_sha")

    # Resolve "@repo:<name>:commit:<index>" references (H4, same as git-protocol tier)
    if isinstance(commit_sha, str) and commit_sha.startswith("@repo:"):
        parts = commit_sha.split(":")
        if len(parts) == 4 and parts[2] == "commit":
            ref_repo_name = parts[1]
            try:
                commit_index = int(parts[3])
            except ValueError:
                return ("fail", f"commit SHA reference {commit_sha!r}: index must be an integer")
            sha_list = repo_commit_shas.get(ref_repo_name)
            if sha_list is None:
                return ("fail", f"commit SHA reference {commit_sha!r}: repo {ref_repo_name!r} not found")
            if commit_index < 0 or commit_index >= len(sha_list):
                return ("fail", f"commit SHA reference {commit_sha!r}: index {commit_index} out of range")
            commit_sha = sha_list[commit_index]
        else:
            return ("fail", f"commit SHA reference {commit_sha!r}: expected format @repo:<name>:commit:<index>")

    dest = tmp_dir / "_deps" / dep_name
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Fetch via the REAL GitFetcher (no CAS admission — mirrors cmd_hash's
    # env.fetcher.inner.fetch() call).
    from milpa.errors import MilpaError as _MilpaError

    registry = FetcherRegistry()
    registry.register(GitFetcher())
    try:
        result = registry.fetch(
            dep_name,
            GitProvenance(url=file_url, ref=ref, commit_sha=commit_sha),
            dest=dest,
        )
    except _MilpaError as e:
        return ("fail", f"GitFetcher.fetch raised unexpected error {e.slug!r}: {e}")
    except Exception as e:
        return ("fail", f"GitFetcher.fetch failed: {e}")

    # The identity printed by milpa hash is result.identity (None → empty stdout).
    # A0-cmd architectural pin: cmd_hash reads identity from result.identity, NOT
    # from compute_content_hash directly (spec/cli-contract.md §5.11 NORMATIVE).
    got_identity = result.identity if result.identity is not None else ""

    if got_identity != expected_stdout:
        return (
            "fail",
            f"hash identity mismatch:\n"
            f"  expected: {expected_stdout!r}\n"
            f"  actual:   {got_identity!r}\n"
            f"  (GitFetcher used file:// URL: {file_url!r})",
        )

    return ("pass", "")


# ---------------------------------------------------------------------------
# The in-process "execute" function — drives core functions directly
# ---------------------------------------------------------------------------


def _execute_fixture(
    fixture: Fixture,
    tmp_dir: Path,
) -> tuple[Literal["pass", "fail", "skip"], str]:
    """Run one fixture and return (verdict, message).

    Returns:
      ("pass", "")       — matched expected outcome
      ("fail", reason)   — did not match expected outcome
      ("skip", reason)   — CLI-only; not for the in-process adapter
    """
    # CLI-only verb fixtures are driven by the black-box CLI harness.
    if fixture.is_cli_only:
        return ("skip", f"CLI-only verb {fixture.cmd!r}; skip in in-process adapter")

    # H-infra: git-protocol fixtures run the REAL GitFetcher against generated
    # local bare repos.  They have no milpa.kdl, mocked-fetches/, or index.kdl —
    # dispatch before _build_env which would fail on those absences.
    if fixture.cmd == "git-protocol":
        return _execute_git_protocol_fixture(fixture, tmp_dir)

    # H-infra: hash fixtures exercise the milpa hash A0-cmd path using the REAL
    # GitFetcher; no milpa.kdl or mocked-fetches/ needed.
    if fixture.cmd == "hash":
        return _execute_hash_fixture(fixture, tmp_dir)

    # Import resolver / frozen lazily (they raise NotImplementedError now)
    from milpa.frozen import resolve_frozen, resolve_workspace_frozen
    from milpa.lockfile import parse_lockfile
    from milpa.resolver import resolve, resolve_workspace
    from milpa.workspace import load_workspace

    fixture_dir = fixture.dir
    # §2.8.1: project-dir selects the project root (the dir passed as -C). All
    # other control inputs (mocked-fetches/, index.kdl, cas-seed/, dep-decl/,
    # expected/) stay rooted at fixture_dir; only the manifest/workspace load
    # uses project_root. Mirrors the black-box harness (runner.py).
    # resolve_project_dir confines the suffix to within fixture_dir (L2).
    _pd_file = fixture_dir / "project-dir"
    project_root = (
        resolve_project_dir(fixture_dir, _pd_file.read_text(encoding="utf-8").strip())
        if _pd_file.is_file()
        else fixture_dir
    )
    deps_dir = tmp_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)

    try:
        env = _build_env(fixture_dir, tmp_dir, no_index=fixture.no_index)
    except MilpaError as e:
        # TNG-* parse errors from index.kdl surface here (before any resolve).
        if fixture.expected_error is not None and e.slug == fixture.expected_error:
            return ("pass", "")
        elif fixture.expected_error is not None:
            return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
        else:
            return ("fail", f"expected success but index parse failed: {e.slug!r}")

    profile = _fixture_profile(fixture_dir)

    cmd = fixture.cmd

    # ------------------------------------------------------------------
    # parse-lockfile: parse the fixture's milpa.lock only
    # ------------------------------------------------------------------
    if cmd == "parse-lockfile":
        lock_path = fixture_dir / "milpa.lock"
        try:
            lock_text = lock_path.read_text(encoding="utf-8")
        except OSError as e:
            return ("fail", f"E2E-LOCKFILE-UNREADABLE: {e}")
        try:
            parse_lockfile(lock_text)
            # parse-lockfile has no success variant (§2.7); if we reach here
            # without error the fixture is an authoring error.
            if fixture.is_success:
                return (
                    "fail",
                    "parse-lockfile: parsed without error but fixture expected success "
                    "(authoring error — no success variant for parse-lockfile)",
                )
            # expected an error but got none
            return ("fail", f"expected error {fixture.expected_error!r} but parse succeeded")
        except MilpaError as e:
            if fixture.expected_error is not None and e.slug == fixture.expected_error:
                return ("pass", "")
            elif fixture.expected_error is not None:
                return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
            else:
                return ("fail", f"expected success but got error {e.slug!r}")

    # ------------------------------------------------------------------
    # lock-roundtrip: parse milpa.lock then re-emit; byte-compare against
    # expected/milpa.lock. Tests parse+format without going through the
    # resolver pipeline (used for fields not populated by fetch, e.g.
    # Phase B aliases). No mocked-fetches/, index.kdl, or milpa.kdl needed.
    # ------------------------------------------------------------------
    if cmd == "lock-roundtrip":
        from milpa.lockfile import format_lockfile, parse_lockfile as _parse_lf
        lock_path = fixture_dir / "milpa.lock"
        try:
            lock_text = lock_path.read_text(encoding="utf-8")
        except OSError as e:
            return ("fail", f"E2E-LOCKFILE-UNREADABLE: {e}")
        try:
            lock_obj = _parse_lf(lock_text)
        except MilpaError as e:
            if fixture.expected_error is not None and e.slug == fixture.expected_error:
                return ("pass", "")
            return ("fail", f"lock-roundtrip: unexpected parse error {e.slug!r}: {e}")
        # Re-emit and byte-compare
        emitted = format_lockfile(lock_obj)
        expected_lock_path = fixture_dir / "expected" / "milpa.lock"
        try:
            expected = expected_lock_path.read_text(encoding="utf-8")
        except OSError as e:
            return ("fail", f"lock-roundtrip: cannot read expected/milpa.lock: {e}")
        if emitted != expected:
            # Show a diff-style excerpt
            emit_lines = emitted.splitlines()
            exp_lines = expected.splitlines()
            diffs = [
                f"  emitted: {el!r}"
                for el, exl in zip(emit_lines, exp_lines)
                if el != exl
            ]
            return ("fail", f"lock-roundtrip: byte mismatch vs expected/milpa.lock\n" +
                    "\n".join(diffs[:5]))
        return ("pass", "")

    # ------------------------------------------------------------------
    # workspace-manifest-roundtrip (S9a): parse milpa.kdl as a workspace
    # manifest → re-emit via format_workspace_manifest → byte-compare vs
    # expected/milpa.kdl. Proves the canonical serializer is byte-stable
    # across impls (manifest-grammar §8 Depth-F6).
    # ------------------------------------------------------------------
    if cmd == "workspace-manifest-roundtrip":
        from milpa.manifest import (
            WorkspaceManifest as _WsManifest,
            format_workspace_manifest as _fmt_ws,
            parse_workspace_or_manifest as _parse_ws_or_pkg,
        )
        kdl_path = fixture_dir / "milpa.kdl"
        try:
            kdl_text = kdl_path.read_text(encoding="utf-8")
        except OSError as e:
            return ("fail", f"E2E-MANIFEST-UNREADABLE: {e}")
        try:
            doc = _parse_ws_or_pkg(kdl_text)
        except MilpaError as e:
            if fixture.expected_error is not None and e.slug == fixture.expected_error:
                return ("pass", "")
            return ("fail", f"workspace-manifest-roundtrip: unexpected parse error {e.slug!r}: {e}")
        if not isinstance(doc, _WsManifest):
            return ("fail", "workspace-manifest-roundtrip: milpa.kdl is a package manifest, not a workspace")
        # Re-emit and byte-compare
        emitted = _fmt_ws(doc)
        expected_kdl_path = fixture_dir / "expected" / "milpa.kdl"
        try:
            expected = expected_kdl_path.read_text(encoding="utf-8")
        except OSError as e:
            return ("fail", f"workspace-manifest-roundtrip: cannot read expected/milpa.kdl: {e}")
        if emitted != expected:
            emit_lines = emitted.splitlines()
            exp_lines = expected.splitlines()
            diffs = []
            for i, (el, exl) in enumerate(zip(emit_lines, exp_lines)):
                if el != exl:
                    diffs.append(f"  line {i+1}: emitted {el!r} vs expected {exl!r}")
            if len(emit_lines) != len(exp_lines):
                diffs.append(f"  line count: emitted {len(emit_lines)} vs expected {len(exp_lines)}")
            return ("fail", "workspace-manifest-roundtrip: byte mismatch vs expected/milpa.kdl\n" +
                    "\n".join(diffs[:5]))
        return ("pass", "")

    # ------------------------------------------------------------------
    # check-certificate: resolve + assert certificate JSON (§2.7.3)
    # ------------------------------------------------------------------
    if cmd == "check-certificate":
        return _execute_check_certificate(fixture, tmp_dir, env)

    # ------------------------------------------------------------------
    # verify: frozen-fetch to populate _deps/, then run verify in-process
    # (S6 / spec §3.7.2)
    # ------------------------------------------------------------------
    if cmd == "verify":
        return _execute_verify(fixture, tmp_dir, env, profile=profile)

    # ------------------------------------------------------------------
    # resolve / frozen: read milpa.kdl + dispatch
    # ------------------------------------------------------------------
    kdl_path = project_root / "milpa.kdl"
    try:
        kdl_text = kdl_path.read_text(encoding="utf-8")
    except OSError as e:
        return ("fail", f"E2E-MANIFEST-UNREADABLE: {e}")

    # Parse to determine workspace vs package
    try:
        doc = parse_workspace_or_manifest(kdl_text)
    except MilpaError as e:
        # Manifest parse error — if fixture expects this error, pass.
        if fixture.expected_error is not None and e.slug == fixture.expected_error:
            return ("pass", "")
        elif fixture.expected_error is not None:
            return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
        else:
            return ("fail", f"expected success but manifest parse failed: {e.slug!r}")

    # ------------------------------------------------------------------
    # frozen path
    # ------------------------------------------------------------------
    if cmd == "frozen":
        lock_path = fixture_dir / "milpa.lock"
        try:
            lock_text = lock_path.read_text(encoding="utf-8")
            lockfile = parse_lockfile(lock_text)
        except MilpaError as e:
            if fixture.expected_error is not None and e.slug == fixture.expected_error:
                return ("pass", "")
            elif fixture.expected_error is not None:
                return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
            else:
                return ("fail", f"expected success but lockfile parse failed: {e.slug!r}")
        except OSError as e:
            return ("fail", f"E2E-LOCKFILE-UNREADABLE: {e}")

        # Seed CAS from cas-seed/ if present (mirrors Rust seed_cas)
        _seed_cas(fixture_dir / "cas-seed", env.store, tmp_dir)

        try:
            if isinstance(doc, WorkspaceManifest):
                try:
                    # M6: use project_root (from the project-dir control file),
                    # not fixture_dir — mirrors the resolve path and the CLI.
                    loaded_ws = load_workspace(project_root)
                except MilpaError as e:
                    if fixture.expected_error is not None and e.slug == fixture.expected_error:
                        return ("pass", "")
                    return ("fail", f"workspace load failed: {e.slug!r}")
                # S2 (RFC: workspace-completion §3.A / Breadth-P1b):
                # FROZEN-ACTIVE-FLAGS-MISMATCH check for workspace frozen path.
                # Must run BEFORE resolve_workspace_frozen so the correct slug
                # fires rather than FROZEN-MANIFEST-DEP-NOT-IN-LOCK.
                from milpa.cli import _check_workspace_frozen_active_flags_mismatch
                _check_workspace_frozen_active_flags_mismatch(
                    loaded_ws, lockfile,
                    features=_fixture_cli_features(fixture_dir),
                    no_default_features=_fixture_no_default_features(fixture_dir),
                    all_features=_fixture_all_features(fixture_dir),
                )
                # Compute cli_seed for resolve_workspace_frozen (so flag-excluded
                # deps are skipped in the alignment check, not mis-fired as
                # FROZEN-MANIFEST-DEP-NOT-IN-LOCK).
                from milpa.resolver import _compute_workspace_cli_seed as _cws
                _fx_cli_seed = _cws(
                    loaded_ws.workspace_manifest,
                    _fixture_cli_features(fixture_dir),
                    _fixture_no_default_features(fixture_dir),
                    _fixture_all_features(fixture_dir),
                )
                graph = resolve_workspace_frozen(
                    loaded_ws, lockfile, env, deps_dir,
                    cli_seed=_fx_cli_seed,
                )
            else:
                assert isinstance(doc, Manifest)
                # S9 (RFC #23 §3.4): FROZEN-ACTIVE-FLAGS-MISMATCH check.
                # Mirrors CLI's _check_frozen_active_flags_mismatch call.
                from milpa.cli import _check_frozen_active_flags_mismatch
                _check_frozen_active_flags_mismatch(
                    doc, lockfile,
                    features=_fixture_cli_features(fixture_dir),
                    no_default_features=_fixture_no_default_features(fixture_dir),
                    all_features=_fixture_all_features(fixture_dir),
                )
                graph = resolve_frozen(doc, lockfile, env, deps_dir)
        except MilpaError as e:
            if fixture.expected_error is not None and e.slug == fixture.expected_error:
                return ("pass", "")
            elif fixture.expected_error is not None:
                return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
            else:
                return ("fail", f"expected success but frozen resolve failed: {e.slug!r}")
        except NotImplementedError:
            # Resolver not yet wired — signal this as a "not_wired" state
            # so the caller can park it as xfail.
            raise

        # Success: byte-diff against expected/
        return _diff_success(fixture, graph, doc, tmp_dir, deps_dir)

    # ------------------------------------------------------------------
    # resolve path (live)
    # ------------------------------------------------------------------
    prior = _load_prior_lockfile(fixture_dir) if cmd == "resolve" else None
    params = ResolveParams(
        strategy=Strategy.MAXVER,
        max_parallel=1,
        profile=profile,
        prior=prior,
        require_attested_metadata=_fixture_require_attested_metadata(fixture_dir),
        manifest_dir=fixture_dir,  # so local="./src-tree" resolves against fixture dir
        # S9 (RFC #23 §3.4): CLI feature-selection from fixture env file.
        features=_fixture_cli_features(fixture_dir),
        no_default_features=_fixture_no_default_features(fixture_dir),
        all_features=_fixture_all_features(fixture_dir),
    )

    try:
        if isinstance(doc, WorkspaceManifest):
            try:
                loaded_ws = load_workspace(project_root)
            except MilpaError as e:
                if fixture.expected_error is not None and e.slug == fixture.expected_error:
                    return ("pass", "")
                return ("fail", f"workspace load failed: {e.slug!r}")
            graph = resolve_workspace(loaded_ws, deps_dir, env, params)
        else:
            assert isinstance(doc, Manifest)
            graph = resolve(doc, deps_dir, env, params)
    except MilpaError as e:
        if fixture.expected_error is not None and e.slug == fixture.expected_error:
            return ("pass", "")
        elif fixture.expected_error is not None:
            return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
        else:
            return ("fail", f"expected success but resolve failed: {e.slug!r}")
    except NotImplementedError:
        # Resolver not yet wired — signal this as a "not_wired" state
        raise

    # Success: byte-diff against expected/
    return _diff_success(fixture, graph, doc, tmp_dir, deps_dir)


# ---------------------------------------------------------------------------
# check-certificate execution (conformance-fixtures §2.7.3)
# ---------------------------------------------------------------------------


def _execute_check_certificate(
    fixture: Fixture,
    tmp_dir: Path,
    env: MilpaEnv,
) -> tuple[Literal["pass", "fail", "skip"], str]:
    """Execute a check-certificate fixture in-process.

    1. Parse the manifest.
    2. Run resolve() (or resolve_workspace()).
    3. On success: extract graph.cert → compare to expected/certificate.json.
       Also assert the normal success outcome (milpa.lock etc).
    4. On SOLVE_CONFLICT: extract solver_error from exc.context → compare
       failure cert to expected/certificate.json. Assert error slug matches.
    """
    fixture_dir = fixture.dir
    deps_dir = tmp_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)

    # Parse manifest
    kdl_path = fixture_dir / "milpa.kdl"
    try:
        kdl_text = kdl_path.read_text(encoding="utf-8")
    except OSError as e:
        return ("fail", f"E2E-MANIFEST-UNREADABLE: {e}")

    try:
        doc = parse_workspace_or_manifest(kdl_text)
    except MilpaError as e:
        if fixture.expected_error is not None and e.slug == fixture.expected_error:
            return ("pass", "")
        elif fixture.expected_error is not None:
            return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
        else:
            return ("fail", f"expected success but manifest parse failed: {e.slug!r}")

    prior = _load_prior_lockfile(fixture_dir)
    profile = _fixture_profile(fixture_dir)
    params = ResolveParams(
        strategy=Strategy.MAXVER,
        max_parallel=1,
        profile=profile,
        prior=prior,
        require_attested_metadata=_fixture_require_attested_metadata(fixture_dir),
        manifest_dir=fixture_dir,  # so local="./src-tree" resolves against fixture dir
    )

    # Expected certificate
    expected_cert_path = fixture_dir / "expected" / "certificate.json"
    if not expected_cert_path.exists():
        return ("fail", "expected/certificate.json not found in fixture")
    try:
        expected_cert = json.loads(expected_cert_path.read_text(encoding="utf-8"))
    except Exception as e:
        return ("fail", f"expected/certificate.json parse error: {e}")

    # Resolve
    try:
        if isinstance(doc, WorkspaceManifest):
            try:
                loaded_ws = load_workspace(fixture_dir)
            except MilpaError as e:
                if fixture.expected_error is not None and e.slug == fixture.expected_error:
                    return ("pass", "")
                return ("fail", f"workspace load failed: {e.slug!r}")
            graph = resolve_workspace(loaded_ws, deps_dir, env, params)
        else:
            assert isinstance(doc, Manifest)
            graph = resolve(doc, deps_dir, env, params)
    except MilpaError as e:
        if fixture.expected_error is not None and e.slug == fixture.expected_error:
            # Error fixture: compare failure certificate.
            if e.slug == SOLVE_CONFLICT:
                solver_err = e.context.get("solver_error")
                if solver_err is None:
                    return ("fail", "SOLVE_CONFLICT MilpaError missing solver_error in context")
                assert isinstance(solver_err, SolverError)
                cert_json_str = certificate_to_json(solver_err)
            else:
                # Non-solver MilpaError (e.g. RES-UNATTESTED-METADATA): emit the
                # empty failure cert that Rust emits for these cases (cli-contract §2.5.2).
                cert_json_str = certificate_to_json(None)
            got_cert = json.loads(cert_json_str)
            mismatch = compare_certificate_json(got_cert, expected_cert)
            if mismatch:
                return ("fail", f"failure certificate mismatch: {mismatch}")
            return ("pass", "")
        elif fixture.expected_error is not None:
            return ("fail", f"expected error {fixture.expected_error!r}, got {e.slug!r}")
        else:
            return ("fail", f"expected success but resolve failed: {e.slug!r}")

    # Success: compare certificate from graph.cert
    if fixture.expected_error is not None:
        return ("fail", f"expected error {fixture.expected_error!r} but resolve succeeded")

    cert_obj = getattr(graph, "cert", None)
    if cert_obj is None:
        return ("fail", "graph.cert is None — resolver did not build a certificate")

    got_cert_str = certificate_to_json(cert_obj)
    got_cert = json.loads(got_cert_str)

    mismatch = compare_certificate_json(got_cert, expected_cert)
    if mismatch:
        return ("fail", f"success certificate mismatch: {mismatch}")

    # Also assert the normal success outputs (milpa.lock etc) depending on verb.
    # For 'fetch', assert lock + nim.cfg + _deps_structure.txt.
    # For 'lock', assert only milpa.lock.
    return _diff_success(fixture, graph, doc, tmp_dir, deps_dir)


# ---------------------------------------------------------------------------
# verify execution (S6 / spec §3.7.2)
# ---------------------------------------------------------------------------


def _execute_verify(
    fixture: Fixture,
    tmp_dir: Path,
    env: MilpaEnv,
    *,
    profile: "Profile | None" = None,
) -> tuple[Literal["pass", "fail", "skip"], str]:
    """Execute a verify fixture in-process.

    Two-phase — mirrors the harness black-box approach exactly:
    1. Regular (non-frozen) resolve to populate _deps/ and warm the CAS.
       This uses the fixture's milpa.kdl + mocked-fetches/ + index.kdl.
       The newly-generated milpa.lock is discarded; the pre-authored fixture
       milpa.lock (with the old dep_decl pins under test) is used for verify.
    2. In-process verify: disk check + dep_decl edge check vs live index.

    The verify fixture ships:
    - milpa.kdl      — the project manifest
    - milpa.lock     — pre-authored lockfile with old dep_decl pins (the tripwire)
    - mocked-fetches/ — dep artifacts for the regular pre-phase fetch
    - dep-decl/      — DepDecl artifacts (injected into env.dep_decl_store)
    - index.kdl      — live (drifted) index for dep_decl edge check
    - expected/error — expected error slug (all S6 verify fixtures are error-class)
    """
    from milpa.lockfile import parse_lockfile, verify_lockfile_against_deps

    fixture_dir = fixture.dir
    # M6: compute project_root from the project-dir control file, mirroring
    # the resolve path and the black-box harness (runner.py §2.8.1).
    # resolve_project_dir confines the suffix to within fixture_dir (L2).
    _pd_file = fixture_dir / "project-dir"
    project_root = (
        resolve_project_dir(fixture_dir, _pd_file.read_text(encoding="utf-8").strip())
        if _pd_file.is_file()
        else fixture_dir
    )
    deps_dir = tmp_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)
    lock_path = fixture_dir / "milpa.lock"

    # Missing lock → LOCK-FILE-NOT-FOUND, mirroring cmd_verify's first check
    # (cli.py: `if not lock_path.exists()`, before any _deps/ work). The S6
    # tripwire path below assumes a pre-authored lock; fixture-164 (#125)
    # exercises the no-lock branch the CLI handles up front.
    if not lock_path.exists():
        from milpa.errors import LOCK_FILE_NOT_FOUND
        if fixture.expected_error == LOCK_FILE_NOT_FOUND:
            return ("pass", "")
        return (
            "fail",
            f"verify: no milpa.lock yields {LOCK_FILE_NOT_FOUND}, "
            f"but fixture expected {fixture.expected_error!r}",
        )

    # Stash the pre-authored milpa.lock (with the old dep_decl pins).
    try:
        lock_text = lock_path.read_text(encoding="utf-8")
        lockfile = parse_lockfile(lock_text)
    except MilpaError as e:
        return ("fail", f"verify: failed to parse fixture milpa.lock: {e.slug!r}")
    except OSError as e:
        return ("fail", f"verify: fixture milpa.lock unreadable: {e}")

    # Phase 1: regular (non-frozen) resolve to populate _deps/ and warm the CAS.
    # M6: read milpa.kdl from project_root (not fixture_dir), mirroring the
    # resolve path and the black-box harness.
    kdl_path = project_root / "milpa.kdl"
    try:
        kdl_text = kdl_path.read_text(encoding="utf-8")
    except OSError as e:
        return ("fail", f"E2E-MANIFEST-UNREADABLE: {e}")
    try:
        doc = parse_workspace_or_manifest(kdl_text)
    except MilpaError as e:
        return ("fail", f"verify: manifest parse failed: {e.slug!r}")

    try:
        if isinstance(doc, WorkspaceManifest):
            try:
                # M6: use project_root (from the project-dir control file).
                loaded_ws = load_workspace(project_root)
            except MilpaError as e:
                return ("fail", f"verify: workspace load failed: {e.slug!r}")
            resolve_workspace(loaded_ws, deps_dir, env, ResolveParams(manifest_dir=fixture_dir, profile=profile))
        else:
            assert isinstance(doc, Manifest)
            resolve(doc, deps_dir, env, ResolveParams(manifest_dir=fixture_dir, profile=profile))
    except MilpaError as e:
        # Regular resolve failed — _deps/ not populated; verify will fail too.
        # For S6 fixtures, the pre-phase resolve should always succeed.
        return ("fail", f"verify: pre-phase resolve failed: {e.slug!r}")

    # The pre-phase resolve generated a new milpa.lock (with the new dep_decl
    # hash from the drifted index).  We ignore it and use the pre-authored lock
    # (with the old pin) — that's the supply-chain tripwire under test.
    # Write the pre-authored lockfile into tmp_dir for the disk check below.
    (tmp_dir / "milpa.lock").write_text(lock_text, encoding="utf-8")

    # Phase 2: in-process verify.
    # We reproduce cmd_verify's logic in-process rather than calling cmd_verify
    # directly (which would re-load env from os.environ, not the fixture env).
    from milpa.registry import parse_index

    flag_require_attested = _fixture_require_attested_metadata(fixture_dir)

    # §13.1: effective strict = OR(manifest attestation-policy "strict", flag).
    # Reuse the same SSOT helper as the CLI cmd_verify.
    # Load workspace once and reuse for both the attestation-policy check and
    # the frozen-flags mismatch check below (L5: avoid double load_workspace).
    from milpa.attestation import effective_strict_policy
    loaded_ws_verify = None
    if isinstance(doc, WorkspaceManifest):
        # Workspace: OR across all members (same rule as resolve_workspace).
        try:
            # M6: use project_root for all workspace loads in verify path.
            loaded_ws_verify = load_workspace(project_root)
            _strict = flag_require_attested or any(
                effective_strict_policy(m.manifest.attestation_policy, False)
                for m in loaded_ws_verify.members
            )
        except MilpaError:
            _strict = flag_require_attested
    else:
        assert isinstance(doc, Manifest)
        _strict = effective_strict_policy(doc.attestation_policy, flag_require_attested)

    # S11b (Breadth-P2c): workspace frozen-flags mismatch check.
    # Runs BEFORE disk check (same as cmd_verify's ordering); uses manifest
    # defaults (no CLI feature overrides at verify time).
    if isinstance(doc, WorkspaceManifest):
        try:
            # Reuse loaded_ws_verify from above (loaded once for this verify path).
            if loaded_ws_verify is None:
                loaded_ws_verify = load_workspace(project_root)
            from milpa.cli import _check_workspace_frozen_active_flags_mismatch
            _check_workspace_frozen_active_flags_mismatch(
                loaded_ws_verify,
                lockfile,
                features=frozenset(),
                no_default_features=False,
                all_features=False,
            )
        except MilpaError as e:
            if fixture.expected_error is not None and e.slug == fixture.expected_error:
                return ("pass", "")
            return ("fail", f"verify: workspace frozen-flags check raised {e.slug!r} (expected {fixture.expected_error!r})")

    # Disk check.
    divergences = verify_lockfile_against_deps(lockfile, deps_dir)
    if divergences:
        slug = "LOCK-GRAPH-MISMATCH"
        if fixture.expected_error is not None and fixture.expected_error == slug:
            return ("pass", "")
        return ("fail", f"verify: disk check failed (expected {fixture.expected_error!r}): {divergences}")

    # Edge check: dep_decl pins vs live index.
    pinned_deps = [d for d in lockfile.deps if d.dep_decl is not None]
    if not pinned_deps:
        # No pins → verify passes; S6 error fixtures always have pins.
        if fixture.expected_error is not None:
            return ("fail", f"verify: expected error {fixture.expected_error!r} but no dep_decl pins to check")
        return ("pass", "")

    index_path = fixture_dir / "index.kdl"
    if not index_path.exists():
        # Offline: no index available.
        if _strict:
            slug = "VERIFY-EDGE-MISMATCH"
        else:
            # Edge check skipped (offline) — treat as pass for fixture purposes.
            if fixture.expected_error is not None:
                return ("fail", f"verify: offline — edge check skipped but expected error {fixture.expected_error!r}")
            return ("pass", "")
        if fixture.expected_error is not None and fixture.expected_error == slug:
            return ("pass", "")
        return ("fail", f"verify: offline strict failed with {slug!r} (expected {fixture.expected_error!r})")

    # Load index.
    try:
        index = parse_index(index_path.read_text(encoding="utf-8"))
    except MilpaError as e:
        return ("fail", f"verify: index parse failed: {e.slug!r}")

    # Per-dep edge check.
    for dep in pinned_deps:
        assert dep.dep_decl is not None
        locked_pin = dep.dep_decl

        pkg = index.lookup_bare(dep.name)
        if pkg is None or hasattr(pkg, "namespaces"):
            slug = "LOCK-DEPDECL-PIN-MISSING"
            if fixture.expected_error is not None and fixture.expected_error == slug:
                return ("pass", "")
            return ("fail", f"verify: dep '{dep.name}' not in index — expected {fixture.expected_error!r}, got {slug!r}")

        iv = next((iv for iv in pkg.versions if iv.version == dep.version), None)
        if iv is None or iv.dep_decl is None:
            slug = "LOCK-DEPDECL-PIN-MISSING"
            if fixture.expected_error is not None and fixture.expected_error == slug:
                return ("pass", "")
            return ("fail", f"verify: dep '{dep.name}@{dep.version}' pin orphaned — expected {fixture.expected_error!r}, got {slug!r}")

        if iv.dep_decl != locked_pin:
            slug = "VERIFY-EDGE-MISMATCH"
            if fixture.expected_error is not None and fixture.expected_error == slug:
                return ("pass", "")
            return ("fail", f"verify: dep '{dep.name}@{dep.version}' dep_decl mismatch — expected {fixture.expected_error!r}, got {slug!r}")

    # All pins matched.
    if fixture.expected_error is not None:
        return ("fail", f"verify: expected error {fixture.expected_error!r} but all checks passed")
    return ("pass", "")


# ---------------------------------------------------------------------------
# Success diff — compare produced outputs against expected/
# ---------------------------------------------------------------------------


def _diff_success(
    fixture: Fixture,
    graph: object,  # ResolvedGraph — typed at runtime
    doc: Manifest | WorkspaceManifest,
    tmp_dir: Path,
    deps_dir: Path,
) -> tuple[Literal["pass", "fail", "skip"], str]:
    """Byte-diff the produced outputs against expected/."""
    from milpa.lockfile import format_lockfile, from_graph
    from milpa.nimcfg import build_flag_defines, format_nimcfg, format_workspace_nimcfgs
    from milpa.workspace import load_workspace

    if fixture.expected_error is not None:
        return ("fail", f"expected error {fixture.expected_error!r} but resolve succeeded")

    expected_dir = fixture.dir / "expected"

    try:
        lockfile_obj = from_graph(graph)  # type: ignore[arg-type]
        lock_text = format_lockfile(lockfile_obj)
    except Exception as e:
        return ("fail", f"from_graph/format_lockfile failed: {e}")

    # Build-mode: normalize the encoder-dependent tarball sha256 using the
    # harness's apply_lock_placeholders (M3 unification: opt-in only when
    # the expected file contains the placeholder token — strictly safer than
    # the old unconditional line-anchored redaction).  We read the expected
    # milpa.lock to discover which tokens to substitute.
    if _is_build_mode_fixture(fixture.dir):
        expected_lock_path = fixture.dir / "expected" / "milpa.lock"
        try:
            expected_lock_text = expected_lock_path.read_text(encoding="utf-8")
        except OSError:
            expected_lock_text = ""
        lock_text = apply_lock_placeholders(expected_lock_text, lock_text)

    # workspace vs single-package nim.cfg
    if isinstance(doc, WorkspaceManifest):
        try:
            loaded_ws = load_workspace(fixture.dir)
            # S11 (RFC #23 §3.8): pass flag_defines so each member's nim.cfg
            # includes the unified -d: defines for shared deps (SSOT).
            ws_flag_defines = build_flag_defines(graph, deps_dir)  # type: ignore[arg-type]
            member_nimcfgs: dict[str, str] = format_workspace_nimcfgs(
                loaded_ws, graph, flag_defines=ws_flag_defines  # type: ignore[arg-type]
            )
        except Exception as e:
            return ("fail", f"format_workspace_nimcfgs failed: {e}")

        # diff lock
        if fail := _diff_file(expected_dir / "milpa.lock", lock_text, "milpa.lock"):
            return fail

        # diff per-member nim.cfg
        for rel_path, nimcfg_text in member_nimcfgs.items():
            label = f"{rel_path}/nim.cfg"
            if fail := _diff_file(expected_dir / rel_path / "nim.cfg", nimcfg_text, label):
                return fail
    else:
        assert isinstance(doc, Manifest)
        try:
            # §7.5 S6: compute flag_defines from each dep's manifest (SSOT —
            # defines live in manifests, not the lockfile; RFC #23 §3.6).
            flag_defines = build_flag_defines(graph, deps_dir)  # type: ignore[arg-type]
            nimcfg_text = format_nimcfg(
                graph,  # type: ignore[arg-type]
                deps_dir=Path("_deps"),
                self_src_dir=doc.src_dir,
                flag_defines=flag_defines,
            )
        except Exception as e:
            return ("fail", f"format_nimcfg failed: {e}")

        if fail := _diff_file(expected_dir / "milpa.lock", lock_text, "milpa.lock"):
            return fail
        if fail := _diff_file(expected_dir / "nim.cfg", nimcfg_text, "nim.cfg"):
            return fail

    # _deps_structure.txt — normalized via normalize_deps_structure from
    # harness/assertions.py (M2 unification: single definition, both call sites
    # import it; the harness expects scratch_dir/cas_dir, so we pass tmp_dir/.cas).
    cas_root = tmp_dir / ".cas"
    raw_structure = normalize_deps_structure(str(tmp_dir), str(cas_root))
    got_structure = raw_structure if raw_structure is not None else ""
    if fail := _diff_file(
        expected_dir / "_deps_structure.txt", got_structure, "_deps_structure.txt"
    ):
        return fail

    return ("pass", "")


def _is_build_mode_fixture(fixture_dir: Path) -> bool:
    """Return True when any mocked-fetches entry has a ``format`` file.

    Build-mode fixtures build real archives at test time; their lockfile's
    tarball ``sha256`` field is encoder-dependent and MUST be redacted before
    the byte-diff (conformance-fixtures.md §2.3.4 build-mode extension).
    """
    mocked_dir = fixture_dir / "mocked-fetches"
    if not mocked_dir.is_dir():
        return False
    return any(
        (entry / "format").is_file()
        for entry in mocked_dir.iterdir()
        if entry.is_dir()
    )


# _TARBALL_SHA256_LINE and _redact_tarball_sha256 deleted (M3 unification):
# the call site uses apply_lock_placeholders from harness/assertions.py,
# which is opt-in (only when the placeholder token appears in expected) and
# uses a non-anchored pattern that never matches the identity field.


def _diff_file(
    expected_path: Path,
    got: str,
    label: str,
) -> tuple[Literal["fail"], str] | None:
    """Compare ``got`` against the bytes of ``expected_path``.

    Returns ``None`` on match, or ``("fail", reason)`` on mismatch.
    """
    try:
        want = expected_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ("fail", f"missing expected/{label}")
    except OSError as e:
        return ("fail", f"cannot read expected/{label}: {e}")
    if want == got:
        return None
    return ("fail", f"{label} mismatch:\n--- expected ---\n{want}\n--- actual ---\n{got}")


# _read_deps_structure deleted (M2 unification): the call site above uses
# normalize_deps_structure from harness/assertions.py directly.


# ---------------------------------------------------------------------------
# CAS seeding from cas-seed/ (for frozen-path fixtures)
# ---------------------------------------------------------------------------


def _seed_cas(seed_root: Path, store: CAStore, scratch_root: Path) -> None:
    """Admit every ``cas-seed/<name>/`` tree into ``store``.

    Mirrors the Rust ``seed_cas`` function.  Each tree is copied to a staging
    dir (same filesystem as the CAS for atomic admit) before admission.
    No-op when ``cas-seed/`` is absent.
    """
    if not seed_root.is_dir():
        return

    import shutil

    from milpa.identity import compute_content_hash

    staging_root = scratch_root / ".cas-seed-staging"

    for child in seed_root.iterdir():
        if not child.is_dir():
            continue
        staged = staging_root / child.name
        if staged.exists():
            shutil.rmtree(staged)
        shutil.copytree(child, staged)
        try:
            identity = compute_content_hash(staged)
            if not store.contains(identity):
                store.admit(staged, identity)
        except Exception:
            pass
        finally:
            if staged.exists():
                shutil.rmtree(staged, ignore_errors=True)


# ---------------------------------------------------------------------------
# parents[N] depth guard — run at module import time after _discover_fixtures
# ---------------------------------------------------------------------------


def _assert_corpus_non_empty() -> None:
    """Assert the corpus path resolves to a non-empty fixture set.

    This is the RED guard for the parents[N] depth.  A wrong N yields 0
    fixtures (vacuous green); the assert ensures the depth is correct.
    Called once at module import time (below).
    """
    fixtures = _discover_fixtures(_CORPUS_ROOT)
    assert len(fixtures) > 0, (
        f"Corpus at {_CORPUS_ROOT} resolved to 0 fixtures — "
        f"parents[N] depth is wrong (expected ≥100 fixtures). "
        f"Repo root resolved to: {_REPO_ROOT}"
    )


# Run the depth assertion immediately so a mis-configured depth fails loudly
# at collection time rather than silently vacuously-greening the test run.
_assert_corpus_non_empty()


# ---------------------------------------------------------------------------
# Fixture collection and parametrization
# ---------------------------------------------------------------------------

# Discover the full corpus
_ALL_FIXTURES: list[Fixture] = _discover_fixtures(_CORPUS_ROOT)
_FIXTURE_IDS: list[str] = [f.id for f in _ALL_FIXTURES]

# Partition into categories for dispatch/marking:
#
# CLI_ONLY: skip — in-process adapter does not drive CLI verbs.
# NOT_YET_WIRED: xfail(strict=False) — resolve/frozen not yet implemented.
# WIRED: normal pass/fail assertion.
#
# At this stage (9a-pre), the resolver raises NotImplementedError, so ALL
# resolve-path and frozen-path fixtures are NOT_YET_WIRED.  Only parse-only
# (MAN-* parse-error, LOCK-* parse-error, TNG-* index parse, WS-* load) are
# currently wired.
#
# The NOT_YET_WIRED set expands to "fixtures whose cmd is resolve or frozen":
# parse-lockfile fixtures are wired (parse_lockfile already works).
# manifest-parse error fixtures (cmd=resolve, expected_error=MAN-*) are
# partially wired — parse_workspace_or_manifest runs, but the route beyond
# returns early on error, so they ARE wired for error matching.
# Similarly TNG-* index parse errors and WS-* topology errors are wired.
#
# Fixtures that go through the resolver proper (success fixtures + error
# fixtures that require the resolver to run, e.g. SOLVE-*, FETCH-*,
# RES-*, FROZEN-*) are NOT_YET_WIRED.

def _is_cli_only(fx: Fixture) -> bool:
    """True when this fixture is driven by the black-box CLI harness only.

    Covers both CLI-verb fixtures (add/remove/update/show/--version) and
    CLI-level filesystem-discovery guard fixtures whose error path cannot be
    modelled by the in-process adapter (no milpa.kdl / no milpa.lock in the
    fixture dir — the adapter reads these files directly by path).
    """
    if fx.is_cli_only:
        return True
    return fx.dir.name in _CLI_DISCOVERY_GUARD_NAMES


##
# NOT_YET_WIRED — explicit allowlist of fixture short-names that still fail.
#
# Updated as resolver slices land:
# Slices 9b-1 (URL deps), 9b-2 (predicates), 9b-3a–3c (named deps) landed.
# Remaining: frozen-path resolver (9c), workspace resolver (9d),
# solver SOLVE-CONFLICT (62), TNG-* resolver errors (87, 90, 93–98),
# RES-PROVENANCE-CONFLICT (99), RES-WS-* (100, 101, 113),
# FETCH-ALL-FAILED tarball refetch (126).
##
_NOT_YET_WIRED_FIXTURE_NAMES: frozenset[str] = frozenset(
    {
        # All resolve-path ERROR fixtures are now wired (slices 9b-1 through 9b-3e).
        # Remaining xfail: none for error fixtures.
        # (RES-WS-*, FETCH-ALL-FAILED tarball, workspace success fixtures
        # remain parked under their own xfail entries — see below.)
        #
        # (fixture-144 un-parked: the adapter now mirrors the CLI's
        # MILPA_INDEX_URL→HttpDepDeclStore path, so an absent dep-decl/ with an
        # index present raises TNG-DEPDECL-FETCH-FAILED — rfc-conformance-parity
        # Slice 2. No remaining in-process xfails.)
    }
)


def _is_not_yet_wired(fx: Fixture) -> bool:
    """True when this fixture requires resolver functionality not yet implemented.

    Maintained as an EXPLICIT allowlist so that newly-passing fixtures are
    caught immediately as xpassed rather than silently staying in xfail.
    Remove entries from ``_NOT_YET_WIRED_FIXTURE_NAMES`` as slices land.
    """
    if fx.is_cli_only:
        return False  # marked skip, not xfail
    if fx.cmd == "parse-lockfile":
        return False  # fully wired
    if fx.cmd == "git-protocol":
        return False  # H-infra tier: wired via _execute_git_protocol_fixture
    if fx.cmd == "hash":
        return False  # H-infra tier: wired via _execute_hash_fixture
    # Explicit allowlist is the primary gate.
    fixture_name = fx.dir.name  # e.g. "fixture-003-single-url-dep"
    return fixture_name in _NOT_YET_WIRED_FIXTURE_NAMES


# Build the fixture list split into three marks.
_FIXTURES_BY_ID: dict[str, Fixture] = {f.id: f for f in _ALL_FIXTURES}


def _mark_for(fx: Fixture) -> str:
    """Return the pytest mark category: 'normal', 'xfail', or 'skip'."""
    if _is_cli_only(fx):
        return "skip"
    if _is_not_yet_wired(fx):
        return "xfail"
    return "normal"


# Build the parametrized test list with marks.
def _make_param(fx: Fixture) -> Any:
    mark = _mark_for(fx)
    if mark == "skip":
        return pytest.param(
            fx.id,
            marks=pytest.mark.skip(
                reason=f"CLI-only verb {fx.cmd!r}; driven by black-box CLI harness"
            ),
        )
    elif mark == "xfail":
        return pytest.param(
            fx.id,
            marks=pytest.mark.xfail(
                strict=False,
                reason=(
                    "resolver not yet implemented (Stage 9b+/9d/9e); "
                    "will green when the relevant slice lands"
                ),
            ),
        )
    else:
        return pytest.param(fx.id)


_PARAMS = [_make_param(fx) for fx in _ALL_FIXTURES]


# ---------------------------------------------------------------------------
# Core adapter assertions (the 9a-pre RED tests)
# ---------------------------------------------------------------------------


class TestConformanceAdapterMachinery:
    """Asserts the ADAPTER MACHINERY — not fixture greenness.

    These tests verify that:
    1. The corpus path resolves to a non-empty fixture set.
    2. Each cmd selector dispatches to the right category (resolve/frozen/parse/skip).
    3. MilpaEnv builds (mocked_registry + CasAdmittingFetcher construction).
    4. Profile from env file parses correctly.
    5. Fixture discovery is deterministic and non-empty.
    """

    def test_corpus_non_empty(self) -> None:
        """The parents[N] depth is correct: corpus resolves to ≥100 fixtures."""
        assert len(_ALL_FIXTURES) >= 100, (
            f"Expected ≥100 fixtures, got {len(_ALL_FIXTURES)}; "
            f"corpus root: {_CORPUS_ROOT}"
        )

    def test_corpus_root_exists(self) -> None:
        assert _CORPUS_ROOT.is_dir(), f"Corpus root not found: {_CORPUS_ROOT}"

    def test_fixture_ids_are_unique(self) -> None:
        ids = [f.id for f in _ALL_FIXTURES]
        assert len(ids) == len(set(ids)), "Duplicate fixture IDs found"

    def test_fixture_ids_sorted(self) -> None:
        ids = [f.id for f in _ALL_FIXTURES]
        assert ids == sorted(ids), "Fixture IDs are not sorted"

    def test_milpa_env_builds(self, tmp_path: Path) -> None:
        """MilpaEnv constructs with mocked_registry + CasAdmittingFetcher."""
        # Use a fixture dir that has a mocked-fetches subdir
        fixture_003 = _CORPUS_ROOT / "spec-v1" / "fixture-003-single-url-dep"
        if not fixture_003.is_dir():
            pytest.skip("fixture-003 not found")
        env = _build_env(fixture_003, tmp_path)
        assert isinstance(env, MilpaEnv)
        assert isinstance(env.fetcher, CasAdmittingFetcher)
        assert isinstance(env.store, CAStore)
        # fixture-003 has an index.kdl (empty index) → index is loaded
        from milpa.registry import Index
        assert isinstance(env.index, Index)

    def test_resolve_params_defaults(self) -> None:
        """ResolveParams has correct defaults."""
        params = ResolveParams()
        assert params.strategy == Strategy.MAXVER
        assert params.max_parallel == 4
        assert params.profile is None
        assert params.prior is None

    def test_profile_from_env_file(self, tmp_path: Path) -> None:
        """Profile is parsed from an env file with MILPA_TARGET_* vars."""
        env_file = tmp_path / "env"
        env_file.write_text(
            "MILPA_TARGET_PLATFORM=linux\n"
            "MILPA_TARGET_ARCH=amd64\n"
            "MILPA_TARGET_NIM=2.0.0\n",
            encoding="utf-8",
        )
        profile = _fixture_profile(tmp_path)
        assert profile is not None
        assert profile.nim == "2.0.0"

    def test_profile_absent_env_file(self, tmp_path: Path) -> None:
        """Profile is None when no env file exists (predicate filtering disabled)."""
        profile = _fixture_profile(tmp_path)
        assert profile is None

    def test_profile_none_when_no_target_axes(self, tmp_path: Path) -> None:
        """Profile is None when env file has no MILPA_TARGET_* keys.

        An env file carrying only MILPA_CLI_FEATURES (or other non-target keys)
        must yield None, mirroring the Rust runner and resolver-semantics §470.
        Host-defaulting is CLI-only behavior.
        """
        env_file = tmp_path / "env"
        env_file.write_text("MILPA_CLI_FEATURES=extras\n", encoding="utf-8")
        profile = _fixture_profile(tmp_path)
        assert profile is None

    def test_cli_only_fixtures_detected(self) -> None:
        """CLI-only verb fixtures (and CLI discovery-guard fixtures) are identified.

        CLI-only verb fixtures have cmd in _CLI_ONLY_VERBS.
        CLI discovery-guard fixtures (no milpa.kdl/milpa.lock on disk) are also
        treated as CLI-only (in-process adapter cannot model them); their cmd
        may be 'resolve' or 'frozen'.
        """
        cli_only = [f for f in _ALL_FIXTURES if _is_cli_only(f)]
        # We know there are mutation + liveness fixtures (120-124, etc.)
        assert len(cli_only) > 0, "Expected some CLI-only fixtures"
        for fx in cli_only:
            is_verb_only = fx.cmd in _CLI_ONLY_VERBS
            is_discovery_guard = fx.dir.name in _CLI_DISCOVERY_GUARD_NAMES
            assert is_verb_only or is_discovery_guard, (
                f"{fx.id}: cli-only fixture has unexpected cmd {fx.cmd!r} "
                f"and is not a known discovery-guard fixture"
            )

    def test_parse_lockfile_fixtures_are_wired(self) -> None:
        """parse-lockfile fixtures are wired (not marked xfail)."""
        parse_lf = [f for f in _ALL_FIXTURES if f.cmd == "parse-lockfile"]
        assert len(parse_lf) > 0, "Expected some parse-lockfile fixtures"
        for fx in parse_lf:
            assert _mark_for(fx) == "normal", (
                f"{fx.id}: parse-lockfile fixture should be 'normal' but got {_mark_for(fx)!r}"
            )

    def test_resolve_success_fixtures_not_skip(self) -> None:
        """resolve success fixtures are either normal or xfail (not skip).

        Slices 9b-1 through 9b-3c landed; most success fixtures are now wired.
        Workspace success fixtures (9d) remain xfail.
        """
        success_resolve = [
            f for f in _ALL_FIXTURES
            if f.cmd == "resolve" and f.is_success and not f.is_cli_only
        ]
        assert len(success_resolve) > 0, "Expected some success resolve fixtures"
        for fx in success_resolve:
            assert _mark_for(fx) in ("normal", "xfail"), (
                f"{fx.id}: resolve success fixture should be 'normal' or 'xfail' "
                f"but got {_mark_for(fx)!r}"
            )

    def test_frozen_fixtures_correct_marking(self) -> None:
        """frozen fixtures: FROZEN-* errors are wired (resolve_frozen implemented).

        CLI-discovery-guard FROZEN-* fixtures (no milpa.lock on disk) are excluded:
        those are skipped here and covered by the black-box CLI harness.
        """
        frozen = [f for f in _ALL_FIXTURES if f.cmd == "frozen"]
        assert len(frozen) > 0, "Expected some frozen fixtures"
        frozen_error_codes = [
            f for f in frozen
            if f.expected_error and f.expected_error.startswith("FROZEN-")
            and f.dir.name not in _CLI_DISCOVERY_GUARD_NAMES
        ]
        assert len(frozen_error_codes) > 0
        for fx in frozen_error_codes:
            mark = _mark_for(fx)
            assert mark in ("normal", "xfail"), (
                f"{fx.id}: FROZEN-* fixture should be normal or xfail but got {mark!r}"
            )

    def test_man_error_resolve_fixtures_are_wired(self) -> None:
        """MAN-* error fixtures with cmd=resolve are wired (parse boundary).

        CLI-discovery-guard fixtures (no milpa.kdl on disk) are excluded:
        those are skipped here and covered by the black-box CLI harness.
        """
        man_errors = [
            f for f in _ALL_FIXTURES
            if f.cmd == "resolve"
            and f.expected_error is not None
            and f.expected_error.startswith("MAN-")
            and f.dir.name not in _CLI_DISCOVERY_GUARD_NAMES
        ]
        assert len(man_errors) > 0, "Expected some non-skip MAN-* resolve error fixtures"
        for fx in man_errors:
            assert _mark_for(fx) == "normal", (
                f"{fx.id}: MAN-* error fixture should be 'normal' but got {_mark_for(fx)!r}"
            )

    def test_dispatch_routes_workspace_fixture(self) -> None:
        """Workspace fixtures dispatch to the workspace route."""
        ws_fx = next(
            (f for f in _ALL_FIXTURES if "ws-two-member" in f.id.lower()),
            None,
        )
        if ws_fx is None:
            pytest.skip("no ws-two-member fixture found")
        assert ws_fx.cmd == "resolve"
        # WorkspaceManifest dispatch is tested at the parse level here
        kdl_text = (ws_fx.dir / "milpa.kdl").read_text(encoding="utf-8")
        from milpa.manifest import WorkspaceManifest, parse_workspace_or_manifest
        doc = parse_workspace_or_manifest(kdl_text)
        assert isinstance(doc, WorkspaceManifest)


# ---------------------------------------------------------------------------
# The actual corpus run — one test per fixture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_id", _PARAMS)
def test_corpus_fixture(fixture_id: str, tmp_path: Path) -> None:
    """Run one conformance fixture and assert the outcome.

    The adapter machinery:
    - Discovers the fixture by ID.
    - Dispatches on cmd (parse-lockfile / resolve / frozen).
    - For error fixtures: asserts the raised MilpaError slug matches expected.
    - For success fixtures: byte-diffs lock + nim.cfg + _deps_structure.txt.

    At this stage:
    - CLI-only fixtures: SKIPPED (skip mark applied above).
    - Success fixtures + FROZEN-*/SOLVE-*/FETCH-*/RES-* error fixtures: XFAIL
      (resolver not yet implemented).
    - MAN-* / WS-* / TNG-* / LOCK-* parse-boundary fixtures: asserted normally.
    """
    fx = _FIXTURES_BY_ID[fixture_id]

    # CLI-only should have been handled by the skip mark.
    if fx.is_cli_only:
        pytest.skip(f"CLI-only verb {fx.cmd!r}")
        return

    verdict, message = _execute_fixture(fx, tmp_path)

    if verdict == "skip":
        pytest.skip(message)
    elif verdict == "fail":
        pytest.fail(f"{fx.id}: {message}")
    # "pass" → test passes
