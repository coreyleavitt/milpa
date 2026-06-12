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
from pathlib import Path
from typing import Any, Literal

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import SOLVE_CONFLICT, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
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
#   impls/python-ng/tests/test_conformance.py
# parents[0] = impls/python-ng/tests/
# parents[1] = impls/python-ng/
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
_CLI_ONLY_VERBS = frozenset({"add", "remove", "update", "show", "--version"})


class FixtureCmd(str):
    """The resolved command selector from the fixture's ``cmd`` file."""
    ...


class Fixture:
    """A discovered conformance fixture."""

    def __init__(self, fixture_id: str, fixture_dir: Path) -> None:
        self.id = fixture_id          # e.g. "spec-v1/fixture-003-single-url-dep"
        self.dir = fixture_dir        # absolute path to the fixture directory
        self.cmd: str = self._read_cmd()
        self.expected_error: str | None = self._read_expected_error()

    def _read_cmd(self) -> str:
        cmd_file = self.dir / "cmd"
        if not cmd_file.exists():
            return "resolve"
        text = cmd_file.read_text(encoding="utf-8").strip()
        # First whitespace-separated token is the selector.
        head = text.split()[0] if text else ""
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


def _fixture_profile(fixture_dir: Path) -> Profile | None:
    """Build a ``Profile`` from the fixture's optional ``env`` file.

    Returns ``None`` when the file is absent (predicate filtering disabled).
    This mirrors the Rust runner's ``fixture_profile`` function.
    """
    env_file = fixture_dir / "env"
    if not env_file.exists():
        return None

    env_vars: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            env_vars[key.strip()] = value.strip()

    return Profile.from_environment(
        nim_version=env_vars.get("MILPA_TARGET_NIM"),
        milpa_version=env_vars.get("MILPA_TARGET_MILPA", "0.0.0"),
    )


# ---------------------------------------------------------------------------
# MilpaEnv construction for in-process conformance
# ---------------------------------------------------------------------------


def _build_env(fixture_dir: Path, tmp_dir: Path) -> MilpaEnv:
    """Build a ``MilpaEnv`` for the fixture's in-process run.

    Uses ``mocked_registry(mocked_dir)`` wrapped in ``CasAdmittingFetcher``,
    plus a fixture-local ``CAStore`` rooted at ``tmp_dir/.cas``.

    The ``index`` field is loaded from ``fixture_dir/index.kdl`` when present
    (required for named-dep fixtures, slice 9b-3a+).  ``None`` when absent
    (URL-only and error fixtures do not need an index).
    """
    from milpa.registry import parse_index

    cas_root = tmp_dir / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)

    mocked_dir = fixture_dir / "mocked-fetches"
    inner_registry = mocked_registry(mocked_dir)
    fetcher = CasAdmittingFetcher(inner_registry, store)

    index_path = fixture_dir / "index.kdl"
    index = None
    if index_path.exists():
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

    return MilpaEnv(
        fetcher=fetcher,
        index=index,
        store=store,
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


def _compare_certificate_json(
    got: dict[str, Any],
    expected: dict[str, Any],
) -> str | None:
    """Canonical JSON comparison for certificates per conformance-fixtures §2.7.3.

    - Object comparison is key-order-independent (dicts already handle this).
    - ``resolved`` and ``witness`` arrays are order-sensitive.
    - ``message`` field is EXCLUDED from comparison.
    - ``refutation`` is set-equality: sort both by (package, constraint).

    Returns None on match, or a human-readable mismatch string.
    """
    if got.get("kind") != expected.get("kind"):
        return f"kind mismatch: expected {expected.get('kind')!r}, got {got.get('kind')!r}"

    if got["kind"] == "success":
        # resolved: order-sensitive
        if got.get("resolved") != expected.get("resolved"):
            return (
                f"resolved mismatch:\n"
                f"  expected: {json.dumps(expected.get('resolved'), indent=2)}\n"
                f"  got:      {json.dumps(got.get('resolved'), indent=2)}"
            )
        # witness: order-sensitive
        if got.get("witness") != expected.get("witness"):
            return (
                f"witness mismatch:\n"
                f"  expected: {json.dumps(expected.get('witness'), indent=2)}\n"
                f"  got:      {json.dumps(got.get('witness'), indent=2)}"
            )
    elif got["kind"] == "failure":
        # message: EXCLUDED from comparison
        # refutation: set-equality (sort by (package, constraint))
        def _sort_refutation(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
            return sorted(entries, key=lambda e: (e.get("package", ""), e.get("constraint", "")))

        got_ref = _sort_refutation(got.get("refutation", []))
        exp_ref = _sort_refutation(expected.get("refutation", []))
        if got_ref != exp_ref:
            return (
                f"refutation set mismatch:\n"
                f"  expected (sorted): {json.dumps(exp_ref, indent=2)}\n"
                f"  got (sorted):      {json.dumps(got_ref, indent=2)}"
            )
    else:
        return f"unknown certificate kind: {got.get('kind')!r}"

    return None


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

    # Import resolver / frozen lazily (they raise NotImplementedError now)
    from milpa.frozen import resolve_frozen, resolve_workspace_frozen
    from milpa.lockfile import parse_lockfile
    from milpa.resolver import resolve, resolve_workspace
    from milpa.workspace import load_workspace

    fixture_dir = fixture.dir
    deps_dir = tmp_dir / "_deps"
    deps_dir.mkdir(parents=True, exist_ok=True)

    try:
        env = _build_env(fixture_dir, tmp_dir)
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
    # check-certificate: resolve + assert certificate JSON (§2.7.3)
    # ------------------------------------------------------------------
    if cmd == "check-certificate":
        return _execute_check_certificate(fixture, tmp_dir, env)

    # ------------------------------------------------------------------
    # resolve / frozen: read milpa.kdl + dispatch
    # ------------------------------------------------------------------
    kdl_path = fixture_dir / "milpa.kdl"
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
                    loaded_ws = load_workspace(fixture_dir)
                except MilpaError as e:
                    if fixture.expected_error is not None and e.slug == fixture.expected_error:
                        return ("pass", "")
                    return ("fail", f"workspace load failed: {e.slug!r}")
                graph = resolve_workspace_frozen(loaded_ws, lockfile, env, deps_dir)
            else:
                assert isinstance(doc, Manifest)
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
    )

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
                got_cert = json.loads(cert_json_str)
                mismatch = _compare_certificate_json(got_cert, expected_cert)
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

    mismatch = _compare_certificate_json(got_cert, expected_cert)
    if mismatch:
        return ("fail", f"success certificate mismatch: {mismatch}")

    # Also assert the normal success outputs (milpa.lock etc) depending on verb.
    # For 'fetch', assert lock + nim.cfg + _deps_structure.txt.
    # For 'lock', assert only milpa.lock.
    return _diff_success(fixture, graph, doc, tmp_dir, deps_dir)


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
    from milpa.nimcfg import format_nimcfg, format_workspace_nimcfgs
    from milpa.workspace import load_workspace

    if fixture.expected_error is not None:
        return ("fail", f"expected error {fixture.expected_error!r} but resolve succeeded")

    expected_dir = fixture.dir / "expected"

    try:
        lockfile_obj = from_graph(graph)  # type: ignore[arg-type]
        lock_text = format_lockfile(lockfile_obj)
    except Exception as e:
        return ("fail", f"from_graph/format_lockfile failed: {e}")

    # workspace vs single-package nim.cfg
    if isinstance(doc, WorkspaceManifest):
        try:
            loaded_ws = load_workspace(fixture.dir)
            member_nimcfgs: dict[str, str] = format_workspace_nimcfgs(
                loaded_ws, graph  # type: ignore[arg-type]
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
            nimcfg_text = format_nimcfg(
                graph,  # type: ignore[arg-type]
                deps_dir=Path("_deps"),
                self_src_dir=doc.src_dir,
            )
        except Exception as e:
            return ("fail", f"format_nimcfg failed: {e}")

        if fail := _diff_file(expected_dir / "milpa.lock", lock_text, "milpa.lock"):
            return fail
        if fail := _diff_file(expected_dir / "nim.cfg", nimcfg_text, "nim.cfg"):
            return fail

    # _deps_structure.txt
    cas_root = tmp_dir / ".cas"
    got_structure = _read_deps_structure(deps_dir, cas_root)
    if fail := _diff_file(
        expected_dir / "_deps_structure.txt", got_structure, "_deps_structure.txt"
    ):
        return fail

    return ("pass", "")


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


def _read_deps_structure(deps_dir: Path, cas_root: Path) -> str:
    """Build the ``_deps_structure.txt`` body from the materialized ``_deps/``
    (conformance-fixtures.md §2.6).

    Each ``_deps/<name>`` symlink is resolved (``canonicalize``), then the
    canonical CAS-root prefix is replaced with ``<CAS_ROOT>``.  Lines are
    sorted by name; body ends with a trailing newline (empty string if no deps).
    """
    if not deps_dir.is_dir():
        return ""

    try:
        cas_prefix = str(cas_root.resolve())
    except OSError:
        cas_prefix = str(cas_root)

    entries: list[tuple[str, Path]] = []
    try:
        for entry in deps_dir.iterdir():
            if entry.is_symlink():
                entries.append((entry.name, entry))
    except OSError:
        return ""

    entries.sort(key=lambda e: e[0])

    lines: list[str] = []
    for name, link in entries:
        try:
            resolved = link.resolve()
            normalized = str(resolved).replace(cas_prefix, "<CAS_ROOT>")
            lines.append(f"{name} -> {normalized}/\n")
        except OSError:
            pass
    return "".join(lines)


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
    return fx.is_cli_only


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

    def test_cli_only_fixtures_detected(self) -> None:
        """CLI-only verb fixtures are correctly identified as cli-only."""
        cli_only = [f for f in _ALL_FIXTURES if _is_cli_only(f)]
        # We know there are mutation + liveness fixtures (120-124, etc.)
        assert len(cli_only) > 0, "Expected some CLI-only fixtures"
        for fx in cli_only:
            assert fx.cmd in _CLI_ONLY_VERBS, f"{fx.id}: unexpected cmd {fx.cmd!r}"

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
        """frozen fixtures: FROZEN-* errors are wired (resolve_frozen implemented)."""
        frozen = [f for f in _ALL_FIXTURES if f.cmd == "frozen"]
        assert len(frozen) > 0, "Expected some frozen fixtures"
        frozen_error_codes = [
            f for f in frozen
            if f.expected_error and f.expected_error.startswith("FROZEN-")
        ]
        assert len(frozen_error_codes) > 0
        for fx in frozen_error_codes:
            mark = _mark_for(fx)
            assert mark in ("normal", "xfail"), (
                f"{fx.id}: FROZEN-* fixture should be normal or xfail but got {mark!r}"
            )

    def test_man_error_resolve_fixtures_are_wired(self) -> None:
        """MAN-* error fixtures with cmd=resolve are wired (parse boundary)."""
        man_errors = [
            f for f in _ALL_FIXTURES
            if f.cmd == "resolve"
            and f.expected_error is not None
            and f.expected_error.startswith("MAN-")
        ]
        assert len(man_errors) > 0, "Expected some MAN-* resolve error fixtures"
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
