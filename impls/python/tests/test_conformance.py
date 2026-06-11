"""Conformance adapter for milpa spec-v1 fixtures (S8b / G4 / #72).

Discovers every conformance/spec-v<N>/fixture-NNN-<slug>/ directory
and parametrizes one pytest case per fixture.

Fixture layout (per spec/conformance-fixtures.md):
  milpa.kdl          — project manifest input
  index.kdl          — frozen tianguis index snapshot input
  mocked-fetches/    — per-URL fake-fetcher returns
    <url-key@ref>/
      sha            — 40-hex commit SHA
      content/       — source tree bytes (identity ground truth)
      <name>.nimble  — optional nimble file
  expected/          — outputs to diff (success) or expected/error (error)

Key encoding rule (§2.3.1): re.sub(r'[^A-Za-z0-9._-]', '_', url) + '@' + ref_encoded

The runner injects fakes via the standard milpa kwarg seams:
  index=      — an Index built from parse_index(index_kdl_text)
  fetcher=    — a FetcherRegistry wrapping a ConformanceFetcher

Workspace manifests (milpa.kdl contains a workspace { } block) are auto-
detected via parse_workspace_or_manifest — the same entry point milpa's CLI
uses. Routing branches on the parsed type (WorkspaceManifest vs Manifest);
no sidecar hint files are needed or permitted.
"""

import os
import shutil
from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.fetchers import FetcherRegistry
from milpa.fetchers.mocked import MockedFetcher
from milpa.frozen import (
    NotFrozen, resolve_frozen, resolve_workspace_frozen,
)
from milpa.identity import compute_content_hash
from milpa.manifest import (
    Manifest, ManifestError, WorkspaceManifest, parse_workspace_or_manifest,
)
from milpa.resolver import ResolvedGraph, resolve, resolve_workspace
from milpa.lockfile import (
    LockfileError, format_lockfile, from_graph, parse_lockfile,
)
from milpa.nimcfg import format_nimcfg, format_workspace_nimcfgs
from milpa.profile import Profile
from milpa.tianguis_client import parse_index, TianguisError
from milpa.solver import SolverError
from milpa.workspace import Workspace, WorkspaceError, load_workspace


# ---------------------------------------------------------------------------
# Fixture discovery
# ---------------------------------------------------------------------------

# The shared conformance corpus is a top-level, impl-neutral peer of impls/ —
# not Python's private tests. From impls/python/tests/ that is parents[3].
_CONFORMANCE_ROOT = Path(__file__).parents[3] / "conformance"


def _discover_fixtures():
    """Yield (fixture_dir, fixture_id) for every spec-vN fixture dir."""
    if not _CONFORMANCE_ROOT.exists():
        return
    for spec_dir in sorted(_CONFORMANCE_ROOT.iterdir()):
        if not spec_dir.is_dir() or not spec_dir.name.startswith("spec-v"):
            continue
        for fixture_dir in sorted(spec_dir.iterdir()):
            if not fixture_dir.is_dir() or not fixture_dir.name.startswith("fixture-"):
                continue
            fixture_id = f"{spec_dir.name}/{fixture_dir.name}"
            yield fixture_dir, fixture_id


_FIXTURES = list(_discover_fixtures())

# KDL-2.0-only fixtures (#123): bare-bool flag values migrated to `#true`/`#false`,
# which the KDL-1.0 Python parser cannot read. Mirrors harness/descriptors.py
# python_known_failing. Removed when Python is rewritten to KDL 2.0 (#6).
_KDL_2_0_ONLY = frozenset({
    "fixture-027-man-dep-flag-too-many-args",
    "fixture-038-man-flag-duplicate",
    "fixture-040-man-flag-unknown-props",
    "fixture-045-man-flag-undeclared-reference",
})


# ---------------------------------------------------------------------------
# _build_fetcher — delegates to production MockedFetcher (SSOT: milpa/fetchers/mocked.py)
# ---------------------------------------------------------------------------

def _build_fetcher(fixture_dir: Path, cas_root: Path) -> FetcherRegistry:
    """Build a FetcherRegistry backed by the fixture's mocked-fetches/.

    Delegates to the production MockedFetcher — single source of truth.
    url_key() is also the production encoder (milpa/fetchers/mocked.py).
    """
    mocked = fixture_dir / "mocked-fetches"
    store = CAStore(root=cas_root)
    reg = FetcherRegistry(store=store)
    reg.register(MockedFetcher(mocked_fetches_dir=mocked))
    return reg


# ---------------------------------------------------------------------------
# CAS-root normalization for _deps_structure.txt
# ---------------------------------------------------------------------------

def _read_deps_structure(deps_dir: Path, cas_root: Path) -> str:
    """Read _deps/ symlinks, produce the normalized _deps_structure.txt.

    Format (per §2.6): '<name> -> <CAS_ROOT>/sha256/<hex>/\\n' per dep,
    sorted lexicographically by name. We resolve the target path absolutely
    and then substitute the CAS root prefix with the <CAS_ROOT> placeholder.
    """
    if not deps_dir.is_dir():
        return ""
    lines = []
    for entry in sorted(deps_dir.iterdir()):
        if entry.is_symlink():
            target = entry.resolve()
            target_str = str(target)
            normalized = target_str.replace(str(cas_root), "<CAS_ROOT>")
            lines.append(f"{entry.name} -> {normalized}/")
    if lines:
        return "\n".join(lines) + "\n"
    return ""


# ---------------------------------------------------------------------------
# Fixture runner — shared parse + resolve logic
# ---------------------------------------------------------------------------

def _fixture_cmd(fixture_dir: Path) -> str:
    """Read the optional `cmd` input file (§2.2).

    Selects which milpa entry point the fixture exercises:
      - "resolve"        (default) — parse_workspace_or_manifest + resolve
                          against index.kdl + mocked-fetches.
      - "parse-lockfile" — parse the milpa.lock input only (LOCK-* codes).
      - "frozen"         — the no-network frozen path against milpa.lock +
                          a CAS seeded from cas-seed/ (FROZEN-* codes).
    """
    cmd_file = fixture_dir / "cmd"
    if cmd_file.exists():
        return cmd_file.read_text().strip()
    return "resolve"


def _seed_cas(fixture_dir: Path, store: CAStore, scratch: Path) -> None:
    """Admit each cas-seed/<name>/ tree into `store` under its content hash.

    Lets a frozen fixture pre-populate the CAS the same way a prior
    `milpa fetch` would have. CAStore.admit() MOVES its source, so we copy
    each seed tree into a scratch staging dir first — the committed fixture
    tree is never mutated. The admitted identity is computed from the seed
    bytes (identity.py), so the fixture's milpa.lock must pin the matching
    `sha256:...` value.
    """
    seed_root = fixture_dir / "cas-seed"
    if not seed_root.is_dir():
        return
    staging = scratch / "_seed_staging"
    staging.mkdir(parents=True, exist_ok=True)
    for tree in sorted(seed_root.iterdir()):
        if tree.is_dir():
            staged = staging / tree.name
            shutil.copytree(tree, staged)
            identity = compute_content_hash(staged)
            if not store.contains(identity):
                store.admit(staged, identity)


def _fixture_profile(fixture_dir: Path):
    """Build a Profile from an optional `env` file (KEY=VALUE per line).

    Lets a fixture drive conditional-dep / `milpa` predicate resolution by
    setting MILPA_TARGET_* values. Returns None when no env file is present
    (profile=None means no predicate filtering — the common case). The Nim
    version is faked so no `nim` subprocess runs during conformance.
    """
    env_file = fixture_dir / "env"
    if not env_file.exists():
        return None
    overrides = {}
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        overrides[key.strip()] = value.strip()
    saved = {k: os.environ.get(k) for k in overrides}
    try:
        os.environ.update(overrides)
        return Profile.from_environment(nim_version_query=lambda: "2.0.0")
    finally:
        for k, old in saved.items():
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old


def _execute(
    fixture_dir: Path, scratch: Path, cmd: str,
) -> tuple[ResolvedGraph | None, str, "Workspace | None"]:
    """Run the fixture's selected entry point.

    Returns (graph, self_src_dir, workspace): a ResolvedGraph + the root
    package's src_dir (for nim.cfg's self-path line) for "resolve"/"frozen",
    plus the loaded Workspace when the fixture is a workspace (else None).
    Returns (None, "", None) for "parse-lockfile" (validated for its raised
    code only). Raises the implementation's coded exception on any error.

    Workspace fixtures route through the real load_workspace() (reading the
    fixture dir tree from disk) — the same entry point milpa's CLI uses — so
    the full set of WS-* structural validations is exercised, with no
    bespoke re-implementation in the test harness.
    """
    deps_dir = scratch / "_deps"
    cas_root = scratch / ".cas"

    if cmd == "parse-lockfile":
        parse_lockfile((fixture_dir / "milpa.lock").read_text())
        return None, "", None

    parsed = parse_workspace_or_manifest((fixture_dir / "milpa.kdl").read_text())
    is_ws = isinstance(parsed, WorkspaceManifest)
    self_src_dir = "" if is_ws else parsed.src_dir
    profile = _fixture_profile(fixture_dir)

    if cmd == "frozen":
        store = CAStore(root=cas_root)
        _seed_cas(fixture_dir, store, scratch)
        lockfile = parse_lockfile((fixture_dir / "milpa.lock").read_text())
        if is_ws:
            workspace = load_workspace(fixture_dir)
            return resolve_workspace_frozen(
                workspace, lockfile=lockfile, deps_dir=deps_dir, store=store,
            ), self_src_dir, workspace
        return resolve_frozen(
            parsed, lockfile=lockfile, deps_dir=deps_dir, store=store,
        ), self_src_dir, None

    # cmd == "resolve" (default). index.kdl is optional — its absence drives
    # the index=None path (RES-NO-INDEX / RES-WS-NO-INDEX).
    index_path = fixture_dir / "index.kdl"
    index = parse_index(index_path.read_text()) if index_path.exists() else None
    fetcher = _build_fetcher(fixture_dir, cas_root)
    if is_ws:
        workspace = load_workspace(fixture_dir)
        return resolve_workspace(
            workspace, deps_dir=deps_dir, index=index, fetcher=fetcher,
            profile=profile,
        ), self_src_dir, workspace
    return resolve(
        parsed, deps_dir=deps_dir, index=index, fetcher=fetcher,
        profile=profile,
    ), self_src_dir, None


def _outputs(
    graph: ResolvedGraph, self_src_dir: str, scratch: Path,
) -> tuple[str, str]:
    """Render the shared byte-diffable outputs from a resolved graph.

    Returns (lockfile_text, deps_structure). nim.cfg is handled
    separately: single-package fixtures use `format_nimcfg`; workspace
    fixtures emit per-member nim.cfg via `_workspace_nimcfgs`.
    """
    lockfile_text = format_lockfile(from_graph(graph))
    deps_structure = _read_deps_structure(scratch / "_deps", scratch / ".cas")
    return lockfile_text, deps_structure


def _workspace_nimcfgs(workspace, graph: ResolvedGraph) -> dict[str, str]:
    """Per-member nim.cfg text keyed by member path, for a workspace fixture.

    Workspaces emit one nim.cfg per member (members point at sibling
    member dirs / shared _deps via relative paths), not a single root
    nim.cfg. The harness byte-diffs each against expected/<member>/nim.cfg.
    Uses the same SSOT emitter milpa's CLI uses (no re-derivation here).
    """
    return format_workspace_nimcfgs(workspace, graph)


# ---------------------------------------------------------------------------
# Parametrized conformance test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_dir",
    [fd for fd, _ in _FIXTURES],
    ids=[fid for _, fid in _FIXTURES],
)
def test_conformance_fixture(fixture_dir: Path, tmp_path: Path):
    # CLI-only verb fixtures (conformance-fixtures.md §2.7.1 mutation
    # add/remove/update + §2.7.2 liveness show/--version) exercise the CLI
    # binary's argv/output contract, which this in-process graph-level adapter
    # does not model. They are driven by the black-box CLI harness (`harness/`).
    _head = _fixture_cmd(fixture_dir).split()[:1]
    if _head and _head[0] in ("add", "remove", "update", "show", "--version"):
        pytest.skip(
            "CLI-only verb fixture (add/remove/update/show/--version); "
            "covered by the black-box CLI harness, not the in-process adapter"
        )
    # KDL-2.0-only fixtures (#123): the corpus is KDL 2.0 (manifest-grammar.md);
    # these use `#true`/`#false` flag values that the (frozen, rewrite-pending)
    # KDL-1.0 Python parser cannot read. Skipped here exactly as the differential
    # harness marks them python_known_failing — Python conforms once it is rewritten
    # to KDL 2.0 (#6). The Rust impl exercises them; do NOT downgrade them.
    if fixture_dir.name in _KDL_2_0_ONLY:
        pytest.skip(
            "KDL-2.0-only fixture; Python parser is KDL 1.0 until the rewrite (#6)"
        )
    """Run one conformance fixture and verify outputs against expected/.

    Error fixtures: assert the implementation raises exc.code == expected/error.
    Success fixtures: byte-diff milpa.lock / nim.cfg / _deps_structure.txt
    against expected/ (with <CAS_ROOT> substitution in _deps_structure.txt).
    """
    expected_dir = fixture_dir / "expected"
    error_file = expected_dir / "error"
    is_error_fixture = error_file.exists()
    cmd = _fixture_cmd(fixture_dir)

    if is_error_fixture:
        expected_code = error_file.read_text().strip()
        raised_code: str | None = None

        try:
            _execute(fixture_dir, tmp_path, cmd)
        except (
            ManifestError, TianguisError, SolverError, WorkspaceError,
            LockfileError, NotFrozen,
        ) as e:
            raised_code = getattr(e, "code", None)
        except Exception as e:
            raised_code = getattr(e, "code", None)

        assert raised_code is not None, (
            f"Expected error {expected_code!r} but no error was raised "
            f"(fixture: {fixture_dir.name})"
        )
        assert raised_code == expected_code, (
            f"Expected error code {expected_code!r}, got {raised_code!r} "
            f"(fixture: {fixture_dir.name})"
        )
        return

    # Success fixture: run and byte-diff against expected/
    try:
        graph, self_src_dir, workspace = _execute(fixture_dir, tmp_path, cmd)
        assert graph is not None, (
            f"Fixture {fixture_dir.name}: cmd {cmd!r} produced no graph but "
            f"is not an error fixture (parse-lockfile success is not a "
            f"byte-diff fixture; add expected/error)"
        )
        lockfile_text, deps_structure = _outputs(
            graph, self_src_dir, tmp_path,
        )
    except Exception as e:
        pytest.fail(
            f"Fixture {fixture_dir.name} expected success but raised "
            f"{type(e).__name__}: {e}"
        )
        return

    expected_lock = expected_dir / "milpa.lock"
    expected_deps = expected_dir / "_deps_structure.txt"

    assert expected_lock.exists(), (
        f"expected/milpa.lock missing in {fixture_dir.name}"
    )
    assert expected_deps.exists(), (
        f"expected/_deps_structure.txt missing in {fixture_dir.name}"
    )

    want_lock = expected_lock.read_text()
    assert lockfile_text == want_lock, (
        f"milpa.lock mismatch in {fixture_dir.name}:\n"
        f"--- expected ---\n{want_lock}\n--- actual ---\n{lockfile_text}"
    )

    # nim.cfg — workspaces emit one per member (expected/<member>/nim.cfg);
    # single-package fixtures emit one root expected/nim.cfg.
    if workspace is not None:
        member_cfgs = _workspace_nimcfgs(workspace, graph)
        for member in workspace.members:
            expected_member_cfg = expected_dir / member.path / "nim.cfg"
            assert expected_member_cfg.exists(), (
                f"expected/{member.path}/nim.cfg missing in {fixture_dir.name} "
                f"(workspace fixtures emit per-member nim.cfg)"
            )
            want = expected_member_cfg.read_text()
            got = member_cfgs[member.path]
            assert got == want, (
                f"{member.path}/nim.cfg mismatch in {fixture_dir.name}:\n"
                f"--- expected ---\n{want}\n--- actual ---\n{got}"
            )
        # A workspace fixture must NOT carry a root expected/nim.cfg.
        assert not (expected_dir / "nim.cfg").exists(), (
            f"workspace fixture {fixture_dir.name} has a root expected/nim.cfg; "
            f"workspaces emit per-member expected/<member>/nim.cfg instead"
        )
    else:
        expected_nimcfg = expected_dir / "nim.cfg"
        assert expected_nimcfg.exists(), (
            f"expected/nim.cfg missing in {fixture_dir.name}"
        )
        nimcfg_text = format_nimcfg(
            graph, deps_dir=Path("_deps"), self_src_dir=self_src_dir,
        )
        want_nimcfg = expected_nimcfg.read_text()
        assert nimcfg_text == want_nimcfg, (
            f"nim.cfg mismatch in {fixture_dir.name}:\n"
            f"--- expected ---\n{want_nimcfg}\n--- actual ---\n{nimcfg_text}"
        )

    # _deps_structure.txt: actual is already <CAS_ROOT>-normalized by _read_deps_structure
    want_deps = expected_deps.read_text()
    assert deps_structure == want_deps, (
        f"_deps_structure.txt mismatch in {fixture_dir.name}:\n"
        f"--- expected ---\n{want_deps}\n--- actual ---\n{deps_structure}"
    )
