"""milpa CLI — slices 10a-0, 10a, 10b, 10c, 10e.

argparse dispatch over 8 conformance-tested verbs:

  fetch   — resolve, clone deps, emit nim.cfg + milpa.lock (frozen fast-path)
  lock    — resolve, write milpa.lock only (always full-resolve)
  show    — print dep tree from milpa.lock (stdout)
  verify  — recheck _deps/ against milpa.lock (no fetch)
  clean   — remove _deps/ + nim.cfg; keep milpa.lock
  add     — add a dep or mirror (10e)
  remove  — remove a dep from milpa.kdl (10e)
  update  — re-resolve and refresh milpa.lock (10e)

Exit-code taxonomy (cli-contract.md §3, R1–R4):
  0  — success; NO milpa-error: line.
  1  — diagnosed failure; EXACTLY ONE terminal `milpa-error: <SLUG>` line on stderr.
  2  — argument-parse / usage error; NO milpa-error: line.

Every MilpaError that escapes a cmd_* function is caught at main()'s outer
wrapper, which emits the slug and exits 1.  An unexpected exception falls back
to MILPA-INTERNAL — so every exit-1 carries exactly one slug (R3).

MilpaEnv is built ONCE per process:
  - MILPA_MOCKED_FETCHES set → mocked_registry(dir) wrapped in CasAdmittingFetcher
  - else → build_registry() wrapped in CasAdmittingFetcher
  - store → default_store()

Index is loaded eagerly for verbs that need named-dep resolution (fetch, lock);
show/verify/clean/frozen path receive index=None.

Spec authority: spec/cli-contract.md
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import sys
from pathlib import Path

from milpa import __version__
from milpa.cas import CAStore, default_store
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import (
    CLI_FEATURE_FLAGS_CONFLICT,
    FETCH_REF_DISCOVERY_FAILED,
    FROZEN_ACTIVE_FLAGS_MISMATCH,
    FROZEN_NO_LOCKFILE,
    LOCK_DEP_NOT_FOUND,
    LOCK_DEPDECL_PIN_MISSING,
    LOCK_FILE_NOT_FOUND,
    LOCK_GRAPH_MISMATCH,
    MAN_ADD_DEP_EXISTS,
    MAN_MIRROR_EDITABLE_PROVENANCE,
    MAN_MUTATE_FILE_NOT_FOUND,
    MAN_MUTATE_WORKSPACE_REFUSED,
    MAN_REMOVE_DEP_ABSENT,
    MILPA_INTERNAL,
    TNG_DEPDECL_FETCH_FAILED,
    VERIFY_DEPS_DIR_MISSING,
    VERIFY_EDGE_MISMATCH,
    MilpaError,
    STORE_AMBIGUOUS_PREFIX,
    CAS_NOT_IN_STORE,
)
from milpa.fetchers import CasAdmittingFetcher, build_registry, mocked_registry
from milpa.fetchers.types import Provenance
from milpa.frozen import resolve_frozen, resolve_workspace_frozen
from milpa.index_cache import load_default_index
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
    from_graph,
    load_lockfile,
    strip_dep_pin,
    verify_lockfile_against_deps,
    write_lockfile,
)
from milpa.manifest import Manifest, flag_enables_closure
from milpa.nimcfg import build_flag_defines, format_nimcfg, format_workspace_nimcfgs
from milpa.predicate import dep_passes_flag_predicates
from milpa.profile import Profile
from milpa.resolver import resolve, resolve_workspace
from milpa.solver import SolverError, SolveSuccess, certificate_to_json
from milpa.version import DepKey, Strategy
from milpa.workspace import (
    LoadedWorkspace,
    find_workspace_root,
    load_or_discover_manifest,
    load_workspace,
    load_workspace_with_member_override,
)

# ---------------------------------------------------------------------------
# R1–R4 error channel
# ---------------------------------------------------------------------------


def _emit_slug(slug: str) -> None:
    """Emit the terminal machine-readable error line (R1–R4).

    Must be called exactly once per exit-1 path; never on exit 0/2.
    """
    print(f"milpa-error: {slug}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Argparse
# ---------------------------------------------------------------------------


def _add_feature_args(sp: argparse.ArgumentParser) -> None:
    """Add the S9 (RFC #23 §3.4) feature-selection flags to a subparser.

    Three flags, Cargo-parity (spec/cli-contract.md §2.7 S9):
    - ``--features <comma-list>`` — additional root flags to activate.
    - ``--no-default-features``  — suppress root default-true flags.
    - ``--all-features``         — activate all declared root flags.

    Applicable to ``fetch``, ``lock``, and ``update``.
    """
    sp.add_argument(
        "--features",
        metavar="<flags>",
        default="",
        help=(
            "comma-separated list of root flags to activate in addition to defaults "
            "(root-only: cannot name a transitive dep's flag directly; use an "
            "'enables { dep { flag } }' on a root flag for that). "
            "Naming a flag not declared in the root manifest is an error."
        ),
    )
    sp.add_argument(
        "--no-default-features",
        action="store_true",
        default=False,
        help=(
            "suppress the implicit activation of the root manifest's default=true flags; "
            "the resolve starts from a zero-default root baseline and is purely additive "
            "via --features. Per §3.1.3 this is absence-of-request, not an error; "
            "a default-true flag still activates if another active edge requests it."
        ),
    )
    sp.add_argument(
        "--all-features",
        action="store_true",
        default=False,
        help="activate every flag declared in the root manifest",
    )


def _parse_features(raw: str) -> frozenset[str]:
    """Parse the ``--features`` comma-list into a frozenset of flag names.

    Empty strings and whitespace-only tokens are dropped.  Strips leading/
    trailing whitespace from each name.

    Example: ``"tls, http"`` → ``frozenset({"tls", "http"})``
    """
    if not raw or not raw.strip():
        return frozenset()
    return frozenset(name.strip() for name in raw.split(",") if name.strip())


def _make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="milpa",
        description="Nim dependency resolver. Reads milpa.kdl, emits nim.cfg.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"milpa {__version__}",
    )
    parser.add_argument(
        "-C",
        "--directory",
        metavar="<dir>",
        default=".",
        help="run as if invoked from <dir> instead of the current directory",
    )
    parser.add_argument(
        "-j",
        "--parallel",
        metavar="<N>",
        type=int,
        default=8,
        help="number of concurrent fetches (default: 8)",
    )
    parser.add_argument(
        "-s",
        "--strategy",
        metavar="<mode>",
        choices=("maxver", "minver", "semver"),
        default="maxver",
        help="resolution strategy: maxver (default), minver, semver",
    )
    parser.add_argument(
        "--frozen",
        action="store_true",
        help=(
            "require lockfile + CAS to satisfy fetch with no network; "
            "exit 1 if any precondition fails"
        ),
    )
    parser.add_argument(
        "--certificate",
        metavar="<path>",
        default=None,
        help=(
            "write the solve result certificate as JSON to <path> "
            "(applies to fetch and lock; silently ignored by other verbs)"
        ),
    )
    parser.add_argument(
        "--no-index",
        action="store_true",
        default=False,
        help=(
            "resolve with no tianguis index (offline / air-gapped): URL and "
            "local deps resolve normally; any named dep raises RES-NO-INDEX. "
            "Explicit form of an empty MILPA_INDEX_URL; OVERRIDES a configured "
            "index (env or default)."
        ),
    )
    parser.add_argument(
        "--require-attested-metadata",
        action="store_true",
        default=False,
        help=(
            "require all resolved deps to have index-attested DepDecl metadata; "
            "exit 1 with RES-UNATTESTED-METADATA if any dep falls back to "
            "un-attested .nimble. Composites with manifest 'attestation-policy "
            "\"strict\"' via OR: once either says strict, the policy is strict "
            "(the flag cannot weaken a manifest-declared strict policy)."
        ),
    )
    # S5 (RFC registry-trust-federation §6.2): index-trust flags.
    parser.add_argument(
        "--require-attested-index",
        action="store_true",
        default=False,
        help=(
            "escalate index-trust policy from 'warn' to 'strict'; CI hard-fail toggle. "
            "Cannot set or clear 'off' — only the manifest can declare index-trust \"off\". "
            "Mirrors --require-attested-metadata for the whole-index attestation axis "
            "(RFC registry-trust-federation §6.2)."
        ),
    )
    parser.add_argument(
        "--refresh-index",
        action="store_true",
        default=False,
        help=(
            "force a fresh index + bundle fetch, bypassing the cache TTL. "
            "Use when upgrading from a pre-RFC cache (no bundle sidecar) or "
            "after a suspected cache-poisoning incident "
            "(RFC registry-trust-federation §6.2, §7.4)."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # fetch
    sp_fetch = subparsers.add_parser(
        "fetch",
        help="resolve manifest, clone deps, emit nim.cfg, write lockfile",
    )
    _add_feature_args(sp_fetch)

    # lock
    sp_lock = subparsers.add_parser(
        "lock",
        help="resolve manifest and write lockfile (no nim.cfg, no _deps/)",
    )
    _add_feature_args(sp_lock)

    # show
    sp_show = subparsers.add_parser(
        "show",
        help="print the resolved dep tree from milpa.lock",
    )
    sp_show.add_argument(
        "--index-trust",
        action="store_true",
        default=False,
        dest="index_trust",
        help=(
            "print index-trust observability: effective policy, cache state, "
            "and bundle claims (no verification — claims only). "
            "spec/cli-contract.md §5.3a."
        ),
    )

    # verify
    subparsers.add_parser(
        "verify",
        help="recheck each dep in _deps/ against milpa.lock",
    )

    # clean
    subparsers.add_parser(
        "clean",
        help="remove _deps/ and nim.cfg (keeps milpa.lock)",
    )

    # add (10e + S10)
    sp_add = subparsers.add_parser(
        "add",
        help="add a new dep or mirror provenance to milpa.kdl",
    )
    sp_add.add_argument("dep_name", metavar="<dep>")
    mode = sp_add.add_mutually_exclusive_group()
    mode.add_argument("--git", metavar="<url>")
    mode.add_argument("--mirror", metavar="<url>")
    sp_add.add_argument("--ref", metavar="<ref>")
    # S10 (RFC #23 §3.7): optional + features flags for `add`.
    sp_add.add_argument(
        "--optional",
        action="store_true",
        default=False,
        help=(
            "mark the dep as optional=#true (RFC #23 §3.2): the dep is only "
            "fetched when its auto-declared feature flag is enabled"
        ),
    )
    sp_add.add_argument(
        "--features",
        metavar="<features>",
        default="",
        help=(
            "comma-separated list of feature flags to request on this dep "
            "(written as `flag` children on the dep node, RFC #23 §3.7)"
        ),
    )

    # remove (stub — 10e)
    sp_remove = subparsers.add_parser(
        "remove",
        help="remove a dep from milpa.kdl (10e, not yet implemented)",
    )
    sp_remove.add_argument("dep_name", metavar="<dep>")

    # update (stub — 10e)
    sp_update = subparsers.add_parser(
        "update",
        help="re-resolve and refresh the lockfile (10e, not yet implemented)",
    )
    sp_update.add_argument("dep_name", metavar="<dep>", nargs="?", default=None)
    _add_feature_args(sp_update)

    # workspace — workspace management subcommands (S10, D4)
    sp_workspace = subparsers.add_parser(
        "workspace",
        help="workspace management (add-member, remove-member)",
    )
    ws_sub = sp_workspace.add_subparsers(dest="workspace_command", metavar="<workspace-command>")

    sp_ws_add = ws_sub.add_parser(
        "add-member",
        help="append a new member to the workspace (appends a member node, then relocks)",
    )
    sp_ws_add.add_argument(
        "member_path",
        metavar="<path>",
        help="path to the member directory (relative to the workspace root)",
    )

    sp_ws_remove = ws_sub.add_parser(
        "remove-member",
        help="remove a member from the workspace (drops the member node, then relocks)",
    )
    sp_ws_remove.add_argument(
        "name_or_path",
        metavar="<name|path>",
        help="member package name or path to remove",
    )

    # hash — content identity probe (A0-cmd slice)
    sp_hash = subparsers.add_parser(
        "hash",
        help=(
            "print the content identity of a source without CAS admission, "
            "lockfile writes, or _deps/ population"
        ),
    )
    sp_hash.add_argument(
        "source",
        nargs="+",
        metavar="<token>",
        help=(
            "source spec tokens: 'git=<url> ref=<sha>' or 'local=<path>'. "
            "The parser accepts the same forms as the manifest dep block."
        ),
    )

    # store — read-only CAS inspection (C-store-ro slice, Phase C)
    sp_store = subparsers.add_parser(
        "store",
        help="inspect the content-addressed store (read-only)",
    )
    store_sub = sp_store.add_subparsers(dest="store_command", metavar="<store-command>")
    store_sub.add_parser(
        "ls",
        help="list all identities in the CAS store (lexicographic order)",
    )
    sp_store_path = store_sub.add_parser(
        "path",
        help="resolve an identity or prefix to its absolute store path",
    )
    sp_store_path.add_argument(
        "identity_or_prefix",
        metavar="<identity-or-prefix>",
        help=(
            "full identity (sha256:<64hex> or bare 64-hex) or a hex-digest prefix "
            "(≥16 hex chars, with or without the 'sha256:' algorithm prefix)"
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# MilpaEnv construction (ONCE per process)
# ---------------------------------------------------------------------------


def _no_index_requested(no_index_flag: bool) -> bool:
    """Single source of truth for "the user wants no index".

    True iff ``--no-index`` was passed OR ``MILPA_INDEX_URL`` is present-but-empty
    (cli-contract §8.1 three-way semantics). The flag takes precedence over any
    env value — it can only ADD the no-index request, never a configured index
    silently re-enabling it.
    """
    if no_index_flag:
        return True
    raw = os.environ.get("MILPA_INDEX_URL")  # None if absent, str if set
    return raw is not None and raw.strip() == ""


def _build_env(no_index: bool = False) -> MilpaEnv:
    """Build the MilpaEnv seam from the process environment.

    - MILPA_MOCKED_FETCHES set → mocked transport (conformance mode).
    - otherwise → real transport.
    - store → default_store() (honours MILPA_CACHE_DIR / XDG).
    - index → None at this point; loaded eagerly per-verb when needed.
    - dep_decl_store (S3b):
        MILPA_DEP_DECL_DIR set → FileDepDeclStore (harness / air-gapped).
        else → HttpDepDeclStore derived from MILPA_INDEX_URL (production).
        ``None`` when MILPA_INDEX_URL is also absent (e.g. pure URL-dep project
        with no index) — the DepDecl branch is unreachable in that case anyway.
    - no_index (``--no-index``) → suppress index + dep_decl_store entirely.
    """
    store: CAStore = default_store()

    mocked_dir = os.environ.get("MILPA_MOCKED_FETCHES", "").strip()
    inner = mocked_registry(Path(mocked_dir)) if mocked_dir else build_registry()

    fetcher = CasAdmittingFetcher(inner, store)

    # S3b: build dep_decl_store from environment — suppressed under no-index.
    dep_decl_store: object | None = _build_dep_decl_store(no_index=no_index)

    return MilpaEnv(
        fetcher=fetcher,
        index=None,  # loaded eagerly per-verb
        store=store,
        dep_decl_store=dep_decl_store,
        no_index=no_index,
    )


def _build_dep_decl_store(no_index: bool = False) -> object | None:
    """Build the dep_decl_store from environment variables (S3b).

    Resolves env vars to canonical paths/URLs, then delegates to the SINGLE
    priority definition ``dep_decl_store_from_paths`` in dep_decl_store.py
    (H1 unification — CLI and in-process conformance adapter share one path).

    Priority:
      0. ``--no-index`` → ``None`` (no index ⇒ DepDecl path unreachable).
      1. ``MILPA_DEP_DECL_DIR`` → ``FileDepDeclStore`` (conformance / air-gapped).
      2. ``MILPA_INDEX_URL`` **absent** → ``HttpDepDeclStore`` from ``DEFAULT_INDEX_URL``.
      3. ``MILPA_INDEX_URL`` **present and non-empty** → ``HttpDepDeclStore`` from that URL.
      4. ``MILPA_INDEX_URL`` **present but empty** → ``None`` (explicitly no index;
         DepDecl branch unreachable).

    Three-way env semantics match ``_load_index_for_verb``:
    absent → default, empty → no-index, non-empty → that URL. The ``--no-index``
    flag forces case 4 regardless of env.
    """
    from milpa.dep_decl_store import dep_decl_store_from_paths
    from milpa.index_cache import DEFAULT_INDEX_URL

    # Resolve env vars to canonical values before handing to the shared helper.
    dep_decl_dir_str = os.environ.get("MILPA_DEP_DECL_DIR", "").strip()
    dep_decl_dir = Path(dep_decl_dir_str) if dep_decl_dir_str else None

    raw = os.environ.get("MILPA_INDEX_URL")  # None if absent, str if set
    # Three-way semantics: absent → DEFAULT_INDEX_URL; empty → None (no index);
    # non-empty → that URL.
    if raw is None:
        index_url: str | None = DEFAULT_INDEX_URL
    else:
        stripped = raw.strip()
        index_url = stripped if stripped else None  # empty → explicitly no index

    return dep_decl_store_from_paths(
        dep_decl_dir=dep_decl_dir,
        index_url=index_url,
        no_index=_no_index_requested(no_index),
    )


# ---------------------------------------------------------------------------
# Index loading helper (for fetch / lock)
# ---------------------------------------------------------------------------


def _load_manifest_trust_fields(
    project_dir: Path,
) -> "tuple[str, str | None, str | None]":
    """Load (policy, signer, bundle) from the resolution ROOT.  Pure I/O.

    index-trust is a root-only policy (spec §3.4.7): the resolution root is the
    workspace root manifest (for a workspace) or the package manifest itself
    (standalone).  Members MUST NOT declare it — ``find_workspace_root`` (via the
    ``load_workspace`` it performs) raises ``WS-INDEX-TRUST-ON-MEMBER`` when one
    does, and that error PROPAGATES from here rather than being swallowed, so
    ``cmd_show_index_trust`` surfaces exactly what the enforcement gate would.

    Only a genuinely-absent standalone manifest degrades to ``("warn", None,
    None)``; a present-but-invalid workspace is a hard error.

    SSOT shared by ``_build_index_trust`` (enforcement gate) and
    ``cmd_show_index_trust`` (observability) — spec §5.3a.
    """
    # Workspace root is the authority for index-trust.  UNGUARDED on purpose: a
    # present-but-invalid workspace (e.g. a member illegally declaring
    # index-trust) MUST raise, not silently fall back to warn.
    ws = find_workspace_root(project_dir)
    if ws is not None:
        wm = ws.workspace_manifest
        return (
            str(wm.index_trust_policy),
            wm.index_trust_signer,
            wm.index_trust_bundle,
        )
    # Standalone package is its own root.  A genuinely-absent manifest (not a
    # workspace, no package manifest) degrades to defaults.
    try:
        m = load_or_discover_manifest(project_dir)
    except (OSError, MilpaError):
        return "warn", None, None
    return str(m.index_trust_policy), m.index_trust_signer, m.index_trust_bundle


def _build_index_trust(
    env: MilpaEnv,
    project_dir: Path,
) -> "tuple[object, object] | tuple[None, None]":
    """Build ``(IndexTrustConfig, IndexBundleVerifier)`` for the index-trust gate.

    Returns ``(None, None)`` when the effective policy is ``'off'`` (gate disabled).

    Authority model (spec §3.4.5 / RFC registry-trust-federation §6.6):
    1. Load manifest index-trust fields (policy, signer, bundle) via
       ``_load_manifest_trust_fields`` (the SSOT shared with ``cmd_show_index_trust``).
    2. Compute effective policy = effective_trust_policy(manifest, flag, env).
    3. If off → return (None, None).
    4. Build IndexTrustConfig from policy + signer + trust_bundle + max_age.
    5. Build verifier: MockVerifier from MILPA_INDEX_TRUST_MOCK_VERIFIER
       (conformance/test seam) or SigstoreVerifier (production).

    MILPA_INDEX_TRUST_MOCK_VERIFIER conformance seam (spec/cli-contract.md §8.6.6):
    When set to one of the 7 wire strings (trusted / sig-invalid /
    digest-mismatch / signer-mismatch / bundle-stale / bundle-missing /
    bundle-malformed), the CLI injects a ``MockVerifier(result)`` instead of
    ``SigstoreVerifier``.  Invalid values are rejected with ``MILPA-INTERNAL``
    (the seam must never fail-open silently).  This seam is IDENTICAL to the
    Rust impl's seam (same single env var name and value semantics) so the shared
    S7 conformance corpus can drive both impls via environment injection.

    IMPORTANT: ``MILPA_INDEX_TRUST_MOCK_VERIFIER`` is ONLY honored when the
    resolved index URL has a ``file://`` scheme (all conformance fixtures and
    hermetic tests use file:// indexes; production indexes are https).  Attempting
    to set the mock seam with a non-file:// index URL raises ``MILPA-INTERNAL``
    — fail closed and visible, never silently bypass.
    """
    import os

    from milpa.index_trust import (
        DEFAULT_INDEX_SIGNER,
        IndexTrustConfig,
        MockVerifier,
        SigstoreVerifier,
        TrustBundle,
        VerificationResult,
    )
    from milpa.trust import effective_trust_policy

    # 1. Read index-trust env vars.
    env_trust_raw = os.environ.get("MILPA_INDEX_TRUST", "").strip() or None
    env_signer = os.environ.get("MILPA_INDEX_TRUST_SIGNER", "").strip() or None
    env_bundle_path = os.environ.get("MILPA_INDEX_TRUST_BUNDLE", "").strip() or None
    env_max_age_raw = os.environ.get("MILPA_INDEX_MAX_AGE", "").strip()
    env_max_age = 604800  # default: 7 days
    if env_max_age_raw:
        try:
            env_max_age = int(env_max_age_raw)
        except ValueError:
            pass  # invalid value: fall back to default (main() already warned)

    # 2. Load manifest index-trust fields (policy, signer, bundle) via SSOT helper.
    manifest_policy, manifest_signer, manifest_bundle = _load_manifest_trust_fields(project_dir)

    # 3. Compute effective policy.
    policy = effective_trust_policy(
        manifest_policy,  # type: ignore[arg-type]
        flag=env.require_attested_index,
        env_override=env_trust_raw,
    )

    if policy == "off":
        return None, None

    # 4. Build trust bundle: env override path > manifest path > production embedded.
    bundle_path = env_bundle_path or manifest_bundle
    if bundle_path:
        # spec/cli-contract.md §8.6 NORMATIVE: the value MUST be a file:// URL.
        # Bare paths (no file:// prefix) MUST be rejected.
        if not bundle_path.startswith("file://"):
            raise MilpaError(
                MILPA_INTERNAL,
                f"MILPA_INDEX_TRUST_BUNDLE (or index-trust-bundle manifest node) "
                f"must be a file:// URL; got: {bundle_path!r}. "
                f"Use file:///abs/path/to/bundle.json (three slashes for an absolute path).",
            )
        # Strip the file:// scheme to get a filesystem path.
        fs_path = bundle_path[len("file://"):]
        try:
            raw = Path(fs_path).read_bytes()
        except OSError as exc:
            raise MilpaError(
                MILPA_INTERNAL,
                f"cannot read index-trust-bundle file {fs_path!r}: {exc}",
                path=fs_path,
            ) from exc
        trust_bundle = TrustBundle(raw_json=raw, label=f"custom:{fs_path}")
    else:
        trust_bundle = TrustBundle.production()

    # 5. Build expected signer: env > manifest > default tianguis signer (SSOT constant).
    expected_signer = env_signer or manifest_signer or DEFAULT_INDEX_SIGNER

    config = IndexTrustConfig(
        policy=policy,
        trust_bundle=trust_bundle,
        expected_signer=expected_signer,
        max_age_seconds=env_max_age,
    )

    # 6. Build verifier: MockVerifier from conformance seam, SigstoreVerifier in production.
    _MOCK_MAP = {
        "trusted": VerificationResult.TRUSTED,
        "sig-invalid": VerificationResult.SIG_INVALID,
        "digest-mismatch": VerificationResult.DIGEST_MISMATCH,
        "signer-mismatch": VerificationResult.SIGNER_MISMATCH,
        "bundle-stale": VerificationResult.BUNDLE_STALE,
        "bundle-missing": VerificationResult.BUNDLE_MISSING,
        "bundle-malformed": VerificationResult.BUNDLE_MALFORMED,
    }
    mock_result_str = os.environ.get("MILPA_INDEX_TRUST_MOCK_VERIFIER", "").strip()
    if mock_result_str:
        # Guard: mock seam is conformance-internal; ONLY honored for file:// indexes.
        # Production indexes are https; using the mock seam on https would silently
        # bypass real Sigstore verification in a misconfigured non-test environment.
        raw_index_url = os.environ.get("MILPA_INDEX_URL", "")
        if not raw_index_url.startswith("file://"):
            raise MilpaError(
                MILPA_INTERNAL,
                "MILPA_INDEX_TRUST_MOCK_VERIFIER is conformance-internal and only "
                "honored for file:// index URLs (all conformance fixtures use file://; "
                "production indexes are https). This variable must not be set in "
                "production or with non-file:// index URLs.",
            )
        mock_result = _MOCK_MAP.get(mock_result_str)
        if mock_result is None:
            raise MilpaError(
                MILPA_INTERNAL,
                f"MILPA_INDEX_TRUST_MOCK_VERIFIER={mock_result_str!r} is not a valid "
                f"VerificationResult wire string (expected one of: {', '.join(_MOCK_MAP)}). "
                "Test seam must never fail-open silently.",
            )
        verifier: object = MockVerifier(mock_result)
    else:
        verifier = SigstoreVerifier()

    return config, verifier


def _load_index_for_verb(env: MilpaEnv, project_dir: "Path | None" = None) -> MilpaEnv:
    """Return a new MilpaEnv with the index eagerly loaded (or None if unreachable).

    Reads MILPA_INDEX_URL (cli-contract.md §8.1) using three-way semantics:

    - ``MILPA_INDEX_URL`` **absent** from env → load from ``DEFAULT_INDEX_URL``
      (the live tianguis index). Network failure → ``index=None`` (soft; the
      resolver raises RES-NO-INDEX only if a named dep needs the index).
    - ``MILPA_INDEX_URL`` **present but empty** (``""``) → explicitly NO index;
      ``index=None`` without any network attempt. Used by the harness for
      air-gapped fixtures that contain no ``index.kdl``.
    - ``MILPA_INDEX_URL`` **present and non-empty** → load from that URL.

    When ``project_dir`` is provided, the manifest's ``index-trust`` policy,
    signer, and bundle are loaded and merged with env vars / CLI flags to build
    the ``IndexTrustConfig`` that is passed to ``load_default_index`` (C1 fix:
    the trust gate was previously unplumbed — ``load_default_index()`` was called
    bare with no config/verifier).

    TNG-* parse errors always propagate — the index was fetched but failed
    validation; the correct slug is more useful than silently treating a
    malformed index as absent.

    spec/cli-contract.md §8.1 NORMATIVE.
    """
    from dataclasses import replace

    from milpa.errors import MILPA_INDEX_UNREACHABLE

    # --no-index flag OR present-but-empty MILPA_INDEX_URL → explicitly no
    # index (the flag overrides any configured index). Absent → default URL.
    if _no_index_requested(env.no_index):
        return replace(env, index=None)

    # Build IndexTrustConfig + verifier when project_dir is provided.
    config: object = None
    verifier: object = None
    if project_dir is not None:
        config, verifier = _build_index_trust(env, project_dir)

    # Absent → DEFAULT_INDEX_URL; non-empty → that URL.
    # load_default_index() calls index_url_from_env() which handles both cases.
    try:
        index = load_default_index(
            config=config,
            verifier=verifier,
            refresh=env.refresh_index,
        )
    except MilpaError as exc:
        if exc.slug == MILPA_INDEX_UNREACHABLE:
            # Unreachable index → let the resolver raise RES-NO-INDEX per dep.
            return replace(env, index=None)
        raise  # TNG-* and other catalog errors propagate
    return replace(env, index=index)


# ---------------------------------------------------------------------------
# Prior-lockfile loader (§8 pin reuse)
# ---------------------------------------------------------------------------


def _maybe_load_prior_lockfile(lock_path: Path) -> None | object:
    """Load the existing lockfile for §8 prior-pin reuse, or return None.

    Silently returns None on any failure (file absent = no prior; parse
    failure = no prior — don't fail the resolve for a corrupt prior lock).
    """
    try:
        return load_lockfile(lock_path)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Atomic file write helper
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, text: str) -> None:
    """Write *text* to *path* atomically (sibling tmp + os.replace).

    cli-contract.md §5.6: writes must be atomic so a mid-write kill leaves
    the file unmodified.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except Exception:
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Certificate write helper (cli-contract.md §2.5)
# ---------------------------------------------------------------------------


def _write_certificate(
    cert_path: Path | None,
    result: object,
) -> None:
    """Atomically write the solve result certificate to *cert_path*.

    ``result`` must be a ``SolveSuccess`` (success), ``SolverError``
    (solver failure), or ``None`` (non-solver MilpaError failure such as
    RES-UNATTESTED-METADATA — emits kind:failure with empty refutation, matching
    Rust's FailureCert { message: "", refutation: [] } shape).

    Uses ``certificate_to_json`` as the SSOT serialiser.  No-op when
    ``cert_path`` is None.

    Atomic discipline: write to a sibling tmp, then os.replace.  If the
    serialisation or write fails, the file at cert_path is left absent or
    unchanged (cli-contract.md §2.5 NORMATIVE).
    """
    if cert_path is None:
        return
    assert result is None or isinstance(result, (SolveSuccess, SolverError)), (
        f"_write_certificate: expected SolveSuccess, SolverError, or None, got {type(result)!r}"
    )
    cert_json = certificate_to_json(result)  # type: ignore[arg-type]
    _atomic_write(cert_path, cert_json)


# ---------------------------------------------------------------------------
# S9: frozen active-flags mismatch check (RFC #23 §3.4 + §4)
# ---------------------------------------------------------------------------


def _check_frozen_active_flags_mismatch(
    manifest: object,
    lockfile: object,
    *,
    features: frozenset[str],
    no_default_features: bool,
    all_features: bool,
) -> None:
    """S9 (RFC #23 §3.4 + §4): FROZEN-ACTIVE-FLAGS-MISMATCH check.

    Under ``--frozen``, recompute the active-flag closure from the current
    manifest + CLI feature inputs and compare to the lockfile's stored
    ``active_flags`` per dep.  A mismatch raises ``FROZEN-ACTIVE-FLAGS-MISMATCH``.

    Per RFC §4: "The frozen check recomputes the active closure from the
    **current manifest + the CLI feature inputs supplied now**" and compares
    it to the lockfile.  It must NOT re-derive from the stored flags (that is
    circular and would pass a pre-RFC lock vacuously).

    When no CLI feature flags are active (no --features/--no-default-features/
    --all-features), the check computes the closure from manifest defaults —
    this catches the case where manifest defaults changed since the lock was
    written.

    Implementation note: the per-dep active_flags in the lockfile are the
    *union* of all consumers' requests after fixpoint convergence; the root-level
    closure we compute here is only the ROOT manifest's active set.  We compare
    the ROOT's computed active_flags to the ROOT's deps' active_flags as stored
    in the lockfile.  A full dep×flag fixpoint recomputation would require a
    live fetch (which frozen forbids); therefore the check is limited to the root
    manifest's own flags vs. the locked root-dep set.  This is the de-circularized
    check from §4: recompute from manifest+CLI, NOT from stored flags.
    """
    from milpa.lockfile import Lockfile as _Lockfile
    from milpa.resolver import _compute_root_active_seed

    if not isinstance(manifest, Manifest) or not isinstance(lockfile, _Lockfile):
        return  # defensive: skip if types don't match (workspace path)

    # Compute the expected root active-flag closure from manifest + CLI inputs.
    has_cli_features = bool(features) or no_default_features or all_features
    try:
        if has_cli_features:
            seed = _compute_root_active_seed(
                manifest,
                features=features,
                no_default_features=no_default_features,
                all_features=all_features,
            )
        else:
            # Default: default-true flags.
            seed = frozenset(fd.name for fd in manifest.flags if fd.default)
    except MilpaError:
        raise  # FROZEN-ACTIVE-FLAGS-MISMATCH from _compute_root_active_seed

    expected_active: frozenset[str] = flag_enables_closure(manifest.flags, seed)

    # NOTE: heuristic — lockfile schema v1 has no root_active_flags field, so
    # we detect drift via flag-gated root-dep admission.  Exact check tracked
    # in gh #158.
    locked_names: set[str] = {d.name for d in lockfile.deps}
    root_dep_names: set[str] = {
        getattr(d, "name", None)
        for d in list(getattr(manifest, "deps", [])) + list(getattr(manifest, "dev_deps", []))
        if getattr(d, "name", None)
    }

    # For each root dep, check if it has a flag predicate.  If its gate flag
    # is NOT in expected_active but the dep IS in the lock → stale lock.
    # If its gate flag IS in expected_active but the dep is NOT in the lock →
    # stale lock.
    for dep in list(getattr(manifest, "deps", [])) + list(getattr(manifest, "dev_deps", [])):
        preds: tuple = dep.predicates
        flag_preds = [p for p in preds if getattr(p, "name", None) == "flag"]
        if not flag_preds:
            continue  # Not flag-gated — no mismatch from feature selection.
        dep_name = getattr(dep, "name", None)
        if dep_name is None:
            continue

        # Route through SSOT: dep_passes_flag_predicates evaluates all flag
        # predicates (OR-within-values, negation, conjunction across predicates).
        would_admit = dep_passes_flag_predicates(preds, expected_active)
        is_locked = dep_name in locked_names

        if would_admit != is_locked:
            raise MilpaError(
                FROZEN_ACTIVE_FLAGS_MISMATCH,
                f"lockfile active-flags mismatch for dep {dep_name!r}: "
                f"the lock was produced under a different feature selection — "
                f"re-run 'milpa fetch' with the same --features / --no-default-features "
                f"/ --all-features flags that were used to write the lock",
                dep=dep_name,
                expected_active=sorted(expected_active),
                locked=is_locked,
                would_admit=would_admit,
            )


# ---------------------------------------------------------------------------
# Workspace frozen active-flags mismatch check (S2 — RFC workspace-completion §3.A)
# ---------------------------------------------------------------------------


def _check_workspace_frozen_active_flags_mismatch(
    workspace: object,
    lockfile: object,
    *,
    features: frozenset[str],
    no_default_features: bool,
    all_features: bool,
) -> None:
    """S2 (RFC: workspace-completion §3.A / Breadth-P1b): workspace analog of
    ``_check_frozen_active_flags_mismatch``.

    For each member in the workspace, recomputes the active-flag closure using
    the member's own flags + the CLI feature inputs (mirroring how the workspace
    resolver builds FilterContext per member).  If a flag-gated member dep's
    admission status disagrees with the lockfile (admitted-but-absent or
    excluded-but-present), raises ``FROZEN-ACTIVE-FLAGS-MISMATCH``.

    Called from the workspace frozen CLI path BEFORE ``resolve_workspace_frozen``
    so the correct slug fires rather than ``FROZEN-MANIFEST-DEP-NOT-IN-LOCK``.
    Per ``cli-contract.md:318-325``, workspaces are NOT exempt from this check.
    """
    from milpa.errors import FROZEN_ACTIVE_FLAGS_MISMATCH as _FAMM
    from milpa.lockfile import Lockfile as _Lockfile
    from milpa.workspace import LoadedWorkspace as _LoadedWorkspace

    if not isinstance(workspace, _LoadedWorkspace) or not isinstance(lockfile, _Lockfile):
        return

    locked_names: set[str] = {d.name for d in lockfile.deps}

    # Compute the workspace-root cli_seed (same logic as resolve_workspace S2 patch).
    _ws_has_cli_features = bool(features) or no_default_features or all_features
    _ws_cli_seed: frozenset[str] | None = None
    if _ws_has_cli_features:
        _ws_root_declared: frozenset[str] = frozenset(
            fd.name for fd in workspace.workspace_manifest.flags
        )
        _unknown_feats = features - _ws_root_declared
        if _unknown_feats:
            raise MilpaError(
                _FAMM,
                f"--features names flags not declared in the workspace root flags "
                f"block: {sorted(_unknown_feats)}",
                unknown=sorted(_unknown_feats),
            )
        if all_features:
            _ws_cli_seed = _ws_root_declared
        elif no_default_features:
            _ws_cli_seed = features
        else:
            _ws_default_seed: frozenset[str] = frozenset(
                fd.name for fd in workspace.workspace_manifest.flags if fd.default
            )
            _ws_cli_seed = _ws_default_seed | features
    else:
        # No CLI features — use workspace root defaults as seed.
        _ws_cli_seed = frozenset(
            fd.name for fd in workspace.workspace_manifest.flags if fd.default
        )
        if not _ws_cli_seed:
            _ws_cli_seed = None  # No root flags → no flag filtering at all.

    for member in workspace.members:
        # Compute per-member active set from member's own flags + ws_cli_seed.
        _member_active: frozenset[str]
        if _ws_cli_seed is not None:
            _member_active = flag_enables_closure(member.manifest.flags, _ws_cli_seed)
        else:
            _member_active = frozenset()

        for dep in list(member.manifest.deps) + list(member.manifest.dev_deps):
            preds = dep.predicates
            flag_preds = [p for p in preds if getattr(p, "name", None) == "flag"]
            if not flag_preds:
                continue
            dep_name = dep.name
            would_admit = dep_passes_flag_predicates(preds, _member_active)
            is_locked = dep_name in locked_names
            if would_admit != is_locked:
                raise MilpaError(
                    _FAMM,
                    f"workspace member {member.manifest.name!r}: frozen lockfile "
                    f"active-flags mismatch for dep {dep_name!r}: "
                    f"the lock was produced under a different feature selection — "
                    f"re-run 'milpa fetch' with the same --features flags that were "
                    f"used to write the lock",
                    dep=dep_name,
                    expected_active=sorted(_member_active),
                    locked=is_locked,
                    would_admit=would_admit,
                )


# ---------------------------------------------------------------------------
# cmd_fetch (10b)
# ---------------------------------------------------------------------------


def cmd_fetch(
    project_dir: Path,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
    frozen: bool,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
) -> int:
    """Resolve, fetch, emit nim.cfg + milpa.lock.

    Frozen fast-path:
    - Attempt if lockfile + CAS available.
    - --frozen absent → silent fallthrough on failure.
    - --frozen present → FROZEN-* slug + exit 1 on failure.

    Two CLI-level guards are raised HERE before entering the frozen resolver:
    - FROZEN-NO-LOCKFILE: lockfile absent.
    - FROZEN-NO-CAS: CAS not available (store missing).
    """
    # Workspace detection (cli-contract.md §7.1).
    ws = find_workspace_root(project_dir)

    if ws is not None:
        return _cmd_fetch_workspace(
            project_dir=project_dir,
            workspace=ws,
            env=env,
            strategy=strategy,
            max_parallel=max_parallel,
            frozen=frozen,
            certificate_path=certificate_path,
            require_attested_metadata=require_attested_metadata,
            features=features,
            no_default_features=no_default_features,
            all_features=all_features,
        )

    # --- Single-package path ---

    # Load manifest first (needed for frozen checks + self_src_dir).
    manifest = load_or_discover_manifest(project_dir)
    self_src_dir = manifest.src_dir or ""

    # deps_dir: absolute for filesystem operations; relative for nim.cfg paths.
    lock_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"
    _DEPS_RELATIVE = Path("_deps")  # relative form for nim.cfg

    # CLI-level guard 1: FROZEN-NO-LOCKFILE.
    if not lock_path.exists():
        if frozen:
            print("frozen: no lockfile found", file=sys.stderr)
            _emit_slug(FROZEN_NO_LOCKFILE)
            return 1
    else:
        # Attempt the frozen fast-path.
        # FROZEN-NO-CAS: our store is always available (default_store); the
        # resolver raises FROZEN-IDENTITY-NOT-IN-STORE per-dep if the CAS has
        # no entry.  FROZEN-NO-CAS would apply if store=None, which never happens.
        try:
            prior_lock = load_lockfile(lock_path)
            # S9 (RFC #23 §3.4): FROZEN-ACTIVE-FLAGS-MISMATCH check.
            # Recompute the active-flag closure from the current manifest + CLI
            # feature inputs; compare to the lockfile's stored active_flags.
            # A mismatch means the lock was produced under a different selection.
            _check_frozen_active_flags_mismatch(
                manifest, prior_lock,
                features=features,
                no_default_features=no_default_features,
                all_features=all_features,
            )
            frozen_graph = resolve_frozen(manifest, prior_lock, env, deps_dir)
            # Frozen path succeeded.
            nim_cfg_text = format_nimcfg(
                frozen_graph,
                deps_dir=_DEPS_RELATIVE,
                self_src_dir=self_src_dir,
                flag_defines=build_flag_defines(frozen_graph, deps_dir),
            )
            _atomic_write(project_dir / "nim.cfg", nim_cfg_text)
            print(
                f"resolved {len(frozen_graph.deps)} deps (frozen)",
                file=sys.stderr,
            )
            return 0
        except MilpaError as exc:
            if frozen:
                print(f"frozen: {exc.message}", file=sys.stderr)
                _emit_slug(exc.slug)
                return 1
            # Silent fallthrough to full resolve.
        except Exception as exc:
            if frozen:
                print(f"frozen: {exc}", file=sys.stderr)
                _emit_slug(MILPA_INTERNAL)
                return 1
            # Silent fallthrough.

    # Full resolve path — load index.
    env_with_index = _load_index_for_verb(env, project_dir)

    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  SOLVE-CONFLICT carries a
    # populated SolverError; all other MilpaError failures get an empty cert
    # (kind:failure, message:null, refutation:[]) matching Rust's behaviour.
    try:
        graph = resolve(manifest, deps_dir, env_with_index, params)
    except MilpaError as exc:
        if certificate_path is not None:
            if exc.slug == "SOLVE-CONFLICT":
                solver_err = exc.context.get("solver_error")
                _write_certificate(certificate_path, solver_err)
            else:
                _write_certificate(certificate_path, None)
        raise

    # Success: write the certificate (built by the resolver, attached to graph).
    if certificate_path is not None and graph.cert is not None:
        _write_certificate(certificate_path, graph.cert)

    lockfile = from_graph(graph, strategy=str(strategy))
    nim_cfg_text = format_nimcfg(
        graph,
        deps_dir=_DEPS_RELATIVE,
        self_src_dir=self_src_dir,
        flag_defines=build_flag_defines(graph, deps_dir),
    )
    write_lockfile(lockfile, lock_path)
    _atomic_write(project_dir / "nim.cfg", nim_cfg_text)
    print(f"resolved {len(graph.deps)} deps", file=sys.stderr)
    return 0


def _cmd_fetch_workspace(
    project_dir: Path,
    workspace: object,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
    frozen: bool,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
) -> int:
    """Workspace variant of cmd_fetch."""
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    # Frozen fast-path.
    if not lock_path.exists():
        if frozen:
            print("frozen: no lockfile found", file=sys.stderr)
            _emit_slug(FROZEN_NO_LOCKFILE)
            return 1
    else:
        try:
            prior_lock = load_lockfile(lock_path)
            # S2 (RFC: workspace-completion §3.A / Breadth-P1b):
            # FROZEN-ACTIVE-FLAGS-MISMATCH check for workspaces.  Must run BEFORE
            # resolve_workspace_frozen so the correct slug fires rather than
            # FROZEN-MANIFEST-DEP-NOT-IN-LOCK.  Per cli-contract.md:318-325,
            # workspaces are NOT exempt from this check.
            _check_workspace_frozen_active_flags_mismatch(
                workspace, prior_lock,
                features=features,
                no_default_features=no_default_features,
                all_features=all_features,
            )
            # Compute the profile and ws_cli_seed for resolve_workspace_frozen so it
            # can filter member deps (flag-excluded deps must not fire
            # FROZEN-MANIFEST-DEP-NOT-IN-LOCK).
            _frozen_profile = Profile.from_environment()
            _frozen_cli_seed: frozenset[str] | None
            _ws_has_feats = bool(features) or no_default_features or all_features
            if _ws_has_feats:
                from milpa.resolver import _compute_workspace_cli_seed as _cws
                _frozen_cli_seed = _cws(workspace.workspace_manifest, features, no_default_features, all_features)
            else:
                _frozen_cli_seed = None
            frozen_graph = resolve_workspace_frozen(
                workspace, prior_lock, env, deps_dir,
                profile=_frozen_profile, cli_seed=_frozen_cli_seed,
            )
            # Emit per-member nim.cfgs. flag_defines carries the workspace-wide
            # flag-union -d: defines (§3.8); without it members lose their defines.
            per_member = format_workspace_nimcfgs(
                workspace, frozen_graph,
                flag_defines=build_flag_defines(frozen_graph, deps_dir),
            )
            for rel_path, nim_cfg_text in per_member.items():
                _atomic_write(ws_root / rel_path / "nim.cfg", nim_cfg_text)
            print(
                f"resolved {len(frozen_graph.deps)} deps across "
                f"{len(workspace.members)} members (frozen); "
                f"emitted {len(per_member)} nim.cfg(s)",
                file=sys.stderr,
            )
            return 0
        except MilpaError as exc:
            if frozen:
                print(f"frozen: {exc.message}", file=sys.stderr)
                _emit_slug(exc.slug)
                return 1
        except Exception as exc:
            if frozen:
                print(f"frozen: {exc}", file=sys.stderr)
                _emit_slug(MILPA_INTERNAL)
                return 1

    # Full workspace resolve.
    env_with_index = _load_index_for_verb(env, ws_root)
    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  Mirrors the single-package path.
    try:
        graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
    except MilpaError as exc:
        if certificate_path is not None:
            if exc.slug == "SOLVE-CONFLICT":
                solver_err = exc.context.get("solver_error")
                _write_certificate(certificate_path, solver_err)
            else:
                _write_certificate(certificate_path, None)
        raise

    # Success: write the certificate (built by the resolver, attached to graph).
    if certificate_path is not None and graph.cert is not None:
        _write_certificate(certificate_path, graph.cert)

    lockfile = from_graph(graph, strategy=str(strategy))
    per_member = format_workspace_nimcfgs(
        workspace, graph, flag_defines=build_flag_defines(graph, deps_dir),
    )

    write_lockfile(lockfile, lock_path)
    for rel_path, nim_cfg_text in per_member.items():
        _atomic_write(ws_root / rel_path / "nim.cfg", nim_cfg_text)

    print(
        f"resolved {len(graph.deps)} deps across "
        f"{len(workspace.members)} members; "
        f"emitted {len(per_member)} nim.cfg(s)",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# cmd_lock (10b)
# ---------------------------------------------------------------------------


def cmd_lock(
    project_dir: Path,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
) -> int:
    """Resolve + write milpa.lock; do NOT emit nim.cfg or populate _deps/.

    Always full-resolves (never frozen fast-path). Still passes a loaded
    prior lockfile for §8 pin reuse (cli-contract.md §5.2).
    """
    ws = find_workspace_root(project_dir)
    if ws is not None:
        return _cmd_lock_workspace(
            workspace=ws,
            env=env,
            strategy=strategy,
            max_parallel=max_parallel,
            certificate_path=certificate_path,
            require_attested_metadata=require_attested_metadata,
            features=features,
            no_default_features=no_default_features,
            all_features=all_features,
        )

    manifest = load_or_discover_manifest(project_dir)
    lock_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"

    env_with_index = _load_index_for_verb(env, project_dir)
    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  Mirrors the fetch path.
    try:
        graph = resolve(manifest, deps_dir, env_with_index, params)
    except MilpaError as exc:
        if certificate_path is not None:
            if exc.slug == "SOLVE-CONFLICT":
                solver_err = exc.context.get("solver_error")
                _write_certificate(certificate_path, solver_err)
            else:
                _write_certificate(certificate_path, None)
        raise

    # Success: write the certificate (built by the resolver, attached to graph).
    if certificate_path is not None and graph.cert is not None:
        _write_certificate(certificate_path, graph.cert)

    lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile, lock_path)
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


def _cmd_lock_workspace(
    workspace: object,
    env: MilpaEnv,
    *,
    strategy: Strategy,
    max_parallel: int,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
) -> int:
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    env_with_index = _load_index_for_verb(env, ws_root)
    prior = _maybe_load_prior_lockfile(lock_path)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  Mirrors the fetch path.
    try:
        graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
    except MilpaError as exc:
        if certificate_path is not None:
            if exc.slug == "SOLVE-CONFLICT":
                solver_err = exc.context.get("solver_error")
                _write_certificate(certificate_path, solver_err)
            else:
                _write_certificate(certificate_path, None)
        raise

    # Success: write the certificate (built by the resolver, attached to graph).
    if certificate_path is not None and graph.cert is not None:
        _write_certificate(certificate_path, graph.cert)

    lockfile = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile, lock_path)
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_show (10c)
# ---------------------------------------------------------------------------


def cmd_show(project_dir: Path) -> int:
    """Read milpa.lock and print the dep tree to stdout.

    stdout: dep tree (one block per dep).
    stderr: error diagnostics only.
    """
    lock_path = project_dir / "milpa.lock"
    if not lock_path.exists():
        print(
            f"no lockfile found at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1
    try:
        lockfile = load_lockfile(lock_path)
    except MilpaError as exc:
        print(f"failed to read lockfile: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    for dep in lockfile.deps:
        print(f"{dep.name:20s} {dep.version}")
        if dep.identity:
            algo, _, digest = dep.identity.partition(":")
            print(f"  identity    {algo}:{digest[:8]}")
        for prov in dep.provenances:
            print(f"  provenance  {_format_provenance(prov)}")
        if dep.requires:
            print(f"  requires    {', '.join(dep.requires)}")
        # S4: display cond_requires (one line per conditional require).
        for cr in dep.cond_requires:
            preds_str = ", ".join(
                f"{p.name}{'!=' if p.negated else '='}{p.values[0]}"
                for p in cr.predicates
            )
            print(f"  cond-req    {cr.name} [{preds_str}]")
        # S10 (RFC #23 §3.7): print per-dep active_flags so a user can see
        # that a transitive optional dep is present (the `cargo tree -e features` need).
        if dep.active_flags:
            print(f"  active_flags {' '.join(dep.active_flags)}")
        # S1 (rfc-resolver-correctness.md #142): surface aliases so a user can see
        # that a dep was deduped (e.g. "bar" → canonical "foo").
        if dep.aliases:
            print(f"  aliases     {', '.join(sorted(dep.aliases))}")
    return 0


def _format_provenance(p: object) -> str:
    from milpa.lockfile import (
        GitProvenanceRecord,
        LocalProvenanceRecord,
        MemberProvenanceRecord,
        OciProvenanceRecord,
        TarballProvenanceRecord,
    )

    if isinstance(p, GitProvenanceRecord):
        parts = [f"git {p.url}"]
        if p.ref:
            parts.append(f"@ {p.ref}")
        if p.commit_sha:
            parts.append(f"(sha {p.commit_sha[:8]})")
        return " ".join(parts)
    if isinstance(p, TarballProvenanceRecord):
        return f"tarball {p.url}"
    if isinstance(p, LocalProvenanceRecord):
        return f"local {p.path}"
    if isinstance(p, MemberProvenanceRecord):
        return f"member {p.name}"
    if isinstance(p, OciProvenanceRecord):
        return f"oci {p.registry}/{p.repository}@{p.digest[:15]}"
    return str(p)


# ---------------------------------------------------------------------------
# cmd_show_index_trust (show --index-trust)
# ---------------------------------------------------------------------------


def cmd_show_index_trust(project_dir: Path) -> int:
    """Print index-trust observability: effective policy + cached bundle claims.

    Reads the configured index URL, locates its cached index and bundle sidecars
    (if any), and prints the observable claims in the fixed-width label format
    defined by ``format_index_trust_info``.

    This command describes CLAIMS ONLY — no cryptographic verification is
    performed.  Verification is enforced at fetch/lock time; this command is
    for human audit of what is cached.

    The effective policy is computed via ``_load_manifest_trust_fields`` — the
    SAME helper used by the enforcement gate in ``_build_index_trust`` — so this
    command always displays the policy that the gate would enforce (spec §5.3a
    SSOT requirement, item M4).

    spec/cli-contract.md §5.3a.
    """
    import os
    import time

    from milpa.index_cache import _bundle_path, _default_cache_dir, cache_path_for, index_url_from_env
    from milpa.index_trust import describe_index_bundle, format_index_trust_info
    from milpa.trust import effective_trust_policy

    index_url = index_url_from_env()

    # Compute effective policy via the SSOT helper (same as the enforcement gate).
    # _load_manifest_trust_fields reads the resolution root and PROPAGATES a
    # present-but-invalid workspace error (WS-INDEX-TRUST-ON-MEMBER) — show must
    # surface exactly what the gate would enforce, so it is not swallowed here.
    manifest_policy, _, _ = _load_manifest_trust_fields(project_dir)

    env_trust = os.environ.get("MILPA_INDEX_TRUST")
    policy = effective_trust_policy(manifest_policy, flag=False, env_override=env_trust)

    cache_dir = _default_cache_dir()
    cache_file = cache_path_for(index_url, cache_dir)
    bundle_file = _bundle_path(cache_file)

    index_cached = cache_file.is_file()
    bundle_cached = bundle_file.is_file()

    info = None
    if bundle_cached:
        try:
            info = describe_index_bundle(bundle_file.read_bytes())
        except OSError:
            pass

    now = int(time.time())
    max_age_str = os.environ.get("MILPA_INDEX_MAX_AGE", "")
    try:
        max_age = int(max_age_str) if max_age_str.strip() else 604800
    except ValueError:
        max_age = 604800

    output = format_index_trust_info(
        index_url=index_url,
        policy=str(policy),
        index_cached=index_cached,
        bundle_cached=bundle_cached,
        info=info,
        now=now,
        max_age=max_age,
    )
    print(output, end="")
    return 0


# ---------------------------------------------------------------------------
# cmd_verify (10c)
# ---------------------------------------------------------------------------


def cmd_verify(
    project_dir: Path,
    env: "MilpaEnv | None" = None,
    *,
    require_attested_metadata: bool = False,
) -> int:
    """Recheck every dep in _deps/ against milpa.lock.

    S6: also checks dep_decl pins in the lockfile against the live index
    (§3.7.2).  Offline → edge check is skipped (not passed); under effective
    strict mode (manifest attestation-policy "strict" OR --require-attested-metadata
    OR MILPA_REQUIRE_ATTESTED_METADATA) → hard-fail with VERIFY-EDGE-MISMATCH.

    Effective strict policy (§13.1): OR of manifest field + flag.  The flag
    MUST NOT weaken a manifest-declared strict policy.

    stdout: none.
    stderr: diagnostics + summary.
    """
    from milpa.trust import effective_trust_policy

    ws = find_workspace_root(project_dir)
    lock_path: Path
    deps_dir: Path

    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        lock_path = ws.root_dir / "milpa.lock"
        deps_dir = ws.root_dir / "_deps"
        # §13.1 workspace attestation rule: strict if ANY member is strict.
        effective_strict = require_attested_metadata or any(
            effective_trust_policy(m.manifest.attestation_policy, False) == "strict"
            for m in ws.members
        )
    else:
        lock_path = project_dir / "milpa.lock"
        deps_dir = project_dir / "_deps"
        # Load manifest to read attestation-policy (may be absent / .nimble fallback).
        try:
            manifest = load_or_discover_manifest(project_dir)
            effective_strict = (
                effective_trust_policy(
                    manifest.attestation_policy, require_attested_metadata
                ) == "strict"
            )
        except MilpaError:
            # Manifest unreadable — fall back to flag-only policy (same as pre-fix
            # behavior; the lock-vs-_deps check below will likely surface the real
            # error anyway).
            effective_strict = require_attested_metadata

    if not lock_path.exists():
        print(
            f"no lockfile found at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1

    if not deps_dir.exists():
        print(
            f"no deps directory at {deps_dir} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(VERIFY_DEPS_DIR_MISSING)
        return 1

    try:
        lockfile = load_lockfile(lock_path)
    except MilpaError as exc:
        print(f"failed to read lockfile: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    # -------------------------------------------------------------------------
    # S10: active_flags mismatch check (RFC #23 §3.7 — flag MEMBERSHIP only,
    # not defines content, §3.6).  Reuses _check_frozen_active_flags_mismatch
    # (SSOT) with no CLI feature overrides — "manifest defaults + no selection".
    # A mismatch means the lockfile was produced under a different feature
    # selection; the user must re-run `milpa fetch`.
    # Runs BEFORE the disk-state check because it's a manifest-vs-lockfile
    # consistency check (not a disk-vs-lockfile check), and should fire even
    # if _deps/ has stale content.
    # -------------------------------------------------------------------------
    if ws is None:
        try:
            verify_manifest = load_or_discover_manifest(project_dir)
            _check_frozen_active_flags_mismatch(
                verify_manifest,
                lockfile,
                features=frozenset(),
                no_default_features=False,
                all_features=False,
            )
        except MilpaError as exc:
            print(f"milpa verify: {exc.message}", file=sys.stderr)
            _emit_slug(exc.slug)
            return 1
        except Exception:
            pass  # manifest unreadable — skip; identity check below will catch real issues
    else:
        # S11b (Breadth-P2c): workspace frozen-flags mismatch check.
        # Reuses _check_workspace_frozen_active_flags_mismatch (SSOT) — no
        # CLI feature overrides at verify time (verify checks manifest defaults).
        # Complements S2's fetch --frozen path.
        try:
            _check_workspace_frozen_active_flags_mismatch(
                ws,
                lockfile,
                features=frozenset(),
                no_default_features=False,
                all_features=False,
            )
        except MilpaError as exc:
            print(f"milpa verify: {exc.message}", file=sys.stderr)
            _emit_slug(exc.slug)
            return 1

    divergences = verify_lockfile_against_deps(lockfile, deps_dir)
    if divergences:
        print(
            f"verification failed — {len(divergences)} divergence(s):",
            file=sys.stderr,
        )
        for msg in divergences:
            print(f"  {msg}", file=sys.stderr)
        _emit_slug(LOCK_GRAPH_MISMATCH)
        return 1

    # -------------------------------------------------------------------------
    # S6: dep_decl pin check (§3.7.2)
    # -------------------------------------------------------------------------
    pinned_deps = [d for d in lockfile.deps if d.dep_decl is not None]
    if pinned_deps:
        result = _verify_dep_decl_pins(
            pinned_deps,
            env=env,
            strict=effective_strict,
        )
        if result != 0:
            return result

    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        print(
            f"verified {len(lockfile.deps)} deps across "
            f"{len(ws.members)} workspace members",
            file=sys.stderr,
        )
    else:
        print(f"verified {len(lockfile.deps)} deps", file=sys.stderr)
    return 0


def _verify_dep_decl_pins(
    pinned_deps: "list[LockedDep]",
    env: "MilpaEnv | None",
    *,
    strict: bool,
) -> int:
    """Check each locked dep_decl pin against the live index.

    ``strict`` is the EFFECTIVE strict policy — the OR of manifest
    ``attestation-policy "strict"`` and the ``--require-attested-metadata``
    flag / ``MILPA_REQUIRE_ATTESTED_METADATA`` env (computed by the caller
    via ``trust.effective_trust_policy``).

    §3.7.2 semantics:
    - Offline (no dep_decl_store or no MILPA_INDEX_URL):
        - Non-strict: skip edge check, warn to stderr.
        - Strict: hard-fail VERIFY-EDGE-MISMATCH.
    - Online:
        - Pin matches index → OK.
        - Index version-node lacks dep_decl → LOCK-DEPDECL-PIN-MISSING.
        - Index dep_decl differs from pin → VERIFY-EDGE-MISMATCH.

    Returns 0 on success; emits slug and returns 1 on failure.
    """
    # Determine offline state: dep_decl_store must exist AND MILPA_INDEX_URL
    # must not be explicitly empty (three-way: absent→default=online,
    # empty→no-index=offline, non-empty→that-URL=online).
    dep_decl_store = env.dep_decl_store if env is not None else None
    raw_index_url = os.environ.get("MILPA_INDEX_URL")  # None if absent
    explicitly_no_index = raw_index_url is not None and raw_index_url.strip() == ""
    offline = dep_decl_store is None or explicitly_no_index

    if offline:
        if strict:
            print(
                "dep_decl edge check requires live index — "
                "network not available (strict mode → VERIFY-EDGE-MISMATCH)",
                file=sys.stderr,
            )
            _emit_slug(VERIFY_EDGE_MISMATCH)
            return 1
        # Non-strict: skip and warn.
        print(
            f"dep_decl edge check SKIPPED for {len(pinned_deps)} dep(s) "
            "(offline — network required for drift detection; "
            "run connected to verify edge integrity)",
            file=sys.stderr,
        )
        return 0

    # Load the live index (same pattern as _load_index_for_verb).
    from milpa.errors import MILPA_INDEX_UNREACHABLE

    try:
        index = load_default_index()
    except MilpaError as exc:
        if exc.slug == MILPA_INDEX_UNREACHABLE:
            if strict:
                print(
                    f"index unreachable — cannot verify dep_decl pins "
                    f"(strict mode): {exc.message}",
                    file=sys.stderr,
                )
                _emit_slug(VERIFY_EDGE_MISMATCH)
                return 1
            print(
                f"dep_decl edge check SKIPPED — index unreachable: {exc.message}",
                file=sys.stderr,
            )
            return 0
        # TNG-* parse errors propagate — real malformation, not just offline.
        print(f"failed to load index: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    # Per-dep check.
    for dep in pinned_deps:
        assert dep.dep_decl is not None  # narrowed above
        locked_pin = dep.dep_decl

        # Find the version-node in the live index.
        pkg = index.lookup_bare(dep.name)
        if pkg is None or hasattr(pkg, "namespaces"):
            # Not found / ambiguous: treat as LOCK-DEPDECL-PIN-MISSING
            # (the pin records a dep_decl but the index no longer has it).
            print(
                f"dep '{dep.name}': dep_decl pin {locked_pin!r} present in lock "
                f"but package is no longer in the index",
                file=sys.stderr,
            )
            _emit_slug(LOCK_DEPDECL_PIN_MISSING)
            return 1

        # Find the exact version-node.
        iv = next(
            (iv for iv in pkg.versions if iv.version == dep.version),
            None,
        )

        if iv is None or iv.dep_decl is None:
            # Version-node not found OR dep_decl field absent → pin is orphaned.
            print(
                f"dep '{dep.name}@{dep.version}': dep_decl pin {locked_pin!r} "
                f"present in lock but the index version-node no longer carries "
                f"a dep_decl pointer — the DepDecl may have been retracted",
                file=sys.stderr,
            )
            _emit_slug(LOCK_DEPDECL_PIN_MISSING)
            return 1

        if iv.dep_decl != locked_pin:
            print(
                f"dep '{dep.name}@{dep.version}': locked dep_decl {locked_pin!r} "
                f"does not match index current dep_decl {iv.dep_decl!r} — "
                f"the dependency graph has drifted",
                file=sys.stderr,
            )
            _emit_slug(VERIFY_EDGE_MISMATCH)
            return 1

    return 0


# ---------------------------------------------------------------------------
# cmd_clean (10c)
# ---------------------------------------------------------------------------


def cmd_clean(project_dir: Path) -> int:
    """Remove _deps/ and nim.cfg; keep milpa.lock.

    Idempotent — exits 0 even if nothing exists to remove.
    stdout: none.
    stderr: none (reference impl); an implementation MAY confirm.
    """
    ws = find_workspace_root(project_dir)

    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        _remove_if_exists(ws.root_dir / "_deps")
        for member in ws.members:
            _remove_if_exists(member.abs_dir / "nim.cfg")
    else:
        _remove_if_exists(project_dir / "_deps")
        _remove_if_exists(project_dir / "nim.cfg")

    return 0


def _remove_if_exists(path: Path) -> None:
    """Remove *path* (file or directory tree) if it exists; no-op otherwise."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Mocked default-branch discovery (conformance-fixtures.md §2.3.3)
# ---------------------------------------------------------------------------


def _mocked_default_branch(mocked_dir: str, git_url: str) -> str | None:
    """Discover the default branch from the mocked fixture tree.

    Scans ``mocked_dir`` for a subdirectory whose URL component (the part
    before ``@``) matches ``url_key(git_url, "")``'s URL portion.  Returns
    the ref component (after ``@``) of the first matching directory name,
    or ``None`` if no fixture directory matches.

    Spec: conformance-fixtures.md §2.3.3 NORMATIVE.
    """
    from milpa.fetchers.mocked import url_key

    dir_path = Path(mocked_dir)
    if not dir_path.is_dir():
        return None

    # url_key(git_url, "") = "{sanitized_url}@"
    # Split on "@" to get the URL portion.
    full_key_empty_ref = url_key(git_url, "")
    # The URL portion is everything before the trailing "@".
    url_portion = full_key_empty_ref.rstrip("@")
    prefix = url_portion + "@"

    for entry in dir_path.iterdir():
        if not entry.is_dir():
            continue
        name = entry.name
        if name.startswith(prefix):
            # The ref is the part after the first (and only) "@" separator.
            at_pos = name.index("@")
            ref = name[at_pos + 1:]
            return ref

    return None


# ---------------------------------------------------------------------------
# cmd_store_ls / cmd_store_path  (C-store-ro slice, Phase C)
# ---------------------------------------------------------------------------


def cmd_store_ls(store: "CAStore") -> int:
    """``milpa store ls`` — list all identities in the CAS store, lex-sorted.

    Prints one ``sha256:<64hex>`` per line to stdout.  Empty store → no output,
    exit 0.  Never mutates the store.
    """
    for identity in store.list_identities():
        print(identity)
    return 0


def cmd_store_path(store: "CAStore", identity_or_prefix: str) -> int:
    """``milpa store path <identity-or-prefix>`` — resolve to an absolute path.

    Prints the absolute canonical path to stdout (machine-readable, for
    ``$(milpa store path ...)``).  On any error (not in store, ambiguous
    prefix) prints to stderr and emits the slug, exit 1.

    Resolution rules:
    - Full identity (64-hex bare or ``sha256:<64hex>``) → exact lookup.
    - Prefix (≥16 hex chars, with or without algorithm prefix) → unique-prefix
      match across store entries.
    - Prefix < 16 hex chars → ``STORE-AMBIGUOUS-PREFIX`` (too weak to be safe).
    """
    try:
        identity = store.resolve_prefix(identity_or_prefix)
    except MilpaError as exc:
        print(f"milpa store path: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    print(str(store.path_for(identity)))
    return 0


# ---------------------------------------------------------------------------
# cmd_hash (A0-cmd) — content identity probe
# ---------------------------------------------------------------------------


def cmd_hash(prov: Provenance, env: MilpaEnv) -> int:
    """Print the content identity of a source (no CAS admission, no lockfile, no _deps/).

    Architectural pin (spec/cli-contract.md §5.N, A0-cmd):
      1. Fetch ``prov`` into a SCRATCH/throwaway destination via
         ``env.fetcher.inner`` — the bare ``FetcherRegistry``, NOT the
         CAS-admitting wrapper. This gives us the identity the REAL fetch path
         produces without any CAS or lockfile side-effects.
      2. Print ``result.identity`` to stdout (exactly one line on success).
      3. Discard the scratch directory (``tempfile.TemporaryDirectory`` context
         manager guarantees cleanup regardless of success or failure).

    MUST NOT call ``compute_content_hash``, ``identity.py``, or any hash
    function directly — the identity comes exclusively from the fetch result.
    This keeps ``milpa hash`` provably consistent with ``milpa fetch``.

    stdout:
      - ``sha256:<64hex>`` for CAS-admissible sources (git, tarball, OCI).
      - Empty for non-admissible sources (local/editable trees) — local sources
        have no stable identity in milpa's model (lockfile §4.3 NORMATIVE).

    stderr: diagnostics only (fetch errors surface here via the outer MilpaError
    handler in ``main()``).

    spec/cli-contract.md §5.N — ``milpa hash``.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "_hash_src"
        result = env.fetcher.inner.fetch("hash-probe", prov, dest=dest)

    if result.identity is not None:
        print(result.identity)
    return 0


# ---------------------------------------------------------------------------
# cmd_add (10e)
# ---------------------------------------------------------------------------


def cmd_add(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    git_url: str | None,
    mirror_url: str | None,
    ref: str | None,
    strategy: Strategy,
    max_parallel: int,
    optional: bool = False,
    features: "tuple[str, ...] | frozenset[str]" = (),
) -> int:
    """Add a new dep (--git) or mirror provenance (--mirror) to milpa.kdl.

    S10 (RFC #23 §3.7): ``--optional`` writes ``optional=#true`` on the dep node;
    ``--features a,b`` writes ``flag "a"`` / ``flag "b"`` children.

    spec/cli-contract.md §5.6.
    """
    manifest_path = project_dir / "milpa.kdl"
    lock_path = project_dir / "milpa.lock"

    # S11a/S11e: workspace detection — distinguish root vs member dir.
    ws = find_workspace_root(project_dir)
    if ws is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws, LoadedWorkspace)
        if ws.root_dir == project_dir.resolve():
            # S11a: at the workspace root — refuse with the canonical directive slug.
            print(
                "milpa add: cannot add a dep to a workspace root — "
                "to add a dep, `cd` to a member; "
                "to add a member, use `milpa workspace add-member`",
                file=sys.stderr,
            )
            _emit_slug(MAN_MUTATE_WORKSPACE_REFUSED)
            return 1
        # S11e: invoked from a member dir — detect-and-delegate (D5).
        # Mutate the MEMBER's manifest; re-resolve the WHOLE workspace.
        # The member-local lock must NOT be written.
        return _cmd_add_from_member_dir(
            member_dir=project_dir,
            workspace=ws,
            env=env,
            dep_name=dep_name,
            git_url=git_url,
            mirror_url=mirror_url,
            ref=ref,
            strategy=strategy,
            max_parallel=max_parallel,
            optional=optional,
            features=features,
        )

    if git_url is not None:
        return _cmd_add_git(
            project_dir=project_dir,
            manifest_path=manifest_path,
            lock_path=lock_path,
            env=env,
            dep_name=dep_name,
            git_url=git_url,
            ref=ref,
            strategy=strategy,
            max_parallel=max_parallel,
            optional=optional,
            features=features,
        )

    if mirror_url is not None:
        return _cmd_add_mirror(
            project_dir=project_dir,
            manifest_path=manifest_path,
            lock_path=lock_path,
            env=env,
            dep_name=dep_name,
            mirror_url=mirror_url,
            strategy=strategy,
            max_parallel=max_parallel,
        )

    # Neither --git nor --mirror — usage error (exit 2, no slug).
    print(
        "milpa add: must specify --git <url> or --mirror <url>",
        file=sys.stderr,
    )
    return 2


def _cmd_add_git(
    project_dir: Path,
    manifest_path: Path,
    lock_path: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    git_url: str,
    ref: str | None,
    strategy: Strategy,
    max_parallel: int,
    optional: bool = False,
    features: "tuple[str, ...] | frozenset[str]" = (),
) -> int:
    """Implement ``milpa add <dep> --git <url> [--ref <ref>] [--optional] [--features f1,f2]``.

    S10 (RFC #23 §3.7):
    - ``optional=True`` → ``UrlDep.optional = True``; ``format_manifest`` serializes
      ``optional=#true`` on the dep node.
    - ``features=(...)`` → ``UrlDep.flag_requests`` with the named flags; serialized
      as ``flag "<name>"`` children on the dep block.
    - Pre-write clash check (normative): if ``optional=True`` and the dep name would
      clash with an existing declared flag, raise ``MAN-DEP-OPTIONAL-FLAG-CLASH``
      BEFORE writing — reuses the S7 ``_desugar_optional_deps`` validation so the
      writer never produces an unparseable manifest. SSOT: the same code path that
      runs at parse time also runs here at add-time.
    """
    from milpa.manifest import FlagRequest, UrlDep
    from milpa.manifest_writer import mutate_manifest_file

    # Ref discovery: if --ref omitted, discover default branch.
    mocked_dir = os.environ.get("MILPA_MOCKED_FETCHES", "").strip()
    if ref is None:
        if mocked_dir:
            # Mocked transport: discover from fixture tree.
            discovered = _mocked_default_branch(mocked_dir, git_url)
            if discovered is None:
                print(
                    f"milpa add: ref discovery failed for {git_url!r} "
                    "(no mocked fixture found)",
                    file=sys.stderr,
                )
                _emit_slug(FETCH_REF_DISCOVERY_FAILED)
                return 1
            ref = discovered
        else:
            # Real transport: run git ls-remote --symref HEAD.
            discovered_ref = _git_discover_default_branch(git_url)
            if discovered_ref is None:
                print(
                    f"milpa add: failed to discover default branch for {git_url!r}",
                    file=sys.stderr,
                )
                _emit_slug(FETCH_REF_DISCOVERY_FAILED)
                return 1
            ref = discovered_ref

    # Read + validate manifest: dep must not already exist.
    from milpa.manifest import parse_manifest

    if not manifest_path.exists():
        print(
            f"milpa add: no milpa.kdl found at {manifest_path}",
            file=sys.stderr,
        )
        _emit_slug(MILPA_INTERNAL)
        return 1

    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = parse_manifest(manifest_text)

    existing_names = {dep.name for dep in manifest.deps}
    if dep_name in existing_names:
        print(
            f"milpa add: dep {dep_name!r} already declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_ADD_DEP_EXISTS)
        return 1

    # S10 pre-write clash check (§3.7 normative): if optional=True, the dep name
    # becomes a flag name at parse time.  Validate NOW, before writing, so the
    # writer never produces an unparseable manifest.  SSOT: re-use the same
    # _desugar_optional_deps path that parse_manifest calls — we build the
    # proposed manifest first, then re-parse it to run the full S7 validation.
    if optional:
        from milpa.manifest import valid_dep_name
        from milpa.errors import MAN_DEP_OPTIONAL_FLAG_CLASH, MAN_DEP_OPTIONAL_INVALID_NAME
        # Validate charset: dep name must match the flag-name charset.
        if not valid_dep_name(dep_name):
            print(
                f"milpa add: dep name {dep_name!r} is not a valid flag name "
                "(must match [A-Za-z0-9_-]+) — required for optional=#true",
                file=sys.stderr,
            )
            _emit_slug(MAN_DEP_OPTIONAL_INVALID_NAME)
            return 1
        # Namespace clash: check if the dep name collides with an existing declared flag.
        declared_flag_names: frozenset[str] = frozenset(fd.name for fd in manifest.flags)
        if dep_name in declared_flag_names:
            print(
                f"milpa add: dep {dep_name!r} optional=#true would clash with the "
                f"existing flag {dep_name!r} — rename one or mark the dep non-optional",
                file=sys.stderr,
            )
            _emit_slug(MAN_DEP_OPTIONAL_FLAG_CLASH)
            return 1

    # Build the new dep + resolve.
    flag_reqs: tuple[FlagRequest, ...] = tuple(
        FlagRequest(name=f, enabled=True) for f in features
    )
    new_dep = UrlDep(
        name=dep_name,
        git=git_url,
        ref=ref,
        optional=optional,
        flag_requests=flag_reqs,
    )
    from dataclasses import replace as _replace
    proposed_manifest = _replace(manifest, deps=manifest.deps + (new_dep,))

    env_with_index = _load_index_for_verb(env, project_dir)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=None,
        manifest_dir=project_dir,
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))

    # Atomic write: manifest first, then lock.
    mutate_manifest_file(manifest_path, lambda _m: proposed_manifest)
    write_lockfile(lockfile_val, lock_path)

    print(f"added {dep_name} (git={git_url} ref={ref})", file=sys.stderr)
    return 0


def _git_discover_default_branch(git_url: str) -> str | None:
    """Discover the default branch via ``git ls-remote --symref HEAD``.

    Returns the branch name, or ``None`` on any failure.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["git", "ls-remote", "--symref", git_url, "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            # Output format: "ref: refs/heads/<branch>\tHEAD"
            if line.startswith("ref: refs/heads/"):
                parts = line.split("\t")
                if parts:
                    return parts[0].removeprefix("ref: refs/heads/")
    except Exception:
        return None
    return None


def _cmd_add_mirror(
    project_dir: Path,
    manifest_path: Path,
    lock_path: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    mirror_url: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Implement ``milpa add <dep> --mirror <url>``.

    Pure manifest mutation — no fetch, no verify, no lockfile write.

    The mirror is recorded as an author CLAIM (a "declared" mirror) in
    ``milpa.kdl``.  It becomes a ``declared`` provenance in the lockfile on
    the next ``milpa lock`` (the D-lifecycle slice) and is verified at USE
    time (D-fallback).

    spec/cli-contract.md §5.6 (amended for D-add).
    """
    from milpa.manifest import Manifest, UrlDep
    from milpa.manifest_writer import mutate_manifest_file

    # Parse manifest — dep must be declared here (NOT in the lockfile).
    try:
        from milpa.manifest import parse_manifest
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = parse_manifest(manifest_text)
    except FileNotFoundError:
        print(
            f"milpa add --mirror: manifest not found at {manifest_path}",
            file=sys.stderr,
        )
        _emit_slug(MAN_MUTATE_FILE_NOT_FOUND)
        return 1

    dep_in_manifest = next((d for d in manifest.deps if d.name == dep_name), None)

    # Reject: dep not declared in milpa.kdl.
    if dep_in_manifest is None:
        print(
            f"milpa add --mirror: dep {dep_name!r} not declared in milpa.kdl",
            file=sys.stderr,
        )
        return 1

    # Reject non-URL deps (local / member / named / tarball — not mirrorable).
    if not isinstance(dep_in_manifest, UrlDep):
        print(
            f"milpa add --mirror: {dep_name!r} is not a git URL dep — "
            "only URL deps (git=...) can carry mirrors",
            file=sys.stderr,
        )
        _emit_slug(MAN_MIRROR_EDITABLE_PROVENANCE)
        return 1

    # Idempotent: URL already a mirror → exit 0 without rewriting.
    if mirror_url in dep_in_manifest.mirrors:
        print(f"added mirror {mirror_url} for {dep_name}", file=sys.stderr)
        return 0

    # Append mirror to the dep in milpa.kdl — NO fetch, NO lockfile write.
    def _add_mirror_to_dep(m: Manifest) -> Manifest:
        from dataclasses import replace as _r
        new_deps = tuple(
            _r(d, mirrors=d.mirrors + (mirror_url,))
            if isinstance(d, UrlDep) and d.name == dep_name
            and mirror_url not in d.mirrors
            else d
            for d in m.deps
        )
        return _r(m, deps=new_deps)

    mutate_manifest_file(manifest_path, _add_mirror_to_dep)

    print(f"added mirror {mirror_url} for {dep_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Alias→canonical resolution (D-update-remove, Phase D item 5)
# ---------------------------------------------------------------------------


def resolve_alias_to_canonical(name: str, lockfile: Lockfile) -> str:
    """Return the canonical dep name for ``name``.

    If ``name`` is already a canonical lockfile dep name, return it unchanged.
    If ``name`` matches a dep's ``aliases`` entry, return that dep's canonical
    name.  If ``name`` is not found as either, return ``name`` unchanged (the
    caller's guard will handle the not-found case).

    SSOT: used by both cmd_update and cmd_remove so alias→canonical logic
    lives in exactly one place per the SSOT principle.
    """
    for dep in lockfile.deps:
        if dep.name == name:
            return name
        if name in dep.aliases:
            return dep.name
    return name


# ---------------------------------------------------------------------------
# cmd_remove (10e)
# ---------------------------------------------------------------------------


def cmd_remove(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Remove a dep from milpa.kdl and regenerate the lockfile.

    spec/cli-contract.md §5.7.
    """
    from milpa.manifest import parse_manifest
    from milpa.manifest_writer import mutate_manifest_file

    manifest_path = project_dir / "milpa.kdl"
    lock_path = project_dir / "milpa.lock"

    # S11a/S11e: workspace detection — distinguish root vs member dir.
    ws_check = find_workspace_root(project_dir)
    if ws_check is not None:
        from milpa.workspace import LoadedWorkspace
        assert isinstance(ws_check, LoadedWorkspace)
        if ws_check.root_dir == project_dir.resolve():
            # S11a: at the workspace root — refuse with the canonical directive slug.
            print(
                "milpa remove: cannot remove a dep from a workspace root — "
                "to remove a dep, `cd` to a member; "
                "to remove a member, use `milpa workspace remove-member`",
                file=sys.stderr,
            )
            _emit_slug(MAN_MUTATE_WORKSPACE_REFUSED)
            return 1
        # S11e: invoked from a member dir — detect-and-delegate (D5).
        return _cmd_remove_from_member_dir(
            member_dir=project_dir,
            workspace=ws_check,
            env=env,
            dep_name=dep_name,
            strategy=strategy,
            max_parallel=max_parallel,
        )

    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = parse_manifest(manifest_text)

    # S5b: parse slash-shorthand in dep_name ("ns1/bar" → namespace="ns1", bare="bar").
    # The lockfile key (solver_var) for a qualified dep is "ns1::bar".
    from milpa.manifest import NamedDep as _NamedDep
    _remove_namespace: str | None = None
    _remove_bare: str = dep_name
    if "/" in dep_name:
        _parts = dep_name.split("/")
        if len(_parts) == 2 and _parts[0] and _parts[1]:
            _remove_namespace, _remove_bare = _parts[0], _parts[1]
        # Malformed (a/b/c or empty parts): leave dep_name as-is; the guard below
        # will produce MAN-REMOVE-DEP-ABSENT with the original dep_name in the message.

    # Compute the solver_var for lockfile lookups when namespace is set.
    # Route through DepKey.solver_var() — the SOLE :: join site.
    _remove_solver_var: str = DepKey(name=_remove_bare, namespace=_remove_namespace).solver_var()

    # D-update-remove: alias→canonical resolution (Phase D item 5).
    # If dep_name is an alias of a canonical lockfile dep, resolve to the
    # canonical manifest name so the guard and manifest mutation operate correctly.
    # For qualified deps, the lockfile dep name IS the solver_var ("ns1::bar").
    prior_for_alias = _maybe_load_prior_lockfile(lock_path)
    if prior_for_alias is not None:
        canonical_name = resolve_alias_to_canonical(_remove_solver_var, prior_for_alias)
    else:
        canonical_name = _remove_solver_var

    # Guard: dep must be declared in milpa.kdl.
    # For qualified deps, match by (namespace, bare_name); for bare deps, match by name.
    def _dep_remove_key(d: object) -> str:
        """Return the remove-key for a dep: solver_var for NamedDep, bare name for others."""
        if isinstance(d, _NamedDep) and d.namespace:
            return DepKey(name=d.name, namespace=d.namespace).solver_var()
        return getattr(d, "name", "")

    existing_keys = {_dep_remove_key(dep) for dep in manifest.deps}
    if canonical_name not in existing_keys:
        print(
            f"milpa remove: dep {dep_name!r} is not declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_REMOVE_DEP_ABSENT)
        return 1

    # Collect prior aliases for the dep being removed, so we can warn if any
    # alias is still required by transitives after re-resolve.
    prior_aliases: tuple[str, ...] = ()
    if prior_for_alias is not None:
        for locked in prior_for_alias.deps:
            if locked.name == canonical_name:
                prior_aliases = locked.aliases
                break

    # Build proposed manifest without the dep.
    from dataclasses import replace as _replace
    new_deps = tuple(d for d in manifest.deps if _dep_remove_key(d) != canonical_name)
    proposed_manifest = _replace(manifest, deps=new_deps)

    # Re-resolve.
    env_with_index = _load_index_for_verb(env, project_dir)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior_for_alias,  # type: ignore[arg-type]
        manifest_dir=project_dir,
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))

    # D-update-remove Phase D item 5: warn per alias (Phase D item 5).
    # If the removed canonical had aliases in the prior lockfile, warn about
    # each one so the user knows that _deps/<alias> will be cleaned up.
    # This also covers the "alias still required by a transitive" case: if the
    # new graph still contains the canonical (pulled in transitively via another
    # dep), the alias symlink remains live and the warning is especially important.
    new_canonical_names = {d.name for d in graph.deps}
    for alias in prior_aliases:
        if canonical_name in new_canonical_names:
            print(
                f"warning: alias {alias!r} of removed dep {canonical_name!r} "
                f"is still required transitively; _deps/{alias} remains live",
                file=sys.stderr,
            )
        else:
            print(
                f"warning: removing dep {canonical_name!r} also removes alias "
                f"{alias!r} (_deps/{alias} will be cleaned up)",
                file=sys.stderr,
            )

    # Atomic write.
    mutate_manifest_file(manifest_path, lambda _m: proposed_manifest)
    write_lockfile(lockfile_val, lock_path)

    print(f"removed {canonical_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_update (10e)
# ---------------------------------------------------------------------------


def cmd_update(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str | None,
    strategy: Strategy,
    max_parallel: int,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
) -> int:
    """Re-resolve and refresh milpa.lock; optionally scoped to one dep.

    spec/cli-contract.md §5.8.
    """
    lock_path = project_dir / "milpa.lock"

    # S11b/S11e (RFC: workspace-completion §3.G): workspace parity.
    # From a workspace root, update does the full workspace re-resolve
    # (drop pins → re-resolve shared graph → refresh shared lock).
    # S11e: from a member dir, detect the parent workspace and delegate there.
    # update writes no nim.cfg in either impl — keep that.
    ws = find_workspace_root(project_dir)
    if ws is not None:
        return _cmd_update_workspace(
            project_dir=project_dir,
            workspace=ws,
            env=env,
            dep_name=dep_name,
            strategy=strategy,
            max_parallel=max_parallel,
            features=features,
            no_default_features=no_default_features,
            all_features=all_features,
        )

    manifest = load_or_discover_manifest(project_dir)
    env_with_index = _load_index_for_verb(env, project_dir)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()

    if dep_name is None:
        # ``update`` with no arg — drop ALL pins (prior=None).
        params = ResolveParams(
            strategy=strategy,
            max_parallel=max_parallel,
            profile=profile,
            prior=None,
            manifest_dir=project_dir,
            features=features,
            no_default_features=no_default_features,
            all_features=all_features,
        )
        graph = resolve(manifest, deps_dir, env_with_index, params)
        lockfile_val = from_graph(graph, strategy=str(strategy))
        write_lockfile(lockfile_val, lock_path)
        print("updated all deps", file=sys.stderr)
        return 0

    # ``update <dep>`` — scoped: require lockfile, drop only this dep's pin.
    if not lock_path.exists():
        print(
            f"milpa update: no lockfile at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1

    prior_lock = load_lockfile(lock_path)

    # D-update-remove: alias→canonical resolution (Phase D item 5).
    # If dep_name matches an alias in the lockfile, operate on the canonical dep.
    canonical_name = resolve_alias_to_canonical(dep_name, prior_lock)

    # Guard: dep (or its canonical) must be in the lockfile.
    if not any(d.name == canonical_name for d in prior_lock.deps):
        print(
            f"milpa update: {dep_name!r} not found in lockfile",
            file=sys.stderr,
        )
        _emit_slug(LOCK_DEP_NOT_FOUND)
        return 1

    # Build a filtered prior: keep all deps EXCEPT the canonical being updated,
    # then add back a "pin-stripped" entry for it that retains its declared
    # mirror provenances (Phase D item 5: explicit provenance preservation).
    # Stripping identity=None means _git_pin_for_url_dep returns None (no pin),
    # so the dep re-resolves fresh. The declared provenances survive so
    # _prior_declared_mirror_urls can carry them forward. URLs that are no
    # longer in milpa.kdl mirrors are naturally dropped by the D-lifecycle
    # dedup logic (only manifest_mirror_urls + primary make it into declared).
    filtered_prior = strip_dep_pin(prior_lock, canonical_name)

    # S10 (RFC #23 §3.7): re-resolve with the lockfile's recorded active_flags
    # for reproducibility.  "Re-resolves with the lockfile's recorded active_flags"
    # means the same CLI feature selection used when the lock was written is used
    # again — NOT that we reset to all-features-off.  The resolver correctly
    # recomputes dep-level active_flags from the dep's own flag tables (default-true
    # flags, cross-package requests via enables); that is the reproduction mechanism.
    # For root-level CLI features the user must pass --features explicitly; the
    # lockfile does not store the prior --features invocation (§3.4 normative).
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=filtered_prior,
        manifest_dir=project_dir,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )

    graph = resolve(manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile_val, lock_path)
    print(f"updated {dep_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# _cmd_update_workspace (S11b)
# ---------------------------------------------------------------------------


def _cmd_update_workspace(
    project_dir: Path,
    workspace: object,
    env: MilpaEnv,
    *,
    dep_name: str | None,
    strategy: Strategy,
    max_parallel: int,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
) -> int:
    """Workspace variant of cmd_update.

    S11b (RFC: workspace-completion §3.G): full workspace re-resolve.
    Drops ALL pins (prior=None) → re-resolves the shared graph → refreshes
    the shared lock.  Mirrors what Rust already does in cmd_update.
    NOTE: update writes no nim.cfg in either impl — keep that.
    """
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    # Scoped update (dep_name given) requires the lockfile.
    if dep_name is not None and not lock_path.exists():
        print(
            f"milpa update: no lockfile at {lock_path} — run `milpa fetch` first",
            file=sys.stderr,
        )
        _emit_slug(LOCK_FILE_NOT_FOUND)
        return 1

    # Build the prior for the workspace resolve.
    # update with no arg: drop ALL pins (prior=None).
    # update <dep>: drop only that dep's pin.
    prior = _maybe_load_prior_lockfile(lock_path)
    if dep_name is None:
        prior = None  # Full drop — re-resolve from scratch.
    elif prior is not None:
        # Scoped: drop only this dep's pin from the prior.
        canonical_name = resolve_alias_to_canonical(dep_name, prior)
        if not any(d.name == canonical_name for d in prior.deps):
            print(
                f"milpa update: {dep_name!r} not found in lockfile",
                file=sys.stderr,
            )
            _emit_slug(LOCK_DEP_NOT_FOUND)
            return 1
        prior = strip_dep_pin(prior, canonical_name)

    env_with_index = _load_index_for_verb(env, ws_root)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )

    graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy))
    write_lockfile(lockfile_val, lock_path)
    print(
        f"updated {dep_name or 'all deps'} across {len(workspace.members)} members",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# _cmd_add_from_member_dir / _cmd_remove_from_member_dir (S11e)
#
# Detect-and-delegate: invoked from a member dir, mutate the MEMBER's manifest
# and re-resolve the WHOLE workspace (shared lock + shared _deps/).
# The member-local lock must NOT be written (D5, cli-contract §5.6-5.8).
# ---------------------------------------------------------------------------


def _cmd_add_from_member_dir(
    member_dir: Path,
    workspace: object,
    env: MilpaEnv,
    *,
    dep_name: str,
    git_url: str | None,
    mirror_url: str | None,
    ref: str | None,
    strategy: Strategy,
    max_parallel: int,
    optional: bool = False,
    features: "tuple[str, ...] | frozenset[str]" = (),
) -> int:
    """S11e: ``milpa add`` invoked from a member dir.

    Mutates the MEMBER's ``milpa.kdl``; re-resolves the WHOLE workspace
    (shared ``<root>/milpa.lock`` + shared ``<root>/_deps/``).
    No member-local lock is written.

    spec/cli-contract.md §5.6 member-dir behavior.
    """
    from dataclasses import replace as _replace
    from milpa.workspace import LoadedWorkspace

    assert isinstance(workspace, LoadedWorkspace)
    ws_root = workspace.root_dir
    member_dir = member_dir.resolve()

    if git_url is None:
        # mirror_url path: pure manifest mutation on the member, no workspace relock.
        # _cmd_add_mirror is manifest-only today (no lock write), but pass the shared
        # workspace lock so a future lock-writing mirror path writes the right file.
        # No relock is needed on this path: adding a mirror is a provenance annotation,
        # not a new dep resolution.
        return _cmd_add_mirror(
            project_dir=member_dir,
            manifest_path=member_dir / "milpa.kdl",
            lock_path=ws_root / "milpa.lock",
            env=env,
            dep_name=dep_name,
            mirror_url=mirror_url or "",
            strategy=strategy,
            max_parallel=max_parallel,
        )

    # --- git URL add path ---
    from milpa.manifest import FlagRequest, UrlDep
    from milpa.manifest_writer import apply_member_manifest_change

    # Ref discovery — same logic as _cmd_add_git.
    mocked_dir = os.environ.get("MILPA_MOCKED_FETCHES", "").strip()
    if ref is None:
        if mocked_dir:
            discovered = _mocked_default_branch(mocked_dir, git_url)
            if discovered is None:
                print(
                    f"milpa add: ref discovery failed for {git_url!r} "
                    "(no mocked fixture found)",
                    file=sys.stderr,
                )
                _emit_slug(FETCH_REF_DISCOVERY_FAILED)
                return 1
            ref = discovered
        else:
            discovered_ref = _git_discover_default_branch(git_url)
            if discovered_ref is None:
                print(
                    f"milpa add: failed to discover default branch for {git_url!r}",
                    file=sys.stderr,
                )
                _emit_slug(FETCH_REF_DISCOVERY_FAILED)
                return 1
            ref = discovered_ref

    # Pre-flight validations against the current member manifest (read once
    # before the orchestration; apply_member_manifest_change will re-read it
    # atomically, but we need these checks to produce user-friendly errors
    # before attempting resolution).
    member_manifest_path = member_dir / "milpa.kdl"
    if not member_manifest_path.exists():
        print(
            f"milpa add: no milpa.kdl found at {member_manifest_path}",
            file=sys.stderr,
        )
        _emit_slug(MILPA_INTERNAL)
        return 1

    from milpa.manifest import parse_manifest
    preflight_manifest = parse_manifest(member_manifest_path.read_text(encoding="utf-8"))

    existing_names = {dep.name for dep in preflight_manifest.deps}
    if dep_name in existing_names:
        print(
            f"milpa add: dep {dep_name!r} already declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_ADD_DEP_EXISTS)
        return 1

    if optional:
        from milpa.manifest import valid_dep_name
        from milpa.errors import MAN_DEP_OPTIONAL_FLAG_CLASH, MAN_DEP_OPTIONAL_INVALID_NAME
        if not valid_dep_name(dep_name):
            print(
                f"milpa add: dep name {dep_name!r} is not a valid flag name "
                "(must match [A-Za-z0-9_-]+) — required for optional=#true",
                file=sys.stderr,
            )
            _emit_slug(MAN_DEP_OPTIONAL_INVALID_NAME)
            return 1
        declared_flag_names: frozenset[str] = frozenset(fd.name for fd in preflight_manifest.flags)
        if dep_name in declared_flag_names:
            print(
                f"milpa add: dep {dep_name!r} optional=#true would clash with the "
                f"existing flag {dep_name!r} — rename one or mark the dep non-optional",
                file=sys.stderr,
            )
            _emit_slug(MAN_DEP_OPTIONAL_FLAG_CLASH)
            return 1

    # Build the mutator: adds the new dep to whatever manifest the primitive reads.
    flag_reqs: tuple[FlagRequest, ...] = tuple(
        FlagRequest(name=f, enabled=True) for f in features
    )
    new_dep = UrlDep(
        name=dep_name,
        git=git_url,
        ref=ref,
        optional=optional,
        flag_requests=flag_reqs,
    )

    def _mutate_add(m: "Manifest") -> "Manifest":
        return _replace(m, deps=m.deps + (new_dep,))

    # Re-resolve the WHOLE workspace via the SSOT orchestration primitive.
    # apply_member_manifest_change: reload-workspace → apply mutator → resolve
    # in-memory → write member manifest → write shared lock.
    env_with_index = _load_index_for_verb(env, ws_root)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=None,
        manifest_dir=ws_root,
    )

    try:
        _graph, _wr = apply_member_manifest_change(
            ws_root, env_with_index, params, member_dir, _mutate_add
        )
    except MilpaError as exc:
        print(f"milpa add: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    print(f"added {dep_name} (git={git_url} ref={ref})", file=sys.stderr)
    return 0


def _cmd_remove_from_member_dir(
    member_dir: Path,
    workspace: object,
    env: MilpaEnv,
    *,
    dep_name: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """S11e: ``milpa remove`` invoked from a member dir.

    Mutates the MEMBER's ``milpa.kdl``; re-resolves the WHOLE workspace
    (shared ``<root>/milpa.lock`` + shared ``<root>/_deps/``).
    No member-local lock is written.

    spec/cli-contract.md §5.7 member-dir behavior.
    """
    from dataclasses import replace as _replace
    from milpa.manifest import Manifest as _Manifest, parse_manifest
    from milpa.manifest_writer import apply_member_manifest_change
    from milpa.workspace import LoadedWorkspace

    assert isinstance(workspace, LoadedWorkspace)
    ws_root = workspace.root_dir
    member_dir = member_dir.resolve()

    # Alias→canonical resolution against the SHARED lockfile (not the member lock).
    shared_lock_path = ws_root / "milpa.lock"
    prior_for_alias = _maybe_load_prior_lockfile(shared_lock_path)
    if prior_for_alias is not None:
        canonical_name = resolve_alias_to_canonical(dep_name, prior_for_alias)
    else:
        canonical_name = dep_name

    # Pre-flight: dep must be declared in the MEMBER's milpa.kdl.
    member_manifest_path = member_dir / "milpa.kdl"
    preflight_manifest = parse_manifest(member_manifest_path.read_text(encoding="utf-8"))
    existing_names = {dep.name for dep in preflight_manifest.deps}
    if canonical_name not in existing_names:
        print(
            f"milpa remove: dep {dep_name!r} is not declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_REMOVE_DEP_ABSENT)
        return 1

    def _mutate_remove(m: _Manifest) -> _Manifest:
        new_deps = tuple(d for d in m.deps if d.name != canonical_name)
        return _replace(m, deps=new_deps)

    # Re-resolve the WHOLE workspace via the SSOT orchestration primitive.
    env_with_index = _load_index_for_verb(env, ws_root)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior_for_alias,  # type: ignore[arg-type]
        manifest_dir=ws_root,
    )

    try:
        _graph, _wr = apply_member_manifest_change(
            ws_root, env_with_index, params, member_dir, _mutate_remove
        )
    except MilpaError as exc:
        print(f"milpa remove: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    print(f"removed {canonical_name}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_workspace_add_member / cmd_workspace_remove_member (S10)
# ---------------------------------------------------------------------------


def cmd_workspace_add_member(
    root: Path,
    env: MilpaEnv,
    *,
    member_path: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Append a member node to the workspace manifest and relock.

    Validation (before any on-disk mutation):
      - dir exists and contains milpa.kdl (→ WS-MEMBER-NO-MANIFEST / WS-MEMBER-DIR-MISSING)
      - milpa.kdl has a ``name`` (→ MAN-NAME-MISSING)
      - name is unique among existing members (→ WS-MEMBER-DUPLICATE-NAME)
      - member is not itself a workspace (→ WS-MEMBER-IS-WORKSPACE)

    Then delegates to apply_workspace_manifest_change for the atomic
    validate→resolve→write-manifest→write-lock ordering.

    spec/cli-contract.md §5.9.
    """
    from dataclasses import replace as _replace
    from milpa.manifest import (
        MAN_NAME_MISSING,
        WorkspaceManifest,
        parse_workspace_or_manifest,
    )
    from milpa.manifest_writer import apply_workspace_manifest_change

    # Resolve the member path relative to the workspace root.
    member_abs = (root / member_path).resolve()

    # Guard 1: directory must exist.
    if not member_abs.is_dir():
        print(
            f"milpa workspace add-member: {member_path!r}: "
            "directory does not exist",
            file=sys.stderr,
        )
        _emit_slug("WS-MEMBER-DIR-MISSING")
        return 1

    # Guard 2: must contain a milpa.kdl.
    kdl_path = member_abs / "milpa.kdl"
    if not kdl_path.exists():
        print(
            f"milpa workspace add-member: {member_path!r}: "
            "no milpa.kdl found",
            file=sys.stderr,
        )
        _emit_slug("WS-MEMBER-NO-MANIFEST")
        return 1

    # Guard 3: parse the member manifest; check for name (MAN-NAME-MISSING)
    # and no-nesting (WS-MEMBER-IS-WORKSPACE).
    try:
        member_text = kdl_path.read_text(encoding="utf-8")
        member_doc = parse_workspace_or_manifest(member_text)
    except MilpaError as exc:
        print(f"milpa workspace add-member: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    if isinstance(member_doc, WorkspaceManifest):
        print(
            f"milpa workspace add-member: {member_path!r} is itself a workspace; "
            "nested workspaces are not supported",
            file=sys.stderr,
        )
        _emit_slug("WS-MEMBER-IS-WORKSPACE")
        return 1

    # member_doc is a Manifest here.
    if member_doc.name is None:
        print(
            f"milpa workspace add-member: {member_path!r}: "
            "milpa.kdl has no name — add a `name \"...\"` declaration",
            file=sys.stderr,
        )
        _emit_slug("MAN-NAME-MISSING")
        return 1

    # Determine the member path to record in the manifest (relative to root).
    # Duplicate-name detection is handled by load_workspace_from_manifest inside
    # apply_workspace_manifest_change, which raises WS-MEMBER-DUPLICATE-NAME
    # before any on-disk mutation occurs.
    # Use the canonical relative path (member_abs relative to root).
    try:
        rel_path = str(member_abs.relative_to(root.resolve()))
    except ValueError:
        rel_path = member_path  # fallback: use as given

    # Delegate to apply_workspace_manifest_change (atomic validate→resolve→write).
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=None,
    )
    env_with_index = _load_index_for_verb(env, root)

    def _mutate(ws: WorkspaceManifest) -> WorkspaceManifest:
        return _replace(ws, members=ws.members + (rel_path,))

    try:
        _graph, _wr = apply_workspace_manifest_change(root, env_with_index, params, _mutate)
    except MilpaError as exc:
        print(f"milpa workspace add-member: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    print(f"added member {rel_path!r}", file=sys.stderr)
    return 0


def cmd_workspace_remove_member(
    root: Path,
    env: MilpaEnv,
    *,
    name_or_path: str,
    strategy: Strategy,
    max_parallel: int,
) -> int:
    """Drop a member node from the workspace manifest and relock.

    Validates BEFORE mutation (two symmetric dangling-reference refusal classes):
      - member not found (→ WS-REMOVE-MEMBER-NOT-FOUND)
      - dangling root override (→ WS-REMOVE-MEMBER-TARGET-EXISTS)
      - dangling member-edge in another member's deps/dev_deps
        (→ WS-REMOVE-MEMBER-REFERENCED)

    Then delegates to apply_workspace_manifest_change for the atomic ordering.

    spec/cli-contract.md §5.9.
    """
    from dataclasses import replace as _replace
    from milpa.manifest import MemberDep, MemberTarget, WorkspaceManifest
    from milpa.manifest_writer import apply_workspace_manifest_change
    from milpa.workspace import load_workspace

    # Load the current workspace (validates topology, raises WS-* on errors).
    try:
        current_ws = load_workspace(root)
    except MilpaError as exc:
        print(f"milpa workspace remove-member: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    ws_manifest = current_ws.workspace_manifest

    # Resolve name_or_path to a member declaration path in the workspace manifest.
    # Accept both a member package NAME (e.g. "liba") and a member PATH
    # (e.g. "member-a", "./member-a", or an absolute path).
    #
    # F19: also handle CWD-relative paths (e.g. "./member-b") by resolving against
    # root so that `milpa workspace remove-member ./member-b` works identically
    # to `milpa workspace remove-member member-b`.
    matched_path: str | None = None
    matched_name: str | None = None

    # Pre-compute the CWD-resolved abs path for relative args (e.g. "./member-b").
    _nop = Path(name_or_path)
    _cwd_resolved: Path | None = None
    if not _nop.is_absolute():
        try:
            _cwd_resolved = (root.resolve() / _nop).resolve()
        except (OSError, ValueError):
            _cwd_resolved = None

    for m in current_ws.members:
        candidate_paths = {m.rel_path, str(m.abs_dir), str(m.abs_dir.relative_to(root.resolve()) if m.abs_dir.is_relative_to(root.resolve()) else m.abs_dir)}
        # CWD-relative arm: if name_or_path resolves (via root) to this member's abs dir, accept it.
        if _cwd_resolved is not None and _cwd_resolved == m.abs_dir.resolve():
            matched_path = m.rel_path
            matched_name = m.manifest.name
            break
        if name_or_path == m.manifest.name or name_or_path in candidate_paths or name_or_path == m.rel_path:
            matched_path = m.rel_path
            matched_name = m.manifest.name
            break

    # Guard 1: member must exist.
    if matched_path is None:
        print(
            f"milpa workspace remove-member: {name_or_path!r} is not a member "
            "of this workspace",
            file=sys.stderr,
        )
        _emit_slug("WS-REMOVE-MEMBER-NOT-FOUND")
        return 1

    # Guard 2 (class-1): check for dangling root overrides (MemberTarget).
    if matched_name is not None:
        for ov in ws_manifest.overrides:
            if isinstance(ov.target, MemberTarget) and ov.target.member_name == matched_name:
                print(
                    f"milpa workspace remove-member: cannot remove member "
                    f"{matched_name!r}: the workspace root's overrides block "
                    f"has a MemberTarget entry for {matched_name!r} "
                    f"(pkg {ov.name!r} → member {matched_name!r}); "
                    "remove or update the override first",
                    file=sys.stderr,
                )
                _emit_slug("WS-REMOVE-MEMBER-TARGET-EXISTS")
                return 1

    # Guard 3 (class-2): check for dangling member-edges in other members'
    # deps AND dev_deps.
    referencing: list[str] = []
    if matched_name is not None:
        for m in current_ws.members:
            if m.rel_path == matched_path:
                continue  # skip the member being removed
            for dep in list(m.manifest.deps) + list(m.manifest.dev_deps):
                if isinstance(dep, MemberDep) and dep.name == matched_name:
                    if m.manifest.name:
                        referencing.append(m.manifest.name)
                    else:
                        referencing.append(m.rel_path)
                    break

    if referencing:
        referencing_str = ", ".join(repr(r) for r in sorted(referencing))
        print(
            f"milpa workspace remove-member: cannot remove member "
            f"{matched_name!r}: it is referenced by member-dep edges in: "
            f"{referencing_str}; remove those deps first",
            file=sys.stderr,
        )
        _emit_slug("WS-REMOVE-MEMBER-REFERENCED")
        return 1

    # Delegate to apply_workspace_manifest_change (atomic validate→resolve→write).
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        max_parallel=max_parallel,
        profile=profile,
        prior=None,
    )
    env_with_index = _load_index_for_verb(env, root)

    _matched_path = matched_path  # capture for closure

    def _mutate(ws: WorkspaceManifest) -> WorkspaceManifest:
        return _replace(ws, members=tuple(p for p in ws.members if p != _matched_path))

    try:
        _graph, _wr = apply_workspace_manifest_change(root, env_with_index, params, _mutate)
    except MilpaError as exc:
        print(f"milpa workspace remove-member: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    print(f"removed member {matched_name or matched_path!r}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# main()
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Top-level entry point.

    Returns the process exit code (0/1/2). Does NOT call sys.exit() —
    __main__.py calls sys.exit(main()).
    """
    parser = _make_parser()

    # No verb → print help + exit 0 (cli-contract.md §1).
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 0

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse exits 0 for --version/--help, 2 for usage errors.
        # R4: exit 2 carries NO milpa-error: line.
        return int(exc.code) if exc.code is not None else 2

    if args.command is None:
        parser.print_help()
        return 0

    # Resolve project directory (cli-contract.md §7).
    project_dir = Path(args.directory).resolve()

    # Build the MilpaEnv seam ONCE per process.
    try:
        env = _build_env(no_index=args.no_index)
    except Exception as exc:
        print(f"milpa: failed to initialise environment: {exc}", file=sys.stderr)
        _emit_slug(MILPA_INTERNAL)
        return 1

    # Resolve strategy enum.
    strategy = Strategy(args.strategy)

    # Parse --certificate path (cli-contract.md §2.5).
    certificate_path: Path | None = (
        Path(args.certificate).resolve() if args.certificate is not None else None
    )

    # S5: effective require_attested_metadata = CLI flag OR env var
    # (same OR semantics as manifest-strict OR flag; the env var cannot weaken
    # a manifest-declared strict policy either — all three are OR'd).
    _env_require_attested = os.environ.get("MILPA_REQUIRE_ATTESTED_METADATA", "")
    _env_require_attested_bool = bool(
        _env_require_attested and _env_require_attested not in ("0", "false")
    )
    effective_require_attested = args.require_attested_metadata or _env_require_attested_bool

    # S5 (RFC registry-trust-federation §6.3): read all 5 index-trust env vars.
    _env_index_trust = os.environ.get("MILPA_INDEX_TRUST", "").strip() or None
    _env_index_trust_signer = os.environ.get("MILPA_INDEX_TRUST_SIGNER", "").strip() or None
    _env_index_trust_bundle = os.environ.get("MILPA_INDEX_TRUST_BUNDLE", "").strip() or None
    _env_index_max_age_raw = os.environ.get("MILPA_INDEX_MAX_AGE", "").strip()
    _env_index_max_age: int = 604800  # default: 7 days
    if _env_index_max_age_raw:
        try:
            _env_index_max_age = int(_env_index_max_age_raw)
        except ValueError:
            print(
                f"milpa: warning: MILPA_INDEX_MAX_AGE={_env_index_max_age_raw!r} is "
                "not a valid integer; using default 604800 (7 days)",
                file=sys.stderr,
            )
    _env_index_bundle_url = os.environ.get("MILPA_INDEX_BUNDLE_URL", "").strip() or None

    # Build the effective IndexTrustConfig from env + CLI flags.
    # The manifest-level policy is applied later, per-verb, when the manifest is loaded.
    # Here we stash the env + flag inputs in MilpaEnv for use in _load_index_for_verb.
    _require_attested_index = getattr(args, "require_attested_index", False)
    _refresh_index = getattr(args, "refresh_index", False)

    # Update the env with index-trust state (env vars + flags).
    # require_attested_index escalates the effective policy warn→strict per-verb
    # in _build_index_trust; it must travel on env (not re-read from args later).
    from dataclasses import replace as _dc_replace
    env = _dc_replace(
        env,
        refresh_index=_refresh_index,
        require_attested_index=_require_attested_index,
    )

    # Dispatch.
    try:
        # S9 (RFC #23 §3.4): extract CLI feature-selection flags.
        # These are per-verb (fetch/lock/update) — only present when those
        # verbs are active; getattr with default handles other verbs safely.
        _cli_features = _parse_features(getattr(args, "features", "") or "")
        _cli_no_default = getattr(args, "no_default_features", False)
        _cli_all_features = getattr(args, "all_features", False)

        # S9 (RFC #23 §3.4): reject the mutually-exclusive combination
        # --all-features + --no-default-features (spec/errors.md §CLI).
        # --all-features activates every declared root flag; --no-default-features
        # suppresses all defaults and starts from an empty baseline — the two
        # intents are contradictory.  Cargo rejects this combination; milpa does
        # too.  Check here, before any resolver call, so the error surfaces
        # immediately (exit 1 + CLI-FEATURE-FLAGS-CONFLICT slug).
        if _cli_all_features and _cli_no_default:
            raise MilpaError(
                CLI_FEATURE_FLAGS_CONFLICT,
                "--all-features and --no-default-features are mutually exclusive: "
                "--all-features activates every declared root flag while "
                "--no-default-features suppresses all defaults — pass at most one",
            )

        if args.command == "fetch":
            return cmd_fetch(
                project_dir,
                env,
                strategy=strategy,
                max_parallel=args.parallel,
                frozen=args.frozen,
                certificate_path=certificate_path,
                require_attested_metadata=effective_require_attested,
                features=_cli_features,
                no_default_features=_cli_no_default,
                all_features=_cli_all_features,
            )
        elif args.command == "lock":
            return cmd_lock(
                project_dir,
                env,
                strategy=strategy,
                max_parallel=args.parallel,
                certificate_path=certificate_path,
                require_attested_metadata=effective_require_attested,
                features=_cli_features,
                no_default_features=_cli_no_default,
                all_features=_cli_all_features,
            )
        elif args.command == "show":
            if getattr(args, "index_trust", False):
                return cmd_show_index_trust(project_dir)
            return cmd_show(project_dir)
        elif args.command == "verify":
            return cmd_verify(
                project_dir,
                env,
                require_attested_metadata=effective_require_attested,
            )
        elif args.command == "clean":
            return cmd_clean(project_dir)
        elif args.command == "add":
            # S10 (RFC #23 §3.7): extract --optional and --features for add verb.
            # --features on `add` is a dep-level flag_requests list (distinct from
            # the resolve-level --features on fetch/lock/update).
            _add_optional = getattr(args, "optional", False)
            _add_features_raw = getattr(args, "features", "") or ""
            # Use _parse_features for comma-list → frozenset, then to tuple for UrlDep.
            _add_features: tuple[str, ...] = tuple(sorted(_parse_features(_add_features_raw)))
            return cmd_add(
                project_dir,
                env,
                dep_name=args.dep_name,
                git_url=args.git,
                mirror_url=args.mirror,
                ref=args.ref,
                strategy=strategy,
                max_parallel=args.parallel,
                optional=_add_optional,
                features=_add_features,
            )
        elif args.command == "remove":
            return cmd_remove(
                project_dir,
                env,
                dep_name=args.dep_name,
                strategy=strategy,
                max_parallel=args.parallel,
            )
        elif args.command == "update":
            return cmd_update(
                project_dir,
                env,
                dep_name=args.dep_name,
                strategy=strategy,
                max_parallel=args.parallel,
                features=_cli_features,
                no_default_features=_cli_no_default,
                all_features=_cli_all_features,
            )
        elif args.command == "workspace":
            ws_cmd = getattr(args, "workspace_command", None)
            if ws_cmd == "add-member":
                return cmd_workspace_add_member(
                    project_dir,
                    env,
                    member_path=args.member_path,
                    strategy=strategy,
                    max_parallel=args.parallel,
                )
            elif ws_cmd == "remove-member":
                return cmd_workspace_remove_member(
                    project_dir,
                    env,
                    name_or_path=args.name_or_path,
                    strategy=strategy,
                    max_parallel=args.parallel,
                )
            else:
                print("usage: milpa workspace <add-member|remove-member> [args]", file=sys.stderr)
                return 2
        elif args.command == "hash":
            from milpa.source_spec import parse_source_spec
            prov = parse_source_spec(list(args.source), base_dir=project_dir)
            return cmd_hash(prov, env)
        elif args.command == "store":
            store_cmd = getattr(args, "store_command", None)
            if store_cmd == "ls":
                return cmd_store_ls(env.store)
            elif store_cmd == "path":
                return cmd_store_path(env.store, args.identity_or_prefix)
            else:
                # No sub-command → print store help, exit 0.
                # (argparse doesn't expose the subparser directly from args,
                # so we re-parse to trigger help.)
                print("usage: milpa store <ls|path> [args]", file=sys.stderr)
                return 2
        else:
            # Should not happen — argparse validates the command.
            print(f"milpa: unknown command {args.command!r}", file=sys.stderr)
            _emit_slug(MILPA_INTERNAL)
            return 1

    except MilpaError as exc:
        # Typed error — carry the slug.
        print(f"milpa: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1
    except Exception as exc:
        # Unexpected exception — MILPA-INTERNAL sentinel (R3 invariant).
        print(f"milpa: unexpected error: {exc}", file=sys.stderr)
        _emit_slug(MILPA_INTERNAL)
        return 1
