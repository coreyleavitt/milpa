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
import dataclasses
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, TypeVar

from milpa import __version__
from milpa.cas import CAStore, default_store
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import (
    CLI_EXCLUDE_NEWER_INVALID,
    CLI_FEATURE_FLAGS_CONFLICT,
    CLI_LOCKED_UPGRADE_CONFLICT,
    FETCH_REF_DISCOVERY_FAILED,
    FROZEN_ACTIVE_FLAGS_MISMATCH,
    FROZEN_NO_LOCKFILE,
    LOCK_DEP_AMBIGUOUS_NAME,
    LOCK_DEP_NOT_FOUND,
    LOCK_DEPDECL_PIN_MISSING,
    LOCK_FILE_NOT_FOUND,
    LOCK_GRAPH_MISMATCH,
    MAN_ADD_DEP_EXISTS,
    MAN_MIRROR_EDITABLE_PROVENANCE,
    MAN_MUTATE_FILE_NOT_FOUND,
    MAN_MUTATE_WORKSPACE_REFUSED,
    MAN_NO_MANIFEST,
    MAN_REMOVE_DEP_ABSENT,
    MILPA_INDEX_UNREACHABLE,
    MILPA_INTERNAL,
    TNG_DEPDECL_FETCH_FAILED,
    TNG_INDEX_NOT_CONFIGURED,
    VERIFY_DEPS_DIR_MISSING,
    VERIFY_EDGE_MISMATCH,
    MilpaError,
    STORE_AMBIGUOUS_PREFIX,
    CAS_NOT_IN_STORE,
)
from milpa.fetchers import CasAdmittingFetcher, build_registry, mocked_registry
from milpa.fetchers.types import Provenance
from milpa.frozen import (
    check_source_id_preconditions_standalone,
    check_source_id_preconditions_workspace,
    resolve_frozen,
    resolve_workspace_frozen,
)
from milpa.index_cache import load_default_index
from milpa.lockfile import (
    GitProvenanceRecord,
    LockedDep,
    Lockfile,
    check_locked_drift,
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
from milpa.registry import _parse_timestamp
from milpa.resolver import (
    _resolve_effective_exclude_newer,
    _resolve_effective_strategy,
    resolve,
    resolve_workspace,
)
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


def _add_locked_arg(sp: argparse.ArgumentParser) -> None:
    """Add the B3 (resolution-semantics RFC §3 Axis B) ``--locked`` flag.

    Scoped to ``fetch``/``lock`` only (per-verb registration), like the other
    new resolution flags this RFC introduces — distinct from the legacy
    global ``--frozen``/``--strategy`` flags (RFC §3 Axis C's C3 migrates
    those to the same scoping later; this flag starts scoped from day one).
    """
    sp.add_argument(
        "--locked",
        action="store_true",
        default=False,
        help=(
            "resolve normally (with the minimal-change preference), then "
            "assert the result matches the committed milpa.lock exactly "
            "(identity + provenance, never the version label); fail with "
            "RES-LOCKED-DRIFT on any deviation or if no lockfile is "
            "committed. Distinct from --frozen: --locked always solves."
        ),
    )


def _add_upgrade_arg(sp: argparse.ArgumentParser) -> None:
    """Add the B4 (resolution-semantics RFC §3 Axis B / D-B3) ``--upgrade`` flag.

    Scoped to ``fetch``/``lock`` only (per-verb registration), like
    ``--locked``. Semantics:

    - bare ``--upgrade`` (no dep names): opt out of the minimal-change
      (lock-preference) default GLOBALLY — pull the latest allowed
      version everywhere (the pre-B2 newest-wins default, now explicit).
    - ``--upgrade <dep> [<dep>...]``: opt out ONLY for the named deps;
      every other dep keeps its locked preference.

    Implemented as DELEGATION to the exact strip-pin mechanism ``milpa
    update``/``milpa update <dep>`` already uses — see
    ``_strip_pins_for_upgrade``, the one shared helper both call, so the
    two verbs cannot structurally drift (D-B3). Mutually exclusive with
    ``--locked`` (``CLI-LOCKED-UPGRADE-CONFLICT``): one forbids deviation,
    the other forces it.
    """
    sp.add_argument(
        "--upgrade",
        nargs="*",
        metavar="<dep>",
        default=None,
        help=(
            "opt out of the minimal-change (lock-preference) default and "
            "pull the latest allowed version; with no names, globally "
            "(the pre-minimal-change newest-wins default); with one or "
            "more <dep> names, only for those deps — everything else "
            "stays locked. Delegates to the same mechanism as `milpa "
            "update`/`milpa update <dep>`. Mutually exclusive with "
            "--locked (CLI-LOCKED-UPGRADE-CONFLICT)."
        ),
    )


def _add_strategy_arg(sp: argparse.ArgumentParser) -> None:
    """Add the C3 (resolution-semantics RFC §3 Axis C / D-C2) ``--strategy``
    flag, scoped per-verb (fetch/lock/update/add/remove/workspace
    add-member/remove-member — the resolve-triggering verbs), like
    ``--locked``/``--upgrade`` — NOT the old global, pre-dispatch
    registration (valid, and silently ignored, on ``show``/``clean``/etc.).

    ``default=None`` is the load-bearing part: ``None`` means "unspecified,
    defer to the manifest's ``resolution { strategy }``, else the global
    default (maxver)" — distinct from an explicit ``--strategy maxver``,
    which always wins even though it names the default value. Before this,
    both impls resolved ``--strategy`` to a *concrete* ``Strategy`` via a
    literal default, so there was no way to tell "typed the default" from
    "typed nothing" — the precedence chain and the D-C2 bypass-on-
    value-divergence both require that distinction.

    R9 (§3 Axis C NORMATIVE: the lockfile-recorded strategy is
    "diagnostic/frozen-parity only, never a live input"): unspecified
    ``--strategy`` no longer falls through to the committed lockfile's
    recorded strategy — a bare resolve's stability against a non-default
    lock rides on B2's lock-preference mechanism instead (see
    ``resolver._resolve_effective_strategy`` / ``_bypasses_lock_preference``).
    """
    sp.add_argument(
        "-s",
        "--strategy",
        metavar="<mode>",
        choices=("maxver", "minver", "semver", "lowest-direct"),
        default=None,
        help=(
            "resolution strategy: maxver, minver, semver, lowest-direct "
            "(minver for root-direct deps, maxver for transitive deps). "
            "Unspecified (the default) defers to the manifest's "
            "'resolution { strategy }' if declared, else maxver."
        ),
    )


def _add_exclude_newer_arg(sp: argparse.ArgumentParser) -> None:
    """Add the D2 (resolution-semantics RFC §3 Axis D) ``--exclude-newer``
    flag, scoped to ``fetch``/``lock`` ONLY — narrower than ``--strategy``'s
    per-verb scoping.  §3 Axis D "Verb reach": a CLI time-bound override is
    a fetch/lock-time CI concern (``milpa fetch --exclude-newer <ts>`` to
    test an LTS snapshot); ``add``/``update``/``remove`` always read the
    manifest's committed ``resolution { exclude-newer }`` bound instead —
    they do not accept this flag at all (a hard parse error, exit 2, if
    passed there).

    ``default=None`` is the same load-bearing sentinel ``_add_strategy_arg``
    uses: ``None`` means "unspecified, defer to the manifest's
    ``resolution { exclude-newer }`` (or no bound at all)" — distinct from
    an explicit value.  The raw string is validated + parsed to a
    ``datetime`` in ``main()`` (not here — argparse has no ISO-8601 type
    hook that raises milpa's own ``CLI-EXCLUDE-NEWER-INVALID`` slug with a
    ``milpa-error:`` line rather than argparse's own exit-2 usage error).
    """
    sp.add_argument(
        "--exclude-newer",
        metavar="<ts>",
        default=None,
        help=(
            "resolve as of this point in time (ISO 8601, e.g. "
            "2026-01-01T00:00:00Z): overrides the manifest's "
            "'resolution { exclude-newer }' if declared. fetch/lock only."
        ),
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
    # P3a (RFC per-entry-attestation.md §4): entry-trust flag.
    parser.add_argument(
        "--require-attested-entries",
        action="store_true",
        default=False,
        help=(
            "escalate entry-trust policy from 'warn' to 'strict'; CI hard-fail toggle. "
            "Cannot set or clear 'off' — only the manifest can declare "
            "entry-trust \"off\". Mirrors --require-attested-index for the "
            "per-entry author-attribution axis (RFC per-entry-attestation.md §4)."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # fetch
    sp_fetch = subparsers.add_parser(
        "fetch",
        help="resolve manifest, clone deps, emit nim.cfg, write lockfile",
    )
    _add_feature_args(sp_fetch)
    _add_locked_arg(sp_fetch)
    _add_upgrade_arg(sp_fetch)
    _add_strategy_arg(sp_fetch)
    _add_exclude_newer_arg(sp_fetch)

    # lock
    sp_lock = subparsers.add_parser(
        "lock",
        help="resolve manifest and write lockfile (no nim.cfg, no _deps/)",
    )
    _add_feature_args(sp_lock)
    _add_locked_arg(sp_lock)
    _add_upgrade_arg(sp_lock)
    _add_strategy_arg(sp_lock)
    _add_exclude_newer_arg(sp_lock)

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
    # A3b (§3 Axis A (b) step 4): write a version= annotation on the new dep,
    # the natural-site workflow for the resolver's declared-version escape hatch.
    sp_add.add_argument(
        "--version",
        metavar="<version>",
        help=(
            "write a 'version=' annotation on the new dep (resolution-semantics "
            "RFC §3 Axis A (b) step 4): a declared version the resolver uses "
            "when the fetched package's own manifest/tag yield none"
        ),
    )
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
    _add_strategy_arg(sp_add)

    # remove (stub — 10e)
    sp_remove = subparsers.add_parser(
        "remove",
        help="remove a dep from milpa.kdl (10e, not yet implemented)",
    )
    sp_remove.add_argument("dep_name", metavar="<dep>")
    _add_strategy_arg(sp_remove)

    # update (stub — 10e)
    sp_update = subparsers.add_parser(
        "update",
        help="re-resolve and refresh the lockfile (10e, not yet implemented)",
    )
    sp_update.add_argument("dep_name", metavar="<dep>", nargs="?", default=None)
    _add_feature_args(sp_update)
    _add_strategy_arg(sp_update)

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
    _add_strategy_arg(sp_ws_add)

    sp_ws_remove = ws_sub.add_parser(
        "remove-member",
        help="remove a member from the workspace (drops the member node, then relocks)",
    )
    _add_strategy_arg(sp_ws_remove)
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

    # index — append-only-ratchet inspection/reset surface (A2e,
    # rfc-registry-append-only.md; cli-contract.md §5.12). Third instance of
    # the nested-subparser pattern established by workspace/store, above.
    sp_index = subparsers.add_parser(
        "index",
        help="inspect and accept append-only-ratchet state (status, accept)",
    )
    index_sub = sp_index.add_subparsers(dest="index_command", metavar="<index-command>")
    sp_index_status = index_sub.add_parser(
        "status",
        help="report the locally-cached append-only-ratchet state (read-only)",
    )
    sp_index_status.add_argument(
        "--refresh",
        action="store_true",
        default=False,
        help="preview a forced refresh's diff, without writing anything (dry-run)",
    )
    index_sub.add_parser(
        "accept",
        help="fetch, print the diff, and atomically accept the new trust baseline",
    )

    # publish — author-side packaging/push/sign (S4, spec/cli-contract.md §10:
    # out-of-v1.0-conformance, impl-specific).
    sp_publish = subparsers.add_parser(
        "publish",
        help="pack the current git HEAD's source tree, push to an OCI registry, and sign it",
    )
    sp_publish.add_argument(
        "--version",
        metavar="<semver>",
        required=True,
        help="the version being published; checked against a matching git tag on HEAD",
    )
    sp_publish.add_argument(
        "--target",
        metavar="<registry>/<repository>",
        required=True,
        help=(
            "OCI push destination as one combined token, split on the FIRST '/' "
            "(mirrors the shipped 'oci=<registry>/<repository>@<digest>' consumer "
            "grammar) — e.g. ghcr.io/coreyleavitt/z3"
        ),
    )
    sp_publish.add_argument(
        "--name",
        metavar="<name>",
        default=None,
        help="package name; auto-derived from the manifest's 'name' node if omitted",
    )
    sp_publish.add_argument(
        "--tag",
        metavar="<tag>",
        default=None,
        help="OCI tag to push under; defaults to --version if omitted",
    )
    sp_publish.add_argument(
        "--output",
        metavar="<path>",
        default=None,
        help=(
            "write the publish result as JSON to <path> — the plan render under "
            "--dry-run, or the PublishReceipt otherwise"
        ),
    )
    sp_publish.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help=(
            "build the plan and print it (content hash + enumeration stats) "
            "without pushing or signing anything; touches no network"
        ),
    )
    sp_publish.add_argument(
        "--allow-untagged",
        action="store_true",
        default=False,
        help=(
            "skip the version<->HEAD git-tag binding guard "
            "(PUBLISH-VERSION-TAG-MISMATCH escape hatch)"
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


def _resolve_index_url_three_way() -> "str | None":
    """Resolve ``MILPA_INDEX_URL`` to the three-way store-selection URL.

    - **absent** → ``DEFAULT_INDEX_URL`` (the live tianguis index).
    - **present but empty** (``""``) → ``None`` (explicitly no index).
    - **present and non-empty** → that URL (stripped).

    SSOT for call sites that need an ``Optional[str]`` to hand to a
    ``*_store_from_paths`` selector (``_build_dep_decl_store``,
    ``_build_entry_trust``) — distinct from ``index_cache.index_url_from_env``,
    whose non-Optional contract ("always resolves to something") serves
    ``_load_index_for_verb``'s different absent-vs-present distinction.
    """
    from milpa.index_cache import DEFAULT_INDEX_URL

    raw = os.environ.get("MILPA_INDEX_URL")  # None if absent, str if set
    if raw is None:
        return DEFAULT_INDEX_URL
    stripped = raw.strip()
    return stripped if stripped else None  # empty → explicitly no index


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

    # Resolve env vars to canonical values before handing to the shared helper.
    dep_decl_dir_str = os.environ.get("MILPA_DEP_DECL_DIR", "").strip()
    dep_decl_dir = Path(dep_decl_dir_str) if dep_decl_dir_str else None

    return dep_decl_store_from_paths(
        dep_decl_dir=dep_decl_dir,
        index_url=_resolve_index_url_three_way(),
        no_index=_no_index_requested(no_index),
    )


# ---------------------------------------------------------------------------
# Index loading helper (for fetch / lock)
# ---------------------------------------------------------------------------


def _manifest_absent(exc: MilpaError) -> bool:
    """True iff ``exc`` represents a genuinely-absent manifest.

    SSOT for the trust-axis manifest loaders (``_load_manifest_trust_fields``
    for index-trust, ``_load_manifest_entry_trust_policy`` for entry-trust,
    ``_load_manifest_index_history_policy`` for index-history): each degrades
    to its policy default ONLY when there is no ``milpa.kdl``/``.nimble`` at
    all (``MAN-NO-MANIFEST``). A PRESENT-but-broken manifest (``MAN-KDL-SYNTAX``,
    ``MAN-UNKNOWN-TOP-LEVEL``, etc.) is a genuine error and must hard-fail —
    spec/cli-contract.md §5.12's soft-fail carve-out is scoped to corrupt
    LOCAL TRUST STATE (a corrupt baseline), not manifest-parse errors; the
    general convention (§5 NORMATIVE) makes manifest errors hard failures.
    Silently downgrading a broken manifest to "warn" would hide it behind a
    normal-looking status block.
    """
    return exc.slug == MAN_NO_MANIFEST


_T = TypeVar("_T")


def _load_root_policy(
    project_dir: Path,
    from_workspace: "Callable[[object], _T]",
    from_manifest: "Callable[[object], _T]",
    default: "_T",
) -> "_T":
    """Shared control-flow for the root-only trust-axis manifest loaders.

    Every trust-axis policy (index-trust, entry-trust, index-history) is a
    ROOT-ONLY setting: the resolution root is the workspace root manifest
    (for a workspace) or the package manifest itself (standalone). Members
    MUST NOT declare it — ``find_workspace_root`` (via the ``load_workspace``
    it performs) raises the axis's own ``WS-*-ON-MEMBER`` error when one
    does, and that error PROPAGATES from here (the workspace branch is
    UNGUARDED on purpose: a present-but-invalid workspace must raise, never
    silently fall back to a default).

    Only a genuinely-absent standalone manifest (``_manifest_absent``)
    degrades to ``default``; any other error (a present-but-broken manifest)
    re-raises.

    ``from_workspace``/``from_manifest`` extract the axis-specific field(s)
    from the workspace root manifest / standalone manifest respectively —
    the one place the three axes genuinely differ (a policy string for
    entry-trust/index-history, a ``(policy, signer, bundle)`` tuple for
    index-trust).
    """
    ws = find_workspace_root(project_dir)
    if ws is not None:
        return from_workspace(ws.workspace_manifest)
    try:
        m = load_or_discover_manifest(project_dir)
    except MilpaError as exc:
        if _manifest_absent(exc):
            return default
        raise
    return from_manifest(m)


def _load_manifest_trust_fields(
    project_dir: Path,
) -> "tuple[str, str | None, str | None]":
    """Load (policy, signer, bundle) from the resolution ROOT.  Pure I/O.

    index-trust is a root-only policy (spec §3.4.7) — see ``_load_root_policy``
    for the shared workspace/standalone/absent-manifest control-flow.

    SSOT shared by ``_build_index_trust`` (enforcement gate) and
    ``cmd_show_index_trust`` (observability) — spec §5.3a.
    """
    return _load_root_policy(
        project_dir,
        lambda wm: (
            str(wm.index_trust_policy),
            wm.index_trust_signer,
            wm.index_trust_bundle,
        ),
        lambda m: (str(m.index_trust_policy), m.index_trust_signer, m.index_trust_bundle),
        ("warn", None, None),
    )


def _resolve_trust_bundle_and_signer(
    env_bundle_path: "str | None",
    manifest_bundle: "str | None",
    env_signer: "str | None",
    manifest_signer: "str | None",
) -> "tuple[object, str]":
    """Resolve ``(TrustBundle, expected_signer)`` from index-trust inputs.

    Extracted from ``_build_index_trust`` so ``_build_entry_trust`` (P3a) can
    derive the SAME effective vendor-bot identity Layer 1 resolved (RFC
    per-entry-attestation.md §5 NORMATIVE: the vendored-kind expected signer
    must be "the SAME effective vendor-bot identity Layer 1 resolved... never
    a second hardcoded copy of the default") without duplicating the
    file-loading / priority logic. Both callers pass their own env/manifest
    values (index-trust and entry-trust share the trust-root/signer INPUTS —
    ``MILPA_INDEX_TRUST_SIGNER`` / ``index-trust-signer`` — even though they
    are separate policy axes, RFC §4).
    """
    from milpa.index_trust import DEFAULT_INDEX_SIGNER, TrustBundle

    # Build trust bundle: env override path > manifest path > production embedded.
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
        trust_bundle: object = TrustBundle(raw_json=raw, label=f"custom:{fs_path}")
    else:
        trust_bundle = TrustBundle.production()

    # Build expected signer: env > manifest > default tianguis signer (SSOT constant).
    expected_signer = env_signer or manifest_signer or DEFAULT_INDEX_SIGNER

    return trust_bundle, expected_signer


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

    trust_bundle, expected_signer = _resolve_trust_bundle_and_signer(
        env_bundle_path, manifest_bundle, env_signer, manifest_signer
    )

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


# ---------------------------------------------------------------------------
# P3a — entry-trust gate config (RFC per-entry-attestation.md §3, §4, §5)
# ---------------------------------------------------------------------------


def _load_manifest_entry_trust_policy(project_dir: Path) -> str:
    """Load the entry-trust policy from the resolution ROOT.  Pure I/O.

    entry-trust is a root-only policy (RFC §4) — see ``_load_root_policy``
    for the shared workspace/standalone/absent-manifest control-flow.
    """
    return _load_root_policy(
        project_dir,
        lambda wm: wm.entry_trust_policy,
        lambda m: m.entry_trust_policy,
        "warn",
    )


def _effective_entry_trust_policy(env: MilpaEnv, project_dir: Path) -> "TrustPolicy":
    """The effective entry-trust policy alone (steps 1-3 of
    ``_build_entry_trust``, factored out as the SSOT both that function and
    the S-EpochCommitment D18 co-requirement check (``_apply_epoch_commitment_phase``)
    call — computing the full ``EntryTrustConfig`` just for its policy field
    would build a bundle store and resolve a verifier for no reason)."""
    from milpa.trust import effective_trust_policy

    env_entry_trust_raw = os.environ.get("MILPA_ENTRY_TRUST", "").strip() or None
    manifest_policy = _load_manifest_entry_trust_policy(project_dir)
    return effective_trust_policy(
        manifest_policy,  # type: ignore[arg-type]
        flag=env.require_attested_entries,
        env_override=env_entry_trust_raw,
    )


def _build_entry_trust(
    env: MilpaEnv,
    project_dir: Path,
) -> "object | None":
    """Build the ``EntryTrustConfig`` for the entry-trust gate, or ``None``.

    Returns ``None`` when the effective policy is ``'off'`` (gate disabled) —
    ``resolve()`` / ``resolve_workspace()`` never invoke the gate machinery
    in that case (mirrors ``_build_index_trust``'s ``(None, None)``).

    Authority model (RFC §4, §5):
    1. Load the entry-trust policy from the resolution ROOT
       (``_load_manifest_entry_trust_policy``).
    2. Compute effective policy = effective_trust_policy(manifest, flag, env).
    3. If off → return None.
    4. Reuse index-trust's trust-root + expected-signer resolution
       (``_resolve_trust_bundle_and_signer``) — RFC §5 NORMATIVE: the
       vendored-kind expected signer MUST be the SAME effective vendor-bot
       identity Layer 1 resolved, never a second hardcoded copy.
    5. Build the bundle store: ``MILPA_ENTRY_BUNDLE_DIR`` (mirror of
       ``MILPA_DEP_DECL_DIR``) or derived from the index URL.
    6. Build verifier: ``MockEntryVerifier`` from the
       ``MILPA_ENTRY_TRUST_MOCK_MAP`` / ``MILPA_ENTRY_TRUST_MOCK_DEFAULT``
       conformance seam (file://-index-only guard, mirroring
       ``MILPA_INDEX_TRUST_MOCK_VERIFIER``), or ``SigstoreEntryVerifier``
       in production.
    """
    import json as _json

    from milpa.entry_bundle_store import entry_bundle_store_from_paths
    from milpa.entry_trust import (
        BundleMalformed,
        DigestMismatch,
        EntryTrustConfig,
        MockEntryVerifier,
        SignatureInvalid,
        SignerMismatch,
        SigstoreEntryVerifier,
        SubjectMismatch,
        Trusted,
    )
    # 1-3. Effective entry-trust policy (SSOT, shared with the
    # S-EpochCommitment D18 co-requirement check).
    policy = _effective_entry_trust_policy(env, project_dir)

    if policy == "off":
        return None

    # 4. Reuse index-trust's trust-root + expected-signer resolution (RFC §5).
    env_signer = os.environ.get("MILPA_INDEX_TRUST_SIGNER", "").strip() or None
    env_bundle_path = os.environ.get("MILPA_INDEX_TRUST_BUNDLE", "").strip() or None
    _, manifest_signer, manifest_bundle = _load_manifest_trust_fields(project_dir)
    trust_bundle, expected_signer = _resolve_trust_bundle_and_signer(
        env_bundle_path, manifest_bundle, env_signer, manifest_signer
    )

    # 5. Build the bundle-acquisition store. Three-way MILPA_INDEX_URL
    # semantics (S-Acq, RFC attestation-v1-normative.md): absent →
    # DEFAULT_INDEX_URL (so a store IS built and acquisition is actually
    # attempted in the normal no-override case — the bug this slice fixes,
    # a plain `raw_index_url if raw_index_url else None` collapsed absent
    # and empty to the same `None`); empty → None (explicitly no index);
    # non-empty → that URL. Same SSOT helper `_build_dep_decl_store` uses.
    entry_bundle_dir_str = os.environ.get("MILPA_ENTRY_BUNDLE_DIR", "").strip()
    entry_bundle_dir = Path(entry_bundle_dir_str) if entry_bundle_dir_str else None
    index_url = _resolve_index_url_three_way()
    bundle_store = entry_bundle_store_from_paths(
        entry_bundle_dir, index_url, no_index=env.no_index
    )

    # 6. Build verifier: MockEntryVerifier from conformance seam, SigstoreEntryVerifier
    # in production. Mirrors MILPA_INDEX_TRUST_MOCK_VERIFIER's file://-only guard.
    _MOCK_MAP = {
        "trusted": Trusted,
        "bundle-malformed": BundleMalformed,
        "digest-mismatch": DigestMismatch,
        "subject-mismatch": SubjectMismatch,
        "signature-invalid": SignatureInvalid,
        "signer-mismatch": SignerMismatch,
    }
    mock_map_raw = os.environ.get("MILPA_ENTRY_TRUST_MOCK_MAP", "").strip()
    mock_default_raw = os.environ.get("MILPA_ENTRY_TRUST_MOCK_DEFAULT", "").strip()
    verifier: object
    if mock_map_raw or mock_default_raw:
        # Guard: mock seam is conformance-internal; ONLY honored for file:// indexes.
        if not (index_url or "").startswith("file://"):
            raise MilpaError(
                MILPA_INTERNAL,
                "MILPA_ENTRY_TRUST_MOCK_MAP / MILPA_ENTRY_TRUST_MOCK_DEFAULT are "
                "conformance-internal and only honored for file:// index URLs "
                "(all conformance fixtures use file://; production indexes are "
                "https). These variables must not be set in production or with "
                "non-file:// index URLs.",
            )
        if mock_default_raw:
            if mock_default_raw not in _MOCK_MAP:
                raise MilpaError(
                    MILPA_INTERNAL,
                    f"MILPA_ENTRY_TRUST_MOCK_DEFAULT={mock_default_raw!r} is not a valid "
                    f"result wire string (expected one of: {', '.join(_MOCK_MAP)}). "
                    "Test seam must never fail-open silently.",
                )
            default_result = _MOCK_MAP[mock_default_raw]
        else:
            default_result = Trusted
        by_subject: dict[str, object] = {}
        if mock_map_raw:
            try:
                raw_map = _json.loads(mock_map_raw)
                for k, v in raw_map.items():
                    if v not in _MOCK_MAP:
                        raise MilpaError(
                            MILPA_INTERNAL,
                            f"MILPA_ENTRY_TRUST_MOCK_MAP entry {k!r}={v!r} is not a valid "
                            f"result wire string (expected one of: {', '.join(_MOCK_MAP)}). "
                            "Test seam must never fail-open silently.",
                        )
                    by_subject[k] = _MOCK_MAP[v]
            except _json.JSONDecodeError as exc:
                raise MilpaError(
                    MILPA_INTERNAL,
                    f"MILPA_ENTRY_TRUST_MOCK_MAP is not valid JSON: {exc}",
                ) from exc
        verifier = MockEntryVerifier(default=default_result, by_subject=by_subject)
    else:
        verifier = SigstoreEntryVerifier()

    return EntryTrustConfig(
        policy=policy,
        trust_bundle=trust_bundle,
        expected_vendor_signer=expected_signer,
        verifier=verifier,
        bundle_store=bundle_store,
    )


# ---------------------------------------------------------------------------
# A2c — index-history policy-axis plumbing (RFC registry-append-only.md §2,
# spec/registry-protocol.md §3.4.0 / §3.5.2)
# ---------------------------------------------------------------------------


def _load_manifest_index_history_policy(project_dir: Path) -> str:
    """Load the index-history policy from the resolution ROOT.  Pure I/O.

    index-history is a root-only policy (RFC registry-append-only.md §2) —
    see ``_load_root_policy`` for the shared workspace/standalone/
    absent-manifest control-flow.
    """
    return _load_root_policy(
        project_dir,
        lambda wm: wm.index_history_policy,
        lambda m: m.index_history_policy,
        "warn",
    )


def _build_index_history(env: MilpaEnv, project_dir: Path) -> str:
    """Compute the effective ``index-history`` policy for this invocation.

    A2c is pure policy-axis plumbing: manifest field + ``MILPA_INDEX_HISTORY``
    env layering, resolved through the shared ``effective_trust_policy`` SSOT
    (``trust.py``) — the SAME authority formula ``index-trust`` / ``entry-trust``
    use (spec/registry-protocol.md §3.4.0). Unlike those two axes, no CLI flag
    escalates ``index-history`` (spec/cli-contract.md §8.7 defines none), so
    ``flag`` is always ``False``.

    Returns the bare ``TrustPolicy`` value, not a config object: this axis has
    no signer/bundle/verifier inputs — the ratchet is a pure content diff
    against a locally-cached baseline, not a Sigstore verification. The A2d
    slice consumes this policy at the index-cache seam to gate the ratchet
    (baseline read/compare/write); A2c performs no baseline I/O.
    """
    from milpa.trust import effective_trust_policy

    env_history_raw = os.environ.get("MILPA_INDEX_HISTORY", "").strip() or None
    manifest_policy = _load_manifest_index_history_policy(project_dir)
    return effective_trust_policy(
        manifest_policy,  # type: ignore[arg-type]
        flag=False,
        env_override=env_history_raw,
    )


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
    index_history_policy = "off"
    if project_dir is not None:
        config, verifier = _build_index_trust(env, project_dir)
        index_history_policy = _build_index_history(env, project_dir)

    # Absent → DEFAULT_INDEX_URL; non-empty → that URL.
    # load_default_index() calls index_url_from_env() which handles both cases.
    try:
        index = load_default_index(
            config=config,
            verifier=verifier,
            refresh=env.refresh_index,
            index_history_policy=index_history_policy,
        )
    except MilpaError as exc:
        if exc.slug == MILPA_INDEX_UNREACHABLE:
            # Unreachable index → let the resolver raise RES-NO-INDEX per dep.
            return replace(env, index=None)
        raise  # TNG-* and other catalog errors propagate

    # S-EpochCommitment (rfc-attestation-v1-normative.md §6, D14-D18;
    # registry-protocol §3.4.8/§3.4.9): the index-gate epoch-commitment
    # phase, once per resolve, after index-trust's own verification
    # succeeds and BEFORE any candidate is selected (this function runs
    # before the resolver in every verb that calls it).
    if project_dir is not None and config is not None and verifier is not None:
        _apply_epoch_commitment_phase(env, project_dir, index, config, index_history_policy)

    return replace(env, index=index)


# ---------------------------------------------------------------------------
# S-EpochCommitment — the index-gate epoch-commitment phase (RFC
# rfc-attestation-v1-normative.md §6, D14-D18; registry-protocol §3.4.8/§3.4.9)
# ---------------------------------------------------------------------------


def _apply_epoch_commitment_phase(
    env: MilpaEnv,
    project_dir: Path,
    index: "object",
    index_trust_config: "object",
    index_history_policy: str,
) -> None:
    """Compute + enforce the epoch-commitment phase for one already-loaded
    ``Index`` (mutated in place — ``Index`` is not frozen).

    Reuses index-trust's already-resolved trust ROOT (``index_trust_config
    .trust_bundle``) — the epoch commitment is authenticated against a
    DEDICATED re-arm signer identity (D15), never the whole-index signer,
    but the Fulcio/Rekor trust root is the same one index-trust resolved
    for this invocation (spec §3.4.8: "resolved the same way").

    JUDGMENT CALL (flagged, not spec-mandated): this phase runs ONLY when
    index-trust is active for this invocation (the caller only invokes this
    function when ``config is not None``, i.e. effective index-trust policy
    is not ``"off"``). Spec §3.4.8 frames the phase as part of "the index
    gate" without explicitly stating whether it is reachable when the
    index-trust axis itself is disabled; since the phase's crypto has no
    trust root to verify against in that case, gating it on index-trust's
    own on/off state is the defensible reading adopted here. An index that
    HAS armed a commitment while a consumer runs with index-trust off is
    therefore silently treated as ``Unarmed`` by this consumer — a
    documented residual, not a silent security downgrade of a check the
    consumer opted into (index-trust off already means "no whole-index
    crypto for this invocation").

    Raises:
        MilpaError(TNG-INDEX-EPOCH-COMMITMENT-INVALID) — unconditional
            abort on ``ArmingInvalid`` (D14).
        MilpaError(TNG-INDEX-EPOCH-RATCHET-REQUIRED) — the D18
            co-requirement (``Armed`` + ``entry-trust=strict`` requires
            ``index-history=strict``).
    """
    from milpa.epoch_commitment import (
        DEFAULT_REARM_SIGNER,
        check_epoch_ratchet_requirement,
        enforce_epoch_commitment,
    )
    from milpa.index_cache import (
        index_url_from_env,
        load_epoch_commitment_status,
        read_cached_epoch_commitment_pointer,
    )
    from milpa.index_trust import MockVerifier, SigstoreVerifier, VerificationResult

    index_url = index_url_from_env()
    pointer = read_cached_epoch_commitment_pointer(index_url)

    # Verifier: MockVerifier from the conformance seam (mirrors
    # MILPA_INDEX_TRUST_MOCK_VERIFIER's file://-only guard exactly), else
    # SigstoreVerifier — the SAME production class index-trust uses (see
    # epoch_commitment.py's "Composed verification reuse" for why this is
    # safe: only expected_signer differs).
    _MOCK_MAP = {
        "trusted": VerificationResult.TRUSTED,
        "sig-invalid": VerificationResult.SIG_INVALID,
        "digest-mismatch": VerificationResult.DIGEST_MISMATCH,
        "signer-mismatch": VerificationResult.SIGNER_MISMATCH,
        "bundle-stale": VerificationResult.BUNDLE_STALE,
        "bundle-missing": VerificationResult.BUNDLE_MISSING,
        "bundle-malformed": VerificationResult.BUNDLE_MALFORMED,
    }
    mock_result_str = os.environ.get("MILPA_INDEX_EPOCH_MOCK_VERIFIER", "").strip()
    verifier: object
    if mock_result_str:
        if not index_url.startswith("file://"):
            raise MilpaError(
                MILPA_INTERNAL,
                "MILPA_INDEX_EPOCH_MOCK_VERIFIER is conformance-internal and only "
                "honored for file:// index URLs (all conformance fixtures use "
                "file://; production indexes are https). This variable must not "
                "be set in production or with non-file:// index URLs.",
            )
        mock_result = _MOCK_MAP.get(mock_result_str)
        if mock_result is None:
            raise MilpaError(
                MILPA_INTERNAL,
                f"MILPA_INDEX_EPOCH_MOCK_VERIFIER={mock_result_str!r} is not a "
                f"valid VerificationResult wire string (expected one of: "
                f"{', '.join(_MOCK_MAP)}). Test seam must never fail-open silently.",
            )
        verifier = MockVerifier(mock_result)
    else:
        verifier = SigstoreVerifier()

    # Signer: a DEDICATED re-arm identity (D15), overridable independently
    # of the whole-index signer (MILPA_INDEX_TRUST_SIGNER is NOT reused here
    # on purpose). No manifest-node override exists yet (env-only for this
    # slice) — a natural follow-up, not a trust-default change.
    expected_signer = (
        os.environ.get("MILPA_INDEX_EPOCH_SIGNER", "").strip() or DEFAULT_REARM_SIGNER
    )

    status = load_epoch_commitment_status(
        index_url=index_url,
        pointer=pointer,
        verifier=verifier,
        trust_bundle=index_trust_config.trust_bundle,  # type: ignore[attr-defined]
        expected_signer=expected_signer,
    )
    index.epoch_commitment_status = status  # type: ignore[attr-defined]

    enforce_epoch_commitment(status)

    entry_trust_policy = _effective_entry_trust_policy(env, project_dir)
    check_epoch_ratchet_requirement(
        status,
        entry_trust_policy=entry_trust_policy,
        index_history_policy=index_history_policy,
    )


def _reverify_cached_index_bundle(env: MilpaEnv, project_dir: "Path | None") -> None:
    """Sv: re-verify the CACHED index attestation bundle offline (never fetches).

    Builds the same ``IndexTrustConfig`` + verifier as index loading, then re-runs
    verification against the on-disk cache via ``index_cache.reverify_cached_index``.
    Skips silently when no index is configured (``--no-index`` / empty
    ``MILPA_INDEX_URL``), when the effective policy is ``off``, or when nothing is
    cached. A failing cached bundle raises the mapped ``TNG-INDEX-*`` slug under
    ``strict`` (warns under ``warn``).
    """
    from milpa.index_cache import (
        _default_cache_dir,
        index_url_from_env,
        reverify_cached_index,
    )

    if _no_index_requested(env.no_index):
        return
    raw_index_url = os.environ.get("MILPA_INDEX_URL")
    if raw_index_url is not None and raw_index_url.strip() == "":
        return  # explicitly no index → nothing to reverify
    config, verifier = _build_index_trust(env, project_dir) if project_dir is not None else (None, None)
    reverify_cached_index(index_url_from_env(), _default_cache_dir(), config, verifier)


def _reverify_cached_entry_attestations(
    env: "MilpaEnv | None",
    project_dir: "Path | None",
    lockfile: "Lockfile",
) -> None:
    """P3a (RFC per-entry-attestation.md §7): re-verify CACHED per-entry
    attestation bundles offline — NEVER fetches.

    For each locked dep carrying an ``attestation`` block, re-derive the
    verification outcome from the cached bundle (crypto + subject binding,
    no freshness — mirrors ``reverify_cached_index``'s shape) against the
    lockfile's recorded kind/signer/namespace. Missing cached bundle →
    ``TNG-ENTRY-BUNDLE-MISSING`` (warn/strict per policy). Skips silently
    when ``env``/``project_dir`` is ``None`` (unit-test bypass, mirrors
    ``_reverify_cached_index_bundle``) or when the effective entry-trust
    policy is ``off``.

    Offline invariant: this function checks ``bundle_store.is_cached(pin)``
    BEFORE ever calling ``bundle_store.get(pin)`` — for ``HttpEntryBundleStore``,
    ``get()`` on an uncached pin would attempt a real network fetch, which
    ``milpa verify`` must never do. A pin that is present but not cached is
    reported as ``TNG-ENTRY-BUNDLE-MISSING`` (cause ``unfetchable``), exactly
    as if the bundle had never been fetched.
    """
    if env is None or project_dir is None:
        return

    from milpa.entry_trust import (
        BundleMissing,
        build_entry_subject,
        enforce_entry_trust,
        evaluate_entry_attestation,
    )
    from milpa.registry import EntryAttestation

    config = _build_entry_trust(env, project_dir)
    if config is None:
        return  # policy off

    for dep in lockfile.deps:
        att = dep.attestation
        if att is None:
            continue

        cause: "str | None" = None
        if att.bundle_pin is None:
            result = BundleMissing
            cause = "no-pin"
        elif config.bundle_store is None or not config.bundle_store.is_cached(att.bundle_pin):
            # NEVER fetch — a present-but-uncached pin is unfetchable-from-cache.
            result = BundleMissing
            cause = "unfetchable"
        else:
            # Cached: reuse the shared gate pipeline. bundle_store.get() on a
            # cached pin never touches the network (verified is_cached above).
            reconstructed = EntryAttestation(kind=att.kind, rekor=att.rekor, bundle_pin=att.bundle_pin)
            result, cause = evaluate_entry_attestation(
                attestation=reconstructed,
                content_hash=dep.identity or "",
                namespace=att.namespace,
                name=dep.name,
                version=dep.version,
                verifier=config.verifier,
                bundle_store=config.bundle_store,
                trust_bundle=config.trust_bundle,
                expected_vendor_signer=config.expected_vendor_signer,
            )

        enforce_entry_trust(
            result,
            config.policy,
            namespace=att.namespace,
            name=dep.name,
            version=dep.version,
            cause=cause,
            bundle_store=config.bundle_store,
        )


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


def _frozen_fast_path_gate(
    locked: bool,
    upgrade: "tuple[str, ...] | None",
    cli_strategy: Strategy | None,
    cli_exclude_newer: "datetime | None",
    prior: "Lockfile | None",
) -> bool:
    """R1 (resolution-semantics RFC §3 Axes C/D, code-review finding):
    whether ``cmd_fetch``/``_cmd_fetch_workspace`` may even ATTEMPT the
    frozen no-solve fast-path (as opposed to going straight to a full
    resolve).

    RR4 (duplicate-fast-path-gate cleanup): this predicate used to be
    duplicated VERBATIM in both ``cmd_fetch`` and ``_cmd_fetch_workspace``.
    Extracted here as the single copy both call.

    ONE unified predicate folds in every reason a real solve is required:
    ``--locked`` (B3), ``--upgrade`` (B4), an EXPLICIT ``--strategy``
    diverging from the prior lock's recorded strategy (C3), or an
    EXPLICIT ``--exclude-newer`` diverging from the prior lock's recorded
    bound (D2).

    Deliberately narrower than "effective diverges from lock": this only
    reacts to an EXPLICIT CLI override (``cli_strategy``/``cli_exclude_newer``
    actually passed, i.e. not ``None``), not a merely-effective divergence
    sourced from the manifest's own ``resolution { }`` block — that
    divergence is already correctly detected INSIDE ``resolve_frozen``
    itself (``FROZEN-STRATEGY-MISMATCH``/``FROZEN-EXCLUDE-NEWER-MISMATCH``,
    C3b/D5), where the fast-path is still attempted and raises (or
    silently falls through when ``--frozen`` is absent) exactly as before.
    Consistent with RR1's single-walk ``_resolve_effective_strategy``: the
    caller passes the RAW CLI arg here (captured before it's overwritten by
    the effective-strategy derivation), not the derived ``strategy_explicit``
    boolean — mirroring this gate's pre-existing CLI-only divergence scope.
    """
    strategy_diverges = (
        cli_strategy is not None
        and prior is not None
        and cli_strategy != prior.strategy
    )
    exclude_newer_diverges = (
        cli_exclude_newer is not None
        and prior is not None
        and cli_exclude_newer != prior.exclude_newer
    )
    return (
        not locked
        and upgrade is None
        and not strategy_diverges
        and not exclude_newer_diverges
    )


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
    strategy: Strategy | None,
    max_parallel: int,
    frozen: bool,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
    locked: bool = False,
    upgrade: tuple[str, ...] | None = None,
    exclude_newer: datetime | None = None,
) -> int:
    """Resolve, fetch, emit nim.cfg + milpa.lock.

    Frozen fast-path:
    - Attempt only when the lockfile exists AND a single unified gate says
      no real solve is required (see R1 below).
    - --frozen absent → silent fallthrough on failure (or when the gate
      says a real resolve is required).
    - --frozen present → FROZEN-* slug + exit 1 on failure.

    Two CLI-level guards are raised HERE before entering the frozen resolver:
    - FROZEN-NO-LOCKFILE: lockfile absent.
    - FROZEN-NO-CAS: CAS not available (store missing).

    B3 (resolution-semantics RFC §3 Axis B): ``--locked`` always performs a
    REAL resolve and asserts the result matches the committed lockfile
    (``check_locked_drift``) — distinct from ``frozen``, which reconstructs
    with no solve at all.  ``locked`` is one of the reasons folded into the
    unified fast-path gate (R1 below), so ``--locked`` cannot be silently
    short-circuited by it.

    B4 (resolution-semantics RFC §3 Axis B / D-B3): ``upgrade`` is ``None``
    when ``--upgrade`` was not passed (ordinary minimal-change applies);
    an empty tuple for bare ``--upgrade`` (opt out globally); a non-empty
    tuple of dep names for ``--upgrade <dep>...`` (opt out for only those).
    For the SAME reason as ``locked`` above, its presence (non-``None``) is
    also folded into the unified gate — otherwise an up-to-date project
    would silently take the no-solve reconstruction path and ``--upgrade``
    would have no effect at all.

    R1 (code-review finding, resolution-semantics RFC §3 Axes C/D): the
    EFFECTIVE strategy and exclude-newer bound are computed
    UNCONDITIONALLY, up front — before the fast-path decision is made —
    via the SAME precedence chain (CLI > manifest > lockfile-recorded >
    default) the full-resolve path uses (``_resolve_effective_strategy`` /
    ``_resolve_effective_exclude_newer``), so both are always ready for
    ``ResolveParams`` regardless of which path is taken.

    The fast-path gate itself, however, only reacts to an EXPLICIT CLI
    override (``--strategy``/``--exclude-newer`` actually passed) that
    diverges from what the prior committed lock recorded — NOT the general
    "effective diverges from lock" comparison. This is deliberate: when
    neither flag is passed and only the MANIFEST's ``resolution { }`` block
    has drifted from the lock, that divergence is already correctly
    detected INSIDE ``resolve_frozen`` itself (``FROZEN-STRATEGY-MISMATCH``/
    ``FROZEN-EXCLUDE-NEWER-MISMATCH``, C3b/D5) — the fast-path is still
    attempted there, and it raises (or silently falls through when
    ``--frozen`` is absent) exactly as before. The bug this fixes is a
    narrower, CLI-specific blind spot: ``resolve_frozen`` has no visibility
    into ``--strategy``/``--exclude-newer`` at all (by design — it takes no
    ``ResolveParams``), so only an external, pre-attempt gate can catch a
    CLI override that diverges from an otherwise genuinely in-sync lock.
    Without it, ``milpa fetch --strategy lowest-direct`` (or
    ``--exclude-newer <ts>``) on an already-locked, manifest-unchanged
    project would silently reconstruct from the stale lock and exit 0,
    never honoring the flag. This replaces the old ad-hoc
    ``elif not locked and upgrade is None:`` gate (which had already
    accreted two booleans across B3/B4 and would silently need two more)
    with one predicate folding in every reason a real solve is required.
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
            locked=locked,
            upgrade=upgrade,
            exclude_newer=exclude_newer,
        )

    # --- Single-package path ---

    # Load manifest first (needed for frozen checks + self_src_dir).
    manifest = load_or_discover_manifest(project_dir)
    self_src_dir = manifest.src_dir or ""

    # deps_dir: absolute for filesystem operations; relative for nim.cfg paths.
    lock_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"
    _DEPS_RELATIVE = Path("_deps")  # relative form for nim.cfg

    # R1: capture the RAW CLI-provided strategy/exclude-newer (before they
    # get overwritten by the effective computation below) — the fast-path
    # gate needs to know whether the USER EXPLICITLY passed ``--strategy``/
    # ``--exclude-newer`` and, if so, whether that explicit value diverges
    # from the prior lock's recorded value.  This is deliberately narrower
    # than "effective diverges from lock": when neither flag was passed and
    # only the MANIFEST's ``resolution { }`` block diverges from the lock,
    # that divergence is already correctly detected INSIDE ``resolve_frozen``
    # itself (``FROZEN-STRATEGY-MISMATCH``/``FROZEN-EXCLUDE-NEWER-MISMATCH``,
    # C3b/D5) — attempting the fast-path there and letting it raise (rather
    # than skipping the attempt here) is what lets ``--frozen`` report the
    # precise slug instead of silently doing a full resolve.  The R1 bug
    # this fixes is specifically the CLI blind spot: those manifest-only
    # checks have no visibility into ``--strategy``/``--exclude-newer``, so
    # only an external, pre-attempt gate can catch a CLI override that
    # diverges from an otherwise genuinely in-sync lock.
    cli_strategy_arg = strategy
    cli_exclude_newer_arg = exclude_newer

    # Load the prior lockfile (if any) and compute the EFFECTIVE
    # strategy/exclude-newer UNCONDITIONALLY, before deciding whether the
    # frozen fast-path may even be attempted — C3 (resolution-semantics
    # RFC §3 Axis C / D-C2) and D2 (Axis D) against this verb's own
    # manifest + the ACTUAL on-disk prior lock.  Computed here (rather than
    # only in the full-resolve path further below) so it's ready either way.
    prior = _maybe_load_prior_lockfile(lock_path) if lock_path.exists() else None
    # R9 (resolution-semantics RFC §3 Axis C / D-C2): whether the effective
    # strategy below was EXPLICITLY sourced (CLI or manifest) — feeds the
    # B2 lock-preference bypass gate (never the lockfile-recorded strategy,
    # which is diagnostic-only, never a live input).
    _strategy_decl = _resolve_effective_strategy(cli_strategy_arg, manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    exclude_newer = _resolve_effective_exclude_newer(cli_exclude_newer_arg, manifest)

    # CLI-level guard 1: FROZEN-NO-LOCKFILE.
    if not lock_path.exists():
        if frozen:
            print("frozen: no lockfile found", file=sys.stderr)
            _emit_slug(FROZEN_NO_LOCKFILE)
            return 1
    else:
        # R1/RR4: ONE unified predicate (shared with _cmd_fetch_workspace via
        # _frozen_fast_path_gate) folds in every reason a real solve is
        # required — --locked (B3), --upgrade (B4), an EXPLICIT --strategy
        # diverging from the lock's recorded strategy (C3), or an EXPLICIT
        # --exclude-newer diverging from the lock's recorded bound (D2).
        attempt_frozen = _frozen_fast_path_gate(
            locked, upgrade, cli_strategy_arg, cli_exclude_newer_arg, prior
        )
        if attempt_frozen:
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

    # B4: delegate to the SAME strip-pin mechanism `milpa update` uses
    # (D-B3) — only when --upgrade was actually passed (upgrade is not None).
    if upgrade is not None:
        prior = _strip_pins_for_upgrade(prior, upgrade)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, project_dir),
        # D2: effective exclude-newer bound (unused for now — D3/D4 consume it).
        exclude_newer=exclude_newer,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  SOLVE-CONFLICT carries a
    # populated SolverError; all other MilpaError failures get an empty cert
    # (kind:failure, message:null, refutation:[]) matching Rust's behaviour.
    try:
        graph = resolve(manifest, deps_dir, env_with_index, params)
        # B3: --locked asserts the resolve matches the committed lock
        # (identity + provenance, never the version label — D-B2) BEFORE
        # anything is written, so a drifted resolve never clobbers the
        # committed lockfile/nim.cfg.
        if locked:
            check_locked_drift(prior, graph, exclude_newer)
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

    lockfile = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
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
    strategy: Strategy | None,
    max_parallel: int,
    frozen: bool,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
    locked: bool = False,
    upgrade: tuple[str, ...] | None = None,
    exclude_newer: datetime | None = None,
) -> int:
    """Workspace variant of cmd_fetch."""
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    # R1: capture the RAW CLI-provided strategy/exclude-newer BEFORE they
    # get overwritten by the effective computation — see cmd_fetch's
    # docstring for why the divergence gate must be scoped to an EXPLICIT
    # CLI override, not the general effective-vs-lock comparison (manifest-
    # only divergence is already correctly handled inside
    # resolve_workspace_frozen's own C3b/D5 checks).
    cli_strategy_arg = strategy
    cli_exclude_newer_arg = exclude_newer

    # Load the prior lockfile (if any) and compute the EFFECTIVE
    # strategy/exclude-newer against the WORKSPACE ROOT manifest (Axis W:
    # resolution{} is root-only) UNCONDITIONALLY, before deciding whether
    # the frozen fast-path may even be attempted — mirrors cmd_fetch.
    prior = _maybe_load_prior_lockfile(lock_path) if lock_path.exists() else None
    # R9: see cmd_fetch's mirror comment above _resolve_effective_strategy.
    _strategy_decl = _resolve_effective_strategy(cli_strategy_arg, workspace.workspace_manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    exclude_newer = _resolve_effective_exclude_newer(cli_exclude_newer_arg, workspace.workspace_manifest)

    # Frozen fast-path.
    if not lock_path.exists():
        if frozen:
            print("frozen: no lockfile found", file=sys.stderr)
            _emit_slug(FROZEN_NO_LOCKFILE)
            return 1
    else:
        # R1/RR4: ONE unified predicate (shared with cmd_fetch via
        # _frozen_fast_path_gate) — see cmd_fetch's docstring — folds in
        # --locked (B3), --upgrade (B4), an EXPLICIT --strategy diverging
        # from the lock (C3), and an EXPLICIT --exclude-newer diverging
        # from the lock (D2).
        attempt_frozen = _frozen_fast_path_gate(
            locked, upgrade, cli_strategy_arg, cli_exclude_newer_arg, prior
        )
        if attempt_frozen:
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
    # B4: delegate to the SAME strip-pin mechanism `milpa update` uses (D-B3).
    if upgrade is not None:
        prior = _strip_pins_for_upgrade(prior, upgrade)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, ws_root),
        # D2: effective exclude-newer bound (unused for now — D3/D4 consume it).
        exclude_newer=exclude_newer,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  Mirrors the single-package path.
    try:
        graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
        # B3: see cmd_fetch's docstring — assert before anything is written.
        if locked:
            check_locked_drift(prior, graph, exclude_newer)
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

    lockfile = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
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
    strategy: Strategy | None,
    max_parallel: int,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
    locked: bool = False,
    upgrade: tuple[str, ...] | None = None,
    exclude_newer: datetime | None = None,
) -> int:
    """Resolve + write milpa.lock; do NOT emit nim.cfg or populate _deps/.

    Always full-resolves (never frozen fast-path). Still passes a loaded
    prior lockfile for §8 pin reuse (cli-contract.md §5.2).

    B3: ``locked`` asserts the resolve matches the committed lock
    (``check_locked_drift``) before anything is (re)written.

    B4: ``upgrade`` delegates to the SAME strip-pin mechanism `milpa
    update` uses (D-B3) — see ``cmd_fetch``'s docstring for the ``None``/
    empty-tuple/named-tuple contract.
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
            locked=locked,
            upgrade=upgrade,
            exclude_newer=exclude_newer,
        )

    manifest = load_or_discover_manifest(project_dir)
    lock_path = project_dir / "milpa.lock"
    deps_dir = project_dir / "_deps"

    env_with_index = _load_index_for_verb(env, project_dir)
    prior = _maybe_load_prior_lockfile(lock_path)
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) before the --upgrade strip below.
    _strategy_decl = _resolve_effective_strategy(strategy, manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2: resolve the EFFECTIVE exclude-newer bound the same way.
    exclude_newer = _resolve_effective_exclude_newer(exclude_newer, manifest)
    # B4: delegate to the SAME strip-pin mechanism `milpa update` uses (D-B3).
    if upgrade is not None:
        prior = _strip_pins_for_upgrade(prior, upgrade)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, project_dir),
        # D2: effective exclude-newer bound (unused for now — D3/D4 consume it).
        exclude_newer=exclude_newer,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  Mirrors the fetch path.
    try:
        graph = resolve(manifest, deps_dir, env_with_index, params)
        if locked:
            check_locked_drift(prior, graph, exclude_newer)
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

    lockfile = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
    write_lockfile(lockfile, lock_path)
    print(f"locked {len(graph.deps)} deps", file=sys.stderr)
    return 0


def _cmd_lock_workspace(
    workspace: object,
    env: MilpaEnv,
    *,
    strategy: Strategy | None,
    max_parallel: int,
    certificate_path: Path | None = None,
    require_attested_metadata: bool = False,
    features: frozenset[str] = frozenset(),
    no_default_features: bool = False,
    all_features: bool = False,
    locked: bool = False,
    upgrade: tuple[str, ...] | None = None,
    exclude_newer: datetime | None = None,
) -> int:
    from milpa.workspace import LoadedWorkspace
    assert isinstance(workspace, LoadedWorkspace)

    ws_root = workspace.root_dir
    lock_path = ws_root / "milpa.lock"
    deps_dir = ws_root / "_deps"

    env_with_index = _load_index_for_verb(env, ws_root)
    prior = _maybe_load_prior_lockfile(lock_path)
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) against the WORKSPACE ROOT manifest before the --upgrade
    # strip below.
    _strategy_decl = _resolve_effective_strategy(strategy, workspace.workspace_manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2: resolve the EFFECTIVE exclude-newer bound the same way.
    exclude_newer = _resolve_effective_exclude_newer(exclude_newer, workspace.workspace_manifest)
    # B4: delegate to the SAME strip-pin mechanism `milpa update` uses (D-B3).
    if upgrade is not None:
        prior = _strip_pins_for_upgrade(prior, upgrade)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        require_attested_metadata=require_attested_metadata,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, ws_root),
        # D2: effective exclude-newer bound (unused for now — D3/D4 consume it).
        exclude_newer=exclude_newer,
    )

    # Resolve — intercept any MilpaError to write a failure certificate when
    # --certificate is set (cli-contract §2.5.2).  Mirrors the fetch path.
    try:
        graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
        if locked:
            check_locked_drift(prior, graph, exclude_newer)
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

    lockfile = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
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

    # A7 (rfc-resolution-semantics.md §3 Axis A): top-level resolution-state
    # header, printed once before the per-dep list. `strategy` is always
    # shown; `exclude_newer` (D5) is shown only when the lockfile recorded
    # one (never a fake/hardcoded value for the absent case).
    print(f"strategy    {lockfile.strategy}")
    if lockfile.exclude_newer is not None:
        from milpa.manifest import _format_resolution_timestamp

        print(f"exclude-newer {_format_resolution_timestamp(lockfile.exclude_newer)}")

    for dep in lockfile.deps:
        # A7: surface the declared-version source next to the version —
        # `manifest`/`nimble`/`tag`/`annotation` when a source was recorded
        # (A5), or `(version-unknown)` for the A5 flattening pairing
        # (`version "0.0.0"` + no `declared_version_source`). A named/index
        # dep also has no `declared_version_source` (out of Axis A's scope)
        # but is NOT version-unknown — it is only flagged when paired with
        # the flattened `0.0.0` sentinel, per the RFC's unambiguous pairing.
        if dep.declared_version_source:
            version_suffix = f" ({dep.declared_version_source})"
        elif dep.version == "0.0.0":
            version_suffix = " (version-unknown)"
        else:
            version_suffix = ""
        print(f"{dep.name:20s} {dep.version}{version_suffix}")
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
            # RFC origin-as-identity.md §4.7/B3 (S3a-req): one human-readable
            # note per dropped label naming the shared origin AND which label
            # survived — the collapse must be VISIBLE, never just a bare list.
            from milpa.lockfile import collapse_notes as _collapse_notes
            for note in _collapse_notes([dep]):
                print(f"  note        {note}")
        # RFC per-entry-attestation.md P2 (§7): render the lockfile's
        # attestation block as an UNVERIFIED claim — no crypto has ever been
        # run over it.  The wording upgrades to a verified fact only once the
        # (later) P3 entry-trust gate exists; this schema does not change.
        if dep.attestation is not None:
            print(f"  attestation {_format_attestation_claim(dep.attestation)}")
    return 0


def _format_attestation_claim(att: object) -> str:
    from milpa.lockfile import LockAttestation
    from milpa.registry import AuthorSigned

    assert isinstance(att, LockAttestation)
    if isinstance(att.kind, AuthorSigned):
        return f"claims author-signed by {att.kind.signer}"
    return "claims milpa-vendored"


def _format_provenance(p: object) -> str:
    from milpa.lockfile import (
        GitProvenanceRecord,
        LocalProvenanceRecord,
        MemberProvenanceRecord,
        OciProvenanceRecord,
        RootProvenanceRecord,
        TarballProvenanceRecord,
    )

    # Defense-in-depth (code-review S2): url/path/registry/repository/ref are
    # free-text fields sourced from a network-fetched `milpa.kdl` (or a
    # hand-edited lockfile). The primary control-char guard lives at
    # `source_id.normalize_source` (source_id.py); this is a belt-and-
    # suspenders escape at the diagnostic-print sink so a value that somehow
    # reaches this far (e.g. predates that guard) still cannot smuggle a
    # terminal-escape sequence into the user's terminal. `repr()` is used
    # rather than a bespoke escaper — it is total, always legible, and is
    # exactly what `MilpaError`'s own `value=` diagnostics already use.
    if isinstance(p, GitProvenanceRecord):
        parts = [f"git {p.url!r}"]
        if p.ref:
            parts.append(f"@ {p.ref!r}")
        if p.commit_sha:
            parts.append(f"(sha {p.commit_sha[:8]})")
        return " ".join(parts)
    if isinstance(p, TarballProvenanceRecord):
        return f"tarball {p.url!r}"
    if isinstance(p, LocalProvenanceRecord):
        return f"local {p.path!r}"
    if isinstance(p, MemberProvenanceRecord):
        return f"member {p.name}"
    if isinstance(p, OciProvenanceRecord):
        return f"oci {p.registry!r}/{p.repository!r}@{p.digest[:15]}"
    if isinstance(p, RootProvenanceRecord):
        return f"root {p.name}"
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
    # Sv (rfc-attestation-verifier): offline reverify of the CACHED index
    # attestation bundle — the offline post-incident audit path (Part-1 §7.5).
    # A tampered/invalid cached bundle fails verify under strict (warns under
    # warn). Never fetches; independent of the online dep_decl edge check below.
    # (env is None only in direct unit-test calls that bypass the CLI env build.)
    # -------------------------------------------------------------------------
    if env is not None:
        try:
            _reverify_cached_index_bundle(
                env, ws.root_dir if ws is not None else project_dir
            )
        except MilpaError as exc:
            print(
                f"cached index attestation reverify failed: {exc.message}",
                file=sys.stderr,
            )
            _emit_slug(exc.slug)
            return 1

    # -------------------------------------------------------------------------
    # P3a (RFC per-entry-attestation.md §7): offline reverify of CACHED
    # per-entry attestation bundles. Same shape as the index reverify above —
    # never fetches, independent of the online dep_decl edge check below.
    # -------------------------------------------------------------------------
    if env is not None:
        try:
            _reverify_cached_entry_attestations(
                env, ws.root_dir if ws is not None else project_dir, lockfile
            )
        except MilpaError as exc:
            print(
                f"cached entry attestation reverify failed: {exc.message}",
                file=sys.stderr,
            )
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
            # RFC origin-as-identity.md §7.1 D2/D3 (S5): FROZEN-REGISTRY-
            # ALIAS-UNRESOLVED (checked first) + FROZEN-SOURCE-ID-MISMATCH
            # (declared-AFTER-override) — the SAME SSOT check resolve_frozen
            # runs, wired into `milpa verify` too (not just --frozen), so
            # editing a git=/local=/tarball= origin (or its override target)
            # without re-fetching fails closed here as well.
            check_source_id_preconditions_standalone(verify_manifest, lockfile.deps)
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
            # RFC origin-as-identity.md §7.1 D2/D3 (S5): same wiring as the
            # standalone branch above, workspace form.
            check_source_id_preconditions_workspace(ws, lockfile.deps)
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

        # Find the version-node in the live index. A namespace-qualified
        # locked dep MUST use the namespace-aware lookup (P5, namespace-
        # conflation audit) — `lookup_bare` ignores `dep.namespace` entirely,
        # so the moment a DIFFERENT namespace also publishes a package with
        # the same bare name, `lookup_bare` returns `AmbiguousName` and the
        # branch below would misreport a perfectly valid, unambiguous
        # namespaced pin as LOCK-DEPDECL-PIN-MISSING. `lookup_qualified`
        # never returns `AmbiguousName` (the namespace disambiguates by
        # construction), so this is only ever taken for un-namespaced deps.
        if dep.namespace is not None:
            pkg = index.lookup_qualified(dep.namespace, dep.name)
        else:
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
# cmd_index_status / cmd_index_accept (A2e — rfc-registry-append-only.md;
# cli-contract.md §5.12) — the append-only-ratchet inspection/reset surface.
#
# Both verbs share: the ``--no-index`` hard error, the effective index URL +
# index-history policy (``_index_verb_setup``), member-dir → workspace-root
# delegation (S11e — implicit here: ``_build_index_history``/
# ``_build_index_trust`` already resolve the workspace root internally given
# a member ``project_dir``, and the baseline sidecar pair is keyed ONLY by
# index URL in the process-global cache dir — there is no member-level
# baseline state to delegate FROM in the first place), and the
# fetch-and-verify + three-branch diff machinery used by ``--refresh``
# (status) and the ordinary path (accept). Neither verb duplicates the
# dominance-fold/digest logic — both compose ``ratchet.py`` /
# ``index_ratchet_seam.py`` primitives directly.
# ---------------------------------------------------------------------------


def _index_verb_setup(project_dir: Path, env: MilpaEnv) -> "tuple[str, str]":
    """Shared preamble for ``index status``/``index accept``: the
    ``--no-index`` hard error, the effective index URL, and the effective
    ``index-history`` policy string.

    Member-dir delegation (S11e) needs no explicit root resolution here:
    ``_build_index_history`` already walks up to the workspace root given a
    member ``project_dir`` (mirroring ``_build_index_trust``), and the
    baseline sidecar pair is keyed purely by index URL in the process-global
    cache dir — so a member-dir invocation is byte-identical to a root-dir
    invocation by construction, not by a special-cased delegation path.
    """
    from milpa.index_cache import index_url_from_env

    if _no_index_requested(env.no_index):
        raise MilpaError(
            TNG_INDEX_NOT_CONFIGURED,
            "milpa index: no index is configured (--no-index, or an empty "
            "MILPA_INDEX_URL) — there is no index to load or compare against",
        )
    url = index_url_from_env()
    policy = _build_index_history(env, project_dir)
    return url, policy


def _fetch_index_candidate(
    env: MilpaEnv, project_dir: Path, url: str
) -> "tuple[str, bool]":
    """Force a network fetch + trust-gate verification of *url*'s index
    candidate for ``index status --refresh`` / ``index accept``. Touches no
    cache state (``fetch_verified_candidate_text`` performs no writes).

    Returns ``(candidate_text, index_trust_is_off)`` — the second element
    drives the index-trust-off caveat both verbs must print (cli-contract
    §5.12 NORMATIVE (contract points)); ``_build_index_trust`` returns
    ``(None, None)`` exactly when the effective policy is ``off``, so
    ``config is None`` is a already the SSOT signal.

    A bare network failure is wrapped as ``MILPA-INDEX-UNREACHABLE``
    (mirroring ``load_index``'s State-4 framing); a trust-gate failure
    propagates its own ``TNG-INDEX-*`` slug unchanged — either way, no cache
    mutation has been attempted (the ``--refresh-index`` precedent, §2.9).
    """
    from milpa.index_cache import (
        fetch_verified_candidate_text,
        urllib_bundle_http_get,
        urllib_http_get,
    )

    config, verifier = _build_index_trust(env, project_dir)
    is_off = config is None
    bundle_get = urllib_bundle_http_get if config is not None else None
    try:
        text = fetch_verified_candidate_text(
            url, urllib_http_get, bundle_get, config, verifier
        )
    except MilpaError:
        raise
    except Exception as exc:
        raise MilpaError(
            MILPA_INDEX_UNREACHABLE,
            f"failed to fetch index candidate from {url!r}: {exc}",
            url=url,
        ) from exc
    return text, is_off


def _read_local_baseline_status(
    baseline_path: Path, meta_path: Path
) -> "tuple[str, str, str, str]":
    """Read-only local inspection of the baseline sidecar pair — the plain
    ``index status`` (no ``--refresh``) path. NEVER raises: a present-but-
    corrupt baseline is reported as ``baseline: corrupt``, not
    ``TNG-INDEX-BASELINE-CORRUPT`` (cli-contract §5.12 NORMATIVE — ``status``
    is a read-only inspection tool and must not hard-fail on a broken local
    trust state).

    Returns ``(baseline_state, established_at, pending, last_reported)``,
    each already formatted for display (``(none)`` for absent timestamps).
    """
    from milpa.index_ratchet_seam import BaselineMeta, parse_baseline, parse_baseline_meta

    if not baseline_path.is_file():
        return "absent", "(none)", "no", "(none)"

    try:
        baseline_text = baseline_path.read_bytes().decode("utf-8")
        parse_baseline(baseline_text)  # presence/parseability only — result unused
    except (UnicodeDecodeError, MilpaError):
        return "corrupt", "(none)", "no", "(none)"

    meta = BaselineMeta()
    if meta_path.is_file():
        try:
            meta_text = meta_path.read_text(encoding="utf-8")
        except OSError:
            meta_text = ""
        meta = parse_baseline_meta(meta_text)  # never raises — advisory

    established_at = meta.established_at or "(none)"
    if meta.reported_digest:
        return "present", established_at, "yes", (meta.reported_at or "(none)")
    return "present", established_at, "no", "(none)"


def _format_index_status_block(
    *,
    index_url: str,
    policy: str,
    baseline: str,
    established_at: str,
    pending: str,
    last_reported: str,
) -> str:
    """The fixed-format ``index status`` block (cli-contract §5.12
    NORMATIVE (status block, fixed format)) — a 19-character label+colon
    column, mirroring ``show --index-trust``'s convention (§5.3a)."""
    fields = (
        ("index-url:", index_url),
        ("policy:", policy),
        ("baseline:", baseline),
        ("established-at:", established_at),
        ("pending:", pending),
        ("last-reported:", last_reported),
    )
    return "\n".join(f"{label:<19}{value}" for label, value in fields) + "\n"


def _compute_index_diff(
    candidate_text: str, baseline_path: Path
) -> "tuple[object, object, str]":
    """Diff *candidate_text* against the on-disk baseline at *baseline_path*
    — the shared computation behind ``status --refresh`` and ``accept``.

    Returns ``(index, outcome, baseline_state)``: ``outcome`` is a
    ``ratchet.RatchetOutcome`` when ``baseline_state == "present"``, else
    ``None`` (nothing to diff against for ``absent``/``corrupt``). Composes
    ``index_ratchet_seam.build_index_state`` / ``parse_baseline`` and
    ``ratchet.Baseline`` directly — this function does NOT reimplement any
    dominance-fold or digest logic (single source of truth: ``ratchet.py``).

    Yank-transition notices (legal, non-error) are printed to stderr here,
    reusing ``index_ratchet_seam``'s own printer — the SAME stderr line the
    ordinary ratchet-gated fetch path prints (registry-protocol §3.5.3).
    """
    from milpa.index_ratchet_seam import _print_yank_notice, build_index_state, parse_baseline
    from milpa.ratchet import Baseline

    index, candidate_state = build_index_state(candidate_text)

    if not baseline_path.is_file():
        return index, None, "absent"

    try:
        baseline_text = baseline_path.read_bytes().decode("utf-8")
        baseline_state = parse_baseline(baseline_text)
    except (UnicodeDecodeError, MilpaError):
        return index, None, "corrupt"

    outcome = Baseline(baseline_state).check(candidate_state)
    for transition in outcome.transitions:
        _print_yank_notice(transition)
    return index, outcome, "present"


def _render_index_verb_diff(outcome: object, baseline_state: str) -> "tuple[str, bool]":
    """Render the shared three-branch diff text (cli-contract §5.12
    NORMATIVE (violation-line format...) / (``accept`` MUST...)) used by
    both ``status --refresh`` and ``accept``. Returns ``(text, clean)``;
    ``clean`` is meaningful only for the ``"present"`` branch (``True`` iff
    the diff has no violations) — callers decide exit code / write behavior
    per-verb from ``baseline_state`` + ``clean`` (the two verbs have
    DIFFERENT rules for the absent/corrupt branches: ``status`` treats
    corrupt as attention-worthy, ``accept`` treats it as successful
    re-establishment)."""
    from milpa.ratchet import canonical_digest

    if baseline_state == "absent":
        return "no prior baseline — this fetch establishes the trust anchor\n", True
    if baseline_state == "corrupt":
        return (
            "baseline unreadable — cannot show what changed; "
            "re-establishing the trust anchor\n"
        ), True

    assert outcome is not None
    if outcome.clean:  # type: ignore[attr-defined]
        return "nothing to accept\n", True

    violations = outcome.violations  # type: ignore[attr-defined]
    lines: list[str] = []
    if any(v.field == "attestation-epoch" for v in violations):
        # registry-protocol §3.5.1: attestation-epoch enforcement is live as
        # of A6. The blast-radius sentence cli-contract §5.12 requires
        # before the ordinary diff.
        lines.append(
            "accepting this change reclassifies every entry between the "
            "epochs as pre-epoch/legacy, nullifying the attestation mandate "
            "for all of them — an index-wide consequence, not a one-row one"
        )
    for v in violations:
        lines.append(
            "\t".join(
                [
                    "violation:",
                    v.class_,
                    v.entry_key.namespace,
                    v.entry_key.name,
                    v.entry_key.version,
                    v.field,
                    v.kind,
                    v.baseline_value,
                    v.candidate_value,
                ]
            )
        )
    lines.append(f"digest: {canonical_digest(violations)}")
    return "\n".join(lines) + "\n", False


def cmd_index_status(project_dir: Path, env: MilpaEnv, *, refresh: bool = False) -> int:
    """``milpa index status [--refresh]`` — read-only append-only-ratchet
    inspection. NEVER writes to disk, under any invocation, including
    ``--refresh`` (cli-contract §5.12 NORMATIVE).

    Without ``--refresh``: reads ONLY the local baseline sidecar pair, no
    network access. With ``--refresh``: performs the same forced
    fetch-and-verify sequence ``accept`` performs and prints the would-be
    diff — still writing nothing (the dry-run of ``accept``).
    """
    from milpa.index_cache import _default_cache_dir, baseline_sidecar_paths

    url, policy = _index_verb_setup(project_dir, env)
    cache_dir = _default_cache_dir()
    baseline_path, meta_path = baseline_sidecar_paths(url, cache_dir)

    if not refresh:
        baseline_state, established_at, pending, last_reported = _read_local_baseline_status(
            baseline_path, meta_path
        )
        block = _format_index_status_block(
            index_url=url,
            policy=policy,
            baseline=baseline_state,
            established_at=established_at,
            pending=pending,
            last_reported=last_reported,
        )
        print(block, end="")
        return 1 if (baseline_state == "corrupt" or pending == "yes") else 0

    candidate_text, trust_off = _fetch_index_candidate(env, project_dir, url)
    if trust_off:
        print(
            "[milpa] warning: index-trust is \"off\" — this fetch has no "
            "cryptographic basis; the diff below attests only to continuity "
            "of whatever the transport delivered",
            file=sys.stderr,
        )

    _, outcome, baseline_state = _compute_index_diff(candidate_text, baseline_path)
    text, clean = _render_index_verb_diff(outcome, baseline_state)
    print(text, end="")

    if baseline_state == "corrupt":
        return 1
    if baseline_state == "absent":
        return 0
    return 0 if clean else 1


def cmd_index_accept(project_dir: Path, env: MilpaEnv) -> int:
    """``milpa index accept`` — fetch, print the diff, and atomically accept
    the new trust baseline (cli-contract §5.12). Non-interactive; idempotent;
    per-URL. Its ONLY mutation is the atomic baseline-pair swap, performed
    UNLESS the diff against a present, parseable baseline is already clean
    (the idempotent no-op case — ``nothing to accept``, no write).
    """
    import time

    from milpa.index_cache import (
        _default_cache_dir,
        baseline_sidecar_paths,
        write_baseline_pair,
    )
    from milpa.index_ratchet_seam import BaselineMeta, iso_timestamp

    url, policy = _index_verb_setup(project_dir, env)
    cache_dir = _default_cache_dir()
    baseline_path, _meta_path = baseline_sidecar_paths(url, cache_dir)

    candidate_text, trust_off = _fetch_index_candidate(env, project_dir, url)
    if trust_off:
        print(
            "[milpa] warning: index-trust is \"off\" — this fetch has no "
            "cryptographic basis; accepting it attests only to continuity of "
            "whatever the transport delivered",
            file=sys.stderr,
        )
    if policy == "off":
        print(
            "[milpa] warning: index-history is \"off\" — the baseline "
            "written by this accept will not be consulted again until the "
            "axis is re-enabled",
            file=sys.stderr,
        )

    _, outcome, baseline_state = _compute_index_diff(candidate_text, baseline_path)
    text, clean = _render_index_verb_diff(outcome, baseline_state)
    print(text, end="")

    if baseline_state == "present" and clean:
        return 0  # idempotent no-op — nothing to accept, no write.

    new_meta = BaselineMeta(
        established_at=iso_timestamp(int(time.time())),
        reported_digest=None,
        reported_at=None,
    )
    write_baseline_pair(url, cache_dir, candidate_text.encode("utf-8"), new_meta)
    return 0


# ---------------------------------------------------------------------------
# cmd_publish (S4) — author-side pack/push/sign CLI wiring
#
# spec/cli-contract.md §10: `publish` is impl-specific, out of v1.0
# conformance. No conformance corpus fixture for this verb (by design — see
# rfc-distribution-and-publishing.handoff.md).
# ---------------------------------------------------------------------------

#: milpa-owned OCI media types for a published source artifact (fixed for
#: this slice — no --artifact-type / --layer-media-type flags; see the RFC
#: handoff for the media-type registry this pins into).
_PUBLISH_ARTIFACT_TYPE = "application/vnd.milpa.source.v1"
_PUBLISH_LAYER_MEDIA_TYPE = "application/vnd.milpa.source.v1.tar+gzip"


def _publish_enumeration_stats(entries: "list[MaterializedEntry]") -> dict:
    """Cheap dry-run guardrail stats over the already-enumerated git tree.

    PURE — no I/O (entries are already materialized in memory by the caller
    via ``enumerate_git_entries``). ``top_dirs`` is the sorted set of each
    entry's first path component, so a reviewer can sanity-check "does this
    look like the right tree" before any bytes leave the machine.
    """
    total_bytes = sum(len(e.content) for e in entries)
    top_dirs = sorted({e.relpath.split("/", 1)[0] for e in entries})
    return {
        "entry_count": len(entries),
        "total_bytes": total_bytes,
        "top_dirs": top_dirs,
    }


@dataclass(frozen=True)
class PublishOutputRecord:
    """M7-code: the typed shape of ``--output``'s REAL-RUN JSON.

    This is a genuine cross-repo wire contract (the tianguis composite
    action's submission tooling consumes it — mirrors ``PublishReceipt``'s
    own cross-repo-contract status, spec/cli-contract.md §10.2). Built by
    exactly ONE call site (``cmd_publish``'s real-run branch) instead of an
    ad hoc dict literal, so the field set can't silently drift — see
    ``tests/test_publish_subcommand.py``'s exact-field-set guardrail test.

    Deliberately a SEPARATE type from ``PublishDryRunRecord`` rather than one
    dataclass with ``Optional`` ``oci_ref``/``layer_digest`` fields: a dry
    run never pushes anything, so those fields don't merely happen to be
    absent — they don't exist yet. Modeling that as ``None`` would read as
    "pushed to nothing" rather than "hasn't pushed".

    ``source_url`` IS genuinely optional (carried straight from
    ``PublishReceipt.source_url`` / ``PublishPlan.source_url``): ``None`` when
    the published repo has no ``origin`` remote configured. Unlike
    ``oci_ref``/``layer_digest``, this absence is a real "hasn't happened"
    outcome even on a completed real run, so it IS modeled as an ``Optional``
    field here (serializes to JSON ``null``, key always present) rather than
    split into a third record type.
    """

    name: str
    version: str
    content_hash: str
    oci_ref: str
    layer_digest: str
    artifact_type: str
    source_url: str | None = None

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass(frozen=True)
class PublishDryRunRecord:
    """M7-code: the typed shape of ``--dry-run``'s JSON — see
    ``PublishOutputRecord``'s docstring for why this is a separate type
    rather than the same one with optional push/sign fields."""

    name: str
    version: str
    content_hash: str
    target: dict
    entry_count: int
    total_bytes: int
    top_dirs: "list[str]"

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def cmd_publish(
    project_dir: Path,
    *,
    version: str,
    target: str,
    name: str | None = None,
    tag: str | None = None,
    output_path: Path | None = None,
    dry_run: bool = False,
    allow_untagged: bool = False,
    push: "OrasPush | None" = None,
    sign: "CosignSign | None" = None,
    manifest_fetch: "OrasManifestFetch | None" = None,
) -> int:
    """``milpa publish`` — pack the git HEAD source tree, push it, verify it,
    sign it.

    Thin glue over ``milpa.publishing`` (S2/S3a-d + M1, all pure/impure seams
    already built there): this function's only job is CLI-shaped assembly —
    derive ``--name`` from the published HEAD tree (M4), split ``--target``
    via the shared ``split_oci_target`` helper (SSOT with ``source_spec.py``'s
    ``oci=`` grammar), enumerate the git tree exactly ONCE (M3-cli) and reuse
    it for the plan's content hash, the dry-run stats, and (real-run)
    ``execute()``'s pack step, and route dry-run vs real execution.

    Injectability seam: ``push``/``sign``/``manifest_fetch`` default to
    ``None`` and are filled with the production closures
    (``make_oras_push``/``make_cosign_sign``/``make_oras_manifest_fetch``)
    HERE, not at the argparse layer — this keeps ``cmd_publish`` itself
    unit-testable with fakes (no ``oras``/``cosign`` binaries needed) while
    the CLI's real invocation (``main()``) never has to know the seam
    exists. Mirrors how ``cmd_fetch`` et al. take an injected ``MilpaEnv``
    rather than constructing one internally.

    Dry-run (``--dry-run``): computes the plan, prints it (content hash +
    cheap enumeration stats) to stdout, and returns — ``execute()`` is never
    called, so no push/sign/network happens by construction (not a branch
    inside ``execute``). ``--target`` is still validated (L5): a flag-
    injection-shaped target must fail identically under ``--dry-run`` and a
    real run, not only once ``execute()``'s push/sign closures run
    ``validate_oci_field``.

    Stream discipline (spec/cli-contract.md §4 NOTE): the dry-run render is
    the SOLE unguarded ``print()`` in this function (stdout); the real-run
    confirmation now ALWAYS goes to stderr (M6), regardless of ``--output``
    — ``execute()`` has already pushed+signed (irreversible) by the time
    ``--output`` is written, so the ``oci_ref`` of a completed publish must
    reach the operator on some stream even if writing ``--output`` fails.
    """
    import json

    from milpa.fetchers.git import enumerate_git_entries
    from milpa.fetchers.oci import validate_oci_field
    from milpa.publishing import (
        PublishTarget,
        build_publish_plan,
        execute,
        make_cosign_sign,
        make_oras_manifest_fetch,
        make_oras_push,
        resolve_publish_name,
        resolve_publish_source,
    )
    from milpa.source_spec import split_oci_target

    registry, repository = split_oci_target(target)
    # L5: validate the target BEFORE dry-run can "pass" on an unsafe value —
    # push()/sign() already call validate_oci_field, but dry-run never
    # reaches them.
    validate_oci_field("registry", registry)
    validate_oci_field("repository", repository)

    effective_tag = tag if tag is not None else version
    pub_target = PublishTarget(
        registry=registry,
        repository=repository,
        tag=effective_tag,
        artifact_type=_PUBLISH_ARTIFACT_TYPE,
        layer_media_type=_PUBLISH_LAYER_MEDIA_TYPE,
    )

    source = resolve_publish_source(project_dir, version, allow_untagged=allow_untagged)

    # M4: --name comes from the PUBLISHED (HEAD) tree, never the working
    # directory.
    effective_name = name if name is not None else resolve_publish_name(source)

    # M3-cli / CR-B1: enumerate the git tree exactly ONCE; reuse it for the
    # plan's content hash (via build_publish_plan's entries= seam), the
    # dry-run stats, and (real-run) execute()'s pack step. build_publish_plan
    # is the ONE plan-builder (validate entries -> compute_dag_identity ->
    # construct PublishPlan) — no second copy of that composition lives here.
    entries, _submodule_shas = enumerate_git_entries(
        source.repo, source.commit, submodule_fetch=None
    )
    plan = build_publish_plan(source, pub_target, entries=entries)

    if dry_run:
        stats = _publish_enumeration_stats(entries)
        dry_run_record = PublishDryRunRecord(
            name=effective_name,
            version=version,
            content_hash=plan.content_hash,
            # R2-L3: PublishTarget is a plain frozen dataclass with exactly
            # the fields this wire shape wants (registry/repository/tag/
            # artifact_type/layer_media_type) -- dataclasses.asdict is the
            # SSOT serialization rather than a hand-rebuilt field-by-field
            # dict that could silently drift from PublishTarget's field set.
            target=dataclasses.asdict(pub_target),
            entry_count=stats["entry_count"],
            total_bytes=stats["total_bytes"],
            top_dirs=stats["top_dirs"],
        )
        rendered = json.dumps(dry_run_record.to_dict(), indent=2)
        print(rendered)
        if output_path is not None:
            _atomic_write(output_path, rendered + "\n")
        return 0

    effective_push = push if push is not None else make_oras_push()
    effective_sign = sign if sign is not None else make_cosign_sign()
    effective_manifest_fetch = (
        manifest_fetch if manifest_fetch is not None else make_oras_manifest_fetch()
    )
    receipt = execute(
        plan,
        push=effective_push,
        sign=effective_sign,
        entries=entries,
        manifest_fetch=effective_manifest_fetch,
    )

    output_record = PublishOutputRecord(
        name=effective_name,
        version=version,
        content_hash=receipt.content_hash,
        oci_ref=receipt.oci_ref,
        layer_digest=receipt.layer_digest,
        artifact_type=receipt.artifact_type,
        source_url=receipt.source_url,
    )

    # M6: the publish is already irreversible at this point (pushed+signed).
    # Print the confirmation FIRST and unconditionally, so the oci_ref
    # reaches the operator even if the --output write below fails.
    print(
        f"published {effective_name}@{version} -> {receipt.oci_ref}",
        file=sys.stderr,
    )
    if output_path is not None:
        _atomic_write(output_path, json.dumps(output_record.to_dict(), indent=2) + "\n")
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
    strategy: Strategy | None,
    max_parallel: int,
    optional: bool = False,
    features: "tuple[str, ...] | frozenset[str]" = (),
    version: str | None = None,
) -> int:
    """Add a new dep (--git) or mirror provenance (--mirror) to milpa.kdl.

    S10 (RFC #23 §3.7): ``--optional`` writes ``optional=#true`` on the dep node;
    ``--features a,b`` writes ``flag "a"`` / ``flag "b"`` children.
    A3b (§3 Axis A (b) step 4): ``--version x.y.z`` writes a ``version=``
    annotation on the new dep node (git dep only per this slice's CLI surface).

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
            version=version,
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
            version=version,
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
    strategy: Strategy | None,
    max_parallel: int,
    optional: bool = False,
    features: "tuple[str, ...] | frozenset[str]" = (),
    version: str | None = None,
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

    # A3b (§3 Axis A (b) step 4): --version validation, same slug as the
    # manifest grammar (MAN-DEP-VERSION-INVALID) — the CLI writes the exact
    # annotation a hand-edit would, so a malformed value is rejected the same
    # way before anything is written.
    parsed_version: "Version | None" = None
    if version is not None:
        from milpa.errors import MAN_DEP_VERSION_INVALID
        from milpa.version import parse_version
        parsed_version = parse_version(version)
        if parsed_version is None:
            print(
                f"milpa add: --version value {version!r} is not a valid semver "
                "version (expected 'x.y.z')",
                file=sys.stderr,
            )
            _emit_slug(MAN_DEP_VERSION_INVALID)
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
        version=parsed_version,
    )
    from dataclasses import replace as _replace
    proposed_manifest = _replace(manifest, deps=manifest.deps + (new_dep,))

    env_with_index = _load_index_for_verb(env, project_dir)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    # B7 (RFC resolution-semantics.md §3 Axis B): thread the committed lock as
    # `prior` so minimal-change re-resolution applies — the new dep resolves
    # while every other already-locked dep stays pinned (#192 through this door).
    _add_prior = _maybe_load_prior_lockfile(lock_path)
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) against the current manifest.
    _strategy_decl = _resolve_effective_strategy(strategy, manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `add` — manifest-only, then (no-silent-drop) the
    # lockfile's own recorded bound.
    exclude_newer = _resolve_effective_exclude_newer(None, manifest, _add_prior)
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=_add_prior,  # type: ignore[arg-type]
        manifest_dir=project_dir,
        exclude_newer=exclude_newer,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, project_dir),
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)

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
    strategy: Strategy | None,
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
# Namespace-qualified dep-ref parsing + structured DepKey matching
# (namespace-conflation audit P3/P4) — shared by cmd_remove,
# _cmd_remove_from_member_dir, and (for the parse step) update's scoped path.
# ---------------------------------------------------------------------------


def _parse_ns_name_ref(ref: str) -> tuple[str | None, str]:
    """Parse a CLI dep reference into ``(namespace, bare_name)``.

    Recognizes the ``ns/name`` slash-shorthand (S5b) accepted by ``remove``
    and ``update``'s scoped dep argument. A malformed reference (more than
    one ``/``, or an empty namespace/name part) is left UNSPLIT —
    ``(None, ref)`` — so the caller's own not-declared/not-found guard
    reports the original string verbatim rather than a mangled bare name.
    """
    if "/" in ref:
        parts = ref.split("/")
        if len(parts) == 2 and parts[0] and parts[1]:
            return parts[0], parts[1]
    return None, ref


def _dep_identity_key(d: object) -> DepKey:
    """Return the structured ``(name, namespace)`` identity key for a dep
    declaration, a ``LockedDep``, or a ``ResolvedDep`` alike.

    Never a joined ``::`` solver-variable string (``DepKey.solver_var()`` is
    SOLVER-INTERNAL ONLY). Shared by ``cmd_remove`` (standalone) and
    ``_cmd_remove_from_member_dir`` (S11e member-dir delegate) so the two
    ``remove`` entry points cannot structurally drift on namespace-qualified
    matching (P3, namespace-conflation audit) — a member-dir ``milpa remove
    foo`` must never match/delete `foo` in ANY namespace but the one asked
    for, exactly like the standalone path.
    """
    return DepKey(name=getattr(d, "name", ""), namespace=getattr(d, "namespace", None))


def _dep_key_display(key: DepKey) -> str:
    """Render a ``DepKey`` as the CLI's ``ns/name`` (or bare) display form —
    the same slash convention the lockfile uses for ``requires`` entries
    (lockfile.py's ``_req_name_to_lockfile``) — never the ``::``-joined
    solver-variable form, which is solver-internal only.
    """
    return key.name if key.namespace is None else f"{key.namespace}/{key.name}"


def _resolve_remove_target(
    dep_name: str,
    prior_for_alias: "Lockfile | None",
) -> tuple[DepKey, str]:
    """Parse + alias-resolve a ``remove`` dep argument into a canonical
    ``(DepKey, display)`` pair.

    Shared by ``cmd_remove`` (standalone) and ``_cmd_remove_from_member_dir``
    (S11e member-dir delegate) so namespace-qualified matching + alias→
    canonical resolution cannot structurally drift between the two ``remove``
    entry points (P3, namespace-conflation audit) — mirrors
    ``_strip_pins_for_upgrade``'s shared role for ``update``.

    Alias resolution operates on the BARE name only (aliases are a
    content-dedup convenience, orthogonal to the namespace axis); the parsed
    namespace is carried through unchanged alongside it.
    """
    namespace, bare = _parse_ns_name_ref(dep_name)
    if prior_for_alias is not None:
        canonical_bare = resolve_alias_to_canonical(bare, prior_for_alias)
    else:
        canonical_bare = bare
    canonical_key = DepKey(name=canonical_bare, namespace=namespace)
    return canonical_key, _dep_key_display(canonical_key)


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


def _strip_pins_for_upgrade(
    prior: Lockfile | None,
    dep_names: tuple[str, ...],
) -> Lockfile | None:
    """Strip the recorded pin for each dep in ``dep_names``.

    THE shared mechanism behind both ``milpa update``/``milpa update <dep>``
    and ``--upgrade [<dep>...]`` on ``fetch``/``lock`` (resolution-semantics
    RFC §3 Axis B / D-B3) — both callers delegate to this ONE function, so
    the two verbs cannot structurally drift.

    - ``dep_names`` empty (bare ``update`` / bare ``--upgrade``): drop
      EVERY pin outright — returns ``None`` (the caller re-resolves with
      no prior at all, newest-wins for the whole graph).
    - ``dep_names`` non-empty (``update <dep>`` / ``--upgrade <dep> ...``):
      opt out ONLY for those deps, looping ``strip_dep_pin`` (lockfile.py)
      once per name (alias→canonical resolved against the running lock)
      so every other dep's pin is untouched and keeps B2's minimal-change
      preference.

    Each entry of ``dep_names`` MAY use the ``ns/name`` slash-shorthand
    (S5b) to disambiguate a bare name shared by locked deps in different
    namespaces — parsed via ``_parse_ns_name_ref``, the same helper
    ``cmd_remove``'s scoped-dep matching uses (namespace-conflation audit
    P4). A BARE name that matches locked deps in 2+ DISTINCT namespaces is
    ambiguous: before this guard, ``strip_dep_pin`` matched (and then
    filtered/rebuilt ``new_deps``) on bare ``name`` alone, so stripping one
    namespaced dep's pin silently DELETED the sibling's entire lockfile
    entry. Raising instead of guessing is the safe behavior.

    Raises ``MilpaError(LOCK_FILE_NOT_FOUND)`` if ``dep_names`` is
    non-empty and ``prior`` is ``None`` (nothing to scope a named upgrade
    against). Raises ``MilpaError(LOCK_DEP_AMBIGUOUS_NAME)`` if a bare name
    matches 2+ distinct namespaces. Raises ``MilpaError(LOCK_DEP_NOT_FOUND)``
    if a (possibly namespace-qualified) name isn't present in ``prior``.
    """
    if not dep_names:
        return None
    if prior is None:
        raise MilpaError(
            LOCK_FILE_NOT_FOUND,
            "no milpa.lock to scope --upgrade/update against — run "
            "`milpa fetch` first",
        )
    result = prior
    for dep_name in dep_names:
        namespace, bare = _parse_ns_name_ref(dep_name)
        canonical_bare = resolve_alias_to_canonical(bare, result)

        if namespace is None:
            # Bare name given: must be unambiguous across namespaces.
            matching_namespaces = sorted(
                {d.namespace for d in result.deps if d.name == canonical_bare},
                key=lambda ns: (ns is None, ns or ""),
            )
            if len(matching_namespaces) > 1:
                displayed = ", ".join(
                    canonical_bare if ns is None else f"{ns}/{canonical_bare}"
                    for ns in matching_namespaces
                )
                raise MilpaError(
                    LOCK_DEP_AMBIGUOUS_NAME,
                    f"{dep_name!r} matches multiple namespaced deps in the "
                    f"lockfile ({displayed}) — specify the namespace "
                    f"(e.g. `ns/{canonical_bare}`) to disambiguate",
                )
            target_namespace = matching_namespaces[0] if matching_namespaces else None
        else:
            target_namespace = namespace

        if not any(
            d.name == canonical_bare and d.namespace == target_namespace
            for d in result.deps
        ):
            raise MilpaError(
                LOCK_DEP_NOT_FOUND,
                f"{dep_name!r} not found in lockfile",
            )
        result = strip_dep_pin(result, canonical_bare, namespace=target_namespace)
    return result


# ---------------------------------------------------------------------------
# cmd_remove (10e)
# ---------------------------------------------------------------------------


def cmd_remove(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str,
    strategy: Strategy | None,
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

    # S5b audit (solver_var/from_solver_var CLI-wide audit): this whole
    # function is a LOCKFILE/manifest mutation operation, never a solver-key
    # lookup — it must NOT use `DepKey.solver_var()`/`from_solver_var()` to
    # identify a dep. Both `LockedDep` and `ResolvedDep` store a qualified
    # dep as two SEPARATE fields (`name` bare, `namespace` separate) — never
    # joined with `::` (`DepKey.solver_var()`'s own docstring: "SOLVER-
    # INTERNAL ONLY. This string MUST NOT be written to disk, the lockfile,
    # or _deps/ paths."). The identity used throughout this function is a
    # plain `DepKey(name, namespace)` tuple, compared structurally — never a
    # joined string — against the manifest's own dep declarations, the prior
    # lockfile's `LockedDep`, and the freshly resolved graph's `ResolvedDep`
    # alike, so a qualified dep's namespace is never dropped nor conflated
    # with a same-named dep in a different (or no) namespace.
    #
    # `_resolve_remove_target` (S5b/P3, namespace-conflation audit): parses
    # the "ns1/bar" slash-shorthand + resolves alias→canonical — shared with
    # `_cmd_remove_from_member_dir` so the two `remove` entry points cannot
    # structurally drift.
    prior_for_alias = _maybe_load_prior_lockfile(lock_path)
    canonical_key, canonical_display = _resolve_remove_target(
        dep_name, prior_for_alias
    )

    # Guard: dep must be declared in milpa.kdl. Match by the STRUCTURED
    # (name, namespace) key — never a joined string.
    existing_keys = {_dep_identity_key(dep) for dep in manifest.deps}
    if canonical_key not in existing_keys:
        print(
            f"milpa remove: dep {dep_name!r} is not declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_REMOVE_DEP_ABSENT)
        return 1

    # Collect prior aliases for the dep being removed, so we can warn if any
    # alias is still required by transitives after re-resolve. Matched by the
    # structured key (name AND namespace), against LockedDep's own separate
    # `name`/`namespace` fields — never a joined solver_var string.
    prior_aliases: tuple[str, ...] = ()
    if prior_for_alias is not None:
        for locked in prior_for_alias.deps:
            if DepKey(name=locked.name, namespace=locked.namespace) == canonical_key:
                prior_aliases = locked.aliases
                break

    # Build proposed manifest without the dep.
    from dataclasses import replace as _replace
    new_deps = tuple(d for d in manifest.deps if _dep_identity_key(d) != canonical_key)
    proposed_manifest = _replace(manifest, deps=new_deps)

    # Re-resolve.
    env_with_index = _load_index_for_verb(env, project_dir)
    deps_dir = project_dir / "_deps"
    profile = Profile.from_environment()
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) against the current manifest.
    _strategy_decl = _resolve_effective_strategy(strategy, manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `remove` — manifest-only, then (no-silent-drop)
    # the already-loaded on-disk lock's own recorded bound.
    exclude_newer = _resolve_effective_exclude_newer(None, manifest, prior_for_alias)
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior_for_alias,  # type: ignore[arg-type]
        manifest_dir=project_dir,
        exclude_newer=exclude_newer,
    )

    graph = resolve(proposed_manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)

    # D-update-remove Phase D item 5: warn per alias (Phase D item 5).
    # If the removed canonical had aliases in the prior lockfile, warn about
    # each one so the user knows that _deps/<alias> will be cleaned up.
    # This also covers the "alias still required by a transitive" case: if the
    # new graph still contains the canonical (pulled in transitively via another
    # dep), the alias symlink remains live and the warning is especially
    # important. Matched by the structured key against ResolvedDep's own
    # separate `name`/`namespace` fields — never a joined solver_var string.
    new_canonical_keys = {DepKey(name=d.name, namespace=d.namespace) for d in graph.deps}
    # `canonical_display` ("ns/name", or bare) was already computed by
    # `_resolve_remove_target` above — the same slash convention the
    # lockfile uses for `requires` entries (lockfile.py's
    # `_req_name_to_lockfile`), never the `::`-joined solver-variable form.
    for alias in prior_aliases:
        if canonical_key in new_canonical_keys:
            print(
                f"warning: alias {alias!r} of removed dep {canonical_display!r} "
                f"is still required transitively; _deps/{alias} remains live",
                file=sys.stderr,
            )
        else:
            print(
                f"warning: removing dep {canonical_display!r} also removes alias "
                f"{alias!r} (_deps/{alias} will be cleaned up)",
                file=sys.stderr,
            )

    # Atomic write.
    mutate_manifest_file(manifest_path, lambda _m: proposed_manifest)
    write_lockfile(lockfile_val, lock_path)

    print(f"removed {canonical_display}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_update (10e)
# ---------------------------------------------------------------------------


def cmd_update(
    project_dir: Path,
    env: MilpaEnv,
    *,
    dep_name: str | None,
    strategy: Strategy | None,
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

    # C3/R9 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
    # EFFECTIVE strategy (+ whether it was explicitly sourced) against the
    # manifest — independent of the `prior` this verb deliberately
    # nulls/strips below for B2's minimal-change preference. Dropping a
    # dep's pin (or all pins, for bare `update`) must not also reset the
    # project's governing strategy.
    _strategy_decl = _resolve_effective_strategy(strategy, manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `update` — manifest-only, then (no-silent-drop)
    # the lockfile's own recorded bound — against the ACTUAL on-disk lock,
    # same rationale as `strategy` just above.
    exclude_newer = _resolve_effective_exclude_newer(
        None, manifest, _maybe_load_prior_lockfile(lock_path)
    )

    if dep_name is None:
        # ``update`` with no arg — drop ALL pins (prior=None).
        params = ResolveParams(
            strategy=strategy,
            strategy_explicit=strategy_explicit,
            max_parallel=max_parallel,
            profile=profile,
            prior=None,
            manifest_dir=project_dir,
            features=features,
            no_default_features=no_default_features,
            all_features=all_features,
            exclude_newer=exclude_newer,
            # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
            entry_trust=_build_entry_trust(env, project_dir),
        )
        graph = resolve(manifest, deps_dir, env_with_index, params)
        lockfile_val = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
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

    # B4 (RFC resolution-semantics.md §3 Axis B / D-B3): delegate to the
    # SAME shared strip-pin mechanism `--upgrade [<dep>...]` on fetch/lock
    # uses, so the two verbs cannot structurally drift. This covers the
    # D-update-remove alias→canonical resolution (Phase D item 5), the
    # not-in-lockfile guard, and the pin-strip (retains declared mirror
    # provenances per Phase D item 5; clears identity so the dep re-resolves
    # fresh) in one call.
    try:
        filtered_prior = _strip_pins_for_upgrade(prior_lock, (dep_name,))
    except MilpaError as exc:
        print(f"milpa update: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

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
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=filtered_prior,
        manifest_dir=project_dir,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
        exclude_newer=exclude_newer,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, project_dir),
    )

    graph = resolve(manifest, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
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
    strategy: Strategy | None,
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
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) against the WORKSPACE ROOT manifest — before the drop/strip
    # below (same rationale as the standalone cmd_update: dropping pins
    # must not also reset the governing strategy).
    _strategy_decl = _resolve_effective_strategy(strategy, workspace.workspace_manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `update` — manifest-only, then (no-silent-drop)
    # the lockfile's own recorded bound — computed against the FRESH
    # on-disk `prior`, before the drop/strip below (same rationale as
    # `strategy` just above).
    exclude_newer = _resolve_effective_exclude_newer(None, workspace.workspace_manifest, prior)
    if dep_name is None:
        prior = None  # Full drop — re-resolve from scratch.
    elif prior is not None:
        # Scoped: drop only this dep's pin from the prior. B4: delegates to
        # the SAME shared helper the standalone path + --upgrade use (D-B3).
        try:
            prior = _strip_pins_for_upgrade(prior, (dep_name,))
        except MilpaError as exc:
            print(f"milpa update: {exc.message}", file=sys.stderr)
            _emit_slug(exc.slug)
            return 1

    env_with_index = _load_index_for_verb(env, ws_root)
    profile = Profile.from_environment()
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
        exclude_newer=exclude_newer,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, ws_root),
    )

    graph = resolve_workspace(workspace, deps_dir, env_with_index, params)
    lockfile_val = from_graph(graph, strategy=str(strategy), exclude_newer=exclude_newer)
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
    strategy: Strategy | None,
    max_parallel: int,
    optional: bool = False,
    features: "tuple[str, ...] | frozenset[str]" = (),
    version: str | None = None,
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

    # A3b (§3 Axis A (b) step 4): --version validation — same slug/behavior
    # as the single-package path (_cmd_add_git).
    parsed_version: "Version | None" = None
    if version is not None:
        from milpa.errors import MAN_DEP_VERSION_INVALID
        from milpa.version import parse_version
        parsed_version = parse_version(version)
        if parsed_version is None:
            print(
                f"milpa add: --version value {version!r} is not a valid semver "
                "version (expected 'x.y.z')",
                file=sys.stderr,
            )
            _emit_slug(MAN_DEP_VERSION_INVALID)
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
        version=parsed_version,
    )

    def _mutate_add(m: "Manifest") -> "Manifest":
        return _replace(m, deps=m.deps + (new_dep,))

    # Re-resolve the WHOLE workspace via the SSOT orchestration primitive.
    # apply_member_manifest_change: reload-workspace → apply mutator → resolve
    # in-memory → write member manifest → write shared lock.
    env_with_index = _load_index_for_verb(env, ws_root)
    profile = Profile.from_environment()
    # B7 (RFC resolution-semantics.md §3 Axis B): thread the SHARED workspace
    # lock as `prior` so adding a dep to one member re-resolves minimally —
    # other members' already-locked deps stay pinned.
    _add_member_prior = _maybe_load_prior_lockfile(ws_root / "milpa.lock")
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) against the WORKSPACE ROOT manifest (Axis W: resolution{} is
    # root-only).
    _strategy_decl = _resolve_effective_strategy(strategy, workspace.workspace_manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `add` — manifest-only, against the WORKSPACE
    # ROOT manifest, then (no-silent-drop) the shared lock's own recorded bound.
    exclude_newer = _resolve_effective_exclude_newer(
        None, workspace.workspace_manifest, _add_member_prior
    )
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=_add_member_prior,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        exclude_newer=exclude_newer,
        # P3a (RFC per-entry-attestation.md §8): entry-trust gate, online/index-loading verbs.
        entry_trust=_build_entry_trust(env, ws_root),
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
    strategy: Strategy | None,
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

    # Alias→canonical resolution against the SHARED lockfile (not the member
    # lock). `_resolve_remove_target` (P3, namespace-conflation audit): parses
    # the "ns1/bar" slash-shorthand + resolves alias→canonical into a
    # structured DepKey — the SAME shared helper the standalone `cmd_remove`
    # uses, so this member-dir path cannot drift onto bare-name matching
    # (which would conflate two same-bare-name deps in different namespaces).
    shared_lock_path = ws_root / "milpa.lock"
    prior_for_alias = _maybe_load_prior_lockfile(shared_lock_path)
    canonical_key, canonical_display = _resolve_remove_target(dep_name, prior_for_alias)

    # Pre-flight: dep must be declared in the MEMBER's milpa.kdl. Matched by
    # the STRUCTURED (name, namespace) key — never bare name — so `milpa
    # remove foo` from a member dir cannot match (and delete) BOTH `foo
    # namespace="ns1"` and `foo namespace="ns2"` at once.
    member_manifest_path = member_dir / "milpa.kdl"
    preflight_manifest = parse_manifest(member_manifest_path.read_text(encoding="utf-8"))
    existing_keys = {_dep_identity_key(dep) for dep in preflight_manifest.deps}
    if canonical_key not in existing_keys:
        print(
            f"milpa remove: dep {dep_name!r} is not declared in milpa.kdl",
            file=sys.stderr,
        )
        _emit_slug(MAN_REMOVE_DEP_ABSENT)
        return 1

    def _mutate_remove(m: _Manifest) -> _Manifest:
        new_deps = tuple(d for d in m.deps if _dep_identity_key(d) != canonical_key)
        return _replace(m, deps=new_deps)

    # Re-resolve the WHOLE workspace via the SSOT orchestration primitive.
    env_with_index = _load_index_for_verb(env, ws_root)
    profile = Profile.from_environment()
    # C3/R9: resolve the EFFECTIVE strategy (+ whether it was explicitly
    # sourced) against the WORKSPACE ROOT manifest.
    _strategy_decl = _resolve_effective_strategy(strategy, workspace.workspace_manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `remove` — manifest-only, then (no-silent-drop)
    # the shared lock's own recorded bound.
    exclude_newer = _resolve_effective_exclude_newer(
        None, workspace.workspace_manifest, prior_for_alias
    )
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=prior_for_alias,  # type: ignore[arg-type]
        manifest_dir=ws_root,
        exclude_newer=exclude_newer,
    )

    try:
        _graph, _wr = apply_member_manifest_change(
            ws_root, env_with_index, params, member_dir, _mutate_remove
        )
    except MilpaError as exc:
        print(f"milpa remove: {exc.message}", file=sys.stderr)
        _emit_slug(exc.slug)
        return 1

    print(f"removed {canonical_display}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# cmd_workspace_add_member / cmd_workspace_remove_member (S10)
# ---------------------------------------------------------------------------


def cmd_workspace_add_member(
    root: Path,
    env: MilpaEnv,
    *,
    member_path: str,
    strategy: Strategy | None,
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
    # B7 (RFC resolution-semantics.md §3 Axis B): thread the SHARED workspace
    # lock as `prior` — adding a member re-resolves minimally, so the OTHER
    # members' already-locked deps stay pinned instead of newest-wins-bumping.
    profile = Profile.from_environment()
    _ws_add_prior = _maybe_load_prior_lockfile(root / "milpa.lock")
    # C3: resolve the EFFECTIVE strategy against the WORKSPACE ROOT manifest
    # (Axis W: resolution{} is root-only) — parsed here directly (this
    # function only pre-parses the MEMBER's manifest above, for validation).
    _root_manifest_for_strategy = parse_workspace_or_manifest(
        (root / "milpa.kdl").read_text(encoding="utf-8")
    )
    _strategy_decl = _resolve_effective_strategy(strategy, _root_manifest_for_strategy)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `workspace add-member` — manifest-only, then
    # (no-silent-drop) the shared lock's own recorded bound.
    exclude_newer = _resolve_effective_exclude_newer(
        None, _root_manifest_for_strategy, _ws_add_prior
    )
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=_ws_add_prior,  # type: ignore[arg-type]
        exclude_newer=exclude_newer,
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
    strategy: Strategy | None,
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
    # B7 (RFC resolution-semantics.md §3 Axis B): thread the SHARED workspace
    # lock as `prior` — removing a member re-resolves minimally, so remaining
    # members' already-locked deps stay pinned.
    profile = Profile.from_environment()
    _ws_remove_prior = _maybe_load_prior_lockfile(root / "milpa.lock")
    # C3: resolve the EFFECTIVE strategy against the WORKSPACE ROOT manifest
    # (Axis W: resolution{} is root-only) — ``ws_manifest`` above is already
    # the workspace root's manifest.
    _strategy_decl = _resolve_effective_strategy(strategy, ws_manifest)
    strategy_explicit = _strategy_decl is not None
    strategy = _strategy_decl if _strategy_decl is not None else Strategy.MAXVER
    # D2/D5: no CLI flag on `workspace remove-member` — manifest-only, then
    # (no-silent-drop) the shared lock's own recorded bound.
    exclude_newer = _resolve_effective_exclude_newer(None, ws_manifest, _ws_remove_prior)
    params = ResolveParams(
        strategy=strategy,
        strategy_explicit=strategy_explicit,
        max_parallel=max_parallel,
        profile=profile,
        prior=_ws_remove_prior,  # type: ignore[arg-type]
        exclude_newer=exclude_newer,
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

    # C3 (resolution-semantics RFC §3 Axis C / D-C2): ``--strategy`` is now
    # an ``Option<Strategy>`` sentinel, scoped per-verb (not every subcommand
    # has this attribute — ``getattr`` handles that safely, mirroring
    # ``locked``/``upgrade`` below). ``None`` means unspecified; each verb's
    # cmd_* function resolves the EFFECTIVE strategy against its own parsed
    # manifest + lockfile (``_resolve_effective_strategy``) — this is no
    # longer a single global value computed once here.
    _cli_strategy_raw = getattr(args, "strategy", None)
    strategy: Strategy | None = (
        Strategy(_cli_strategy_raw) if _cli_strategy_raw is not None else None
    )

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
    # P3a: entry-trust escalation flag (mirrors _require_attested_index).
    _require_attested_entries = getattr(args, "require_attested_entries", False)

    # Update the env with index-trust state (env vars + flags).
    # require_attested_index escalates the effective policy warn→strict per-verb
    # in _build_index_trust; it must travel on env (not re-read from args later).
    from dataclasses import replace as _dc_replace
    env = _dc_replace(
        env,
        refresh_index=_refresh_index,
        require_attested_index=_require_attested_index,
        require_attested_entries=_require_attested_entries,
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

        # B4 (resolution-semantics RFC §3 Axis B / D-B3): `--locked` (forbids
        # deviation) and `--upgrade` (forces it) are contradictory. `_cli_upgrade`
        # is None when --upgrade was not passed, [] for bare --upgrade, or a
        # list of dep names — any non-None value conflicts with --locked.
        _cli_locked = getattr(args, "locked", False)
        _cli_upgrade_raw = getattr(args, "upgrade", None)
        if _cli_locked and _cli_upgrade_raw is not None:
            raise MilpaError(
                CLI_LOCKED_UPGRADE_CONFLICT,
                "--locked and --upgrade are mutually exclusive: --locked "
                "forbids any deviation from the committed lock while "
                "--upgrade forces it for the targeted package(s) — pass "
                "at most one",
            )
        _cli_upgrade: tuple[str, ...] | None = (
            tuple(_cli_upgrade_raw) if _cli_upgrade_raw is not None else None
        )

        # D2 (resolution-semantics RFC §3 Axis D): `--exclude-newer <ts>` is
        # scoped to fetch/lock only (`_add_exclude_newer_arg`); other verbs
        # never have this attribute, so `getattr` defaults to `None`.  A
        # malformed value raises CLI-EXCLUDE-NEWER-INVALID (exit 1 + slug),
        # distinct from the manifest's own MAN-RESOLUTION-EXCLUDE-NEWER-
        # INVALID parse error. Reuses the same shared timestamp parser
        # (`_parse_timestamp`) the manifest node uses (D1) rather than a
        # second implementation.
        _cli_exclude_newer_raw = getattr(args, "exclude_newer", None)
        cli_exclude_newer: datetime | None = None
        if _cli_exclude_newer_raw is not None:
            cli_exclude_newer = _parse_timestamp(_cli_exclude_newer_raw)
            if cli_exclude_newer is None:
                raise MilpaError(
                    CLI_EXCLUDE_NEWER_INVALID,
                    f"--exclude-newer value {_cli_exclude_newer_raw!r} is not "
                    "a parseable ISO 8601 timestamp",
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
                locked=_cli_locked,
                upgrade=_cli_upgrade,
                exclude_newer=cli_exclude_newer,
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
                locked=_cli_locked,
                upgrade=_cli_upgrade,
                exclude_newer=cli_exclude_newer,
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
                version=getattr(args, "version", None),
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
        elif args.command == "publish":
            return cmd_publish(
                project_dir,
                version=args.version,
                target=args.target,
                name=args.name,
                tag=args.tag,
                output_path=Path(args.output).resolve() if args.output else None,
                dry_run=args.dry_run,
                allow_untagged=args.allow_untagged,
            )
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
        elif args.command == "index":
            index_cmd = getattr(args, "index_command", None)
            if index_cmd == "status":
                return cmd_index_status(
                    project_dir, env, refresh=getattr(args, "refresh", False)
                )
            elif index_cmd == "accept":
                return cmd_index_accept(project_dir, env)
            else:
                print("usage: milpa index <status|accept> [args]", file=sys.stderr)
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
