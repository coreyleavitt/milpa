"""Resolver — live dependency resolution.

Implements ``resolve(manifest, deps_dir, env, params) -> ResolvedGraph`` per
``spec/resolver-semantics.md`` (the authoritative contract).

Architecture
------------
``resolve()`` drives a BFS over the dep graph:

1. **Profile filtering** (§6, slice 9b-2): ``filter_manifest``
   strips deps whose predicates don't match the active profile BEFORE any
   fetch or solver input is built.  No-profile → all deps included.

2. **BFS materialisation** (§4.2.1): URL deps are fetched eagerly; named deps
   are enumerated from the index (Phase A stubs) then fetched lazily when the
   solver selects them (Phase B materialisation).

3. **Canonical-solution selection invariant** (§4.2.1 NORMATIVE):
   The order in which packages enter the solver MUST equal the BFS package
   order P — the BFS traversal from root in declaration order.  Concretely:
   deps at BFS depth d emit their dependency terms before any dep at depth
   d+1, and a named dep takes the BFS position of the package that first
   introduced it.  This invariant is enforced by the BFS queue structure
   below: the root's deps are seeded first (declaration order), and each
   newly-discovered transitive dep is appended to the queue only on first
   occurrence (first-occurrence dedup).  The solver's ``_next_undecided``
   function walks ``partial.assignments`` in insertion order, which mirrors
   the queue-insertion order — so solver entry order == BFS P order.
   A different iteration order (e.g. DFS, or alpha-sort before seeding)
   yields a different lex-maximal solution that passes unit tests but FAILS
   fixture-063.

4. **Graph assembly**: ``_build_graph`` maps the solver's
   ``{name: version}`` output back to ``ResolvedGraph`` of ``ResolvedDep``
   records.

Public surface
--------------
``resolve(manifest, deps_dir, env, params) -> ResolvedGraph``
    Full live resolve for a single-package manifest.  Slices 9b-*.

``resolve_workspace(workspace, deps_dir, env, params) -> ResolvedGraph``
    Workspace live resolve.  Slice 9d (not yet implemented).

Spec authority: spec/resolver-semantics.md
"""

from __future__ import annotations

import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING

from milpa.binding import (
    DEFAULT_REGISTRY_ALIAS,
    BindingResolver,
    BindOutcome,
    Claim,
    check_registry_shadow,
    reconcile_root_claims,
    resolved_registry_namespace,
)
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import (
    FETCH_ALL_FAILED,
    FETCH_PROVENANCE_DIVERGENCE,
    MILPA_INTERNAL,
    RES_EXCLUDE_NEWER_EMPTY,
    RES_EXCLUDE_NEWER_PIN,
    RES_MEMBER_OUTSIDE_WORKSPACE,
    RES_NO_INDEX,
    RES_ROOT_SELF_VERSION_CONSTRAINT,
    RES_VERSION_UNKNOWN_CONSTRAINED,
    RES_WS_MEMBER_REF_UNKNOWN,
    RES_WS_MEMBER_VERSION_CONSTRAINT,
    RES_WS_NO_INDEX,
    RES_WS_OVERRIDE_MEMBER_COLLISION,
    TNG_NO_IDENTITY,
    MilpaError,
)
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.fetchers.local import LocalProvenance
from milpa.fetchers.oci import OciProvenance
from milpa.fetchers.tarball import TarballProvenance
from milpa.fetchers.types import Provenance
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    GitProvenanceRecord,
    LocalProvenanceRecord,
    Lockfile,
    MemberProvenanceRecord,
    OciProvenanceRecord,
    ProvenanceRecord,
    ResolvedDep,
    ResolvedGraph,
    RootProvenanceRecord,
    TarballProvenanceRecord,
)
from milpa.manifest import (
    Dep,
    FlagDecl,
    FlagRequest,
    GitTarget,
    LocalDep,
    LocalTarget,
    Manifest,
    MemberDep,
    MemberTarget,
    NamedDep,
    OciTarget,
    Override,
    Predicate,
    RegistryTarget,
    TarballDep,
    TarballTarget,
    UrlDep,
    flag_enables_closure,
)
from milpa.predicate import dep_passes_flag_predicates
from milpa.edge_sources import (
    DepDeclEdgeSource,
    EdgeSourceCtx,
    MilpaKdlEdgeSource,
    NimbleEdgeSource,
    _resolve_edges_pure,
    declared_version_for,
    edgeset_to_bfs_deps,
    edgeset_to_terms,
    resolve_edges,
)
from milpa.dep_decl import EdgeSet, NamedRequire
from milpa.profile import Profile
from milpa.registry import (
    EntryAttestation,
    GitIndexProvenance,
    Index,
    IndexVersion,
    OciIndexProvenance,
    filter_by_exclude_newer,
)
from milpa.solver import SolverError, Term, VersionUnknownConstrained, solve_with_cert
from milpa.source_id import (
    GitSourceId,
    MemberSourceId,
    RegistrySourceId,
    SourceId,
    normalize_source,
)
from milpa.version import (
    DepKey,
    SolverKey,
    Strategy,
    Version,
    VersionSet,
    VersionSource,
    dep_dir_name,
    format_version_str,
    parse_version,
)
from milpa.workspace import LoadedWorkspace

if TYPE_CHECKING:
    from milpa.lockfile import Lockfile


# ---------------------------------------------------------------------------
# Sentinel version for URL/local/tarball/member deps (resolver-semantics §3)
# ---------------------------------------------------------------------------

# URL deps, local deps, and member deps have exactly one canonical version.
# The exact sentinel value is an incidental implementation detail (§3 NOTE).
_URL_DEP_VERSION: Version = Version(0, 0, 1)


def _candidate_label(ctx: EdgeSourceCtx) -> tuple[Version, VersionSource | None, bool]:
    """Axis A (b): the git/url/local/tarball candidate's version label (D-A2).

    Precedence steps 1-4 (§3 Axis A): the fetched package's ``milpa.kdl
    version``, else its ``.nimble version`` (A1), else — git deps only,
    ``ctx.ref`` populated — a version-shaped tag (A3), else the dep
    declaration's ``version=`` annotation (``ctx.version``, A3b).  None
    present/parseable → the existing sentinel.  Member candidates never call
    this (A2c owns their label, via ``_member_candidate_version``).

    Returns ``(label, source, version_unknown)`` — ``source`` is the A5
    sibling field (``None`` iff ``version_unknown``); ``version_unknown`` is
    True iff no declared version was found (A4: the sentinel value alone is
    not a reliable signal, since a real declared version could coincidentally
    equal it; both are computed here, from the same ``declared_version_for``
    call, so callers never need a second — potentially file-re-reading — lookup).
    """
    declared = declared_version_for(ctx)
    if declared is not None:
        version, source = declared
        return version, source, False
    return _URL_DEP_VERSION, None, True


def _member_candidate_version(
    manifest: Manifest, abs_dir: Path
) -> tuple[Version, VersionSource | None]:
    """A2c/A5: a workspace member's declared-version label + source (§3 Axis A
    member block, D-A2).

    Same precedence as ``_candidate_label`` (``milpa.kdl version`` else
    ``.nimble version`` else sentinel), but step 1 is free here: a member's
    manifest is already parsed in memory (A1's ``milpa.kdl version`` field),
    so no extra I/O is needed to check it.  ``has_milpa_kdl=False`` is passed
    to ``declared_version_for`` deliberately — step 1 has already been
    settled by ``manifest.version`` above, so the reused call goes straight
    to step 2 (the ``.nimble`` scan of the member's own directory).

    A member that declares no version (no ``milpa.kdl version``, no
    ``.nimble``) keeps the existing sentinel, paired with ``source=None`` —
    version-unknown just works for an unconstrained member; the
    constrained-and-unknown partition + ``RES-VERSION-UNKNOWN-CONSTRAINED``
    hard error is A4, out of scope here.

    Returns ``(label, source)`` — the same two-sibling-field pairing
    ``_candidate_label`` returns for git/url/local/tarball candidates.
    """
    if manifest.version is not None:
        return manifest.version, VersionSource.MANIFEST
    ctx = EdgeSourceCtx(
        dep_path=abs_dir,
        dep_name=manifest.name,
        dep_decl=None,
        is_overridden=False,
        has_milpa_kdl=False,
    )
    declared = declared_version_for(ctx)
    if declared is not None:
        version, source = declared
        return version, source
    return _URL_DEP_VERSION, None


def _root_self_candidate_version(
    manifest: Manifest, manifest_dir: Path | None
) -> tuple[Version, VersionSource | None]:
    """§14.1: the standalone root's own candidate-label version — a
    standalone package is a workspace-of-one, so this uses the EXACT same
    precedence ``_member_candidate_version`` already applies for a workspace
    member (``milpa.kdl version`` else ``.nimble version`` else the
    sentinel), just against the root's own project directory instead of a
    member's directory.

    ``manifest_dir`` is ``ResolveParams.manifest_dir`` — ``None`` for some
    call sites (mostly unit tests constructing a manifest in memory with no
    real project directory).  Without a real directory there is nothing to
    ``.nimble``-scan, so this falls back to ``manifest.version`` (if set)
    else the sentinel — the same terminal fallback
    ``_member_candidate_version`` reaches when neither `milpa.kdl version`
    nor a `.nimble` file is found.
    """
    if manifest_dir is None:
        if manifest.version is not None:
            return manifest.version, VersionSource.MANIFEST
        return _URL_DEP_VERSION, None
    return _member_candidate_version(manifest, manifest_dir)


def _validate_root_self_constraint(
    dep_key: "DepKey",
    constraint_str: str | None,
    root_self_name: str | None,
    root_self_version: "Version | None",
) -> None:
    """§14.3: validate a transitive claim's version constraint against the
    standalone root's own candidate-label version, when the claim's name IS
    the root's own name.

    A no-op (returns without raising) when ``root_self_name`` is ``None``
    (the workspace path never passes it — resolve_workspace's pre-existing
    member auto-coerce, §11.5, is a separate mechanism and untouched by
    this function), the claim is namespaced (a namespaced name can never be
    the bare root name — root deps carry no namespace), the claim's name
    doesn't match, or the claim carries no explicit constraint.

    Raises ``MilpaError(RES-ROOT-SELF-VERSION-CONSTRAINT)`` when the root's
    own version does not satisfy the constraint — mirrors
    ``RES-WS-MEMBER-VERSION-CONSTRAINT``'s reasoning exactly (§11.5): the
    consumer's constraint is a real requirement, never silently discarded,
    and never "solved" by fetching an unrelated second copy of the name.
    """
    if (
        root_self_name is None
        or dep_key.namespace is not None
        or dep_key.name != root_self_name
    ):
        return
    if not constraint_str:
        return
    try:
        vs = VersionSet.from_constraint(constraint_str)
    except Exception:
        return
    if root_self_version is not None and not vs.contains(root_self_version):
        raise MilpaError(
            RES_ROOT_SELF_VERSION_CONSTRAINT,
            f"{dep_key.name!r} is the resolving package's own name; a "
            f"transitive dep requires {dep_key.name!r} {constraint_str!r} "
            f"but the root's own declared version "
            f"{format_version_str(root_self_version)!r} does not satisfy "
            f"it — the root itself is the only candidate for its own name "
            f"(no second copy is fetched); add a version= annotation "
            f"matching the constraint, or resolve the mismatch with the "
            f"transitive consumer",
            name=dep_key.name,
            constraint=constraint_str,
            version=format_version_str(root_self_version),
        )


def _version_unknown_constrained_err(
    exc: VersionUnknownConstrained,
    root_authority: set[str],
    binding_resolver: "BindingResolver | None" = None,
) -> MilpaError:
    """A4 (resolver-semantics RFC §3 Axis A (c) / §6 D-A1): wrap
    ``VersionUnknownConstrained``'s raw facts into
    ``RES-VERSION-UNKNOWN-CONSTRAINED``, branching the remedy on whether
    ``exc.package`` has a user-owned declaration site (``root_authority`` — a
    root-declared dep or an override rule) or is a purely transitive dep with
    no such site. ``exc.constrainers`` is enumerated in full (never just the
    first — the amoxtli incident floored two packages at once).

    ``exc.package``/each constrainer's ``consumer`` are PubGrub solver-
    variable strings — S5-rekey (RFC origin-as-identity §4.4): a named/
    registry dep's is now a BOUND source-id's canonical form, never meant to
    leak into a user-facing error message. Projected back to the legacy
    "ns::name"/bare form via ``_depkey_for_solved_name`` before formatting
    (mirrors the certificate projection, ``_project_solver_error``).
    ``binding_resolver is None`` only for a caller with no live resolve() in
    progress — falls back to the identity projection (``exc.package``/
    ``consumer`` unchanged), matching pre-S5-rekey behavior.
    """
    _pkg = _depkey_for_solved_name(exc.package).solver_var() if binding_resolver is not None else exc.package
    _constrainers = [
        (
            _depkey_for_solved_name(consumer).solver_var()
            if binding_resolver is not None
            else consumer,
            constraint,
        )
        for consumer, constraint in exc.constrainers
    ]
    constrainer_strs = [
        f"{consumer!r} requires {constraint!r}"
        for consumer, constraint in _constrainers
    ]
    if _pkg in root_authority:
        remedy = (
            f"add a version= annotation to {_pkg!r}'s dep declaration "
            f"(or the overrides rule redirecting it), or pin a versioned git tag"
        )
    else:
        remedy = (
            f"add a root-level pin for {_pkg!r} or an "
            f"overrides {{ {_pkg} … version= }} rule"
        )
    return MilpaError(
        RES_VERSION_UNKNOWN_CONSTRAINED,
        f"{_pkg!r} has no declared version (a git/url/local/tarball dep "
        f"with no milpa.kdl/.nimble/tag/version= source) but is constrained by: "
        f"{'; '.join(constrainer_strs)} — {remedy}",
        name=_pkg,
        constrainers=[{"by": c, "constraint": v} for c, v in _constrainers],
    )


# ---------------------------------------------------------------------------
# S3 (RFC #23 §7 + §3.1.2): Activation source enumeration
# ---------------------------------------------------------------------------


class ActivationSource(Enum):
    """Source of a flag activation in active(D).

    Defined identically in both Python and Rust impls (SSOT for cross-impl
    divergence prevention — §5 RFC #23).  Sources are tracked per activated
    flag to support RESOLVE-FLAG-CONFLICT payloads (§3.1.4) and the future
    ``milpa features`` trace (§3.7).

    Variants:
      DEFAULT       — flag is active because its manifest declares ``default=#true``.
      EDGE_REQUEST  — flag is active because an edge ``dep { flag "x" }`` requested it.
      ENABLES_RULE  — flag is active because an active flag's ``enables`` targets it
                      (same-package enables closure, S2 + S3).
      CLI           — flag is active because the user passed ``--features``/``--all-features``
                      on the command line (S9, RFC #23 §3.4).

    Variant ORDER is normative (both impls must use the same declaration order):
    DEFAULT / EDGE_REQUEST / ENABLES_RULE / CLI — serialized names must match
    the Rust ActivationSource variant names exactly for RESOLVE-FLAG-CONFLICT
    payload byte-identity.
    """

    DEFAULT = auto()
    EDGE_REQUEST = auto()
    ENABLES_RULE = auto()
    CLI = auto()


def compute_dep_active_flags(
    flags: tuple[FlagDecl, ...],
    requested: tuple[FlagRequest, ...],
) -> dict[str, set[ActivationSource]]:
    """Compute active(D) for a dep with the given flag declarations and consumer requests.

    S3 (RFC #23 §3.1.2 + §7 S3): single-hop seeding.

    Returns a dict mapping active flag name → set of ActivationSource values.
    This is the source-tracked set; the flag-name projection is ``set(result)``.

    Rules applied (monotone):
      1. ``active(D) ⊇ { f ∈ D.flags : f.default }`` — seed from default-true flags.
      2. ``active(D) ⊇ { f : requested[f].enabled }`` — seed from edge requests
         (only for flags actually declared in D.flags; unknown flag names are
         silently ignored per RESOLVE-FLAG-UNKNOWN-ON-TARGET warn-and-ignore).
      3. ``active(D) ⊇ enables-closure within D`` — propagate via same-package
         ``enables_same_pkg`` (S2 ``flag_enables_closure``), tagging new entries
         with ENABLES_RULE.

    Negative requests (``flag "x" #false``) are absence-of-request (§3.1.3):
    they are NOT subtracted from the active set.  If the DEFAULT source activates
    a flag, a negative request does not remove it.

    ``requested`` that name flags not declared in ``flags`` are silently ignored
    (RESOLVE-FLAG-UNKNOWN-ON-TARGET, §3.1.1, warn-and-ignore; warnings not yet
    emitted — observability via future S3.1 warning infrastructure).
    """
    flag_by_name: dict[str, FlagDecl] = {fd.name: fd for fd in flags}

    # Result: flag name → set of sources that activated it.
    active: dict[str, set[ActivationSource]] = {}

    # Rule 1: default-true flags.
    for fd in flags:
        if fd.default:
            if fd.name not in active:
                active[fd.name] = set()
            active[fd.name].add(ActivationSource.DEFAULT)

    # Rule 2: edge requests (positive only; negative = absence-of-request).
    for fr in requested:
        if fr.enabled and fr.name in flag_by_name:
            if fr.name not in active:
                active[fr.name] = set()
            active[fr.name].add(ActivationSource.EDGE_REQUEST)
        # Negative or unknown: silently ignored (absence-of-request / warn-and-ignore).

    # Rule 3: same-package enables closure over the current active seed.
    seed = frozenset(active.keys())
    closed = flag_enables_closure(flags, seed)
    # New entries from closure (not already in active) get ENABLES_RULE source.
    for flag_name in closed:
        if flag_name not in active:
            active[flag_name] = {ActivationSource.ENABLES_RULE}

    return active


# ---------------------------------------------------------------------------
# S4a (RFC #23 §7 + §3.1.2): cross-package enables propagation helpers
# ---------------------------------------------------------------------------


def compute_cross_pkg_enables(
    flags: "tuple[FlagDecl, ...]",
    active_flag_names: "frozenset[str]",
) -> "dict[str, list[FlagRequest]]":
    """Compute cross-package flag requests generated by dep's currently-active flags.

    S4a (RFC #23 §3.1.2 "Activation = a monotone closure"): for each active flag
    in ``active_flag_names``, inspect its ``enables_cross_pkg`` entries and
    emit FlagRequest objects for the target deps.

    Parameters
    ----------
    flags:
        The ``FlagDecl`` tuple from the dep's parsed manifest (``Manifest.flags``).
    active_flag_names:
        The name-projection of the current ``active(D)`` map — i.e.
        ``frozenset(active_map.keys())`` where ``active_map`` is the
        ``dict[str, set[ActivationSource]]`` returned by
        ``compute_dep_active_flags``.

    Returns
    -------
    dict[str, list[FlagRequest]]
        Maps target dep name → list of FlagRequest objects generated by cross-pkg
        enables from active flags of this dep.  Empty dict if no enables fire.
    """
    # Build a name→FlagDecl lookup for O(1) access.
    flag_by_name: dict[str, FlagDecl] = {fd.name: fd for fd in flags}

    result: dict[str, list[FlagRequest]] = {}
    for flag_name in active_flag_names:
        fd = flag_by_name.get(flag_name)
        if fd is None:
            continue
        for cpe in fd.enables_cross_pkg:
            # cpe: CrossPkgEnable(dep=str, flag_requests=tuple[FlagRequest])
            target = cpe.dep
            if target not in result:
                result[target] = []
            result[target].extend(cpe.flag_requests)

    return result



# ---------------------------------------------------------------------------
# Local dep provenance holder (before _Candidate to avoid forward-ref)
# ---------------------------------------------------------------------------


@dataclass
class _LocalDepProvenance:
    """Thin holder for a local dep's DECLARED (relative) path.

    Used as ``_Candidate.provenance`` for local deps so that ``_build_graph``
    can construct ``LocalProvenanceRecord(path=declared_path)`` from the
    declared relative path (not the resolved absolute path used for fetching).

    Not a Provenance subclass — it is only ever stored in ``_Candidate.provenance``
    and read by ``_build_graph``.
    """

    declared_path: str


# ---------------------------------------------------------------------------
# Internal candidate type
# ---------------------------------------------------------------------------


@dataclass
class _Candidate:
    """One materialised dep in the candidate set.

    Populated by the BFS fetch phase; consumed by the solver and graph builder.
    """

    name: str
    version: Version
    identity: str | None        # sha256:<hex>; None for root/__root__/root-self (§14.5) only
    src_dir: str
    dep_terms: list[Term]       # solver terms for this dep's declared requires
    requires_names: list[str]   # dep names (parallel to dep_terms, for graph)
    # typed; None only for __root__
    provenance: (
        Provenance | _LocalDepProvenance | MemberProvenanceRecord
        | RootProvenanceRecord | None
    ) = None
    # D-lifecycle: declared mirror URLs (manifest mirrors + prior declared) that
    # were NOT the observed candidate. Stored by _process_url_worker so
    # _build_graph can assemble observed + declared ProvenanceRecords.
    # Empty for non-git deps (local, tarball, member) that have no mirrors.
    declared_mirror_urls: tuple[str, ...] = ()
    # S6: the dep_decl hash this candidate's edges were sourced from.
    # Populated from IndexVersion.dep_decl (S2) when DepDeclEdgeSource is used;
    # None for URL/tarball/local/member deps and named deps without a dep_decl pointer.
    dep_decl: str | None = None
    # S4: advisory predicate metadata from edgeset_to_terms (RFC §3.4.3 option a).
    # Maps dep-name → LIST of predicate-tuples, one per occurrence with non-empty
    # predicates (a dep in ≥2 when-branches yields ≥2 list entries).
    # Never consulted for selection/solving. Empty for root/synthetic candidates.
    requires_predicates: dict[str, list[tuple[Predicate, ...]]] = field(default_factory=dict)
    # R1-04: submodule SHA provenance map from the GitReceipt (H5).
    # Maps submodule POSIX path (relative to dep root) → 40-hex gitlink SHA.
    # Empty for non-git deps and git deps with no submodules.
    # Populated by _process_url_worker from receipt.submodule_shas so that
    # _build_graph can wire it into GitProvenanceRecord(submodule_shas=...).
    submodule_shas: dict[str, str] = field(default_factory=dict)
    # RFC per-entry-attestation.md P2: the index's EntryAttestation CLAIM,
    # carried unconditionally from IndexVersion.attestation for named
    # (registry-resolved) deps.  None for URL/tarball/local/member deps (no
    # index entry) and for named deps whose index entry had no attestation
    # record or one that collapsed to unattested at index-parse time.
    attestation: EntryAttestation | None = None
    # P3a (RFC per-entry-attestation.md §3): True iff this candidate was
    # materialised via the named-dep (registry) path — the entry-trust gate's
    # discriminator for "is this a registry-resolved dep at all", distinct
    # from ``attestation is None`` (which is also true for an unattested
    # registry dep). False for URL/tarball/local/member candidates.
    is_registry: bool = False
    # P3a: the entry's REAL index namespace (registry.py IndexVersion.namespace),
    # always populated for registry candidates — distinct from the manifest-
    # qualification-only namespace used for the lockfile record (a bare dep
    # declaration has no qualifier there, but still resolves through a real
    # namespaced index entry). Empty string for non-registry candidates.
    registry_namespace: str = ""
    # A4 (resolver-semantics RFC §3 Axis A (c)): True iff this candidate's
    # ``version`` is the sentinel purely because no declared version was
    # found (``declared_version_for(ctx) is None``) — NOT a value-equality
    # check against the sentinel, since a real declared version could
    # coincidentally equal it. Drives the decision-priority + hard-error
    # partition via ``_Provider.is_version_unknown``. Always False for the
    # root and named/index candidates (always a real version) and,
    # deliberately, for workspace members too: a member's own solver term is
    # unconditionally ``full()`` (A2c), so no real PubGrub constraint can
    # ever reach it — applying the last-scheduling rule to members would
    # only reorder when their transitive deps are discovered, with no
    # hard-error path to gain, so A4 scopes the mechanism to the git/url/
    # local/tarball candidates it actually protects.
    version_unknown: bool = False
    # A5 (resolver-semantics RFC §3 Axis A (b) / §5): the sibling field to
    # ``version`` — WHICH precedence step produced it (manifest/nimble/tag/
    # annotation), or ``None`` for a version-unknown candidate (``declared_
    # version_for(ctx) is None``).  Never merged into ``version`` itself (two
    # sibling fields, not a sum type — identity ⊥ provenance discipline
    # applied to version ⊥ source).  Populated at the same 4 call sites as
    # ``version_unknown`` (the 3 fetch workers + the member-candidate
    # builder); always ``None`` for root/named candidates, which never call
    # ``declared_version_for``/``_candidate_label``/``_member_candidate_version``.
    declared_version_source: VersionSource | None = None


# ---------------------------------------------------------------------------
# Provider — PackageProvider backed by the candidate set
# ---------------------------------------------------------------------------


class _Provider:
    """``PackageProvider`` protocol backed by two-phase candidate population.

    Phase A (enumeration): named deps are registered as lightweight stubs
    (``_NamedStub``) — all versions from the index, no fetch.

    Phase B (materialisation): when the solver calls ``dependencies()`` for a
    stub, the stub is fetched and nimble-parsed inline; transitive named deps
    discovered during materialisation are immediately enrolled as stubs.
    """

    def __init__(
        self,
        env: MilpaEnv,
        deps_dir: Path,
        params: ResolveParams,
        overrides_by_name: dict[str, Override],
        root_direct_keys: set[DepKey],
        seen_named: set[DepKey],
        seen_url: set[tuple[str, str, str | None]],
        binding_resolver: "BindingResolver",
        edge_cache: dict[tuple[SourceId, Version], EdgeSet] | None = None,
        strict_attestation: bool = False,
        root_self_name: "str | None" = None,
    ) -> None:
        # S5-rekey (RFC origin-as-identity §4.4) + §14 "root satisfies its
        # own name": the resolving root's own manifest name, threaded to
        # ``_materialize`` so a materialized named stub's OWN transitive
        # requirement on the root's own name resolves correctly via
        # ``binding.canonical_key_for_requirement``. ``None`` for
        # ``resolve_workspace`` (§14 is a standalone-resolve-only concept).
        self._root_self_name = root_self_name
        # name → {version → _Candidate}
        self._candidates: dict[str, dict[Version, _Candidate]] = {}
        # name → {version → _NamedStub}
        self._stubs: dict[str, dict[Version, _NamedStub]] = {}

        # Injected seams
        self._env = env
        self._deps_dir = deps_dir
        self._params = params
        self._overrides_by_name = overrides_by_name
        # RFC origin-as-identity §4.5 (S4): the SAME BindingResolver instance
        # resolve()/resolve_workspace() constructed — the single source of
        # truth for "what source_id is this name bound to," reused by
        # _materialize (edge_cache key) rather than re-derived.
        self._binding_resolver = binding_resolver

        # S3 (RFC #23 §3.1.2 + §7 S3): consumer-side flag requests for named deps.
        # name → tuple[FlagRequest, ...]; populated from the root manifest's
        # NamedDep.flag_requests at queue-seeding time (step 5 in resolve()).
        # Used by _materialize to seed ctx.active_flags for the dep's edge resolve.
        self._flag_requests_by_name: dict[str, tuple[FlagRequest, ...]] = {}

        # Shared dedup sets (owned by resolve(), borrowed here for callbacks)
        #
        # NOTE: ``root_authority`` (a bare-name ``set[str]``) is deliberately
        # NOT a constructor param here (RFC origin-as-identity §6 "Kept" —
        # post-S3b cleanup): its sole surviving consumer is the module-level
        # ``_version_unknown_constrained_err``, which ``resolve()``/
        # ``resolve_workspace()`` call directly with their own copy of the
        # set. The former second consumer — the deleted ``provenance_gate``/
        # ``_check_provenance_gate`` side-table this class used to carry —
        # is gone; ``BindingResolver`` (``binding.py``) is now the sole
        # admission authority. Its bare-name (not ``DepKey``) scoping is the
        # open #192/R6 namespace door, out of scope here.
        # R6: namespace-aware authority set, used ONLY by is_root_direct (the
        # C2/C3 lowest-direct precompute + bypass scoping).
        self._root_direct_keys = root_direct_keys
        self._seen_named = seen_named
        self._seen_url = seen_url

        # Resolver-scoped edge memo (§4.2.1 resolve_edges, clause a).
        # Owned by resolve() and shared here so _materialize can seal it.
        self._edge_cache: dict[tuple[SourceId, Version], EdgeSet] = (
            edge_cache if edge_cache is not None else {}
        )
        # Shared edge source singletons (one per resolve() call).
        self._nimble_source: NimbleEdgeSource = NimbleEdgeSource()
        self._milpakdl_source: MilpaKdlEdgeSource = MilpaKdlEdgeSource()
        # S3b: DepDeclEdgeSource; None if no dep_decl_store is configured.
        self._dep_decl_source: DepDeclEdgeSource | None = (
            DepDeclEdgeSource(env.dep_decl_store) if env.dep_decl_store is not None else None
        )
        # S5: strict attestation policy (OR of manifest + flag).
        self._strict_attestation: bool = strict_attestation

        # S3 (RFC #23 §3.1.2 + §7 S3): resolver-scoped dep_active_flags map.
        # Maps resolved dep identity → dict[flag_name, set[ActivationSource]].
        # Keyed by resolved identity after override application (§3.1.2 "Keying
        # (normative)") so alias folding and dedup work correctly in S4a.
        # Populated incrementally: named deps from _materialize; URL deps populated
        # from the resolver main thread after workers return (S3 single-hop scope).
        # Full fixpoint iteration (S4a) will expand this to multi-hop.
        self.dep_active_flags: dict[str, dict[str, set[ActivationSource]]] = {}

    def add(self, c: _Candidate) -> None:
        """Add a candidate unconditionally (for __root__ and pre-built deps)."""
        self._candidates.setdefault(c.name, {})[c.version] = c

    def register_named_stubs(self, dep_key: DepKey, stubs: list[_NamedStub]) -> None:
        """Phase A: register all satisfying IndexVersion stubs for ``dep_key``.

        The dict key is ``binding_resolver.canonical_for(dep_key)`` (RFC
        origin-as-identity §4.4, S5-rekey) — the BOUND source-id's canonical
        string, the same key the PubGrub solver uses as the package variable,
        so ``_stubs`` and ``_candidates`` are always in sync with the
        solver's view. Two different consumer labels bound to the SAME
        origin collapse to the SAME dict key here.
        """
        solver_var = self._binding_resolver.canonical_for(dep_key)
        stub_map = self._stubs.setdefault(solver_var, {})
        for stub in stubs:
            ver = stub.version
            # Don't revert a materialised candidate back to a stub.
            if ver in self._candidates.get(solver_var, {}):
                continue
            stub_map[ver] = stub

    def _materialize(self, stub: _NamedStub) -> _Candidate:
        """Phase B: fetch + parse the named dep for the selected version.

        ``solver_var`` is the solver-package-variable string
        (``binding_resolver.canonical_for(stub.dep_key)``, S5-rekey); used as
        the dict key in _candidates/_stubs.  ``bare_name`` is the plain
        package name used for file-system operations (dest path, EdgeSourceCtx.dep_name,
        nimble file lookup) — always stub.dep_key.name regardless of namespace.
        """
        solver_var = stub.name  # stub.canonical; same as stub.name property
        bare_name = stub.dep_key.name  # plain name for filesystem / EdgeSourceCtx
        iv = stub.index_version

        # Check identity gate (TNG-NO-IDENTITY).
        if not iv.content_hash:
            raise MilpaError(
                TNG_NO_IDENTITY,
                f"package {bare_name!r} version {iv.version!r} has no identity "
                f"(content_hash is absent) — cannot fetch",
                name=bare_name,
                version=iv.version,
            )

        # Phase B fetch: pick the first provenance from the index.
        prov_record = iv.provenances[0]  # preference-ordered, element 0 is canonical
        if isinstance(prov_record, GitIndexProvenance):
            prov: Provenance = GitProvenance(
                url=prov_record.url,
                ref=prov_record.ref,
                commit_sha=prov_record.commit_sha,
            )
        elif isinstance(prov_record, OciIndexProvenance):
            prov = OciProvenance(
                registry=prov_record.registry,
                repository=prov_record.repository,
                digest=prov_record.digest,
            )
        else:
            # Genuinely unknown index provenance type — an internal invariant
            # violation (registry.py's IndexProvenance union is closed to
            # GitIndexProvenance | OciIndexProvenance), not a user-facing
            # condition, so this is MILPA-INTERNAL rather than a TNG-* slug.
            raise MilpaError(
                MILPA_INTERNAL,
                f"package {bare_name!r}: unknown index provenance type "
                f"{type(prov_record).__name__!r} — this is an internal milpa bug; "
                f"please report it",
                name=bare_name,
            )

        # C1 (rfc-resolver-correctness.md): file-system destination uses the
        # canonical dep_dir_name form: bare deps at ``_deps/<name>``, qualified
        # deps at ``_deps/@<namespace>/<name>`` (Windows-safe, no ``::`` on disk).
        _dir_entry = dep_dir_name(bare_name, stub.dep_key.namespace)
        dest = self._deps_dir / _dir_entry
        # Ensure the parent @<ns>/ directory exists for qualified deps.
        dest.parent.mkdir(parents=True, exist_ok=True)
        result = self._env.fetcher.fetch(bare_name, prov, dest=dest)

        # Resolve the commit_sha from the receipt (may differ from index if
        # the index had a symbolic ref; the receipt reflects the actual commit).
        fetched_commit_sha: str | None = result.receipt.transport_fields().get(
            "commit_sha"
        )

        # Resolve edges via the coordinator (§4.2.1 resolve_edges, NORMATIVE).
        # ctx.dep_name = bare_name: used for .nimble file lookup (filesystem).
        # ctx.dep_decl comes from IndexVersion.dep_decl (S2 field — may be None
        # for old index entries).  ctx.is_overridden = False for named deps that
        # reach materialisation (overridden named deps are coerced to URL deps
        # before Phase A; they never become stubs).
        has_milpa_kdl = (result.path / "milpa.kdl").exists()
        # S3 (RFC #23 §3.1.2 + §7 S3): seed active_flags from positive flag
        # requests stored at queue-seeding time (step 5 in resolve()).
        _name_flag_reqs = self._flag_requests_by_name.get(solver_var, ())
        _requested_flags: frozenset[str] = frozenset(
            fr.name for fr in _name_flag_reqs if fr.enabled
        )
        ctx = EdgeSourceCtx(
            dep_path=result.path,
            dep_name=bare_name,  # bare name for filesystem (nimble file lookup)
            dep_decl=iv.dep_decl,  # S2 field; None when absent
            dep_decl_schema_version=iv.dep_decl_schema_version,  # S3b schema check
            is_overridden=False,   # overridden named → URL coercion before Phase A
            has_milpa_kdl=has_milpa_kdl,
            overrides_by_name=self._overrides_by_name,
            active_flags=_requested_flags,  # S3: consumer-requested flags
        )
        es = resolve_edges(
            solver_var,  # qualified solver variable (= bare name when namespace=None)
            stub.version,
            ctx,
            self._edge_cache,
            # RFC origin-as-identity §4.5 (S4): edge_cache keyed by (source_id,
            # version) — the origin BindingResolver already bound this solver
            # variable to, so two labels reaching the same registry coordinate
            # coalesce to one sealed EdgeSet.
            source_id=_source_id_for_edge_cache(self._binding_resolver, solver_var),
            nimble_source=self._nimble_source,
            milpakdl_source=self._milpakdl_source,
            dep_decl_source=self._dep_decl_source,  # S3b: wired from MilpaEnv.dep_decl_store
            strict_attestation=self._strict_attestation,  # S5: policy-gated FETCH-FAILED fallback
        )
        dep_terms, requires_names, requires_predicates = edgeset_to_terms(
            es, self._overrides_by_name, self._env.index, self._root_self_name, self._binding_resolver
        )
        src_dir = es.src_dir

        # S6: record the dep_decl hash in the candidate when edges came from DepDecl.
        # EdgeSet.source == DEP_DECL iff DepDeclEdgeSource fired; only then is
        # iv.dep_decl meaningful as a lockfile pin (§3.7).
        from milpa.dep_decl import EdgeSource as _EdgeSource
        _dep_decl_pin: str | None = (
            iv.dep_decl if es.source == _EdgeSource.DEP_DECL else None
        )

        candidate = _Candidate(
            name=solver_var,  # qualified solver variable — matches _candidates dict key
            version=stub.version,
            identity=result.identity,
            src_dir=src_dir,
            dep_terms=dep_terms,
            requires_names=requires_names,
            # For git, prefer the receipt's observed commit_sha (the index may
            # have carried a symbolic ref) — this is the only "fetched update"
            # a named dep's provenance ever needs. For OCI the digest IS the
            # immutable identity (no ref-to-commit resolution step exists), so
            # `prov` (already built above) is used as-is.
            provenance=(
                GitProvenance(
                    url=prov_record.url,
                    ref=prov_record.ref,
                    commit_sha=fetched_commit_sha or prov_record.commit_sha,
                )
                if isinstance(prov_record, GitIndexProvenance)
                else prov
            ),
            dep_decl=_dep_decl_pin,
            requires_predicates=requires_predicates,
            # RFC per-entry-attestation.md P2: carried straight through from the
            # index — already None when absent or collapsed (registry.py's
            # conservative-collapse rule), so no re-derivation needed here.
            attestation=iv.attestation,
            # P3a: this candidate came from the named-dep (registry) path.
            is_registry=True,
            registry_namespace=iv.namespace,
        )

        # S3: compute and store dep_active_flags for this named dep.
        # The dep's manifest flags are available from the fetched tree.
        # Identity key: iv.content_hash (resolved identity after override
        # application — §3.1.2 "Keying (normative)").
        if iv.content_hash and result.path is not None:
            dep_manifest_flags: tuple[FlagDecl, ...] = ()
            _kdl_path = result.path / "milpa.kdl"
            if _kdl_path.exists():
                try:
                    from milpa.manifest import parse_manifest as _pm
                    _dep_m = _pm(_kdl_path.read_text(encoding="utf-8"))
                    dep_manifest_flags = _dep_m.flags
                except Exception:
                    pass  # non-fatal; flags remain empty
            _flag_reqs = self._flag_requests_by_name.get(solver_var, ())
            _active_entry = compute_dep_active_flags(dep_manifest_flags, _flag_reqs)
            if _active_entry:
                self.dep_active_flags[iv.content_hash] = _active_entry
            # S4c (RFC #23 §3.1.4): check for flag conflicts at materialisation time.
            # Named deps are materialised inside the PubGrub solver (via
            # `_Provider.dependencies_of`), AFTER `_s4c_check_flag_conflicts` runs.
            # The post-fixpoint S4c pass therefore never sees named dep candidates.
            # Closing this gap: check conflicts here, right after active_entry is
            # computed — same algorithm as `_s4c_check_flag_conflicts` / `_raise_if_flag_conflicts`.
            if _active_entry and dep_manifest_flags:
                _raise_if_flag_conflicts(bare_name, dep_manifest_flags, _active_entry)

        # Register and clear stub (both keyed by solver_var).
        self._candidates.setdefault(solver_var, {})[stub.version] = candidate
        self._stubs.get(solver_var, {}).pop(stub.version, None)

        # Enroll any newly-discovered transitive named deps. Extracted from
        # the EdgeSet's own NamedRequire entries (not dep_terms/solver_var
        # strings — S5-rekey, see _edgeset_named_requires) so the callback
        # receives the original (name, namespace) pair, never a lossy
        # reverse-decode of an already-canonicalized solver variable.
        if self._on_transitive_named is not None:
            for _dk_req, _vs in _edgeset_named_requires(es, self._overrides_by_name):
                self._on_transitive_named(_dk_req)

        return candidate

    # Callback wired by resolve() after initial BFS; fires during solve.
    _on_transitive_named: None = None  # will be set to Callable[[DepKey], None]

    def set_transitive_callback(
        self, on_named: object  # Callable[[DepKey], None]
    ) -> None:
        self._on_transitive_named = on_named  # type: ignore[assignment]

    # --- PackageProvider protocol ---

    def versions(self, package: str) -> list[Version]:
        """Return all known versions: materialised candidates + Phase A stubs."""
        known: set[Version] = set(self._candidates.get(package, {}).keys())
        known.update(self._stubs.get(package, {}).keys())
        return sorted(known)

    def dependencies(self, package: str, version: Version) -> list[Term]:
        """Return dep terms for (package, version); materialise if needed."""
        if version in self._candidates.get(package, {}):
            return list(self._candidates[package][version].dep_terms)
        stub = self._stubs.get(package, {}).get(version)
        if stub is not None:
            candidate = self._materialize(stub)
            return list(candidate.dep_terms)
        raise KeyError(f"no candidate for {package!r} @ {version}")

    def is_version_unknown(self, package: str) -> bool:
        """A4 (resolver-semantics RFC §3 Axis A (c)): True iff ``package``'s
        sole eager candidate has no declared version.

        All single-candidate kinds (git/url/local/tarball) that can go
        version-unknown are added to ``_candidates`` eagerly during the BFS
        phase, before the solver ever runs — so by the time
        ``milpa.solver.solve`` queries this, the eager candidate (if any) is
        already present. Named/index candidates always carry
        ``version_unknown=False`` (see that field's doc comment); an
        as-yet-unmaterialized stub correctly falls through to False too.
        """
        for c in self._candidates.get(package, {}).values():
            return c.version_unknown
        return False

    def is_root_direct(self, package: str) -> bool:
        """C2 (resolver-semantics RFC §3 Axis C, D-C2): True iff ``package``
        is a root-declared or override-named dep — used for the solver's
        ``LowestDirect`` effective-strategy precompute (and C3's bypass
        scoping), never for source-admission arbitration (that is
        ``BindingResolver``'s job, RFC origin-as-identity §4.3 — a separate
        concern, #193/#192).

        ``package`` is a PubGrub solver variable — RFC origin-as-identity
        §4.4: for a named/registry dep its string value is a BOUND source-id's
        canonical form, decoded back to a full ``DepKey`` (name AND namespace)
        via ``_depkey_for_solved_name`` — a direct read of the ``SolverKey``'s
        ``.display`` (DE1), with ``DepKey.from_solver_var`` for the
        identity==label (bare/``ns::name``) case — checked against
        ``root_direct_keys`` — a
        namespace-aware set (R6 fix). A bare-name-only check would wrongly
        match a namespace-qualified TRANSITIVE dep against an unrelated
        root dep that merely shares the same bare name under a DIFFERENT
        namespace (e.g. root ``ns1::foo`` must NOT make a purely-transitive
        ``ns2::foo`` look root-direct).
        """
        dk = _depkey_for_solved_name(package)
        return dk in self._root_direct_keys

    def _bypasses_lock_preference(self, package: str) -> bool:
        """C3/R9 (resolver-semantics RFC §3 Axis C, D-C2): whether B2's
        lock-preference is BYPASSED for ``package``.

        The bypass requires BOTH of:

        1. ``self._params.strategy_explicit`` — the effective strategy this
           resolve is running under was EXPLICITLY sourced (CLI
           ``--strategy`` or manifest ``resolution { strategy }``), never
           merely default-filled. R9 (§3 Axis C NORMATIVE: the lockfile-
           recorded strategy is "diagnostic/frozen-parity only, never a
           live input"): a bare resolve with no CLI flag and no manifest
           ``resolution`` block must NEVER bypass, even against a lock
           recorded under a non-default strategy — otherwise a bare
           ``milpa fetch`` on a ``minver``-recorded lock would compute
           effective=``maxver`` (the default), see it "diverge" from the
           lock, and newest-wins the WHOLE graph — a worse regression than
           the sticky-state bug this fixes. Stability of a bare re-resolve
           rides on B2's preference mechanism below, not on treating the
           lock's strategy as live governing state.
        2. **value-divergence**, never CLI flag *presence* alone:
           ``str(self._params.strategy) != self._params.prior.strategy``
           (the effective strategy versus the strategy string the
           committed lock was actually produced under). This is the
           load-bearing regression guard (#192): ``milpa fetch --strategy
           maxver`` on an already-maxver lock must be a NO-OP — a
           presence-gate ("was --strategy typed") would instead flip the
           whole graph to newest-wins even when the effective strategy
           equals the locked one.

        Scope is strategy-specific, per D-C2:
        - ``maxver``/``minver``/``semver`` diverging from the lock: bypass
          is WHOLE-GRAPH (every package).
        - ``lowest-direct`` diverging from the lock: bypass is
          ROOT-DIRECT-ONLY (``is_root_direct``) — transitives keep their
          lock preference, because a whole-graph bypass under
          ``lowest-direct`` would drag unrelated transitives forward
          (#192 again, through a different door).

        A pure function of (explicit-sourced?, effective strategy, locked
        strategy, directness) — assembled here as ``preference = None`` for
        the bypassed packages, never a concept the picker itself learns
        about (§4 stage 4: "bypass is not a picker parameter").
        """
        prior = self._params.prior
        if prior is None:
            return False
        if not self._params.strategy_explicit:
            return False
        if str(self._params.strategy) == prior.strategy:
            return False
        if self._params.strategy == Strategy.LOWEST_DIRECT:
            return self.is_root_direct(package)
        return True

    def preference(self, package: str) -> Version | None:
        """B2 (resolver-semantics RFC §4 stage 4): the prior lockfile's
        recorded version for ``package``, if one exists and parses.

        ``package`` is a PubGrub solver variable — RFC origin-as-identity
        §4.4: for a named dep its string value is a BOUND source-id's canonical
        form, decoded via ``_depkey_for_solved_name`` (the ``SolverKey``'s
        ``.display``, DE1; ``DepKey.from_solver_var`` for the identity==label
        case) so the lookup matches against
        ``LockedDep.name``/``LockedDep.namespace`` — never a raw ``::`` split
        or a canonical-string split. Returns
        ``None`` when there is no prior lock, the package is new (not in the
        prior lock), its recorded version string doesn't parse (never a hard
        error — a preference miss just falls through to ordinary strategy
        selection in ``_pick_version``), or C3's value-divergence bypass
        applies (``_bypasses_lock_preference``).
        """
        if self._params.prior is None:
            return None
        if self._bypasses_lock_preference(package):
            return None
        dk = _depkey_for_solved_name(package)
        locked = next(
            (
                d
                for d in self._params.prior.deps
                if d.name == dk.name and d.namespace == dk.namespace
            ),
            None,
        )
        if locked is None:
            return None
        if locked.identity is None:
            # B4 (RFC resolution-semantics.md §3 Axis B / D-B3): a
            # pin-stripped entry (``strip_dep_pin`` — the shared mechanism
            # both ``update <dep>`` and ``--upgrade <dep>`` delegate to)
            # carries no preference. This is the SAME "identity=None means
            # unpinned" convention ``_git_pin_for_url_dep`` already applies
            # for git-pin reuse, extended uniformly here so a NAMED/index
            # dep (the only kind where this distinction is observable —
            # git/url/local/tarball deps have exactly one solver-visible
            # candidate regardless, per the RFC's own B2 dependency note)
            # actually opts out of the minimal-change preference when its
            # pin is stripped, instead of silently keeping its old version.
            return None
        return parse_version(locked.version)

    def get(self, name: str, version: Version) -> _Candidate:
        """Retrieve a candidate (materialising a stub if needed)."""
        if name in self._candidates and version in self._candidates[name]:
            return self._candidates[name][version]
        stub = self._stubs.get(name, {}).get(version)
        if stub is not None:
            return self._materialize(stub)
        raise KeyError(f"no candidate for {name!r} @ {version}")


@dataclass
class _NamedStub:
    """Phase A stub — lightweight placeholder before fetch.

    ``dep_key`` carries the qualified identity (namespace + bare name).
    ``canonical`` is ``binding_resolver.canonical_for(dep_key)`` (RFC
    origin-as-identity §4.4, S5-rekey) — computed ONCE at construction time
    (``_enumerate_named_stubs`` has the resolver's ``binding_resolver`` on
    hand via ``provider``), since a bare dataclass property has no seam to
    reach ``BindingResolver`` itself (it needs the BOUND source-id, which
    only ``BindingResolver`` holds).  ``name`` is kept as the property every
    existing call site reads — it now returns ``canonical`` rather than
    ``dep_key.solver_var()``.
    """

    dep_key: DepKey
    version: Version
    index_version: IndexVersion
    canonical: str

    @property
    def name(self) -> str:
        """Solver-variable string: the bound source-id's canonical form."""
        return self.canonical


# ---------------------------------------------------------------------------
# Predicate filtering (resolver-semantics §6, slice 9b-2)
# ---------------------------------------------------------------------------


def _compute_cli_active_seed(
    flags: "tuple[FlagDecl, ...]",
    features: frozenset[str],
    no_default_features: bool,
    all_features: bool,
) -> frozenset[str]:
    """Compute the active-flag seed from CLI feature inputs (S9 SSOT).

    Single source of truth for both single-package and workspace CLI feature
    validation + seed computation.  Takes only what it needs — the ``flags``
    sequence — not a full manifest or workspace-manifest object.

    Applies the three CLI feature-selection inputs (RFC #23 §3.4):

    - ``all_features=True``: seed = all declared flag names.
    - ``no_default_features=True``: seed = ``features`` only (no defaults).
    - Neither: seed = default-true flags ∪ ``features``.

    ``features`` naming a flag not in ``flags`` raises
    ``MilpaError(FROZEN_ACTIVE_FLAGS_MISMATCH, ...)`` — surface-don't-hide
    (spec §3.4: "a --features naming a flag the root doesn't declare → error").

    Returns the raw seed BEFORE enables-closure; caller applies
    ``flag_enables_closure`` over this seed.

    **Callers are responsible for the "no CLI features active" guard**
    (i.e. checking ``bool(features) or no_default_features or all_features``
    before calling).  This function always returns a ``frozenset`` — it does
    NOT return ``None`` for the passthrough case.
    """
    from milpa.errors import FROZEN_ACTIVE_FLAGS_MISMATCH, MilpaError as _MilpaError

    declared_names: frozenset[str] = frozenset(fd.name for fd in flags)

    # Validate: --features names must be declared in the flags block.
    unknown = features - declared_names
    if unknown:
        raise _MilpaError(
            FROZEN_ACTIVE_FLAGS_MISMATCH,
            f"--features names flags not declared in the manifest flags block: "
            f"{sorted(unknown)} — add them to the 'flags' block or remove them",
            unknown=sorted(unknown),
        )

    if all_features:
        # All declared flags active.
        return declared_names

    if no_default_features:
        # No defaults; only explicit --features additions.
        return features

    # Default: default-true flags ∪ --features.
    default_seed: frozenset[str] = frozenset(fd.name for fd in flags if fd.default)
    return default_seed | features


def _resolve_effective_strategy(
    cli_strategy: Strategy | None,
    manifest: "Manifest | object",
) -> Strategy | None:
    """C3 (resolution-semantics RFC §3 Axis C / D-C2): resolve the
    EXPLICITLY-DECLARED strategy for one verb's resolve, walking the
    precedence chain ONCE:

    1. explicit CLI ``--strategy`` (``cli_strategy is not None``);
    2. else the manifest's ``resolution { strategy }`` (``manifest`` is
       either a single-package ``Manifest`` or a workspace-root
       ``WorkspaceManifest`` — both carry a ``.resolution`` field; accessed
       via ``getattr`` so either type works here without an isinstance
       branch);
    3. else ``None`` — neither source declared a strategy.

    RR1 (duplicate-precedence-walk cleanup): this used to be a PAIR of
    near-identical functions — ``_resolve_effective_strategy`` (returning
    a default-filled ``Strategy``) and a sibling ``_is_strategy_explicit``
    (returning whether it was explicit) — that walked this SAME precedence
    chain twice per call site (~12 sites in ``cli.py`` alone). Collapsed
    into a single walk: every call site now derives BOTH facts from this
    one ``Strategy | None`` result::

        decl = _resolve_effective_strategy(cli_strategy, manifest)
        strategy_explicit = decl is not None
        strategy = decl if decl is not None else Strategy.MAXVER

    R9 (resolution-semantics RFC §3 Axis C NORMATIVE text: "the lockfile-
    recorded strategy is diagnostic/frozen-parity only, never a live
    input"): there used to be a third tier here that fell back to
    ``prior.strategy`` before the global default. That made a one-off
    ``--strategy X`` invisibly and permanently govern every future bare
    resolve (hidden sticky state), and made the lockfile a live resolution
    input rather than a pure diagnostic record — contradicting the RFC
    text above. That tier is gone; ``manifest`` is the only thing this
    function ever reads besides the CLI arg.

    Stability of a bare re-resolve against a lock recorded under a
    non-default strategy is preserved a DIFFERENT way — via B2's
    lock-preference mechanism (``_Provider.preference``), not by treating
    the lockfile's strategy as a governing tier here. See
    ``_bypasses_lock_preference`` for how: the bypass that would otherwise
    drop B2's preference and newest-wins the whole graph only fires when
    the strategy declared here is not ``None`` AND diverges from the
    lock's recorded value — never when it is merely default-filled.

    Lives here (not in ``cli.py``) so it is the SINGLE SOURCE OF TRUTH for
    strategy precedence usable by BOTH the CLI layer (every
    resolve-triggering verb) and the frozen path (C3b, ``frozen.py``'s
    ``FROZEN-STRATEGY-MISMATCH`` baseline) — which calls this with the
    same two-arg signature (there is no CLI ``--strategy`` in the frozen
    path, so it collapses to tier 2 only, then default-fills to MAXVER
    itself since the baseline has no ``strategy_explicit`` need).
    """
    if cli_strategy is not None:
        return cli_strategy
    resolution = getattr(manifest, "resolution", None)
    if resolution is not None and resolution.strategy is not None:
        return resolution.strategy
    return None


def _resolve_effective_exclude_newer(
    cli_exclude_newer: "datetime | None",
    manifest: "Manifest | object",
    prior: "Lockfile | None" = None,
) -> "datetime | None":
    """D2/D5 (resolution-semantics RFC §3 Axis D): resolve the EFFECTIVE
    exclude-newer time-bound for one verb's resolve, in precedence order:

    1. explicit CLI ``--exclude-newer`` (``cli_exclude_newer is not None``);
    2. else the manifest's ``resolution { exclude-newer }`` (``manifest`` is
       either a single-package ``Manifest`` or a workspace-root
       ``WorkspaceManifest`` — both carry a ``.resolution`` field; accessed
       via ``getattr`` so either type works here without an isinstance
       branch, mirroring ``_resolve_effective_strategy``);
    3. else ``prior.exclude_newer`` when a prior lockfile was passed;
    4. else ``None`` (no time bound).

    **Callers choose whether tier 3 is live, by what they pass for
    ``prior``** — this is the load-bearing design point, not an oversight:

    - ``fetch``/``lock`` (the only verbs with a CLI ``--exclude-newer``
      surface, §3 Axis D "Verb reach") call this with ``prior=None``,
      collapsing to the ORIGINAL 2-tier chain (CLI > manifest > ``None``).
      An absent CLI flag + absent manifest declaration is therefore a
      genuine "nothing declared this run" result for these verbs — which is
      exactly what makes ``--locked``'s no-silent-drop check meaningful
      (D5, §6 D-D3): comparing THIS honest 2-tier value against the
      committed lock's recorded value is how a real drop gets caught.
    - ``add``/``update``/``remove``/workspace add-member/remove-member have
      NO CLI override at all, so they call this with the REAL on-disk prior
      lockfile — tier 3 then CARRIES FORWARD a bound that was set only via
      a one-off ``fetch --exclude-newer`` and never mirrored into the
      manifest, rather than silently dropping it (D5, §6 D-D3 no-silent-drop
      — the exact scenario the RFC's own text calls out for these verbs).

    ``prior`` here (when passed) must be the ACTUAL on-disk lockfile, never
    the resolve-scoped ``prior`` that ``update``/``--upgrade`` null out or
    strip for B2's minimal-change preference.

    NOTE (R9): ``_resolve_effective_strategy`` no longer has an analogous
    tier 3 at all — the lockfile-recorded ``strategy`` is diagnostic/
    frozen-parity only, never a live input (unlike ``exclude_newer``,
    which legitimately keeps its own D5 no-silent-drop lockfile-fallback
    tier here, by design, for the verbs that call this with a real
    ``prior``). The two functions' precedence chains are NOT symmetric
    post-R9 — this asymmetry is intentional, not a residual inconsistency.
    """
    if cli_exclude_newer is not None:
        return cli_exclude_newer
    resolution = getattr(manifest, "resolution", None)
    if resolution is not None and resolution.exclude_newer is not None:
        return resolution.exclude_newer
    if prior is not None and prior.exclude_newer is not None:
        return prior.exclude_newer
    return None


def _compute_root_active_seed(
    manifest: Manifest,
    features: frozenset[str],
    no_default_features: bool,
    all_features: bool,
) -> frozenset[str]:
    """Thin wrapper for backward-compat: delegates to ``_compute_cli_active_seed``.

    Single-package call site — passes ``manifest.flags`` to the SSOT.
    """
    return _compute_cli_active_seed(
        manifest.flags,
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )


def _compute_workspace_cli_seed(
    workspace_manifest: object,  # WorkspaceManifest — typed at runtime
    features: frozenset[str],
    no_default_features: bool,
    all_features: bool,
) -> frozenset[str] | None:
    """Thin wrapper for backward-compat: delegates to ``_compute_cli_active_seed``.

    Workspace call site — passes ``workspace_manifest.flags`` to the SSOT.
    Returns ``None`` when no CLI feature selection is active (passthrough
    semantics for the workspace flag gate).
    """
    has_cli_features = bool(features) or no_default_features or all_features
    if not has_cli_features:
        return None
    return _compute_cli_active_seed(
        workspace_manifest.flags,  # type: ignore[attr-defined]
        features=features,
        no_default_features=no_default_features,
        all_features=all_features,
    )


# ---------------------------------------------------------------------------
# Manifest filtering — FilterContext + filter_manifest (resolver-semantics §3.A)
#
# The three-row dispatch is encoded as TWO INDEPENDENT PREDICATES in FilterContext:
#
#   profile present              → profile gate evaluates platform/arch/nim/milpa
#   active_flags nonempty        → flag gate evaluates flag predicates
#   profile absent + flags empty → passthrough (both gates are no-ops)
#
# The two predicates are INDEPENDENT (Depth-F7):
#   - Profile gate evaluates ONLY platform/arch/nim/milpa predicates; it
#     SKIPS pred.name == "flag" (returns True for flag preds, leaving them to
#     the flag gate).  This prevents double-evaluation and ensures a single
#     owner for each predicate kind.
#   - Flag gate evaluates ONLY flag predicates via dep_passes_flag_predicates.
#
# Construction discipline (Design-F1):
#   Always build FilterContext via FilterContext.build(manifest, profile, *,
#   cli_seed), which runs flag_enables_closure against the *passed manifest's*
#   flags block.  At a workspace member site the passed manifest is the member's
#   manifest — not the root's — so the closure uses the right flags block.
#   Raw FilterContext(profile, active_flags) is public for Rust symmetry and
#   unit tests; all production call-sites use build().
#
# resolver-semantics §470 NORMATIVE: absent profile disables platform/arch/nim/
# milpa-predicate filtering entirely.  Do NOT synthesise a Profile{platform=None}
# and call filter_manifest — that would violate §470 via _predicate_satisfied_profile_only
# returning False for absent axes (silent prune instead of pass).
# ---------------------------------------------------------------------------


def _manifest_flag_seed(manifest: Manifest) -> frozenset[str]:
    """Default flag seed: names of default-true flags in *manifest*.

    SSOT for the "no CLI seed → use manifest defaults" path.  Called by
    FilterContext.build when cli_seed is None.
    """
    return frozenset(fd.name for fd in manifest.flags if fd.default)


@dataclass(frozen=True)
class FilterContext:
    """Value type encoding both independent filter predicates (resolver-semantics §3.A).

    Fields
    ------
    profile:
        ``None`` ⟺ platform/arch/nim/milpa-predicate filtering disabled (§470).
    active_flags:
        Already-closed flag set.  Empty ⟺ no flag filtering (passthrough for
        flag predicates).

    Construction
    ------------
    Always use ``FilterContext.build(manifest, profile, *, cli_seed)`` in
    production code.  The raw constructor is public for Rust symmetry and for
    unit tests that need an exact active_flags value.
    """

    profile: Profile | None
    active_flags: frozenset[str]

    @classmethod
    def build(
        cls,
        manifest: Manifest,
        profile: Profile | None,
        *,
        cli_seed: frozenset[str] | None,
    ) -> "FilterContext":
        """Smart constructor — computes the flag closure from *manifest's* flags.

        Design-F1: the closure runs against ``manifest.flags`` (the manifest
        being filtered), NOT any root manifest's flags.  At a workspace member
        site the caller passes the member's manifest; the member's flags block
        determines which flags are declared and what enables-chains fire.

        Parameters
        ----------
        manifest:
            The manifest that will be passed to ``filter_manifest``.
        profile:
            Active platform profile, or ``None`` to disable platform filtering.
        cli_seed:
            Explicit CLI-selected flag seed (pre-validated; ``None`` ⟺ use
            manifest's default-true flags as seed).
        """
        seed = cli_seed if cli_seed is not None else _manifest_flag_seed(manifest)
        active = flag_enables_closure(manifest.flags, seed) if seed else frozenset()
        return cls(profile=profile, active_flags=active)


def filter_manifest(manifest: Manifest, ctx: FilterContext) -> Manifest:
    """Return a ``Manifest`` with deps filtered by the two independent predicates.

    Applies two INDEPENDENT predicates (resolver-semantics §3.A):

    1. **Profile gate** (iff ``ctx.profile is not None``): keep deps whose
       non-flag predicates match ``ctx.profile``.  Flag predicates are owned
       exclusively by the flag gate and are SKIPPED here (Depth-F7).

    2. **Flag gate**: keep deps whose flag predicates are satisfied by
       ``ctx.active_flags``.  Runs when either (a) profile is present — the
       old Row-1 path always evaluated flag predicates — or (b) active_flags
       is nonempty (the flag-only Row-2 path).  When both profile and
       active_flags are absent, the flag gate is a no-op (Row-3 passthrough).

    **Passthrough condition**: ``ctx.profile is None`` AND
    ``ctx.active_flags`` is empty → every dep is retained (§470 / §489
    NORMATIVE).  This corresponds to "profile absent + no feature selection"
    in the original three-row dispatch.

    When both gates are active, a dep must pass BOTH (conjunction).

    Parameters
    ----------
    manifest:
        The manifest to filter (deps + dev_deps).  Not mutated.
    ctx:
        Pre-built filter context (use ``FilterContext.build`` in production).

    Returns
    -------
    The same ``manifest`` object when no filtering changes anything, or a
    new ``Manifest`` with the filtered ``deps`` / ``dev_deps`` tuples.
    """
    from dataclasses import replace as _dc_replace

    # Fast path: neither gate is active → return unchanged.
    if ctx.profile is None and not ctx.active_flags:
        return manifest

    def _dep_passes(dep: Dep) -> bool:
        preds: tuple[Predicate, ...] = dep.predicates

        # --- Profile gate (platform/arch/nim/milpa predicates only) ---
        if ctx.profile is not None:
            for pred in preds:
                if pred.name == "flag":
                    # Depth-F7: flag predicates owned by flag gate; skip here.
                    continue
                if not _predicate_satisfied_profile_only(pred, ctx.profile):
                    return False

        # --- Flag gate (flag predicates) ---
        # Reached only when profile is not None OR active_flags nonempty (fast path above).
        if not dep_passes_flag_predicates(preds, ctx.active_flags):
            return False

        return True

    kept = tuple(d for d in manifest.deps if _dep_passes(d))
    kept_dev = tuple(d for d in manifest.dev_deps if _dep_passes(d))
    if len(kept) == len(manifest.deps) and len(kept_dev) == len(manifest.dev_deps):
        return manifest
    return _dc_replace(manifest, deps=kept, dev_deps=kept_dev)


def _predicate_satisfied_profile_only(
    pred: Predicate,
    profile: Profile,
) -> bool:
    """Evaluate a single NON-FLAG predicate against ``profile``.

    Called exclusively from the profile gate in ``filter_manifest``.
    Callers MUST NOT pass flag predicates here (Depth-F7: flag gate owns them).

    OR semantics within a predicate's values (§6 NORMATIVE).
    Negation inverts the OR result.
    """
    actual: str | None = getattr(profile, pred.name, None)
    if actual is None:
        return False

    any_match = any(_value_matches(pred.name, actual, v) for v in pred.values)
    return (not any_match) if pred.negated else any_match


def _value_matches(predicate_name: str, actual: str, declared: str) -> bool:
    """Match a single predicate value.

    For ``nim``/``milpa`` predicates: a value starting with a comparison
    operator is treated as a version constraint (§6 NORMATIVE).
    Plain values are matched by equality.
    """
    if predicate_name in ("nim", "milpa") and _looks_like_constraint(declared):
        return _version_satisfies(actual, declared)
    return actual == declared


def _looks_like_constraint(s: str) -> bool:
    return s.startswith((">=", "<=", ">", "<", "==", "!=", "~", "^"))


def _version_satisfies(actual: str, constraint: str) -> bool:
    """Check ``actual`` (semver string) against a constraint expression."""
    parts = actual.split(".")
    digits = [int(x) for x in parts[:3]]
    while len(digits) < 3:
        digits.append(0)
    triple = Version(digits[0], digits[1], digits[2])
    try:
        vs = VersionSet.from_constraint(_normalize_constraint(constraint))
    except Exception:
        return False
    return vs.contains(triple)


def _normalize_constraint(s: str) -> str:
    """Insert space after operator; expand short version triples."""
    s = re.sub(r"^(>=|<=|==|!=|>|<|~|\^)\s*", r"\1 ", s)

    def expand(m: re.Match[str]) -> str:
        digits = [int(x) for x in m.group(0).split(".")]
        while len(digits) < 3:
            digits.append(0)
        return ".".join(str(x) for x in digits)

    return re.sub(r"\d+(?:\.\d+){0,2}", expand, s)


# ---------------------------------------------------------------------------
# Prior-lockfile pin helpers (resolver-semantics §8)
# ---------------------------------------------------------------------------


def _git_pin_for_url_dep(
    dep: UrlDep,
    prior: Lockfile | None,
) -> tuple[str, str | None] | None:
    """Return ``(identity, commit_sha)`` from the prior lockfile iff the
    manifest's ``(git, ref)`` still matches a locked ``GitProvenanceRecord``.
    Returns ``None`` when no prior, no matching entry, or provenance changed.

    Searches ALL GitProvenanceRecords (not just the first) so that a declared
    mirror record appearing before the observed record in the sorted provenances
    list does not shadow the observed record (§8 pin-reuse, D-provenance ordering).
    """
    if prior is None:
        return None
    locked = next((d for d in prior.deps if d.name == dep.name), None)
    if locked is None or not locked.identity:
        return None
    for p in locked.provenances:
        if isinstance(p, GitProvenanceRecord) and p.url == dep.git and p.ref == dep.ref:
            return (locked.identity, p.commit_sha)
    return None


def _tarball_pin(
    dep: TarballDep,
    prior: Lockfile | None,
) -> tuple[str | None, str | None] | None:
    """Return ``(identity, archive_sha256)`` from the prior lockfile iff the
    manifest's tarball URL matches.  Returns ``None`` when no match.
    """
    if prior is None:
        return None
    locked = next((d for d in prior.deps if d.name == dep.name), None)
    if locked is None or not locked.identity:
        return None
    for p in locked.provenances:
        if isinstance(p, TarballProvenanceRecord) and p.url == dep.url:
            return (locked.identity, p.sha256)
    return None


def _prior_declared_mirror_urls(name: str, prior: Lockfile | None) -> tuple[str, ...]:
    """Return declared-mirror URLs from the prior lockfile for ``name``.

    D-provenance: self_mirrors removed from LockedDep. Declared mirrors are now
    stored as GitProvenanceRecord(origin="declared") entries in the provenances
    list. This function extracts those URLs for fallback fetch ordering (§8a).
    """
    from milpa.lockfile import GitProvenanceRecord as _GPR  # noqa: PLC0415
    if prior is None:
        return ()
    locked = next((d for d in prior.deps if d.name == name), None)
    if locked is None:
        return ()
    return tuple(
        p.url
        for p in locked.provenances
        if isinstance(p, _GPR) and p.origin == "declared"
    )


# ---------------------------------------------------------------------------
# Transitive dep extraction from a fetched tree
# ---------------------------------------------------------------------------


def _find_nimble_file(dep_path: Path, name: str) -> Path:
    """Locate the ``.nimble`` file for dep ``name`` under ``dep_path``."""
    # Try canonical location: <dep_path>/<name>.nimble
    candidate = dep_path / f"{name}.nimble"
    if candidate.is_file():
        return candidate
    # Fallback: any .nimble file in the root
    matches = list(dep_path.glob("*.nimble"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        # Prefer the one whose stem matches the dep name.
        named = [m for m in matches if m.stem == name]
        if named:
            return named[0]
        return matches[0]
    raise FileNotFoundError(f"no .nimble file found under {dep_path}")


@dataclass(frozen=True)
class _OciOverrideDep:
    """Internal-only carrier for an ``OciTarget`` override's effective dep
    (S8b, rfc-origin-as-identity.md §7 B5).

    There is deliberately NO first-class ``oci=`` dep-declaration grammar in
    ``manifest.py``'s ``Dep`` union (see ``test_oci_registry_consumer.py``'s
    "NOT the manifest oci= dep form" note) — an OCI source is reachable ONLY
    via an override target. This dataclass is the BFS-internal analogue of
    ``LocalDep``/``TarballDep`` for that one path: a fixed
    (registry, repository, digest) triple IS the whole identity (no version
    enumeration, unlike the registry-index OCI path in ``_Provider._materialize``)
    — exactly one candidate, mirroring ``_process_local_worker``/
    ``_process_tarball_worker``.
    """

    name: str
    registry: str
    repository: str
    digest: str
    subpath: str | None = None
    version: Version | None = None


def _apply_git_override_to_url_dep(dep: UrlDep, ov: Override) -> UrlDep:
    """Apply a git-form override to a UrlDep, returning the overridden dep.

    S8 dispatch: GitTarget → rewrite URL.  Every OTHER target kind raises
    NotImplementedError — callers that accept a non-git override result MUST
    use ``_apply_override`` (which returns the correct ``Dep``-ish union
    member) and route to the matching BFS queue slot BEFORE ever reaching
    this function. This function is kept only for existing git-path callers
    that specifically want a ``UrlDep`` back.

    A3b/D-A3: the redirected dep's ``version`` is the OVERRIDE RULE's
    ``version=`` (``ov.version``), never the original ``dep.version`` — this
    function builds a brand-new ``UrlDep`` from the override target alone, so
    a stale annotation on the now-redirected original is structurally
    discarded, never read.
    """
    if isinstance(ov.target, GitTarget):
        return UrlDep(
            name=dep.name, git=ov.target.git, ref=ov.target.ref, version=ov.version,
            subpath=ov.target.subpath,
        )
    if isinstance(ov.target, LocalTarget):
        raise NotImplementedError(
            f"LocalTarget override for {dep.name!r} is not yet wired "
            "(S8a — resolver interception sites for local= targets)"
        )
    if isinstance(ov.target, MemberTarget):
        raise NotImplementedError(
            f"MemberTarget override for {dep.name!r} is not yet wired "
            "(S8b — resolver interception sites for member targets)"
        )
    if isinstance(ov.target, (OciTarget, TarballTarget, RegistryTarget)):
        raise NotImplementedError(
            f"{type(ov.target).__name__} override for {dep.name!r} must be "
            "pre-intercepted by the caller via _apply_override (S8b) — "
            "_apply_git_override_to_url_dep only ever returns a UrlDep"
        )
    raise NotImplementedError(f"Unknown override target kind: {type(ov.target)}")


def _apply_override(
    name: str, ov: Override
) -> "UrlDep | LocalDep | TarballDep | NamedDep | _OciOverrideDep":
    """Apply an override to a dep by name, returning the effective dep.

    S8a: GitTarget → UrlDep; LocalTarget → LocalDep.
    S8b: OciTarget → ``_OciOverrideDep``; TarballTarget → TarballDep;
    RegistryTarget → NamedDep. MemberTarget — callers must handle
    MemberTarget BEFORE calling this function (workspace BFS seed,
    _enqueue_dep, BFS wave loop); this function is never reached for it.

    The caller is responsible for routing the returned value to the matching
    BFS queue slot (``("url", …)`` / ``("local", …)`` / ``("tarball", …)`` /
    ``("named", …)`` / ``("oci", …)``).

    A3b/D-A3: ``version=ov.version`` — the override rule's own annotation,
    never the original dep's (discarded by construction; see
    ``_apply_git_override_to_url_dep``). For every kind EXCEPT
    ``RegistryTarget`` this is the A3b declared-version FALLBACK label
    (consulted only when the redirected tree carries no readable version).
    For ``RegistryTarget`` it means something different (RFC §7 B5,
    "version-scoped overrides"): the registry always carries real
    per-version data, so ``ov.version`` becomes an EXACT solver constraint
    (``== <version>``) on the redirected coordinate rather than a fallback
    label — see ``RegistryTarget``'s docstring.
    """
    if isinstance(ov.target, GitTarget):
        return UrlDep(
            name=name, git=ov.target.git, ref=ov.target.ref, version=ov.version,
            subpath=ov.target.subpath,
        )
    if isinstance(ov.target, LocalTarget):
        return LocalDep(name=name, path=ov.target.path, version=ov.version)
    if isinstance(ov.target, TarballTarget):
        return TarballDep(
            name=name,
            url=ov.target.url,
            sha256=ov.target.sha256,
            strip_components=ov.target.strip_components,
            version=ov.version,
            subpath=ov.target.subpath,
        )
    if isinstance(ov.target, OciTarget):
        return _OciOverrideDep(
            name=name,
            registry=ov.target.registry,
            repository=ov.target.repository,
            digest=ov.target.digest,
            subpath=ov.target.subpath,
            version=ov.version,
        )
    if isinstance(ov.target, RegistryTarget):
        # NOTE: the produced NamedDep's `.name` is the REGISTRY coordinate's
        # own name (ov.target.name — e.g. "widget"), NOT the overridden
        # dep's own name (`name` param, e.g. "old-fork"). This is the one
        # target kind where those two can genuinely differ (the whole point
        # of "redirect to a registry coordinate" is a possibly-different
        # name). The caller's root Term/solver-var still keys off the
        # ORIGINAL name (via binding_resolver.canonical_for(DepKey(name=name))
        # in _seed_extended_override_target) — that already-bound root claim
        # and this "named" BFS-arm enumeration coincide because BOTH resolve
        # to the SAME canonical(SourceId) (content-addressed), even though
        # they are two distinct BindingResolver claim keys internally.
        constraint = f"== {format_version_str(ov.version)}" if ov.version is not None else None
        return NamedDep(name=ov.target.name, constraint=constraint, namespace=ov.target.namespace)
    if isinstance(ov.target, MemberTarget):
        # Should not reach here — callers intercept MemberTarget before _apply_override.
        # If this fires, a new call-site was added without handling S8b.
        raise AssertionError(
            f"_apply_override reached MemberTarget for {name!r}; callers must "
            "intercept MemberTarget before calling _apply_override (S8b)"
        )
    raise NotImplementedError(f"Unknown override target kind: {type(ov.target)}")


def _extended_override_bfs_item(name: str, ov: Override) -> tuple:
    """The BFS queue tuple for a Tarball/Oci/Registry override target,
    with NO root ``Term``/discovery bookkeeping (S8b) — the transitive-
    enqueue counterpart of ``_seed_extended_override_target`` (root-only),
    used by ``_enqueue_dep`` (the shared transitive-sub-dep enqueue path).
    Caller must have already confirmed ``ov.target`` is one of these three
    kinds (Git/Local/Member are handled by the caller's own branches).
    """
    eff = _apply_override(name, ov)
    if isinstance(eff, TarballDep):
        return ("tarball", eff)
    if isinstance(eff, _OciOverrideDep):
        return ("oci", eff)
    assert isinstance(eff, NamedDep)
    return ("named", DepKey(name=eff.name, namespace=eff.namespace), eff.constraint)


def _seed_extended_override_target(
    name: str,
    ov: Override,
    *,
    binding_resolver: "BindingResolver",
    root_terms: list[Term],
    root_requires: list[str],
    bfs_queue: list[object],
    record_discovery: "Callable[[str], None]",
) -> bool:
    """S8b (rfc-origin-as-identity.md §7 B5): seed the BFS queue + root
    ``Term`` for a Tarball/Oci/Registry override target on a ROOT dep.

    Single source of truth for this one seeding pattern, reused at every
    root-dep loop (``resolve()``'s UrlDep/NamedDep branches,
    ``resolve_workspace()``'s per-member loop) — mirrors the existing
    LocalTarget/MemberTarget root-seeding branches already inline at each of
    those call sites, but factored out here (rather than copy-pasted a
    THIRD/FOURTH time) since there is no natural single BFS-queue-kind
    dispatch shared across three heterogeneous target kinds the way
    LocalTarget's single ``("local", …)`` slot is.

    Returns True iff ``ov.target`` is one of these three kinds and was fully
    handled (the caller should ``continue``); False for Git/Local/Member,
    which the caller's own pre-existing branches own.

    Version-scoped overrides (D-A3, RFC §7 B5): for a ``RegistryTarget``,
    ``ov.version`` (already folded into ``_apply_override``'s ``NamedDep``
    as an exact ``== <version>`` constraint) becomes the root Term's
    ``VersionSet`` — the solver only admits that one version. For Tarball/
    Oci (single-fixed-artifact kinds — exactly one candidate always exists),
    the term is ``full()`` regardless (Axis A (a)/D-A2 convention, matching
    every other git/local/tarball root dep); ``ov.version`` there is instead
    the A3b declared-version FALLBACK LABEL threaded through by
    ``_apply_override``, not a solver constraint.
    """
    if not isinstance(ov.target, (TarballTarget, OciTarget, RegistryTarget)):
        return False
    eff = _apply_override(name, ov)
    svar = binding_resolver.canonical_for(DepKey(name=name))
    if isinstance(eff, TarballDep):
        root_terms.append(Term.require(svar, VersionSet.full()))
        bfs_queue.append(("tarball", eff))
    elif isinstance(eff, _OciOverrideDep):
        root_terms.append(Term.require(svar, VersionSet.full()))
        bfs_queue.append(("oci", eff))
    else:
        assert isinstance(eff, NamedDep)
        vs = eff.constraint_set if eff.constraint_set is not None else VersionSet.full()
        root_terms.append(Term.require(svar, vs))
        bfs_queue.append(("named", DepKey(name=eff.name, namespace=eff.namespace), eff.constraint))
    root_requires.append(svar)
    record_discovery(svar)
    return True


def _dep_to_term(
    dep: Dep,
    overrides_by_name: dict[str, Override],
    binding_resolver: "BindingResolver",
) -> tuple[Term | None, str | None]:
    """Convert a dep to a solver Term + require name.

    Returns ``(None, None)`` for dep kinds that are not solver-visible
    (MemberDep — member resolution is a workspace concern, slice 9d).

    Axis A (a) (D-A2): a git/url/tarball/local dep's own term — and an
    overridden named dep's term (redirected to such a kind) — is always
    ``VersionSet.full()``, never ``eq(sentinel)``.  The candidate label
    (real declared version, when parseable) is assigned post-fetch;
    ``full()`` removes the pre-commitment so it never races the label.

    ``binding_resolver`` (RFC origin-as-identity §4.4, S5-rekey): the
    solver-variable string for a ``NamedDep`` is the BOUND source-id's
    canonical form, not the bare/qualified label — the caller must already
    have this dep's root claim bound (true for every current caller:
    ``_build_member_candidate``'s deps are included in the workspace's
    ``reconcile_root_claims`` set, bound before ``BindingResolver``
    construction completes).
    """
    if isinstance(dep, UrlDep):
        # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — no
        # eager-kind bare-name carve-out. Caller's root claim already bound.
        _svar_u = binding_resolver.canonical_for(DepKey(name=dep.name))
        # S8b: an override to RegistryTarget is the ONE kind where the term
        # is NOT full() — the registry carries real per-version data, so a
        # version-scoped override (ov.version set) becomes an exact
        # constraint here too (mirrors _seed_extended_override_target).
        # Every other override kind (Git/Local/Tarball/Oci) is a single-
        # fixed-candidate source — term is full() either way, override or not.
        if dep.name in overrides_by_name and isinstance(
            overrides_by_name[dep.name].target, RegistryTarget
        ):
            _eff_u = _apply_override(dep.name, overrides_by_name[dep.name])
            assert isinstance(_eff_u, NamedDep)
            _vs_u = _eff_u.constraint_set if _eff_u.constraint_set is not None else VersionSet.full()
            return (Term.require(_svar_u, _vs_u), _svar_u)
        return (Term.require(_svar_u, VersionSet.full()), _svar_u)

    if isinstance(dep, NamedDep):
        if dep.name == "nim":
            return (None, None)
        # S5b: populate DepKey.namespace from the manifest dep (None for unqualified deps).
        _dep_key = DepKey(name=dep.name, namespace=dep.namespace)
        svar = binding_resolver.canonical_for(_dep_key)
        vs = dep.constraint_set if dep.constraint_set is not None else VersionSet.full()
        # Check if this named dep is overridden (becomes a URL-like dep, full() term) —
        # UNLESS the override target is itself a RegistryTarget (S8b), in which
        # case the redirect's own (possibly version-scoped) constraint applies.
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            if isinstance(ov.target, RegistryTarget):
                _eff_n = _apply_override(dep.name, ov)
                assert isinstance(_eff_n, NamedDep)
                _vs_n = _eff_n.constraint_set if _eff_n.constraint_set is not None else VersionSet.full()
                return (Term.require(svar, _vs_n), svar)
            return (Term.require(svar, VersionSet.full()), svar)
        return (Term.require(svar, vs), svar)

    if isinstance(dep, TarballDep):
        _svar_tb = binding_resolver.canonical_for(DepKey(name=dep.name))
        return (Term.require(_svar_tb, VersionSet.full()), _svar_tb)

    if isinstance(dep, LocalDep):
        _svar_lo = binding_resolver.canonical_for(DepKey(name=dep.name))
        return (Term.require(_svar_lo, VersionSet.full()), _svar_lo)

    if isinstance(dep, MemberDep):
        # Member resolution is a workspace concern (slice 9d).
        return (None, None)

    return (None, None)


# ---------------------------------------------------------------------------
# Named dep enumeration (Phase A) — resolver-semantics §4.2.1
# ---------------------------------------------------------------------------


def _enumerate_named_stubs(
    dep_key: DepKey,
    constraint: VersionSet | None,
    index: Index,
    provider: _Provider,
    deps_dir: Path,
    env: MilpaEnv,
    exclude_newer: "datetime | None" = None,
) -> None:
    """Phase A: enumerate all satisfying IndexVersions as stubs (no fetch).

    Takes a ``DepKey`` (S5a) so the solver variable and ``seen_named`` key
    are the qualified identity.  The bare name (``dep_key.name``) is used for
    the registry lookup; the solver variable
    (``provider._binding_resolver.canonical_for(dep_key)``, S5-rekey) is used
    as the dict key in the provider's ``_stubs`` / ``_candidates``.

    Passes ``constraint=None`` to ``resolve_named_all`` so the solver sees
    the full candidate space — constraint accumulation is the solver's job.
    The dep_terms (registered in Phase B materialisation) will carry the
    actual constraint as incompatibility terms.

    D3 (resolution-semantics RFC §3 Axis D / §4 stage 2): *this* is "the
    enumeration layer" the RFC names — after stage 1's constraint-blind
    enumerate above, ``exclude_newer`` (when set) applies a hard,
    fail-closed ``published_at`` cut over the SAME candidate list, strictly
    before the solver ever sees it (stage 3's accumulated-constraint filter
    is the solver's, unaffected).  Emptying an otherwise-non-empty candidate
    set this way raises ``RES-EXCLUDE-NEWER-EMPTY`` — a distinct error class
    from ``TNG-NO-SATISFYING-VERSION``, per #100's error-taxonomy
    discipline.
    """
    # S5b: use qualified lookup when namespace is set, bare lookup otherwise.
    # Qualified lookup bypasses TNG-AMBIGUOUS-NAME (registry-protocol §5.1).
    if dep_key.namespace is not None:
        all_versions = index.resolve_named_all_qualified(
            dep_key.namespace, dep_key.name, constraint=None
        )
    else:
        all_versions = index.resolve_named_all(dep_key.name, constraint=None)

    if exclude_newer is not None:
        kept, dropped = filter_by_exclude_newer(all_versions, exclude_newer)
        if dropped and not kept:
            raise MilpaError(
                RES_EXCLUDE_NEWER_EMPTY,
                f"{dep_key.name!r} has {dropped} candidate version(s), but "
                f"exclude-newer {exclude_newer.isoformat()!r} excluded all of "
                f"them (a candidate with no provable published_at is excluded "
                f"too, fail-closed)",
                name=dep_key.name,
                namespace=dep_key.namespace,
                exclude_newer=exclude_newer.isoformat(),
                dropped=dropped,
            )
        all_versions = kept

    _canonical = provider._binding_resolver.canonical_for(dep_key)
    stubs: list[_NamedStub] = []
    for iv in all_versions:
        ver = _parse_version_strict(iv.version)
        if ver is not None:
            stubs.append(
                _NamedStub(dep_key=dep_key, version=ver, index_version=iv, canonical=_canonical)
            )
    provider.register_named_stubs(dep_key, stubs)


def _parse_version_strict(s: str) -> Version | None:
    """Parse a version string; return None if unparseable."""
    return parse_version(s)


# ---------------------------------------------------------------------------
# Provenance gate (resolver-semantics §10)
# ---------------------------------------------------------------------------


def _provenance_key_for_url_dep(
    dep: UrlDep,
    overrides_by_name: dict[str, Override],
) -> tuple[object, ...]:
    if dep.name in overrides_by_name:
        ov = overrides_by_name[dep.name]
        from milpa.manifest import GitTarget as _GitTarget
        if isinstance(ov.target, _GitTarget):
            return ("url", ov.target.git, ov.target.ref)
        # LocalTarget / MemberTarget: provenance key uses the target kind.
        # (Resolution wired in S8a/S8b; key is distinct from any git URL.)
        from milpa.manifest import LocalTarget as _LocalTarget, MemberTarget as _MemberTarget
        if isinstance(ov.target, _LocalTarget):
            return ("local-override", ov.target.path)
        if isinstance(ov.target, _MemberTarget):
            return ("member-override", ov.target.member_name)
    return ("url", dep.git, dep.ref)



def _provenance_key_for_tarball(dep: TarballDep) -> tuple[object, ...]:
    return ("tarball", dep.url)


def _provenance_key_for_local(dep: LocalDep) -> tuple[object, ...]:
    return ("local", dep.path)


# ---------------------------------------------------------------------------
# Helper: extract named requires from an EdgeSet (for transitive callback)
# ---------------------------------------------------------------------------


def _edgeset_named_requires(
    es: EdgeSet,
    overrides_by_name: dict[str, Override],
) -> list[tuple[DepKey, VersionSet]]:
    """Extract ``(DepKey, VersionSet)`` pairs for every ``NamedRequire`` in an
    already-materialized ``EdgeSet``.

    S5-rekey (RFC origin-as-identity §4.4): this replaces the old
    ``_terms_to_named_reqs`` (which extracted ``(str, VersionSet)`` pairs
    from ``dep_terms``, the SOLVER-facing Term keys). Since a NamedRequire's
    solver-variable Term key is now a BOUND source-id's canonical form (not
    a ``"ns::name"`` string), it cannot be decoded from the string alone at
    ``_on_transitive_named`` time — the callback fires mid-solve, on first
    discovery, and a canonical string is not a ``ns::name`` string
    ``DepKey.from_solver_var`` can parse (the ``SolverKey.display`` carries the
    label, but this callback receives the requirement's own fields, not the
    key). Extracting directly from the EdgeSet's own ``NamedRequire``
    entries (which still carry the original ``name``/``namespace`` fields)
    avoids that lossy round-trip entirely — the root-cause fix, not a
    reverse-decode workaround.

    Mirrors ``edgeset_to_terms``'s NamedRequire branch exactly (same
    override/namespace rules — an overridden name is treated as bare,
    namespace dropped, matching the term key ``edgeset_to_terms`` built for
    it) so the ``DepKey`` returned here always agrees with what
    ``edgeset_to_terms`` already registered as this require's Term.
    """
    from milpa.version import VersionSet as _VS

    result: list[tuple[DepKey, VersionSet]] = []
    for entry in es.requires:
        if not isinstance(entry, NamedRequire):
            continue
        if entry.name == "nim":
            continue
        if entry.name in overrides_by_name:
            # Mirrors edgeset_to_terms's override branch: bare name, full().
            result.append((DepKey(name=entry.name), _VS.full()))
            continue
        vs = _VS.full()
        if entry.constraint_str:
            try:
                vs = _VS.from_constraint(entry.constraint_str)
            except Exception:
                vs = _VS.full()
        result.append((DepKey(name=entry.name, namespace=entry.namespace), vs))
    return result


# ---------------------------------------------------------------------------
# Helper: name -> bound source_id (RFC origin-as-identity §4.5, S4)
# ---------------------------------------------------------------------------


def _source_id_for_edge_cache(binding_resolver: "BindingResolver", name: str) -> SourceId:
    """The ``SourceId`` ``edge_cache`` seals/looks up entries under for *name*.

    RFC origin-as-identity §4.5 (S4): ``edge_cache`` is keyed by
    ``(source_id, Version)``, not ``(name, Version)`` — two BFS parents that
    reach ONE repo under TWO different labels must coalesce to ONE sealed
    EdgeSet. The accepted ``SourceId`` for *name* is exactly what
    ``BindingResolver`` already bound (root claim or accepted transitive
    claim) — the single source of truth for "what does this label denote,"
    reused here rather than re-derived.

    Every call site (BFS-loop seal, ``_materialize``, Phase B dedup lookup,
    attestation-policy's post-hoc EdgeSet collection) reaches *name* only
    after it passed through ``BindingResolver`` (root-bound at construction,
    or ``submit()`` returned ``NEW``/``DUPLICATE`` — a ``LOST_TO_ROOT`` name
    never reaches a fetch/materialize/discovery-recording step). An unbound
    name here is therefore an internal invariant violation, not a user-facing
    condition — raised loudly (``MILPA_INTERNAL``) rather than silently
    falling back to name-keying, which would quietly resurrect the bug this
    slice fixes.

    S5-rekey (RFC origin-as-identity §4.4): *name* is now the PubGrub
    solver-variable string — a BOUND source-id's canonical form for a named/
    registry dep, or the plain ``dep.name`` for a git/tarball/local/member
    dep (those never route through ``DepKey``/``canonical_for`` — the term
    key literally stays ``dep.name``, see ``_dep_to_term``/root-term
    construction). Decoded via ``_depkey_for_solved_name`` (the shared
    canonical-or-legacy decode — SSOT with ``_build_graph``'s equivalent
    decode).
    """
    dk = _depkey_for_solved_name(name)
    sid = binding_resolver.source_id_for(dk)
    if sid is None:
        raise MilpaError(
            MILPA_INTERNAL,
            f"edge_cache seal/lookup for {name!r} has no source_id bound in "
            f"BindingResolver — this is an internal milpa bug; please report it",
            name=name,
        )
    return sid


# ---------------------------------------------------------------------------
# BFS wave-drain loop — shared by resolve() and resolve_workspace()
# ---------------------------------------------------------------------------


def _run_bfs_wave_loop(
    bfs_queue: list[object],
    executor: object,
    seen_named: set[DepKey],
    seen_url: set[tuple[str, str, str | None]],
    seen_tarball: set[str],
    seen_local: set[str],
    seen_oci: set[str],
    edge_cache: "dict[tuple[SourceId, Version], EdgeSet]",
    provider: "_Provider",
    overrides_by_name: "dict[str, Override]",
    deps_dir: Path,
    env: "MilpaEnv",
    params: "ResolveParams",
    index: "Index",
    root_authority: "set[str]",
    record_discovery: "Callable[[str], None]",
    binding_resolver: "BindingResolver",
    is_strict: bool,
    root_self_name: "str | None" = None,
    root_self_version: "Version | None" = None,
) -> None:
    """BFS wave-drain loop — runs in-place on *bfs_queue*.

    Processes the queue in waves of parallel I/O-bound items (URL / tarball /
    local) interleaved with synchronous named-dep enumeration.  All mutable
    state (seen_* sets, edge_cache, provider, bfs_queue) is updated in-place.

    Parameters mirror the closed-over locals in the old per-function copies
    except ``record_discovery``, which is the only thing that differed between
    the single-package and workspace copies.

    ``root_self_name``/``root_self_version`` (§14.3): standalone-resolve-only
    — the root's own name + candidate-label version, used to validate a
    transitive ``named`` claim's constraint against the root's own version
    BEFORE ``BindingResolver`` suppresses it as ``LOST_TO_ROOT`` (§14.2).
    Both ``None`` (the default) for ``resolve_workspace``, which never passes
    them — the workspace member auto-coerce (§11.5) is a separate,
    pre-existing mechanism, untouched by this parameter.
    """
    from concurrent.futures import Future as _Future
    from typing import cast as _cast

    # Eager-fetch tree location for each successfully-fetched URL dep, keyed
    # by candidate name — persists ACROSS waves (S4b's multi-consumer-union
    # re-read can reference a name fetched in an EARLIER wave). This is the
    # single source of truth for "where is this url dep's fetched tree on
    # disk right now" — since ``_process_url_worker``'s scratch destination
    # is a unique per-invocation path (not necessarily ``deps_dir / name``;
    # see its docstring), the S3/S4b flag-re-read blocks below MUST consult
    # this map rather than reconstructing ``deps_dir / name`` themselves.
    url_dep_paths: dict[str, Path] = {}

    i = 0
    while i < len(bfs_queue):
        # --- Collect the next wave of I/O-bound items -------------------
        # A wave ends when we hit a "named" item (synchronous) or the
        # queue runs out of new I/O items (all remaining are named or
        # already-seen URL/tarball/local).
        wave_futures: list[object] = []
        # S3: track which UrlDep each future corresponds to, for dep_active_flags
        # population in the result-drain phase (keyed by future identity).
        future_to_url_dep: dict[int, UrlDep] = {}
        # S4b: accumulate flag_requests from ADDITIONAL consumers of an already-seen
        # URL dep (multi-consumer union, §3.1.3).  Keyed by dep name; applied after
        # the wave drain so the dep's identity is confirmed.
        wave_pending_flag_reqs: dict[str, list[FlagRequest]] = {}
        # Names for which a url-dep fetch worker has already been submitted
        # THIS wave — reset every wave (concurrency, not cross-wave, is the
        # only thing that can race). Ordinarily every name gets exactly one
        # url-dep candidate, so this set only ever gains a SECOND entry for
        # a name in the rare validate-against-registry "two agreeing pins of
        # the same registry name, different refs" shape (resolver-semantics
        # §10.0/§10.3) — see the ``kind == "url"`` dest computation below.
        wave_url_names_dispatched: set[str] = set()

        j = i
        while j < len(bfs_queue):
            item = bfs_queue[j]
            j += 1
            if not isinstance(item, tuple):
                continue
            kind: str = item[0]

            if kind == "named":
                # Named items are synchronous (Phase A enumeration, no I/O).
                # Process them inline now; they may add more items to the queue.
                dep_key_n: DepKey = item[1]  # S5a: qualified DepKey (namespace+name)
                if dep_key_n not in seen_named and dep_key_n.name != "nim":
                    seen_named.add(dep_key_n)
                    # §14.3: validate (and possibly raise) BEFORE the gate
                    # suppresses this claim below — a no-op unless this claim
                    # names the standalone root's own name (root_self_name is
                    # None for resolve_workspace and for any resolve() call
                    # where nothing needs it).
                    _validate_root_self_constraint(
                        dep_key_n, item[2], root_self_name, root_self_version,
                    )
                    # RFC origin-as-identity §4.3 (S3a) — BindingResolver is
                    # now authoritative. This claim is ALWAYS submitted
                    # (never skipped via a bare is_root/root_authority
                    # shortcut) — that distinction matters for the root's
                    # OWN self-name (§14 "root satisfies its own name"): its
                    # root claim is a ``MemberSourceId`` sentinel (RFC §6
                    # "workspace-of-one"), not a ``RegistrySourceId``, so a
                    # constructed registry claim against it correctly comes
                    # back ``LOST_TO_ROOT`` (suppressed — root_self_cand
                    # alone already satisfies the term, no registry
                    # enumeration needed/possible) rather than being
                    # mistaken for an ordinary root-authoritative name that
                    # should proceed unconditionally. An ordinary root-
                    # declared registry dep re-arriving through this same
                    # BFS arm instead comes back ``DUPLICATE`` (its claim
                    # was already bound, identically, at
                    # ``BindingResolver.__init__`` via
                    # ``reconcile_root_claims``) and still proceeds. A
                    # genuinely NAMESPACED transitive claim
                    # (``dep_key_n.namespace is not None``) is no longer
                    # specially excluded either — B1/G1's whole point is
                    # that ``BindingResolver`` keys by the full ``DepKey``
                    # (via the qualified ``ns::name`` solver var), so
                    # ``ns1::foo``/``ns2::foo`` never cross-bind without a
                    # bare-name special case.
                    _named_claim = Claim(
                        name=dep_key_n.solver_var(),
                        source_id=normalize_source(
                            RegistrySourceId(
                                registry=DEFAULT_REGISTRY_ALIAS,
                                namespace=resolved_registry_namespace(
                                    dep_key_n.name, dep_key_n.namespace, index,
                                ),
                                name=dep_key_n.name,
                            )
                        ),
                        is_root=False,
                        claimant="transitive",
                    )
                    _named_decision = binding_resolver.submit(_named_claim)
                    # NEW or DUPLICATE both proceed to enumeration (a
                    # DUPLICATE named claim is a harmless re-enumeration of
                    # the same registry coordinate — including root's OWN
                    # named dep re-arriving through this same BFS arm);
                    # only LOST_TO_ROOT — this name is root/override/root-
                    # self-pinned to a DIFFERENT source — is suppressed.
                    _proceed = _named_decision.outcome is not BindOutcome.LOST_TO_ROOT
                    if _proceed:
                        # S5-rekey (RFC origin-as-identity §4.4): record the
                        # CANONICAL solver variable — computed only now,
                        # AFTER submit() bound the key (canonical_for
                        # requires it) — so _dedup_candidates' discovery-order
                        # tie-break can actually find this entry (it looks up
                        # by the SAME canonical string _candidates/solution
                        # use). A LOST_TO_ROOT name never gets recorded here
                        # (it never gets a solved candidate either).
                        record_discovery(binding_resolver.canonical_for(dep_key_n))  # Phase B: transitive named dep
                        # Enumerate-all normative (resolver-semantics §2.1):
                        # do NOT pre-filter by constraint here.  The solver
                        # owns satisfiability via incompatibility accumulation;
                        # pre-filtering would emit TNG-NO-SATISFYING-VERSION
                        # instead of the canonical SOLVE-CONFLICT on the error path.
                        _enumerate_named_stubs(
                            dep_key_n, None, index, provider, deps_dir, env,
                            exclude_newer=params.exclude_newer,
                        )
                # Named items are always processed inline, not as futures.
                continue

            # URL/tarball/local — determine if this item is new (not seen).
            if kind == "url":
                dep_u: UrlDep = item[1]
                if dep_u.name in overrides_by_name:
                    ov = overrides_by_name[dep_u.name]
                    # S8a: LocalTarget override → route to the "local" BFS slot.
                    if isinstance(ov.target, LocalTarget):
                        _local_ov = LocalDep(name=dep_u.name, path=ov.target.path, version=ov.version)
                        if _local_ov.path not in seen_local:
                            seen_local.add(_local_ov.path)
                            # P6/DE1: canonical SolverKey, not bare name.
                            record_discovery(binding_resolver.canonical_for(DepKey(name=_local_ov.name)))
                            def _local_ov_worker(
                                _dep: LocalDep = _local_ov,
                            ) -> tuple[str, object]:
                                return ("local", _process_local_worker(
                                    _dep,
                                    deps_dir=deps_dir,
                                    env=env,
                                    params=params,
                                    overrides_by_name=overrides_by_name,
                                ))
                            wave_futures.append(executor.submit(_local_ov_worker))  # type: ignore[union-attr]
                        continue
                    # S8b: MemberTarget override — member already pre-registered.
                    # The provenance gate was pre-seeded with root authority, so any
                    # transitive dep claiming this name externally is suppressed below.
                    # We skip external queueing here.
                    if isinstance(ov.target, MemberTarget):
                        continue
                    # S8b: TarballTarget/OciTarget/RegistryTarget override →
                    # re-enqueue under the matching BFS kind. Appending to
                    # bfs_queue from mid-scan is safe and already this
                    # function's established idiom: the inner `while j <
                    # len(bfs_queue)` scan re-checks its length every
                    # iteration, so the newly-appended item is visited later
                    # in this SAME wave's scan (before any futures are
                    # drained) and dispatched by the ordinary "tarball"/
                    # "oci"/"named" arms below — including their OWN
                    # seen_tarball/seen_oci/seen_named dedup, so there is no
                    # separate dedup check needed here (single source of
                    # truth for the dedup, not a second copy).
                    if isinstance(ov.target, (TarballTarget, OciTarget, RegistryTarget)):
                        bfs_queue.append(_extended_override_bfs_item(dep_u.name, ov))
                        continue
                    dep_u = _apply_git_override_to_url_dep(dep_u, ov)
                # RFC origin-as-identity §4.3/§6.1 (S3a/S3c) — BindingResolver
                # is now authoritative; the old validate-against-registry
                # AGREE/DISAGREE/DEFER lattice is retired (present-but-
                # unreferenced below, deletion is a later slice). This claim
                # is ALWAYS submitted (never skipped via a bare
                # root_authority shortcut) — root's OWN item re-arriving
                # through this same BFS arm (root-seeded exactly like a
                # transitive claim) correctly comes back DUPLICATE (matches
                # the binding already established at
                # ``BindingResolver.__init__`` via ``reconcile_root_claims``)
                # and proceeds; a TRANSITIVE claim disagreeing with a root-
                # authoritative name for THIS SAME name correctly comes back
                # LOST_TO_ROOT and is suppressed (Cargo-`[patch]` semantics —
                # root wins silently). Skipping submit() entirely for any
                # root-authoritative name (an earlier version of this code)
                # was a real bug: it let a TRANSITIVE's disagreeing source
                # for a root-declared name fall through to an unconditional
                # fetch, since ``seen_url`` is keyed by (git, ref, subpath),
                # not name (conformance fixture-065 "root override precedence").
                #
                # The registry-shadow tripwire (S3c) is gated on whether ROOT
                # holds authority over this EXACT source key — it exists to
                # catch a TRANSITIVE's bare name silently shadowing a registry
                # coordinate, not to second-guess root's OWN explicit choice
                # (root's own source is authoritative by construction; warning
                # about it would be pure noise). The gate MUST key on the exact
                # ``DepKey``, not a bare name: an unrelated root ``foo
                # namespace="ns1"`` must NOT disable the dependency-confusion
                # check for a bare ``foo`` a transitive sources elsewhere (that
                # bare-name-projection gap was a real dependency-confusion
                # bypass — a transitive could shadow a DIFFERENT registry-owned
                # ``ns2/foo`` unchecked).
                _url_claim = Claim(
                    name=dep_u.name,
                    source_id=normalize_source(GitSourceId(url=dep_u.git, subpath=dep_u.subpath)),
                    is_root=False,
                    claimant="transitive",
                )
                if not binding_resolver.is_root_authority(DepKey(name=dep_u.name)):
                    check_registry_shadow(_url_claim, index, is_strict=is_strict)
                _url_decision = binding_resolver.submit(_url_claim)
                if _url_decision.outcome is BindOutcome.LOST_TO_ROOT:
                    continue
                # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver
                # key, computed NOW that the claim is bound (NEW or
                # DUPLICATE) — used for every PubGrub-facing/candidate-dict
                # key below (record_discovery, wave_pending_flag_reqs,
                # url_dep_paths via the candidate's own name).
                _svar_url_t = binding_resolver.canonical_for(DepKey(name=dep_u.name))
                # NEW or DUPLICATE both fall through to the ordinary
                # seen_url-keyed fetch-dedup below. A DUPLICATE outcome
                # only means this source-id is ALREADY bound to this
                # name — it does NOT mean this exact (url, ref) fetch
                # already happened: a different pinned ref of the SAME
                # source-id (RFC §12 case B — "declares the same URL+ref"
                # is the only case that was already pkey-identical; a
                # DIFFERING ref is a genuinely separate version
                # candidate) must still be fetched and must still
                # coexist as a candidate the solver can pick between —
                # exactly what the ``seen_url``/``wave_url_names_dispatched``
                # machinery below already does, keyed by (git, ref, subpath),
                # not by name. The subpath component is REQUIRED (RFC §7
                # "same repo + different subpath = different source-ids,
                # correctly" — S8 monorepo grammar): omitting it collapses
                # two deps that share a url+ref but live at different
                # subdirectories into a single candidate, silently dropping
                # the second one's distinct source-id.
                url_key_u = (dep_u.git, dep_u.ref, dep_u.subpath)
                if url_key_u in seen_url:
                    # Same URL already submitted in a prior wave (cross-wave dup).
                    # Accumulate flag_requests for multi-consumer union (§3.1.3).
                    if dep_u.flag_requests:
                        wave_pending_flag_reqs.setdefault(_svar_url_t, []).extend(
                            dep_u.flag_requests
                        )
                    continue
                seen_url.add(url_key_u)
                record_discovery(_svar_url_t)  # Phase B: transitive URL dep first-enqueue
                # Ordinarily dest is exactly deps_dir/name (unchanged from
                # before) — the disambiguated branch is reachable only when
                # ANOTHER url-dep candidate for this SAME name was already
                # dispatched earlier in THIS wave (the "two agreeing pins,
                # different refs" shape — RFC origin-as-identity §10 S3a
                # "same-URL / different-ref completeness": a ``DUPLICATE``
                # binding decision still registers the pinned ref as a
                # separate version candidate for the bound source-id).
                # Concurrent CasAdmittingFetcher symlink placement at the
                # SAME dest across two threads races and raises an OS-level
                # error; a unique suffix on the SECOND-and-later occurrence
                # sidesteps it without touching the common case at all.
                if dep_u.name in wave_url_names_dispatched:
                    _dest_u = deps_dir / f"{dep_u.name}.{uuid.uuid4().hex[:12]}"
                else:
                    _dest_u = deps_dir / dep_u.name
                wave_url_names_dispatched.add(dep_u.name)
                # Submit to thread pool — captures dep_u/_dest_u by value (closure).
                def _url_worker(
                    _dep: UrlDep = dep_u,
                    _dest: Path = _dest_u,
                ) -> tuple[str, object]:  # (kind, result)
                    return ("url", _process_url_worker(
                        _dep,
                        dest=_dest,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                        root_self_name=root_self_name,
                        binding_resolver=binding_resolver,
                    ))
                _url_fut = executor.submit(_url_worker)  # type: ignore[union-attr]
                wave_futures.append(_url_fut)
                # S3: record dep reference so result-drain can compute dep_active_flags.
                future_to_url_dep[id(_url_fut)] = dep_u

            elif kind == "tarball":
                dep_t: TarballDep = item[1]
                if dep_t.url in seen_tarball:
                    continue
                seen_tarball.add(dep_t.url)
                # P6/DE1: record the canonical SolverKey (matches this dep's own
                # term key), NOT the bare name — else it never matches the
                # discovery_index and the BFS-first dedup tiebreak degrades to
                # _LARGE. Bound at __init__ (an override target is a root claim).
                record_discovery(binding_resolver.canonical_for(DepKey(name=dep_t.name)))
                def _tarball_worker(
                    _dep: TarballDep = dep_t,
                ) -> tuple[str, object]:
                    return ("tarball", _process_tarball_worker(
                        _dep,
                        deps_dir=deps_dir,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                        root_self_name=root_self_name,
                        binding_resolver=binding_resolver,
                    ))
                wave_futures.append(executor.submit(_tarball_worker))  # type: ignore[union-attr]

            elif kind == "local":
                dep_l: LocalDep = item[1]
                if dep_l.path in seen_local:
                    continue
                seen_local.add(dep_l.path)
                # P6/DE1: canonical SolverKey, not bare name (see tarball arm).
                record_discovery(binding_resolver.canonical_for(DepKey(name=dep_l.name)))
                def _local_worker(
                    _dep: LocalDep = dep_l,
                ) -> tuple[str, object]:
                    return ("local", _process_local_worker(
                        _dep,
                        deps_dir=deps_dir,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                        root_self_name=root_self_name,
                        binding_resolver=binding_resolver,
                    ))
                wave_futures.append(executor.submit(_local_worker))  # type: ignore[union-attr]

            elif kind == "oci":
                dep_o: "_OciOverrideDep" = item[1]
                _oci_ref_o = f"{dep_o.registry}/{dep_o.repository}@{dep_o.digest}"
                if _oci_ref_o in seen_oci:
                    continue
                seen_oci.add(_oci_ref_o)
                # P6/DE1: canonical SolverKey, not bare name (see tarball arm).
                record_discovery(binding_resolver.canonical_for(DepKey(name=dep_o.name)))
                def _oci_worker(
                    _dep: "_OciOverrideDep" = dep_o,
                ) -> tuple[str, object]:
                    return ("oci", _process_oci_worker(
                        _dep,
                        deps_dir=deps_dir,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                        root_self_name=root_self_name,
                        binding_resolver=binding_resolver,
                    ))
                wave_futures.append(executor.submit(_oci_worker))  # type: ignore[union-attr]

        i = j  # advance read head past all items we just processed

        # --- Drain wave futures in any order ----------------------------
        # Result-collection order doesn't affect lockfile bytes
        # (lockfile is lex-sorted, not BFS-order-sorted).
        completed_futs: list[_Future[tuple[str, object]]] = list(
            as_completed(wave_futures)  # type: ignore[arg-type]
        )
        for fut in completed_futs:
            fut_result = fut.result()  # propagates exceptions
            kind_result = fut_result[0]
            fetch_result = fut_result[1]
            # Register candidate, seal edge_cache, and enqueue transitives.
            if kind_result in ("url", "tarball", "local", "oci"):
                if kind_result == "url":
                    # _process_url_worker's scratch destination is NOT
                    # necessarily deps_dir/name (see its docstring) — record
                    # it in url_dep_paths so the S3/S4b re-reads below (and
                    # any later wave's S4b re-read) find the real tree.
                    cand_and_deps_u: tuple[_Candidate, list[object], EdgeSet, Path] = _cast(
                        "tuple[_Candidate, list[object], EdgeSet, Path]", fetch_result
                    )
                    cand_r, transitive_deps_r, es_r, dest_r = cand_and_deps_u
                    url_dep_paths[cand_r.name] = dest_r
                else:
                    # tarball/local workers still return the plain 3-tuple —
                    # their destination IS always deps_dir/name (root-declared
                    # only; M2 security gate drops transitive tarball/local
                    # deps before they ever reach this loop, so no two
                    # distinct claims can ever share a name here).
                    cand_and_deps: tuple[_Candidate, list[object], EdgeSet] = _cast(
                        "tuple[_Candidate, list[object], EdgeSet]", fetch_result
                    )
                    cand_r, transitive_deps_r, es_r = cand_and_deps
                provider.add(cand_r)
                # Seal the edge_cache for this (source_id, version) — clause
                # (a). RFC origin-as-identity §4.5 (S4): keyed by source_id,
                # not name — two BFS parents reaching the SAME origin under
                # TWO different labels (e.g. `z3` vs `nimz3` for one repo)
                # must coalesce to ONE sealed EdgeSet, not two.
                # First-encounter wins; no overwrite (worker produced the EdgeSet
                # deterministically from the fetched tree).
                cache_key_r = (
                    _source_id_for_edge_cache(binding_resolver, cand_r.name),
                    cand_r.version,
                )
                if cache_key_r not in edge_cache:
                    edge_cache[cache_key_r] = es_r

                # S3 / C1: unconditionally seed dep_active_flags for URL deps so
                # that default-true flags are visible to the S4a fixpoint even
                # when no consumer flag_requests exist.  Keyed by identity
                # (content_hash) — NORMATIVE per spec/identity.md §3.1.2.
                if kind_result == "url" and cand_r.identity is not None:
                    _orig_url_dep = future_to_url_dep.get(id(fut))
                    _url_flag_reqs: tuple[FlagRequest, ...] = (
                        _orig_url_dep.flag_requests
                        if _orig_url_dep is not None
                        else ()
                    )
                    # dest_r is this SAME candidate's actual fetched tree
                    # (bound above, this branch only reachable when
                    # kind_result == "url") — NOT necessarily deps_dir/name.
                    _dep_kdl = dest_r / "milpa.kdl"
                    _url_manifest_flags: tuple[FlagDecl, ...] = ()
                    if _dep_kdl.exists():
                        try:
                            from milpa.manifest import parse_manifest as _pm2
                            _udm = _pm2(_dep_kdl.read_text(encoding="utf-8"))
                            _url_manifest_flags = _udm.flags
                        except Exception:
                            pass  # non-fatal
                    _url_active = compute_dep_active_flags(
                        _url_manifest_flags, _url_flag_reqs
                    )
                    if _url_active:
                        provider.dep_active_flags[cand_r.identity] = _url_active

                for sub_dep in transitive_deps_r:
                    _enqueue_dep(sub_dep, overrides_by_name, bfs_queue)

        # S4b: apply pending flag_requests from additional consumers of already-seen
        # URL deps (multi-consumer union, §3.1.3).  All wave futures are drained above,
        # so every dep in wave_pending_flag_reqs is now registered as a candidate.
        #
        # After merging active_flags, call find_newly_admitted_deps to admit any
        # subdeps that are now unblocked — exactly the same step as in the S4a
        # fixpoint (steps 4–5).  Newly admitted subdeps are enqueued into bfs_queue
        # for the next BFS wave; the outer while-loop picks them up automatically.
        if wave_pending_flag_reqs:
            from milpa.manifest import parse_manifest as _s4b_pm
            for _pname, _preqs in wave_pending_flag_reqs.items():
                _pcand_map = provider._candidates.get(_pname, {})
                for _pcand in _pcand_map.values():
                    if _pcand.identity is None:
                        continue
                    # Load the dep's manifest (already on disk from BFS fetch).
                    # url_dep_paths is the single source of truth for where a
                    # url dep's fetched tree actually landed (NOT necessarily
                    # deps_dir/name — see _process_url_worker's docstring);
                    # this consumer may be referencing a name fetched in an
                    # EARLIER wave, so the map (not just this wave's dest_r)
                    # is required here. RFC §4.4.1 (S5-rekey): _pname is now
                    # the canonical solver-variable string (matches
                    # provider._candidates/url_dep_paths keys) — the
                    # FALLBACK path (defensive; url_dep_paths should always
                    # have an entry by the time this runs) must decode back
                    # to the bare filesystem name, never the canonical
                    # string itself (filesystem layout stays name-based,
                    # dep_dir_name SSOT — orthogonal to the solver key).
                    _pkdl = url_dep_paths.get(
                        _pname, deps_dir / _depkey_for_solved_name(_pname).name
                    ) / "milpa.kdl"
                    _pmf: tuple[FlagDecl, ...] = ()
                    _pmanifest = None
                    if _pkdl.exists():
                        try:
                            _pmanifest = _s4b_pm(_pkdl.read_text(encoding="utf-8"))
                            _pmf = _pmanifest.flags
                        except Exception:
                            pass  # non-fatal; remain with empty flag table
                    # Compute additional active flags from the pending requests.
                    # Uses the SSOT compute_dep_active_flags: negative requests are
                    # treated as absence-of-request (§3.1.3), never subtracted.
                    _pnew = compute_dep_active_flags(_pmf, tuple(_preqs))
                    # Union with existing dep_active_flags (monotone — never subtract).
                    _pprev = provider.dep_active_flags.get(_pcand.identity, {})
                    _old_flag_names = frozenset(_pprev.keys())
                    _pmerged: dict[str, set[ActivationSource]] = dict(_pprev)
                    for _pfn, _psrcs in _pnew.items():
                        if _pfn not in _pmerged:
                            _pmerged[_pfn] = set()
                        _pmerged[_pfn].update(_psrcs)
                    _new_flag_names = frozenset(_pmerged.keys())
                    if _new_flag_names != _old_flag_names:
                        provider.dep_active_flags[_pcand.identity] = _pmerged
                        # S4b steps 4+5 (one-pass): check admission and extend/enqueue
                        # in the same loop — matches Rust's inlined single-pass in
                        # process_url S4b (~1444-1496).
                        if _pmanifest is not None:
                            from milpa.solver import Term as _S4bTerm
                            from milpa.version import VersionSet as _S4bVS
                            for _nsub in _pmanifest.deps:
                                _npreds = _nsub.predicates
                                if not (
                                    dep_passes_flag_predicates(_npreds, _new_flag_names)
                                    and not dep_passes_flag_predicates(_npreds, _old_flag_names)
                                ):
                                    continue
                                # Newly admitted — extend parent dep_terms and enqueue.
                                _nsub_name = getattr(_nsub, "name", None)
                                if _nsub_name:
                                    # RFC §4.4.1 (S5-rekey, phase 2): uniform
                                    # canonical solver key — pure guess
                                    # (claim not yet submitted; that happens
                                    # later when _enqueue_dep's target is
                                    # dequeued by the "url"/"named" BFS arm).
                                    from milpa.binding import canonical_key_for_requirement as _ckfr_s4b
                                    _nsub_svar = _ckfr_s4b(
                                        name=_nsub_name,
                                        namespace=getattr(_nsub, "namespace", None),
                                        url=_nsub.git if isinstance(_nsub, UrlDep) else None,
                                        overrides_by_name=overrides_by_name,
                                        index=index,
                                        root_self_name=root_self_name,
                                        binding_resolver=binding_resolver,
                                    )
                                    if _nsub_svar not in _pcand.requires_names:
                                        if isinstance(_nsub, UrlDep):
                                            # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
                                            _pcand.dep_terms.append(
                                                _S4bTerm.require(_nsub_svar, _S4bVS.full())
                                            )
                                        else:
                                            _vs_sub = getattr(_nsub, "constraint_set", None) or _S4bVS.full()
                                            _pcand.dep_terms.append(
                                                _S4bTerm.require(_nsub_svar, _vs_sub)
                                            )
                                        _pcand.requires_names.append(_nsub_svar)
                                _enqueue_dep(_nsub, overrides_by_name, bfs_queue)
                    break  # only one candidate per name at any time


# ---------------------------------------------------------------------------
# S4a (RFC #23 §7 §3.1.2): outer dep×flag fixpoint
# ---------------------------------------------------------------------------

def _s4a_run_fixpoint(
    *,
    provider: "_Provider",
    bfs_queue: "list[object]",
    executor: object,
    seen_named: "set[DepKey]",
    seen_url: "set[tuple[str, str, str | None]]",
    seen_tarball: "set[str]",
    seen_local: "set[str]",
    seen_oci: "set[str]",
    edge_cache: "dict[tuple[SourceId, Version], EdgeSet]",
    overrides_by_name: "dict[str, Override]",
    deps_dir: Path,
    env: "MilpaEnv",
    params: "ResolveParams",
    index: "Index",
    root_authority: "set[str]",
    record_discovery: "Callable[[str], None]",
    binding_resolver: "BindingResolver",
    is_strict: bool,
    extra_manifests: "dict[str, object] | None" = None,
    root_self_name: "str | None" = None,
    root_self_version: "Version | None" = None,
) -> None:
    """S4a outer dep×flag fixpoint loop.

    Iterates until neither ``dep_active_flags`` nor the admitted dep set grows:
      1. Load manifests for all known fetched URL deps (from ``deps_dir``).
         ``extra_manifests`` (optional) injects pre-loaded manifests for deps
         whose files live outside ``deps_dir`` (e.g. workspace members).
      2. Compute cross-pkg enables from every dep's current active flags:
         for each active flag f on dep D, f.enables_cross_pkg generates
         FlagRequest(s) for target deps.
      3. Recompute ``active(target)`` for each target dep that received new
         FlagRequest(s), using the SSOT ``compute_dep_active_flags``.
      4. For deps with updated ``active_flags``, find newly-admitted edges
         (deps whose flag predicates now pass but didn't before).
      5. For each newly-admitted dep:
         a. Enqueue into BFS for fetch (if not already seen).
         b. Extend the parent dep's candidate ``dep_terms`` / ``requires_names``
            so the solver sees the new edge.
      6. Re-run ``_run_bfs_wave_loop`` to fetch newly-admitted deps.
      7. Repeat until stable (no new deps or active_flags changes).

    **Thread-safety**: this function runs entirely in the main thread between
    BFS waves.  The BFS executor is idle during fixpoint computation; shared
    state (``provider.dep_active_flags``, candidate ``dep_terms``) is only
    read/written from the main thread here.  This is safe — the GIL and the
    executor quiescence guarantee mutual exclusion without additional locking.

    **Sealed-edge invariant preserved**: ``edge_cache`` entries are NEVER
    invalidated or replaced here.  Newly-admitted deps get new entries on first
    fetch; existing EdgeSets stay immutably sealed.  Candidate ``dep_terms``
    lists are EXTENDED (append), not replaced.

    **PubGrub runs exactly once**: this function is called BEFORE the solver.
    The fixpoint is a pre-solver / edge-admission concern (RFC §3.1.2).

    **Termination**: bounded by the finite union of (deps reachable from root)
    × (flags declared per dep) — both finite in milpa (no dep cycles).  Union
    is monotone (sets only grow); fixpoint exists in O(|deps|×max_flags) iters.
    """
    from milpa.manifest import parse_manifest as _parse_manifest
    from milpa.manifest import UrlDep as _UrlDep, NamedDep as _NamedDep

    # Max guard: in the extremely unlikely event of a logic bug leading to a
    # non-converging loop, cap iterations.  This is a safety belt, not the
    # termination argument (that rests on monotonicity + finite universe).
    # M3: cap exhaustion is a bug — fail loud rather than silently truncating.
    # Monotonicity guarantees convergence well under 50 for any valid input.
    _MAX_ITERS = 50
    # R2-M DoS hardening: absolute bound on total (dep,flag) activations across
    # the whole fixpoint.  Monotonicity bounds this by |deps|×max_flags; a
    # generous cap makes pathological-width manifests fail-loud instead of
    # hanging.  10_000 is far above any realistic graph and far below a
    # crafted-wide DoS attempt.  Must match Rust MAX_TOTAL_ACTIVATIONS.
    _MAX_TOTAL_ACTIVATIONS = 10_000
    _total_activations = 0
    _converged = False

    for _iter in range(_MAX_ITERS):
        # ---------------------------------------------------------------
        # Step 1: build name→manifest map for all fetched URL deps.
        # We use deps_dir as the source of truth (manifests are already on
        # disk from the BFS wave; re-parsing is non-blocking).
        # ---------------------------------------------------------------
        dep_manifests: dict[str, "Manifest"] = {}
        # Collect all known dep names from the candidate map.
        for dep_name_k in list(provider._candidates.keys()):
            if dep_name_k == "__root__":
                continue
            # C1/H2 fix: decompose the solver-var (S5-rekey: a BOUND
            # source-id's canonical form for a named dep) into a DepKey and
            # use dep_dir_name so qualified deps resolve to
            # ``_deps/@ns/bar/milpa.kdl`` rather than the nonexistent
            # ``_deps/ns::bar/milpa.kdl``.
            _dk_s4b = _depkey_for_solved_name(dep_name_k)
            kdl_path = deps_dir / dep_dir_name(_dk_s4b.name, _dk_s4b.namespace) / "milpa.kdl"
            if kdl_path.exists():
                try:
                    dm = _parse_manifest(kdl_path.read_text(encoding="utf-8"))
                    dep_manifests[dep_name_k] = dm
                except Exception:
                    pass  # non-fatal

        # Merge extra_manifests (e.g. workspace members not in deps_dir).
        # extra_manifests takes lower precedence — only inject names not
        # already loaded from deps_dir (deps_dir is the authoritative source
        # for fetched content; members are injected for enables propagation).
        if extra_manifests:
            for _em_name, _em_manifest in extra_manifests.items():
                if _em_name not in dep_manifests:
                    dep_manifests[_em_name] = _em_manifest  # type: ignore[assignment]

        # ---------------------------------------------------------------
        # Step 2: compute cross-pkg enables from all currently-active flags.
        # Collect additional FlagRequest(s) for each target dep.
        # ---------------------------------------------------------------
        # Maps target_dep_name → list[FlagRequest] to MERGE into active(target).
        additional_requests: dict[str, list] = {}

        for dep_name_k, dm in dep_manifests.items():
            # Look up this dep's current active flags.
            cand_map = provider._candidates.get(dep_name_k, {})
            identity_for_dep: str | None = None
            for cand in cand_map.values():
                if cand.identity is not None:
                    identity_for_dep = cand.identity
                    break

            active_now = (
                provider.dep_active_flags.get(identity_for_dep, {})
                if identity_for_dep is not None
                else {}
            )

            cross_pkg = compute_cross_pkg_enables(
                flags=dm.flags,
                active_flag_names=frozenset(active_now.keys()),
            )
            for target_name, flag_reqs in cross_pkg.items():
                # S5-rekey (RFC origin-as-identity §4.4): target_name is the
                # BARE identifier from the dep's own `flags{}.enables{}`
                # block — project to whatever key its ALREADY-admitted
                # candidate is actually registered under (bare for an eager
                # git/tarball/local target, canonical for a named/registry
                # one — the M1 security gate above guarantees the target is
                # already bound by this point, so canonical_key_for_
                # requirement's binding_resolver-first branch always fires,
                # never the guess fallback).
                from milpa.binding import canonical_key_for_requirement as _ckfr_step2
                _svar_target = _ckfr_step2(
                    name=target_name,
                    namespace=None,
                    url=None,
                    overrides_by_name=overrides_by_name,
                    index=index,
                    root_self_name=root_self_name,
                    binding_resolver=binding_resolver,
                )
                if _svar_target not in additional_requests:
                    additional_requests[_svar_target] = []
                additional_requests[_svar_target].extend(flag_reqs)

        if not additional_requests:
            _converged = True
            break  # No cross-pkg enables fired — stable.

        # ---------------------------------------------------------------
        # Step 3: recompute active(target) for each target that received
        # new flag requests.  Detect changes to trigger more iterations.
        # ---------------------------------------------------------------
        any_change = False

        for target_name, new_reqs in additional_requests.items():
            # M1 security gate: cross-pkg enables may only affect deps that are
            # ALREADY in the graph (already fetched and in dep_manifests).
            # A cross-pkg enable from ANY source (root OR transitive) MUST NOT
            # force-admit a brand-new dep T that was not already reachable from
            # the root's declared dep closure.  Only T's *sub-deps* (admitted
            # naturally when T's active_flags grow) can be newly enqueued — and
            # only because T was already legitimately admitted.
            target_manifest = dep_manifests.get(target_name)
            if target_manifest is None:
                continue  # T not yet fetched — do NOT admit via cross-pkg enable.

            # Find the target's identity (for dep_active_flags keying).
            target_cand_map = provider._candidates.get(target_name, {})
            target_identity: str | None = None
            for cand in target_cand_map.values():
                if cand.identity is not None:
                    target_identity = cand.identity
                    break

            # Previous active_flags for this target.
            prev_active = (
                provider.dep_active_flags.get(target_identity, {})
                if target_identity is not None
                else {}
            )
            old_flag_names = frozenset(prev_active.keys())

            # Merge the new requests with the target's existing flag_requests.
            # The SSOT is compute_dep_active_flags — don't reimplement.
            # We convert new_reqs into a tuple of FlagRequest for the SSOT.
            all_reqs = tuple(new_reqs)
            new_active = compute_dep_active_flags(target_manifest.flags, all_reqs)

            # Union with the previous active set (monotone — never subtract).
            merged: dict[str, set[ActivationSource]] = dict(prev_active)
            for flag_name_v, sources_v in new_active.items():
                if flag_name_v not in merged:
                    merged[flag_name_v] = set()
                    any_change = True
                merged[flag_name_v].update(sources_v)

            new_flag_names = frozenset(merged.keys())
            if new_flag_names == old_flag_names:
                continue  # No change for this dep.

            any_change = True

            # R2-M DoS hardening: count newly-added (dep,flag) activations.
            _total_activations += len(new_flag_names - old_flag_names)
            if _total_activations > _MAX_TOTAL_ACTIVATIONS:
                raise MilpaError(
                    MILPA_INTERNAL,
                    f"S4a flag fixpoint exceeded {_MAX_TOTAL_ACTIVATIONS} total "
                    "(dep,flag) activations — this is an internal milpa bug or a "
                    "pathologically wide manifest; please report it",
                )

            # Update dep_active_flags.
            if target_identity is not None:
                provider.dep_active_flags[target_identity] = merged

            # ---------------------------------------------------------------
            # Steps 4+5 (one-pass): for each dep in the target manifest, check
            # if it is newly admitted by the updated active_flags and if so
            # extend the parent's dep_terms + enqueue into BFS.  Mirrors
            # Rust's inlined single-pass in run_s4a_fixpoint (~2803-2870).
            # ---------------------------------------------------------------
            target_cand = (
                next(iter(target_cand_map.values()), None)
                if target_cand_map
                else None
            )

            for sub_dep in target_manifest.deps:
                _preds_s4a = sub_dep.predicates
                if not (
                    dep_passes_flag_predicates(_preds_s4a, new_flag_names)
                    and not dep_passes_flag_predicates(_preds_s4a, old_flag_names)
                ):
                    continue
                if isinstance(sub_dep, _UrlDep):
                    # (git, ref, subpath) — see the identical comment on the
                    # BFS wave loop's ``url_key_u`` above; the two dedup
                    # sites must agree on this key's granularity (RFC §7 —
                    # same url+ref, different subpath, is a DIFFERENT dep).
                    dep_key = (sub_dep.git, sub_dep.ref, sub_dep.subpath)
                    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver
                    # key — no eager-kind bare-name carve-out. Computed via
                    # the pure canonical_key_for_requirement (not
                    # BindingResolver.canonical_for) because this sub_dep's
                    # claim is not yet submitted at this point — that happens
                    # later, when the "url" BFS arm processes it off the
                    # queue (mirrors the NamedDep branch below).
                    from milpa.binding import canonical_key_for_requirement as _ckfr_s4a_url
                    _svar_sub = _ckfr_s4a_url(
                        name=sub_dep.name,
                        namespace=None,
                        url=sub_dep.git,
                        overrides_by_name=overrides_by_name,
                        index=index,
                        root_self_name=root_self_name,
                        binding_resolver=binding_resolver,
                    )
                    if dep_key in seen_url:
                        # Already fetched — just extend the parent's terms if needed.
                        # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
                        if target_cand is not None:
                            if _svar_sub not in target_cand.requires_names:
                                from milpa.solver import Term as _Term
                                from milpa.version import VersionSet as _VS
                                target_cand.dep_terms.append(
                                    _Term.require(_svar_sub, _VS.full())
                                )
                                target_cand.requires_names.append(_svar_sub)
                        continue

                    # Not yet fetched — extend terms AND enqueue.
                    if target_cand is not None:
                        if _svar_sub not in target_cand.requires_names:
                            from milpa.solver import Term as _Term
                            from milpa.version import VersionSet as _VS
                            target_cand.dep_terms.append(
                                _Term.require(_svar_sub, _VS.full())
                            )
                            target_cand.requires_names.append(_svar_sub)
                    _enqueue_dep(sub_dep, overrides_by_name, bfs_queue)

                elif isinstance(sub_dep, _NamedDep):
                    # S5b: use DepKey with namespace from sub_dep (transitive named deps
                    # discovered during solve have namespace=None; direct manifest deps carry
                    # the namespace from their manifest declaration).
                    _sdk = DepKey(name=sub_dep.name, namespace=sub_dep.namespace)
                    # S5-rekey (RFC origin-as-identity §4.4): the solver
                    # variable is the BOUND source-id's canonical form.
                    # Computed via the pure canonical_key_for_requirement
                    # (not BindingResolver.canonical_for) because this
                    # sub_dep's claim is not yet submitted at this point —
                    # that happens later, when ``_enqueue_dep`` below lands
                    # it back on the BFS queue and the "named" arm processes
                    # it (mirrors edgeset_to_terms's identical pre-submission
                    # need for the same reason).
                    from milpa.binding import canonical_key_for_requirement as _ckfr_s4a
                    _svar = _ckfr_s4a(
                        name=sub_dep.name,
                        namespace=sub_dep.namespace,
                        url=None,
                        overrides_by_name=overrides_by_name,
                        index=index,
                        root_self_name=root_self_name,
                        binding_resolver=binding_resolver,
                    )
                    if _sdk in seen_named:
                        if target_cand is not None:
                            if _svar not in target_cand.requires_names:
                                from milpa.solver import Term as _Term
                                from milpa.version import VersionSet as _VS
                                vs = (
                                    sub_dep.constraint_set
                                    if sub_dep.constraint_set is not None
                                    else _VS.full()
                                )
                                target_cand.dep_terms.append(
                                    _Term.require(_svar, vs)
                                )
                                target_cand.requires_names.append(_svar)
                        continue
                    if target_cand is not None:
                        if _svar not in target_cand.requires_names:
                            from milpa.solver import Term as _Term
                            from milpa.version import VersionSet as _VS
                            vs = (
                                sub_dep.constraint_set
                                if sub_dep.constraint_set is not None
                                else _VS.full()
                            )
                            target_cand.dep_terms.append(
                                _Term.require(_svar, vs)
                            )
                            target_cand.requires_names.append(_svar)
                    _enqueue_dep(sub_dep, overrides_by_name, bfs_queue)

        if not any_change:
            _converged = True
            break

        # ---------------------------------------------------------------
        # Step 6: re-run BFS for newly-enqueued items.
        # The executor is passed in; it remains open for the fixpoint duration.
        # ---------------------------------------------------------------
        _run_bfs_wave_loop(
            bfs_queue=bfs_queue,
            executor=executor,
            seen_named=seen_named,
            seen_url=seen_url,
            seen_tarball=seen_tarball,
            seen_local=seen_local,
            seen_oci=seen_oci,
            edge_cache=edge_cache,
            provider=provider,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            root_authority=root_authority,
            record_discovery=record_discovery,
            binding_resolver=binding_resolver,
            is_strict=is_strict,
            root_self_name=root_self_name,
            root_self_version=root_self_version,
        )

        # After each BFS wave we loop back to step 1 to re-check if the newly-
        # fetched deps' manifests generate further cross-pkg enables.

    # M3: if the loop exhausted MAX_ITERS without converging, it's a bug.
    # Monotonicity guarantees convergence in O(|deps|×max_flags) — well under 50.
    if not _converged:
        raise MilpaError(
            MILPA_INTERNAL,
            f"S4a flag fixpoint did not converge in {_MAX_ITERS} iterations — "
            "this is an internal milpa bug; please report it",
        )


# ---------------------------------------------------------------------------
# S4c (RFC #23 §3.1.4): post-fixpoint flag-conflict validation
# ---------------------------------------------------------------------------

#: Canonical serialization order for ActivationSource variants (normative —
#: matches enum declaration order: DEFAULT, EDGE_REQUEST, ENABLES_RULE, CLI).
#: Both impls must serialize source sets using this ordering so that the
#: ``RESOLVE-FLAG-CONFLICT`` payload is byte-identical cross-impl (§5 risk #3).
_ACTIVATION_SOURCE_ORDER: "dict[ActivationSource, int]" = {
    ActivationSource.DEFAULT: 0,
    ActivationSource.EDGE_REQUEST: 1,
    ActivationSource.ENABLES_RULE: 2,
    ActivationSource.CLI: 3,
}

#: Canonical string names for ActivationSource variants in the error payload.
_ACTIVATION_SOURCE_NAMES: "dict[ActivationSource, str]" = {
    ActivationSource.DEFAULT: "default",
    ActivationSource.EDGE_REQUEST: "edge_request",
    ActivationSource.ENABLES_RULE: "enables_rule",
    ActivationSource.CLI: "cli",
}


def _serialize_sources(sources: "set[ActivationSource]") -> "list[str]":
    """Serialize an ActivationSource set to a sorted list of string names.

    Normative ordering: enum declaration order (DEFAULT < EDGE_REQUEST <
    ENABLES_RULE).  Both impls apply this ordering so the payload is
    byte-identical cross-impl (RFC #23 §5 risk #3).
    """
    return [
        _ACTIVATION_SOURCE_NAMES[s]
        for s in sorted(sources, key=lambda s: _ACTIVATION_SOURCE_ORDER[s])
    ]


def _raise_if_flag_conflicts(
    dep_name: str,
    flag_decls: "Sequence[FlagDecl]",
    active_map: "dict[str, set[ActivationSource]]",
) -> None:
    """SSOT inner conflict check: raise RESOLVE-FLAG-CONFLICT if any pair conflicts.

    Algorithm (normative, RFC §3.1.4):
        for each flag f ∈ active_map,
        for each g in f.conflicts:
            if g ∈ active_map: raise RESOLVE-FLAG-CONFLICT.

    Used by both ``_s4c_check_flag_conflicts`` (transitive deps) and the root
    CLI-flag conflict check (C1b-completion).  The error payload is byte-identical
    regardless of call site: ``{dep, flag_a, flag_b, sources_a, sources_b}``.
    """
    from milpa.errors import RESOLVE_FLAG_CONFLICT

    flag_by_name: "dict[str, FlagDecl]" = {fd.name: fd for fd in flag_decls}
    active_flag_names: "frozenset[str]" = frozenset(active_map.keys())

    for flag_name, sources in active_map.items():
        fd = flag_by_name.get(flag_name)
        if fd is None:
            continue
        for conflict_name in fd.conflicts:
            if conflict_name not in active_flag_names:
                continue

            # Both flags are active.  Canonical ordering: lex on names.
            if flag_name <= conflict_name:
                fa, fb = flag_name, conflict_name
            else:
                fa, fb = conflict_name, flag_name

            sources_a = active_map.get(fa, set())
            sources_b = active_map.get(fb, set())
            raise MilpaError(
                RESOLVE_FLAG_CONFLICT,
                f"dep {dep_name!r}: flags {fa!r} and {fb!r} are declared "
                f"mutually exclusive (conflicts) but both are active",
                dep=dep_name,
                flag_a=fa,
                flag_b=fb,
                sources_a=_serialize_sources(sources_a),
                sources_b=_serialize_sources(sources_b),
            )


def _s4c_check_flag_conflicts(
    provider: "_Provider",
    deps_dir: "Path",
) -> None:
    """S4c post-fixpoint validation pass (RFC #23 §3.1.4).

    Runs AFTER the dep×flag fixpoint (``_s4a_run_fixpoint``) fully converges
    and BEFORE the solver.  Only *reads* the converged ``dep_active_flags`` —
    never retracts, so monotonicity is untouched and the check is
    order-independent (both impls see the same converged set).

    Algorithm (normative, RFC §3.1.4):
        for each dep D,
        for each flag f ∈ active(D),
        for each g in f.conflicts:
            if g ∈ active(D): raise RESOLVE-FLAG-CONFLICT.

    Same-package only — cross-package conflicts are deferred (#151).

    The error carries ``{dep, flag_a, flag_b, sources_a, sources_b}`` where:
      - dep     — the dep name (string)
      - flag_a  — the lexicographically smaller conflicting flag name
      - flag_b  — the lexicographically larger conflicting flag name
      - sources_a / sources_b — ActivationSource sets for flag_a / flag_b,
                  serialized as sorted lists using _ACTIVATION_SOURCE_ORDER
                  (enum declaration order, identical in both impls — §5 risk #3)
    """
    from milpa.manifest import parse_manifest as _pm

    for dep_name in list(provider._candidates.keys()):
        if dep_name == "__root__":
            continue

        # Find the candidate's identity (dep_active_flags is keyed by identity).
        cand_map = provider._candidates.get(dep_name, {})
        identity: str | None = None
        for cand in cand_map.values():
            if cand.identity is not None:
                identity = cand.identity
                break

        if identity is None:
            continue  # no materialised candidate (e.g. named stub not yet fetched)

        # Load the dep's manifest to get its flag declarations (for conflicts).
        # We need this regardless of whether dep_active_flags has an entry,
        # because a dep with no consumer requests may still have default=#true
        # flags that conflict.
        # C1/H2 fix: decompose the solver-var (S5-rekey: a BOUND source-id's
        # canonical form for a named dep) via DepKey so qualified deps
        # resolve to ``_deps/@ns/bar/milpa.kdl``.
        _dk_s4c = _depkey_for_solved_name(dep_name)  # type: ignore[attr-defined]
        kdl_path = deps_dir / dep_dir_name(_dk_s4c.name, _dk_s4c.namespace) / "milpa.kdl"
        if not kdl_path.exists():
            continue
        try:
            dm = _pm(kdl_path.read_text(encoding="utf-8"))
        except Exception:
            continue  # non-fatal: can't load manifest → skip conflict check

        # Get or derive the active_map.
        # dep_active_flags may not have an entry if the dep had no consumer
        # flag requests.  In that case, derive active from defaults only (§3.1.2
        # rule 1: active(D) ⊇ { f ∈ D.flags : f.default }).
        active_map = provider.dep_active_flags.get(identity)
        if not active_map:
            # Compute defaults-only active set.
            active_map = compute_dep_active_flags(dm.flags, ())
            if not active_map:
                continue  # no active flags — nothing to check

        # Delegate to the SSOT helper (also used for root CLI flag check).
        # RFC §4.4.1 (S5-rekey): the error payload's ``dep`` field must be
        # the bare/qualified legacy name, never the raw canonical solver
        # key — _dk_s4c (decoded above) is already the correct projection.
        _raise_if_flag_conflicts(_dk_s4c.solver_var(), dm.flags, active_map)


# ---------------------------------------------------------------------------
# Core resolve() implementation
# ---------------------------------------------------------------------------


def resolve(
    manifest: Manifest,
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
) -> ResolvedGraph:
    """Full live resolve for a single-package manifest.

    Parameters
    ----------
    manifest:
        The parsed package manifest.
    deps_dir:
        Where fetched dep trees are placed (typically ``_deps/``).
    env:
        Injectable seams: ``fetcher``, ``index``, ``store``.
    params:
        Per-call parameters: ``strategy``, ``max_parallel``, ``profile``,
        ``prior``.

    Returns
    -------
    ResolvedGraph
        The complete set of resolved deps.

    Raises
    ------
    MilpaError
        Any MAN-*, TNG-*, FETCH-*, SOLVE-*, RES-* slug.
    """
    deps_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Step 1: predicate filtering (§6, slice 9b-2)
    #
    # Run BEFORE any BFS or solver input construction.
    # Profile=None → no filtering (§6 NORMATIVE).
    #
    # S9 (RFC #23 §3.4): CLI feature inputs override root flag seeding.
    # Compute the cli_active_seed from ResolveParams.features /
    # no_default_features / all_features; pass it into the filter so that
    # flag-predicated deps are admitted/pruned based on the CLI selection.
    # An unknown --features flag name raises FROZEN-ACTIVE-FLAGS-MISMATCH
    # (surface-don't-hide: the user named a non-existent root flag).
    # ------------------------------------------------------------------
    _has_cli_features = (
        bool(params.features) or params.no_default_features or params.all_features
    )
    _cli_active_seed: frozenset[str] | None = None
    if _has_cli_features:
        _cli_active_seed = _compute_cli_active_seed(
            manifest.flags,
            features=params.features,
            no_default_features=params.no_default_features,
            all_features=params.all_features,
        )
        # C1b-completion: root CLI-selected flags participate in conflict
        # detection (RFC #23 §3.1.4).  The root has no fetched identity so
        # it bypasses the dep_active_flags machinery; use the SSOT helper
        # directly with a synthetic active_map where every flag in the CLI
        # seed has source CLI.  Mirrors the Rust check_s4c_flag_conflicts
        # root path (both impls do this check at the same point: immediately
        # after _cli_active_seed is finalised, before BFS).
        #
        # R2-M C1b fix: apply same-package enables-closure BEFORE the conflict
        # check so that flags enabled transitively by CLI-active root flags are
        # included.  Without this, a CLI-active flag A that enables B where B
        # conflicts C (also CLI-active) would be silently missed.
        if manifest.flags and _cli_active_seed:
            _cli_closed: frozenset[str] = flag_enables_closure(manifest.flags, _cli_active_seed)
            _root_cli_active_map: dict[str, set[ActivationSource]] = {
                flag_name: {ActivationSource.CLI}
                for flag_name in _cli_active_seed
            }
            # Flags added by enables-closure get source ENABLES_RULE (not CLI).
            for _ec_flag in _cli_closed - _cli_active_seed:
                _root_cli_active_map[_ec_flag] = {ActivationSource.ENABLES_RULE}
            _raise_if_flag_conflicts(manifest.name, manifest.flags, _root_cli_active_map)

    # Route through the shared FilterContext + filter_manifest (S1 §3.A).
    # FilterContext.build computes the enables-closure from this manifest's flags;
    # filter_manifest applies the two independent predicates (profile gate +
    # flag gate) in a single pass with no double-evaluation (Depth-F7).
    _filter_ctx = FilterContext.build(
        manifest,
        params.profile,
        cli_seed=_cli_active_seed,
    )
    manifest = filter_manifest(manifest, _filter_ctx)

    # ------------------------------------------------------------------
    # Step 2: check index availability for named deps
    # ------------------------------------------------------------------
    overrides_by_name: dict[str, Override] = {ov.name: ov for ov in manifest.overrides}

    # M7: warn early about member= overrides in a single-package manifest.
    # These silently no-op (member overrides require a workspace context); warn
    # before the BFS so the user gets feedback even if resolution fails.
    import warnings as _warnings_early
    _member_override_names_early = sorted(
        ov.name for ov in manifest.overrides
        if isinstance(ov.target, MemberTarget)
    )
    if _member_override_names_early:
        _warnings_early.warn(
            f"member override(s) {', '.join(_member_override_names_early)!r} have no effect in a "
            f"single-package manifest (member= overrides require a workspace context)",
            UserWarning,
            stacklevel=4,
        )

    # Collect all deps (regular + dev-deps; dev-deps are enrolled for the root
    # per §9 NORMATIVE).
    all_root_deps = list(manifest.deps) + list(manifest.dev_deps)

    # Check for named deps that require the index.
    named_needing_index = [
        d.name for d in all_root_deps
        if isinstance(d, NamedDep) and d.name not in overrides_by_name
    ]
    if named_needing_index and env.index is None:
        raise MilpaError(
            RES_NO_INDEX,
            f"manifest has named dep(s) {named_needing_index!r} but no tianguis "
            f"index was provided — pass index= to resolve named deps",
            names=named_needing_index,
        )

    index: Index = env.index if env.index is not None else Index()

    # ------------------------------------------------------------------
    # Step 3: root authority set (§10 provenance precedence)
    # ------------------------------------------------------------------
    # RR2 (R6 dual-set cleanup): build the namespace-aware set ONCE, then
    # derive the bare-name authority set as a pure name-projection of it —
    # replacing two independently hand-built collections (which could
    # silently desync when a dep kind was added to one loop and missed in
    # the other) with one populated collection + one projection.
    #
    # Each root dep's ACTUAL namespace is threaded through (NamedDep carries
    # `.namespace`; url/local/tarball/member deps have none, so
    # `getattr(..., None)` yields the same None that DepKey.from_solver_var
    # decomposes their bare solver var into). Overrides are name-based only
    # (no namespace concept).
    root_direct_keys: set[DepKey] = {
        DepKey(name=d.name, namespace=getattr(d, "namespace", None))
        for d in all_root_deps
    } | {DepKey(name=ov.name) for ov in manifest.overrides}

    # R6: namespace-aware authority set — used ONLY by is_root_direct (the
    # lowest-direct precompute). Provably byte-identical to the old
    # independently-built `root_authority` set: both are sourced from
    # exactly `all_root_deps` (regular + dev-deps) + `manifest.overrides`
    # names — the SAME two sources — so projecting `root_direct_keys` down
    # to just its `.name` field yields the exact same set of bare names.
    #
    # RFC origin-as-identity §6 "Kept": ``root_authority`` (this bare-name
    # projection) survives post-S3b for TWO remaining single-purpose
    # consumers, now that the ``provenance_gate``/``_check_provenance_gate``
    # side-table that used to be its primary consumer is deleted:
    #   1. ``_version_unknown_constrained_err`` — branches the
    #      ``RES-VERSION-UNKNOWN-CONSTRAINED`` remedy on whether the
    #      package has a user-owned declaration site.
    #   2. the registry-shadow tripwire gate in ``_run_bfs_wave_loop``
    #      (``if dep_u.name not in root_authority: check_registry_shadow(...)``)
    #      — root's own explicit source choice is never second-guessed.
    # Source ADMISSION/arbitration itself is entirely ``BindingResolver``'s
    # job now (``binding.py``). Its bare-name (not ``DepKey``) scoping is a
    # known, deliberately out-of-scope gap — the open #192/R6 namespace door.
    root_authority: set[str] = {k.name for k in root_direct_keys}

    # ------------------------------------------------------------------
    # Step 4: build the provider and dedup sets
    # ------------------------------------------------------------------
    seen_url: set[tuple[str, str, str | None]] = set()
    seen_named: set[DepKey] = set()  # S5a: qualified key (namespace+name)
    seen_local: set[str] = set()
    seen_tarball: set[str] = set()
    seen_oci: set[str] = set()  # S8b: keyed by "registry/repository@digest"

    # Phase B dedup: BFS-insertion discovery order (list of dep names in first-
    # enqueue order).  Root deps in declaration order first; transitive deps in
    # first-occurrence-enqueue order.  Canonical name = group member with the
    # smallest discovery_order index (BFS-first, not lex-min).
    discovery_order: list[str] = []
    _discovery_seen: set[str] = set()

    def _record_discovery(name: str) -> None:
        """Record a name in BFS-insertion discovery order (idempotent)."""
        if name not in _discovery_seen:
            _discovery_seen.add(name)
            discovery_order.append(name)

    # Resolver-scoped edge memo (§4.2.1 resolve_edges clause a).
    # Sealed once per (name, version) — shared with provider for _materialize.
    edge_cache: dict[tuple[SourceId, Version], EdgeSet] = {}

    from milpa.trust import effective_trust_policy as _eff_trust
    _is_strict_early = _eff_trust(manifest.attestation_policy, params.require_attested_metadata) == "strict"

    # RFC origin-as-identity §4.3 (S3a): the binding phase that produces the
    # solver's source-id variables. Root/override claims are reconciled
    # (override pre-empts a same-name root dep declaration) and bound here,
    # once, before any transitive claim can arrive; only transitive claims
    # go through ``binding_resolver.submit()`` in the BFS loop below.
    # MemberTarget overrides are excluded from reconciliation for a
    # standalone (non-workspace) resolve — mirrors the root-seeding loop's
    # own MemberTarget-in-single-package no-op below (M7): there is no
    # workspace context for such an override to redirect into.
    # §14/§6 "root satisfies its own name" — the standalone root is a
    # workspace-of-one (RFC §6 "Kept"): its OWN name binds to a
    # ``MemberSourceId`` sentinel, exactly like a workspace member's self-
    # registration, so a transitive `requires "<manifest.name>"` naturally
    # comes back ``LOST_TO_ROOT`` (never a registry enumeration attempt —
    # there is no registry entry for the project's own name) when it
    # reaches the "named" BFS arm below.
    #
    # Constructed BEFORE ``_Provider`` (S4): ``_Provider._materialize`` needs
    # ``binding_resolver.source_id_for`` to key the edge_cache by source_id
    # rather than name (RFC §4.5) — neither construction depends on the
    # other's output, so this is a pure reorder, not a behavior change.
    binding_resolver = BindingResolver(
        reconcile_root_claims(
            all_root_deps,
            [ov for ov in manifest.overrides if not isinstance(ov.target, MemberTarget)],
            index=index,
        )
        + [
            Claim(
                name=manifest.name,
                source_id=MemberSourceId(member_name=manifest.name),
                is_root=True,
                claimant="root-self",
            )
        ]
    )

    provider = _Provider(
        env=env,
        deps_dir=deps_dir,
        params=params,
        overrides_by_name=overrides_by_name,
        root_direct_keys=root_direct_keys,
        seen_named=seen_named,
        seen_url=seen_url,
        binding_resolver=binding_resolver,
        edge_cache=edge_cache,
        strict_attestation=_is_strict_early,
        root_self_name=manifest.name,
    )

    # ------------------------------------------------------------------
    # Step 5: seed the root candidate
    #
    # ORDERING INVARIANT (§4.2.1 NORMATIVE):
    # Root deps are seeded in declaration order (manifest.deps first, then
    # manifest.dev_deps — same as all_root_deps).  The BFS queue processes
    # items FIFO; transitive deps are appended to the queue on first
    # occurrence.  This preserves the canonical BFS package order P.
    # ------------------------------------------------------------------
    root_terms: list[Term] = []
    root_requires: list[str] = []

    # BFS queue: items are tuples dispatched below.
    # Format: ("url", UrlDep) | ("named", DepKey, str|None)
    #        | ("tarball", TarballDep) | ("local", LocalDep)
    # S5a: named items carry a DepKey (namespace + bare name) so the solver
    # variable and seen_named key agree on the qualified identity.
    bfs_queue: list[object] = []

    for dep in all_root_deps:
        # Apply overrides: a named dep whose name is in overrides_by_name
        # is treated as a URL dep at the sentinel version (git form),
        # or as local (S8a) / member (S8b).
        if isinstance(dep, UrlDep):
            if dep.name in overrides_by_name:
                ov = overrides_by_name[dep.name]
                # S8a: LocalTarget override on a root UrlDep → local BFS slot.
                if isinstance(ov.target, LocalTarget):
                    # RFC §4.4.1 (S5-rekey, phase 2): solver variable = BOUND
                    # source-id canonical form, UNIFORMLY (no eager-kind bare-
                    # name carve-out). Root claim already bound at
                    # BindingResolver.__init__ (reconcile_root_claims), above.
                    _svar_lt = binding_resolver.canonical_for(DepKey(name=dep.name))
                    # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
                    root_terms.append(Term.require(_svar_lt, VersionSet.full()))
                    root_requires.append(_svar_lt)
                    bfs_queue.append(("local", LocalDep(name=dep.name, path=ov.target.path, version=ov.version)))
                    _record_discovery(_svar_lt)
                    continue
                # S8b: TarballTarget/OciTarget/RegistryTarget override on a
                # root UrlDep → route to the matching BFS slot.
                if _seed_extended_override_target(
                    dep.name, ov,
                    binding_resolver=binding_resolver, root_terms=root_terms,
                    root_requires=root_requires, bfs_queue=bfs_queue,
                    record_discovery=_record_discovery,
                ):
                    continue
                # S8b: MemberTarget in a single-package manifest is a no-op (no
                # workspace context; member candidates are never pre-registered
                # for single-package resolve).  Treat as if the override were absent.
                if isinstance(ov.target, MemberTarget):
                    effective_dep = dep
                else:
                    effective_dep = _apply_git_override_to_url_dep(dep, ov)
            else:
                effective_dep = dep
            # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
            _svar_url = binding_resolver.canonical_for(DepKey(name=dep.name))
            # Axis A (a)/D-A2: full() self-term, never eq(sentinel) — the causality
            # fix (term built pre-fetch; the real label is assigned post-fetch).
            root_terms.append(Term.require(_svar_url, VersionSet.full()))
            root_requires.append(_svar_url)
            bfs_queue.append(("url", effective_dep))
            _record_discovery(_svar_url)  # Phase B: root URL deps in declaration order

        elif isinstance(dep, NamedDep):
            if dep.name == "nim":
                continue
            if dep.name in overrides_by_name:
                # Named dep with override → URL fetch or local (S8a).
                ov = overrides_by_name[dep.name]
                # S8a: LocalTarget override on a root NamedDep → local BFS slot.
                if isinstance(ov.target, LocalTarget):
                    _svar_nlt = binding_resolver.canonical_for(DepKey(name=dep.name))
                    # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
                    root_terms.append(
                        Term.require(_svar_nlt, VersionSet.full())
                    )
                    root_requires.append(_svar_nlt)
                    bfs_queue.append(("local", LocalDep(name=dep.name, path=ov.target.path, version=ov.version)))
                    _record_discovery(_svar_nlt)  # Phase B: overridden named → local
                    continue
                # S8b: TarballTarget/OciTarget/RegistryTarget override on a
                # root NamedDep → route to the matching BFS slot.
                if _seed_extended_override_target(
                    dep.name, ov,
                    binding_resolver=binding_resolver, root_terms=root_terms,
                    root_requires=root_requires, bfs_queue=bfs_queue,
                    record_discovery=_record_discovery,
                ):
                    continue
                # S8b: MemberTarget in a single-package manifest is a no-op;
                # fall through to named-dep handling (no workspace member to resolve to).
                if isinstance(ov.target, MemberTarget):
                    # S5b: carry namespace from manifest dep
                    _dk_mt = DepKey(name=dep.name, namespace=dep.namespace)
                    vs = dep.constraint_set if dep.constraint_set is not None else VersionSet.full()
                    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver
                    # key. Root claim already bound at BindingResolver.__init__
                    # (reconcile_root_claims), above.
                    _svar_mt = binding_resolver.canonical_for(_dk_mt)
                    root_terms.append(Term.require(_svar_mt, vs))
                    root_requires.append(_svar_mt)
                    bfs_queue.append(("named", _dk_mt, dep.constraint))
                    _record_discovery(_svar_mt)
                    continue
                effective_dep = _apply_git_override_to_url_dep(
                    UrlDep(name=dep.name, git="", ref=""), ov
                )
                _svar_nu = binding_resolver.canonical_for(DepKey(name=dep.name))
                # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
                root_terms.append(
                    Term.require(_svar_nu, VersionSet.full())
                )
                root_requires.append(_svar_nu)
                bfs_queue.append(("url", effective_dep))
                _record_discovery(_svar_nu)  # Phase B: overridden named → URL
            else:
                # S5b: carry namespace from manifest dep.
                _dk = DepKey(name=dep.name, namespace=dep.namespace)
                vs = dep.constraint_set if dep.constraint_set is not None else VersionSet.full()
                # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
                # Root claim already bound at BindingResolver.__init__
                # (reconcile_root_claims), above.
                _svar = binding_resolver.canonical_for(_dk)
                root_terms.append(Term.require(_svar, vs))
                root_requires.append(_svar)
                bfs_queue.append(("named", _dk, dep.constraint))
                _record_discovery(_svar)  # Phase B: named deps in declaration order
                # S3: store flag_requests keyed by solver_var so _materialize can use them.
                if dep.flag_requests:
                    provider._flag_requests_by_name[_svar] = dep.flag_requests

        elif isinstance(dep, TarballDep):
            # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
            _svar_tb = binding_resolver.canonical_for(DepKey(name=dep.name))
            # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
            root_terms.append(Term.require(_svar_tb, VersionSet.full()))
            root_requires.append(_svar_tb)
            bfs_queue.append(("tarball", dep))
            _record_discovery(_svar_tb)  # Phase B: root tarball deps in declaration order

        elif isinstance(dep, LocalDep):
            # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
            _svar_lo = binding_resolver.canonical_for(DepKey(name=dep.name))
            # Axis A (a)/D-A2: full() self-term, never eq(sentinel).
            root_terms.append(Term.require(_svar_lo, VersionSet.full()))
            root_requires.append(_svar_lo)
            bfs_queue.append(("local", dep))
            _record_discovery(_svar_lo)  # Phase B: root local deps in declaration order

        elif isinstance(dep, MemberDep):
            # RFC §4.4.1 (D3): a `member "<name>"` reference is workspace-only
            # topology. In a single-package (non-workspace) manifest it has no
            # candidate to resolve to. Fail closed with a coded error rather
            # than silently dropping the edge (which would mask a real authoring
            # mistake). The Rust impl raises the SAME slug at its root-seed arm.
            raise MilpaError(
                RES_MEMBER_OUTSIDE_WORKSPACE,
                f"member {dep.name!r} is declared in a single-package manifest; "
                "`member` deps are only valid inside a workspace — declare a "
                "`workspace { member … }` block, or use git=/local= for a "
                "cross-repo dependency",
                name=dep.name,
            )

    root_cand = _Candidate(
        name="__root__",
        version=Version(0, 0, 0),
        identity=None,
        src_dir="",
        dep_terms=root_terms,
        requires_names=root_requires,
        provenance=None,
    )
    provider.add(root_cand)

    # ------------------------------------------------------------------
    # Step 5b (§14 "root satisfies its own name"): pre-register the root
    # itself as a candidate for its OWN declared name — a standalone package
    # is a workspace-of-one (§11.5's member self-registration, applied to
    # the non-workspace path).  No dep_terms of its own: the root's deps are
    # already fully represented by root_cand above; this candidate exists
    # purely so a transitive `requires "<manifest.name>"` has something to
    # bind to other than a second fetch.
    # ------------------------------------------------------------------
    _root_self_version, _root_self_version_source = _root_self_candidate_version(
        manifest, params.manifest_dir
    )
    # S5-rekey (RFC origin-as-identity §4.4): keyed by the BOUND source-id's
    # canonical form (the root-self MemberSourceId sentinel), not the bare
    # manifest name — so a transitive requirement on the root's own name
    # (computed via canonical_key_for_requirement's root_self_name branch)
    # finds this candidate under the SAME key it requires.
    root_self_cand = _Candidate(
        name=binding_resolver.canonical_for(DepKey(name=manifest.name)),
        version=_root_self_version,
        # §14.5: no separate identity — the project root is not an isolated,
        # independently-hashed tree the way a fetched dep or workspace
        # member directory is (it typically also holds _deps/, milpa.lock,
        # etc.); mirrors __root__'s own identity=None.
        identity=None,
        src_dir=manifest.src_dir or "",
        dep_terms=[],
        requires_names=[],
        provenance=RootProvenanceRecord(name=manifest.name),
        declared_version_source=_root_self_version_source,
    )
    provider.add(root_self_cand)

    # §14.2: the root's own name is root-authoritative (§10.1) — added here
    # (rather than folded into the root_direct_keys/root_authority
    # construction above) so the two additions stay visually adjacent to the
    # self-candidate they protect. The root's OWN claim on its own name is
    # bound into ``binding_resolver`` above (the ``root-self`` ``Claim`` with
    # a ``MemberSourceId`` — RFC origin-as-identity §4.3/§6 "root satisfies
    # its own name"), so a transitive claim on this same name is suppressed
    # by ``BindingResolver.submit`` returning ``LOST_TO_ROOT``, with no
    # dedicated pre-seed needed here.
    root_direct_keys.add(DepKey(name=manifest.name))
    root_authority.add(manifest.name)

    # ------------------------------------------------------------------
    # Step 6: BFS materialisation loop (slice 9b-7: parallel fetch)
    #
    # The BFS queue is processed in waves (see _run_bfs_wave_loop for the
    # full wave-processing spec and ordering invariant commentary).
    #
    # ORDERING INVARIANT (§4.2.1 NORMATIVE, §4.4 NORMATIVE):
    # The lockfile output MUST be identical regardless of ``params.max_parallel``
    # (resolver-semantics §4.4 second NORMATIVE block).  This holds because:
    #   (a) BFS package order P is determined by declaration order only —
    #       parallel fetch does not change WHICH deps enter the solver, only
    #       WHEN their I/O completes.
    #   (b) The lockfile is sorted lexicographically by dep name (§4.4), not
    #       by BFS arrival time — so fetch-completion order has no effect on
    #       output bytes.
    #   (c) Named dep enumeration (Phase A) is synchronous — the thread pool
    #       only executes URL/tarball/local fetches (I/O-bound).
    # ------------------------------------------------------------------
    workers = max(1, params.max_parallel)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        _run_bfs_wave_loop(
            bfs_queue=bfs_queue,
            executor=executor,
            seen_named=seen_named,
            seen_url=seen_url,
            seen_tarball=seen_tarball,
            seen_local=seen_local,
            seen_oci=seen_oci,
            edge_cache=edge_cache,
            provider=provider,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            root_authority=root_authority,
            record_discovery=_record_discovery,
            binding_resolver=binding_resolver,
            is_strict=_is_strict_early,
            root_self_name=manifest.name,
            root_self_version=_root_self_version,
        )

        # ------------------------------------------------------------------
        # Step 6a: S4a dep×flag fixpoint (RFC #23 §3.1.2 + §7 S4a)
        #
        # After the initial BFS wave, iterate until neither the admitted dep
        # set nor the active-flag set grows.  The executor remains open so
        # newly-admitted deps can be fetched in parallel within the fixpoint.
        #
        # PubGrub runs exactly ONCE, AFTER this fixpoint converges (§3.1.2
        # "PubGrub runs exactly once, after the dep×flag fixpoint fully
        # converges").  Feature activation is a pre-solver / edge-admission
        # concern, never interleaved with unit-propagation.
        # ------------------------------------------------------------------
        _s4a_run_fixpoint(
            provider=provider,
            bfs_queue=bfs_queue,
            executor=executor,
            seen_named=seen_named,
            seen_url=seen_url,
            seen_tarball=seen_tarball,
            seen_local=seen_local,
            seen_oci=seen_oci,
            edge_cache=edge_cache,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            root_authority=root_authority,
            record_discovery=_record_discovery,
            binding_resolver=binding_resolver,
            is_strict=_is_strict_early,
            root_self_name=manifest.name,
            root_self_version=_root_self_version,
        )

    # ------------------------------------------------------------------
    # Step 6b-pre: S4c post-fixpoint flag-conflict validation
    #
    # Runs AFTER the dep×flag fixpoint converges, BEFORE solver entry.
    # Only reads the converged dep_active_flags — never retracts.
    # Raises RESOLVE-FLAG-CONFLICT if any dep has two mutually-exclusive
    # flags co-active in the final converged set (RFC #23 §3.1.4).
    # ------------------------------------------------------------------
    _s4c_check_flag_conflicts(provider, deps_dir)

    # ------------------------------------------------------------------
    # Step 7: wire Phase B transitive callback BEFORE solve
    #
    # When the solver calls ``provider.dependencies()`` for a named stub,
    # any newly-discovered transitive named deps must be enrolled
    # immediately so the solver can see them.
    # ------------------------------------------------------------------
    def _on_transitive_named(dep_key: DepKey) -> None:
        # S5-rekey (RFC origin-as-identity §4.4): the caller
        # (``_edgeset_named_requires`` via ``_Provider._materialize``) now
        # passes the ORIGINAL ``DepKey`` directly — no ``DepKey.from_solver_var``
        # reverse-decode here, since the solver-variable string this dep's
        # Term used is a BOUND source-id's canonical form, not a
        # ``"ns::bar"`` string (and may not even be bound yet — this
        # callback's whole job is the first-ever admission of a mid-solve
        # transitive named dep).
        if dep_key in seen_named or dep_key.name == "nim":
            return
        seen_named.add(dep_key)
        # RFC origin-as-identity §4.3 (S3a): this callback fires OUTSIDE the
        # BFS wave loop entirely (Phase B lazy materialisation, mid-solve —
        # ``_Provider._materialize`` calls it for every newly-discovered
        # transitive named dep), so it must independently route through
        # ``BindingResolver`` too — it is a SEPARATE admission site from the
        # "named" BFS arm, not a re-entry into it. This is what makes §14.2
        # "root satisfies its own name" (the MemberSourceId sentinel claim,
        # see ``resolve()``'s BindingResolver construction) work here too:
        # a late transitive claim on the root's own name mismatches that
        # sentinel and comes back LOST_TO_ROOT, exactly like a root/override-
        # pinned name would — root_self_cand alone remains the sole
        # candidate. A genuine mid-solve conflict (RFC's own
        # "TestMidSolveResidualClosedByImmediateValidation" fixture — a
        # registry package's OWN manifest requires a name an eager transitive
        # already bound to a disagreeing source) raises RES-BINDING-CONFLICT
        # here, exactly like the BFS "named" arm would.
        _named_claim_t = Claim(
            name=dep_key.solver_var(),
            source_id=normalize_source(
                RegistrySourceId(
                    registry=DEFAULT_REGISTRY_ALIAS,
                    namespace=resolved_registry_namespace(
                        dep_key.name, dep_key.namespace, index,
                    ),
                    name=dep_key.name,
                )
            ),
            is_root=False,
            claimant="transitive",
        )
        _named_decision_t = binding_resolver.submit(_named_claim_t)
        if _named_decision_t.outcome is BindOutcome.LOST_TO_ROOT:
            return
        # S5-rekey: record_discovery AFTER the claim is bound (canonical_for
        # requires it) — moved past the LOST_TO_ROOT early-return above, which
        # only tightens discovery_order to actually-participating deps (a
        # LOST_TO_ROOT name never gets a solved candidate anyway, so this is
        # a no-op for _dedup_candidates' tie-break, never a behavior change).
        _record_discovery(binding_resolver.canonical_for(dep_key))  # Phase B/S4b: mid-solve named dep —
        # a dedup canonical-selection tie-break now needs this position too,
        # since S4b's cross-origin collapse runs post-solve and can include a
        # named dep that was only ever discovered via THIS callback (mirrors
        # resolve_workspace()'s equivalent _ws_record_discovery call, which
        # already did this — this was a latent asymmetry between the two
        # entry points, harmless while dedup ran pre-solve, load-bearing now).
        _enumerate_named_stubs(
            dep_key, None, index, provider, deps_dir, env,
            exclude_newer=params.exclude_newer,
        )

    provider.set_transitive_callback(_on_transitive_named)

    # ------------------------------------------------------------------
    # Step 8: solve (+ build §5.1 certificate for --certificate flag)
    # ------------------------------------------------------------------
    try:
        solution, cert = solve_with_cert(
            provider,
            "__root__",
            Version(0, 0, 0),
            strategy=params.strategy,
        )
        # S5-rekey (RFC origin-as-identity §4.4): project the certificate's
        # PubGrub package strings back to the legacy "ns::name"/bare form —
        # certificate_to_json (solver.py) has no BindingResolver access.
        cert = _project_solve_success(cert)
    except VersionUnknownConstrained as exc:
        raise _version_unknown_constrained_err(exc, root_authority, binding_resolver) from exc
    except SolverError as exc:
        from milpa.errors import SOLVE_CONFLICT
        _projected_exc = _project_solver_error(exc)
        raise MilpaError(
            SOLVE_CONFLICT,
            f"dependency conflict: {_projected_exc}",
            chain=_projected_exc.chain,
            solver_error=_projected_exc,
        ) from exc

    # ------------------------------------------------------------------
    # Step 8b: Phase B content-hash dedup/alias (RFC origin-as-identity §3.3/
    # §4.5, S4b — cross-origin reconciliation)
    #
    # Runs on the SOLVED graph (post-solve, pre-build): group the solution's
    # chosen candidates by identity.  Groups of size ≥ 2 share a content hash
    # → collapse to one canonical dep.  Canonical = group member earliest in
    # BFS-insertion order (discovery_order list).  Running post-solve (not
    # pre-solve, as Phase B originally did) is what makes this cross-origin:
    # a named (registry) candidate is only ever materialized (fetched) when
    # the solver asks for its dependencies, so its real identity isn't known
    # until solve_with_cert returns — by then, every solved candidate (named
    # or eager) has been. _build_graph uses aliases_map to fold each
    # non-canonical entry into its canonical peer, carrying its own
    # provenance along (both origins' audit trail survives the collapse).
    # ------------------------------------------------------------------
    aliases_map: dict[str, str] = _dedup_candidates(
        provider, deps_dir, discovery_order, overrides_by_name, solution
    )

    # ------------------------------------------------------------------
    # Step 9: build the ResolvedGraph (attach cert for CLI §2.5)
    # ------------------------------------------------------------------
    graph = _build_graph(
        solution, provider, deps_dir, params.strategy,
        aliases_map=aliases_map, entry_trust=params.entry_trust,
        binding_resolver=binding_resolver,
    )

    # ------------------------------------------------------------------
    # Step 10: S5 attestation policy enforcement
    #
    # Collect the EdgeSets for all resolved non-root deps from edge_cache.
    # The effective policy is the OR of manifest.attestation_policy and
    # params.require_attested_metadata.  Under non-strict: emit one summary
    # warning if any dep used NimbleFallback.  Under strict: raise
    # RES-UNATTESTED-METADATA.
    # ------------------------------------------------------------------
    from milpa.attestation import enforce_attestation_policy
    is_strict = _is_strict_early  # already computed above
    # edge_cache holds (source_id, version) → EdgeSet for all deps seen during
    # BFS (RFC origin-as-identity §4.5, S4). __root__ and workspace members
    # are excluded naturally: neither is ever recorded in ``discovery_order``
    # (root never goes through BFS-seal; members are pre-registered
    # candidates, never fetched/materialized). Reverse-map source_id → a
    # display name via ``discovery_order`` (BFS-first wins on a coalesced
    # diamond — the same canonical-selection convention ``_dedup_candidates``
    # uses) so ``enforce_attestation_policy``'s messages stay name-keyed.
    _name_by_source_id: dict[SourceId, str] = {}
    for _n in discovery_order:
        # S5-rekey: discovery_order now holds canonical solver-variable
        # strings for named deps (bare dep.name for eager deps) — decode via
        # the shared canonical-or-legacy helper for BOTH the lookup key and
        # the DISPLAY name stored below (attestation-policy warning text
        # must never show the raw canonical string).
        _dk_disp = _depkey_for_solved_name(_n)
        _sid = binding_resolver.source_id_for(_dk_disp)
        if _sid is not None and _sid not in _name_by_source_id:
            _name_by_source_id[_sid] = _dk_disp.solver_var()
    resolved_edge_map: dict[str, EdgeSet] = {
        _name_by_source_id[sid]: es
        for (sid, _ver), es in edge_cache.items()
        if sid in _name_by_source_id
    }
    enforce_attestation_policy(resolved_edge_map, is_strict)

    from dataclasses import replace as _replace
    graph = _replace(graph, cert=cert)

    # S8a: non-reproducible override warning (RFC #23 §3.3 reproducibility carve-out).
    # A local= override produces a LocalProvenanceRecord for a dep that was originally
    # declared as a git/named dep — it is non-reproducible for anyone without the same
    # sibling checkout at the same relative path.  Warn once per affected dep name.
    import warnings as _warnings
    from milpa.lockfile import LocalProvenanceRecord as _LPR
    _local_override_names = sorted(
        dep.name for dep in graph.deps
        if dep.name in overrides_by_name
        and isinstance(overrides_by_name[dep.name].target, LocalTarget)
        and any(isinstance(p, _LPR) for p in dep.provenances)
    )
    if _local_override_names:
        _warnings.warn(
            f"non-reproducible local override(s): {', '.join(_local_override_names)} — "
            f"lockfile will not reproduce on machines without the same local checkouts "
            f"at the declared relative paths (RFC #23 §3.3 reproducibility carve-out)",
            UserWarning,
            stacklevel=4,
        )

    # M6 / RES-DEAD-OVERRIDE (rfc-origin-as-identity.md §10 item 12 / B10,
    # S5b): warn about overrides that name a dep not in the resolved graph.
    # A typo in an override name silently no-ops without this check.
    # Non-fatal — resolution still succeeds — same warn-only pattern as
    # RES-REGISTRY-SHADOW's default policy.
    _resolved_dep_names = {dep.name for dep in graph.deps}
    _dead_override_names = sorted(
        ov.name for ov in manifest.overrides
        if ov.name not in _resolved_dep_names
    )
    if _dead_override_names:
        _warnings.warn(
            f"override(s) {', '.join(_dead_override_names)!r} name dep(s) not present in the "
            f"resolved graph — check for typos in override names",
            UserWarning,
            stacklevel=4,
        )

    # RFC origin-as-identity.md §4.7/B3 (S3a-req): when the slot projection
    # dropped a declared label in favor of another, that collapse must be
    # VISIBLE — never a silent disappearance from _deps/ / nim.cfg. One note
    # per dropped alias, on the resolve trace (stderr).
    from milpa.lockfile import collapse_notes as _collapse_notes
    for _note in _collapse_notes(list(graph.deps)):
        print(f"[milpa] note: {_note}", file=sys.stderr)

    # RFC origin-as-identity.md §4.6 (S6 + S7): the complete import-slot
    # check — post-solve, post-dedup, before anything is written under
    # _deps/. Runs the S6 directory-slot floor first, then the symbol-level
    # scan over the same CAS store rebuild_deps_view materializes from
    # below. live_symbol_provider() is manifest_declared fidelity ONLY —
    # see its docstring for the evidence-based reason tree_scanned fidelity
    # is not (yet) part of the zero-config hard-fail default.
    from milpa.import_slot import check_import_slot_collisions, live_symbol_provider
    check_import_slot_collisions(graph, live_symbol_provider(), store=env.store)

    # B-nimcfg: rebuild the _deps/ view as a pure function of the resolved graph.
    # This creates alias symlinks and removes stale entries from prior resolves.
    # SSOT: rebuild_deps_view is the single place that decides _deps/ contents.
    # MilpaEnv.store is typed CAStore (non-Optional); the None guard was dead code.
    rebuild_deps_view(graph, deps_dir, env.store)

    return graph


# ---------------------------------------------------------------------------
# URL dep processing
# ---------------------------------------------------------------------------


def _process_url_worker(
    dep: UrlDep,
    dest: Path,
    env: MilpaEnv,
    params: ResolveParams,
    overrides_by_name: dict[str, Override],
    root_self_name: "str | None" = None,
    binding_resolver: "BindingResolver | None" = None,
) -> tuple[_Candidate, list[object], EdgeSet, Path]:
    """Fetch one URL dep (worker: pure I/O, no shared-state mutation).

    ``dest`` is the caller-computed scratch destination for this fetch —
    ordinarily ``deps_dir / dep.name``, EXCEPT when the caller (the
    ``kind == "url"`` branch of ``_run_bfs_wave_loop``) detects that a
    SECOND, differently-keyed url-dep candidate for the SAME name is being
    dispatched within the SAME BFS wave (only reachable via the validate-
    against-registry rework, resolver-semantics.md §10.0/§10.3: two
    transitives that each AGREE with a registry name's source, at different
    refs, both bypass the provenance gate and are legitimately fetched
    concurrently) — in that case the caller disambiguates ``dest`` with a
    unique suffix so the two concurrent ``CasAdmittingFetcher`` symlink
    placements don't race on the same path (which otherwise raises an
    OS-level error, e.g. "Cannot call rmtree on a symbolic link", aborting
    resolution outright). This function never computes ``dest`` itself so
    that the ordinary (non-colliding) case stays byte-for-byte identical to
    before — every OTHER consumer of ``deps_dir / dep.name`` (S3/S4a/S4b's
    manifest re-reads) is unaffected by the rare disambiguated case, since
    ``url_dep_paths`` (populated by the caller from this function's
    returned ``fetched_path``) is the only place that needs to know the
    real location.

    Returns ``(_Candidate, transitive_dep_list, edge_set, fetched_path)`` where:
    - ``transitive_dep_list`` are raw dep objects for BFS enqueuing.
    - ``edge_set`` is the EdgeSet produced by the appropriate source (MilpaKdl
      or Nimble); the caller seals this into the resolver-scoped ``edge_cache``.
    - ``fetched_path`` is simply ``dest`` echoed back, for the caller's
      ``url_dep_paths`` bookkeeping.

    This is the thread-pool worker body for 9b-7 parallel fetch (§4.4 NORMATIVE:
    output is deterministic regardless of -j because the lockfile is lex-sorted).
    """
    # Prior pin (§8).
    git_pin = _git_pin_for_url_dep(dep, params.prior)
    expected_identity: str | None
    pinned_commit_sha: str | None
    if git_pin is not None:
        expected_identity, pinned_commit_sha = git_pin
    else:
        expected_identity, pinned_commit_sha = None, None

    # Build ordered candidate list (§8a).
    # D-lifecycle: track ALL candidate URLs (primary + manifest mirrors + prior
    # declared) so we know which one became observed and which are declared.
    primary_url = dep.git
    manifest_mirror_urls: tuple[str, ...] = tuple(dep.mirrors)
    # D-update-remove (Phase D item 5): filter prior declared URLs to only those
    # still in the manifest mirror set. URLs removed from milpa.kdl are dropped
    # ("drop only those whose URL left the manifest" per RFC §D.5).
    _manifest_mirror_set: frozenset[str] = frozenset(manifest_mirror_urls)
    prior_declared_urls: tuple[str, ...] = tuple(
        u for u in _prior_declared_mirror_urls(dep.name, params.prior)
        if u in _manifest_mirror_set
    )

    # Ordered deduped set of ALL candidate URLs: primary first, then manifest
    # mirrors, then prior declared (manifest-filtered). Whichever succeeds becomes
    # "observed"; the rest become "declared" provenances in the lockfile.
    _seen_all: set[str] = set()
    _all_candidate_urls: list[str] = []
    for _u in (primary_url, *manifest_mirror_urls, *prior_declared_urls):
        if _u not in _seen_all:
            _seen_all.add(_u)
            _all_candidate_urls.append(_u)

    candidates: list[Provenance] = [
        GitProvenance(url=url, ref=dep.ref, commit_sha=pinned_commit_sha)
        for url in _all_candidate_urls
    ]

    # dest is caller-computed — see the docstring above.
    last_transport_exc: Exception | None = None
    result = None
    observed_prov: GitProvenance | None = None
    for prov in candidates:
        try:
            result = env.fetcher.fetch(dep.name, prov, dest=dest)
        except Exception as exc:
            # Transport failure (network error, git non-zero, dead mirror, etc.):
            # record and try the next candidate.  Do NOT persist any "failed"
            # state — the lockfile is a build artifact, not a retry log.
            last_transport_exc = exc
            result = None
            continue

        # Fetch succeeded — validate identity gate when prior pin is set.
        # A mismatch is a SUPPLY-CHAIN SIGNAL: raise loudly, do NOT try the
        # next candidate.  A mirror serving different bytes than the lock
        # pinned must not be silently worked around.
        if expected_identity is not None and result.identity != expected_identity:
            raise MilpaError(
                FETCH_PROVENANCE_DIVERGENCE,
                f"fetching {dep.name!r}: provenance {prov.url!r} succeeded but "  # type: ignore[union-attr]
                f"delivered divergent bytes — "
                f"expected {expected_identity[:23]}..., "
                f"got {result.identity[:23]}...",
                name=dep.name,
                expected_identity=expected_identity,
                got_identity=result.identity,
                url=prov.url,  # type: ignore[union-attr]
            )

        assert isinstance(prov, GitProvenance)
        observed_prov = prov
        break

    if result is None or observed_prov is None:
        # Every candidate transport-failed.  Wrap the last transport error in
        # FETCH-ALL-FAILED so the caller sees a uniform slug.
        msg = (
            str(last_transport_exc)
            if last_transport_exc is not None
            else "no candidates"
        )
        raise MilpaError(
            FETCH_ALL_FAILED,
            f"all candidates for {dep.name!r} failed: {msg}",
            name=dep.name,
        ) from last_transport_exc

    # D-lifecycle: collect declared mirror URLs — all candidate URLs except the one
    # that was observed (dedup vs observed URL, no self-reference).
    observed_url = observed_prov.url
    declared_mirror_urls = tuple(u for u in _all_candidate_urls if u != observed_url)

    # Extract edges via the appropriate source (NORMATIVE §9: transitive .deps only).
    # URL deps are not in the index → dep_decl=None; is_overridden reflects whether
    # this dep's provenance was redirected by a root override.
    has_milpa_kdl = (result.path / "milpa.kdl").exists()
    # S3 (RFC #23 §3.1.2 + §7 S3): seed active_flags from positive flag requests
    # on the dep declaration (single-hop; consumer-side requests only).
    # Positive requests (enabled=True) are passed as frozenset; the merge with
    # the dep's own default-true flags and enables closure happens inside
    # _manifest_to_edgeset (via EdgeSourceCtx.active_flags → MilpaKdlEdgeSource).
    requested_flags: frozenset[str] = frozenset(
        fr.name for fr in dep.flag_requests if fr.enabled
    )
    ctx = EdgeSourceCtx(
        dep_path=result.path,
        dep_name=dep.name,
        dep_decl=None,   # URL deps are not index-registered → no DepDecl
        is_overridden=dep.name in overrides_by_name,
        has_milpa_kdl=has_milpa_kdl,
        overrides_by_name=overrides_by_name,
        active_flags=requested_flags,  # S3: consumer-requested flags
        ref=dep.ref,  # A3: git tag-derived version fallback (step 3)
        version=dep.version,  # A3b: version= annotation fallback (step 4)
    )
    # Call _resolve_edges_pure (worker thread — no shared edge_cache yet).
    # The main thread seals edge_cache from the returned EdgeSet.
    # S2b: route through the coordinator (clauses b/c/d) — honors override-suppression
    # and DepDecl (clause c); _pick_edges only implemented clause d.
    es = _resolve_edges_pure(
        dep.name, _URL_DEP_VERSION, ctx,
        dep_decl_source=DepDeclEdgeSource(env.dep_decl_store) if env.dep_decl_store is not None else None,
    )

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, overrides_by_name, env.index, root_self_name, binding_resolver)
    src_dir = es.src_dir

    commit_sha: str | None = result.receipt.transport_fields().get("commit_sha")
    # R1-04: read submodule_shas directly from the GitReceipt (not transport_fields,
    # which only returns commit_sha and drops submodule provenance).
    submodule_shas: dict[str, str] = (
        result.receipt.submodule_shas
        if isinstance(result.receipt, GitReceipt)
        else {}
    )

    # D4 (resolution-semantics RFC §3 Axis D / §6 D-D1/D-D2): exclude-newer
    # VALIDATION for the pinned git commit — not selection (git deps have
    # exactly one candidate, unlike an index dep's enumerated set, which is
    # filtered at the enumeration layer instead, D3).  Keys on the resolved
    # commit's own COMMITTER date (never an annotated tag's tagger date —
    # guaranteed by GitReceipt.committer_date's own contract).  local/tarball
    # deps have no commit and are not validated here (no meaningful timestamp).
    if params.exclude_newer is not None and isinstance(result.receipt, GitReceipt):
        committer_date = result.receipt.committer_date
        if committer_date is not None and committer_date > params.exclude_newer:
            raise MilpaError(
                RES_EXCLUDE_NEWER_PIN,
                f"{dep.name!r} is pinned to commit {commit_sha!r} whose "
                f"committer date {committer_date.isoformat()!r} is newer than "
                f"exclude-newer {params.exclude_newer.isoformat()!r} — git/url "
                f"deps have exactly one candidate (validated, not selected), "
                f"so there is no older version to fall back to; loosen or "
                f"remove exclude-newer, or pin an older commit",
                name=dep.name,
                commit_sha=commit_sha,
                committer_date=committer_date.isoformat(),
                exclude_newer=params.exclude_newer.isoformat(),
            )

    # Axis A (b)/D-A2: label with the fetched package's declared version
    # (milpa.kdl → .nimble), else the sentinel (version-unknown stays as-is).
    _candidate_version, _version_source, _version_unknown = _candidate_label(ctx)
    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — this
    # candidate's own claim was already submitted (root at
    # BindingResolver.__init__, or transitive via the "url" BFS arm's
    # binding_resolver.submit()) BEFORE this worker was ever dispatched, so
    # canonical_for is safe to call directly (no guess-fallback needed).
    _svar_cand_url = (
        binding_resolver.canonical_for(DepKey(name=dep.name))
        if binding_resolver is not None
        else dep.name
    )
    candidate = _Candidate(
        name=_svar_cand_url,
        version=_candidate_version,
        identity=result.identity,
        src_dir=src_dir,
        dep_terms=dep_terms,
        requires_names=requires_names,
        # D-lifecycle: provenance is the OBSERVED candidate (the one that succeeded).
        provenance=GitProvenance(url=observed_url, ref=dep.ref, commit_sha=commit_sha),
        # D-lifecycle: declared mirrors (all manifest+prior declared URLs != observed).
        declared_mirror_urls=declared_mirror_urls,
        requires_predicates=requires_predicates,
        # R1-04: submodule SHA provenance from the GitReceipt (H5).
        submodule_shas=submodule_shas,
        # A4: no declared version found — version-unknown.
        version_unknown=_version_unknown,
        declared_version_source=_version_source,
    )

    # Collect transitive deps for the BFS queue (returned to caller for enqueuing).
    # S2b: derived from the EdgeSet (already flag-filtered); no second parse.
    transitive_deps = edgeset_to_bfs_deps(es, overrides_by_name)
    return candidate, transitive_deps, es, dest


def _enqueue_dep(
    dep: object,
    overrides_by_name: dict[str, Override],
    bfs_queue: list[object],
) -> None:
    """Append a dep to the BFS queue (FIFO)."""
    if isinstance(dep, UrlDep):
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            # S8a: LocalTarget override → route to local BFS slot.
            if isinstance(ov.target, LocalTarget):
                bfs_queue.append(("local", LocalDep(name=dep.name, path=ov.target.path, version=ov.version)))
                return
            # S8b: MemberTarget override — member already pre-registered in workspace;
            # no external queue entry (provenance gate suppresses any stale git claim).
            if isinstance(ov.target, MemberTarget):
                return
            # S8b: TarballTarget/OciTarget/RegistryTarget → route to the
            # matching BFS slot.
            if isinstance(ov.target, (TarballTarget, OciTarget, RegistryTarget)):
                bfs_queue.append(_extended_override_bfs_item(dep.name, ov))
                return
            dep = _apply_git_override_to_url_dep(dep, ov)
        bfs_queue.append(("url", dep))
    elif isinstance(dep, NamedDep):
        if dep.name == "nim":
            return
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            # S8a: LocalTarget override → route to local BFS slot.
            if isinstance(ov.target, LocalTarget):
                bfs_queue.append(("local", LocalDep(name=dep.name, path=ov.target.path, version=ov.version)))
                return
            # S8b: MemberTarget override — member already pre-registered in workspace.
            if isinstance(ov.target, MemberTarget):
                return
            # S8b: TarballTarget/OciTarget/RegistryTarget → route to the
            # matching BFS slot.
            if isinstance(ov.target, (TarballTarget, OciTarget, RegistryTarget)):
                bfs_queue.append(_extended_override_bfs_item(dep.name, ov))
                return
            bfs_queue.append(("url", _apply_git_override_to_url_dep(
                UrlDep(name=dep.name, git="", ref=""), ov
            )))
        else:
            # S5b: transitive named deps have namespace=None (only direct manifest deps
            # carry a namespace); bare name is used for registry lookup.
            bfs_queue.append(("named", DepKey(name=dep.name, namespace=dep.namespace), dep.constraint))
    elif isinstance(dep, TarballDep):
        # M2: TarballDep from transitive manifests is out of scope —
        # only root-declared tarball deps are admitted (mirrors edge_sources.py:333).
        pass
    elif isinstance(dep, LocalDep):
        # M2: LocalDep from transitive manifests is DROPPED here (security gate).
        # A transitive dep's local= path could point to an arbitrary location on
        # the filesystem — allowing it would let an attacker-controlled manifest
        # symlink _deps/<name> to any path.  Only root-declared local deps (enqueued
        # directly via bfs_queue.append, not through _enqueue_dep) are admitted.
        # This mirrors edge_sources.py:333 (Local/Tarball/Member out of scope) and
        # the Rust impl's edgeset_to_extracted filter (Dep::Local | Dep::Tarball | Dep::Member => {}).
        pass


# ---------------------------------------------------------------------------
# Tarball dep processing
# ---------------------------------------------------------------------------


def _process_tarball_worker(
    dep: TarballDep,
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
    overrides_by_name: dict[str, Override],
    root_self_name: "str | None" = None,
    binding_resolver: "BindingResolver | None" = None,
) -> tuple[_Candidate, list[object], EdgeSet]:
    """Fetch one tarball dep (worker: pure I/O, no shared-state mutation).

    Tarball TOFU re-assertion (slice 9c / RFC S9c + #116):
    - First fetch (no prior lock): receipt carries ``archive_sha256``; recorded
      to the lockfile via the TOFU precedence in ``from_graph``.
    - Refetch (prior lock present): locked ``archive_sha256`` is threaded back
      as ``TarballProvenance.expected_sha256``; a mismatch raises
      ``FETCH-SHA256-MISMATCH`` inside the fetcher, which is caught here and
      re-raised as ``FETCH-ALL-FAILED`` (mirrors Rust ``fetch_any`` wrapping).
    - TOFU precedence in the candidate: ``dep.sha256 or receipt.archive_sha256
      or locked_sha256`` (manifest-declared sha256 is authoritative; receipt
      sha is used when dep.sha256 is None; falls back to locked sha on refetch).

    Returns ``(_Candidate, transitive_dep_list, edge_set)``.
    The caller seals ``edge_set`` into the resolver-scoped ``edge_cache``.
    """
    # Prior pin (§8): locked identity + locked archive sha256.
    tarball_pin_result = _tarball_pin(dep, params.prior)
    expected_identity: str | None = None
    locked_sha256: str | None = None
    if tarball_pin_result is not None:
        expected_identity, locked_sha256 = tarball_pin_result

    # TOFU re-assertion: manifest sha256 is authoritative; else use locked sha256
    # (empty on first fetch; set on refetch).
    expected_sha256 = dep.sha256 or locked_sha256

    prov = TarballProvenance(
        url=dep.url,
        expected_sha256=expected_sha256,
        strip_components=dep.strip_components,
    )

    dest = deps_dir / dep.name
    try:
        result = env.fetcher.fetch(dep.name, prov, dest=dest)
    except MilpaError as exc:
        raise MilpaError(
            "FETCH-ALL-FAILED",
            f"all candidates for {dep.name!r} failed: {exc.message}",
            name=dep.name,
            inner_slug=exc.slug,
        ) from exc
    except Exception as exc:
        raise MilpaError(
            "FETCH-ALL-FAILED",
            f"all candidates for {dep.name!r} failed: {exc}",
            name=dep.name,
        ) from exc

    # Identity gate (§8): tarball fetched successfully but delivered divergent
    # bytes vs. the prior lockfile pin — this is a supply-chain signal, not a
    # generic fetch failure.  Raise FETCH-PROVENANCE-DIVERGENCE (matches Rust
    # fetch_any_tracked and the D-fallback spec intent).
    if expected_identity is not None and result.identity != expected_identity:
        raise MilpaError(
            FETCH_PROVENANCE_DIVERGENCE,
            f"{dep.name!r}: tarball at {dep.url!r} succeeded but delivered "
            f"divergent bytes — expected {expected_identity[:23]}..., "
            f"got {result.identity[:23]}...",
            name=dep.name,
        )

    archive_sha256: str | None = result.receipt.transport_fields().get("archive_sha256")

    # Extract edges via the appropriate source (NORMATIVE §9: transitive .deps only).
    has_milpa_kdl = (result.path / "milpa.kdl").exists()
    ctx = EdgeSourceCtx(
        dep_path=result.path,
        dep_name=dep.name,
        dep_decl=None,   # Tarball deps are not index-registered → no DepDecl
        is_overridden=False,  # Tarball deps cannot be overridden (no name-override mechanism)
        has_milpa_kdl=has_milpa_kdl,
        overrides_by_name=overrides_by_name,
        version=dep.version,  # A3b: version= annotation fallback (step 4)
    )
    es = _resolve_edges_pure(
        dep.name, _URL_DEP_VERSION, ctx,
        dep_decl_source=DepDeclEdgeSource(env.dep_decl_store) if env.dep_decl_store is not None else None,
    )

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, overrides_by_name, env.index, root_self_name, binding_resolver)
    src_dir = es.src_dir
    recorded_sha256 = dep.sha256 or archive_sha256 or locked_sha256

    # Axis A (b)/D-A2: label with the fetched package's declared version
    # (milpa.kdl → .nimble), else the sentinel (version-unknown stays as-is).
    _candidate_version, _version_source, _version_unknown = _candidate_label(ctx)
    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — this
    # candidate's own claim is always a root claim (M2 gate: transitive
    # tarball deps are dropped), bound at BindingResolver.__init__ before
    # any worker runs.
    _svar_cand_tb = (
        binding_resolver.canonical_for(DepKey(name=dep.name))
        if binding_resolver is not None
        else dep.name
    )
    candidate = _Candidate(
        name=_svar_cand_tb,
        version=_candidate_version,
        identity=result.identity,
        src_dir=src_dir,
        dep_terms=dep_terms,
        requires_names=requires_names,
        provenance=TarballProvenance(
            url=dep.url,
            expected_sha256=recorded_sha256,
            strip_components=dep.strip_components,
        ),
        requires_predicates=requires_predicates,
        # A4: no declared version found — version-unknown.
        version_unknown=_version_unknown,
        declared_version_source=_version_source,
    )
    transitive_deps = edgeset_to_bfs_deps(es, overrides_by_name)
    return candidate, transitive_deps, es


# ---------------------------------------------------------------------------
# OCI-override dep processing (S8b, rfc-origin-as-identity.md §7 B5)
# ---------------------------------------------------------------------------


def _process_oci_worker(
    dep: "_OciOverrideDep",
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
    overrides_by_name: dict[str, Override],
    root_self_name: "str | None" = None,
    binding_resolver: "BindingResolver | None" = None,
) -> tuple[_Candidate, list[object], EdgeSet]:
    """Fetch one OCI-override dep (worker: pure I/O, no shared-state mutation).

    An OCI dep is reachable ONLY via an ``OciTarget`` override — there is no
    first-class manifest ``oci=`` dep-declaration grammar (see
    ``_OciOverrideDep``'s docstring). The fixed (registry, repository,
    digest) triple IS the whole identity — no "version enumeration" like the
    registry-index OCI path in ``_Provider._materialize``; exactly one
    candidate, mirroring ``_process_local_worker``/``_process_tarball_worker``.

    Returns ``(_Candidate, transitive_dep_list, edge_set)``.
    The caller seals ``edge_set`` into the resolver-scoped ``edge_cache``.
    """
    prov = OciProvenance(registry=dep.registry, repository=dep.repository, digest=dep.digest)
    dest = deps_dir / dep.name
    try:
        result = env.fetcher.fetch(dep.name, prov, dest=dest)
    except MilpaError as exc:
        raise MilpaError(
            "FETCH-ALL-FAILED",
            f"all candidates for {dep.name!r} failed: {exc.message}",
            name=dep.name,
            inner_slug=exc.slug,
        ) from exc
    except Exception as exc:
        raise MilpaError(
            "FETCH-ALL-FAILED",
            f"all candidates for {dep.name!r} failed: {exc}",
            name=dep.name,
        ) from exc

    # Extract edges via the appropriate source (NORMATIVE §9: transitive .deps only).
    has_milpa_kdl = (result.path / "milpa.kdl").exists()
    ctx = EdgeSourceCtx(
        dep_path=result.path,
        dep_name=dep.name,
        dep_decl=None,   # OCI-override deps are not index-registered → no DepDecl
        # False, matching Local/Tarball: dep_decl is already None here, so
        # this flag's real purpose (distrust an index-sourced DepDecl for a
        # redirected package) is moot — there is no DepDecl to distrust.
        is_overridden=False,
        has_milpa_kdl=has_milpa_kdl,
        overrides_by_name=overrides_by_name,
        version=dep.version,  # A3b: version= annotation fallback (step 4)
    )
    es = _resolve_edges_pure(
        dep.name, _URL_DEP_VERSION, ctx,
        dep_decl_source=DepDeclEdgeSource(env.dep_decl_store) if env.dep_decl_store is not None else None,
    )

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(
        es, overrides_by_name, env.index, root_self_name, binding_resolver
    )
    src_dir = es.src_dir

    # Axis A (b)/D-A2: label with the fetched package's declared version
    # (milpa.kdl → .nimble), else the sentinel (version-unknown stays as-is).
    _candidate_version, _version_source, _version_unknown = _candidate_label(ctx)
    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — this
    # candidate's own claim is always a root claim (an OCI override is only
    # ever reachable as a redirected root/root-catch-up claim — there is no
    # transitive OCI-dep grammar), bound at BindingResolver.__init__ before
    # any worker runs.
    _svar_cand_oci = (
        binding_resolver.canonical_for(DepKey(name=dep.name))
        if binding_resolver is not None
        else dep.name
    )
    candidate = _Candidate(
        name=_svar_cand_oci,
        version=_candidate_version,
        identity=result.identity,
        src_dir=src_dir,
        dep_terms=dep_terms,
        requires_names=requires_names,
        provenance=prov,
        requires_predicates=requires_predicates,
        # A4: no declared version found — version-unknown.
        version_unknown=_version_unknown,
        declared_version_source=_version_source,
    )
    transitive_deps = edgeset_to_bfs_deps(es, overrides_by_name)
    return candidate, transitive_deps, es


# ---------------------------------------------------------------------------
# Local dep processing
# ---------------------------------------------------------------------------


def _process_local_worker(
    dep: LocalDep,
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
    overrides_by_name: dict[str, Override],
    root_self_name: "str | None" = None,
    binding_resolver: "BindingResolver | None" = None,
) -> tuple[_Candidate, list[object], EdgeSet]:
    """Fetch one local dep (worker: pure I/O, no shared-state mutation).

    Local deps resolve with NO traditional fetch (cas_admissible=False):
    ``LocalFetcher`` symlinks the source tree in-place at ``_deps/<name>``
    and computes identity from the tree bytes (resolver-semantics §3, slice 9b-6).

    The declared ``dep.path`` is relative to the project root (``manifest_dir``).
    Resolves it to absolute for ``LocalProvenance`` (which requires absolute),
    but records the DECLARED relative path in the lockfile (§4.3 NORMATIVE).

    Returns ``(_Candidate, transitive_dep_list, edge_set)``.
    The caller seals ``edge_set`` into the resolver-scoped ``edge_cache``.
    """
    declared_path_str = dep.path  # as declared in milpa.kdl (may be relative)
    if params.manifest_dir is not None:
        abs_path = (params.manifest_dir / dep.path).resolve()
    else:
        abs_path = Path(dep.path).resolve()

    prov = LocalProvenance(path=abs_path)
    result = env.fetcher.fetch(dep.name, prov, dest=deps_dir / dep.name)

    # Extract edges via the appropriate source (NORMATIVE §9: transitive .deps only).
    has_milpa_kdl = (result.path / "milpa.kdl").exists()
    ctx = EdgeSourceCtx(
        dep_path=result.path,
        dep_name=dep.name,
        dep_decl=None,   # Local deps are not index-registered → no DepDecl
        is_overridden=False,  # Local deps are always literal paths; no override applies
        has_milpa_kdl=has_milpa_kdl,
        overrides_by_name=overrides_by_name,
        version=dep.version,  # A3b: version= annotation fallback (step 4)
    )
    es = _resolve_edges_pure(
        dep.name, _URL_DEP_VERSION, ctx,
        dep_decl_source=DepDeclEdgeSource(env.dep_decl_store) if env.dep_decl_store is not None else None,
    )

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, overrides_by_name, env.index, root_self_name, binding_resolver)
    src_dir = es.src_dir

    # Axis A (b)/D-A2: label with the fetched package's declared version
    # (milpa.kdl → .nimble), else the sentinel (version-unknown stays as-is).
    _candidate_version, _version_source, _version_unknown = _candidate_label(ctx)
    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — this
    # candidate's own claim is always a root claim (M2 gate: transitive
    # local deps are dropped), bound at BindingResolver.__init__ before
    # any worker runs.
    _svar_cand_lo = (
        binding_resolver.canonical_for(DepKey(name=dep.name))
        if binding_resolver is not None
        else dep.name
    )
    candidate = _Candidate(
        name=_svar_cand_lo,
        version=_candidate_version,
        identity=result.identity,
        src_dir=src_dir,
        dep_terms=dep_terms,
        requires_names=requires_names,
        provenance=_LocalDepProvenance(declared_path=declared_path_str),
        requires_predicates=requires_predicates,
        # A4: no declared version found — version-unknown.
        version_unknown=_version_unknown,
        declared_version_source=_version_source,
    )
    transitive_deps = edgeset_to_bfs_deps(es, overrides_by_name)
    return candidate, transitive_deps, es


# ---------------------------------------------------------------------------
# Observed-provenance dispatch — shared by _build_graph's per-candidate
# assembly and its S4b alias-provenance merge (single source of truth; see
# CLAUDE.md's audit-for-duplication discipline).
# ---------------------------------------------------------------------------


def _observed_provenance_record_for_candidate(
    cand: "_Candidate",
) -> "ProvenanceRecord | None":
    """Map a ``_Candidate``'s ``.provenance`` to its OBSERVED lockfile record.

    Used both for a candidate's OWN entry in ``_build_graph`` and — RFC
    origin-as-identity §3.3/§4.5 (S4b) — for each alias folded into a
    canonical dep by the post-solve content-hash collapse: a cross-origin
    merge (e.g. a ``RegistrySourceId`` coordinate and a ``GitSourceId`` URL
    that fetch byte-identical trees) must carry BOTH origins' observed
    provenance forward, never just the survivor's.
    """
    prov = cand.provenance
    if isinstance(prov, GitProvenance):
        return GitProvenanceRecord(
            url=prov.url,
            ref=prov.ref,
            commit_sha=prov.commit_sha,
            # R1-04: wire submodule_shas from _Candidate into the lockfile record.
            submodule_shas=cand.submodule_shas,
            origin="observed",
        )
    if isinstance(prov, LocalProvenance):
        # Dead branch: _process_local_worker always wraps local deps in
        # _LocalDepProvenance (the declared relative path) before storing
        # them in _Candidate.provenance, so a raw LocalProvenance (which
        # carries the ABSOLUTE resolved path) is never stored here.
        # If this fires, the caller wired a LocalProvenance directly into
        # _Candidate — that would silently write an absolute path to the
        # lockfile, violating lockfile-schema §4.3.  Raise hard.
        raise AssertionError(
            f"_build_graph: _Candidate for {cand.name!r} carries a raw "
            f"LocalProvenance (absolute path={prov.path!r}); "
            f"local deps must use _LocalDepProvenance so the declared "
            f"relative path is written to the lockfile (§4.3)."
        )
    if isinstance(prov, _LocalDepProvenance):
        # _LocalDepProvenance stores the DECLARED (relative) path — correct for lockfile.
        return LocalProvenanceRecord(path=prov.declared_path, origin="observed")
    if isinstance(prov, TarballProvenance):
        return TarballProvenanceRecord(
            url=prov.url,
            sha256=prov.expected_sha256,
            origin="observed",
        )
    if isinstance(prov, MemberProvenanceRecord):
        # Member candidate — provenance record already typed correctly.
        return prov
    if isinstance(prov, OciProvenance):
        return OciProvenanceRecord(
            registry=prov.registry,
            repository=prov.repository,
            digest=prov.digest,
            origin="observed",
        )
    if isinstance(prov, RootProvenanceRecord):
        # §14.5: root-self candidate — provenance record already typed correctly.
        return prov
    return None


def _version_str_for_candidate(cand: "_Candidate", version: Version) -> str:
    """The lockfile-boundary version string for one solved candidate.

    A5 (§5 NORMATIVE): a version-unknown candidate flattens to the
    absent-version literal "0.0.0" — paired with declared_version_source=None,
    a combination no Known case ever produces (a Known always names its
    source). Scoped to non-registry candidates ONLY (``not cand.is_registry``):
    a named/index dep's real version comes straight from the index and never
    goes through declared_version_for, so it always keeps its real formatted
    version regardless of declared_version_source (never populated for that
    kind — out of Axis A's scope). Shared by the canonical dep's own
    assembly and (S4b) an aliased-away candidate's own entry-trust check.
    """
    return (
        "0.0.0"
        if (not cand.is_registry and cand.declared_version_source is None)
        else format_version_str(version)
    )


def _run_entry_trust_gate(
    cand: "_Candidate",
    bare_name: str,
    version_str: str,
    entry_trust: "EntryTrustConfig | None",
) -> None:
    """Evaluate + enforce the entry-trust gate for one registry candidate.

    P3a (RFC per-entry-attestation.md §3, §5): post-solve, per selected
    registry-resolved dep. A ``strict``-policy failure raises and aborts
    graph construction (RFC §3: "a failing selected version is a hard, late
    resolve failure with no automatic fallback").

    Shared by the canonical dep's own gate check and — RFC origin-as-
    identity.md §3.3/§4.5 (S4b) — an aliased-away registry candidate's: a
    cross-origin dedup collapse must never let a package skip its OWN
    attestation obligation merely because a non-registry (or differently-
    attested) peer happened to win the BFS canonical tie-break. No-op when
    ``entry_trust`` is ``None`` or the candidate isn't registry-resolved.
    """
    if entry_trust is None or not cand.is_registry:
        return
    from milpa.entry_trust import enforce_entry_trust, evaluate_entry_attestation

    _gate_result, _gate_cause = evaluate_entry_attestation(
        attestation=cand.attestation,
        content_hash=cand.identity or "",
        namespace=cand.registry_namespace,
        name=bare_name,
        version=version_str,
        verifier=entry_trust.verifier,
        bundle_store=entry_trust.bundle_store,
        trust_bundle=entry_trust.trust_bundle,
        expected_vendor_signer=entry_trust.expected_vendor_signer,
    )
    enforce_entry_trust(
        _gate_result,
        entry_trust.policy,
        namespace=cand.registry_namespace,
        name=bare_name,
        version=version_str,
        cause=_gate_cause,
    )


# ---------------------------------------------------------------------------
# Phase B: content-hash dedup/alias
# ---------------------------------------------------------------------------


def _dedup_candidates(
    provider: _Provider,
    deps_dir: Path,
    discovery_order: list[str],
    overrides_by_name: dict[str, Override],
    solution: dict[str, Version],
) -> dict[str, str]:
    """Collapse solved candidates that share a content identity.

    Returns ``aliases_map``: a dict mapping non-canonical name → canonical name.
    Empty when no dedup occurred.

    RFC origin-as-identity.md §3.3/§4.5 (S4b — cross-origin reconciliation of
    Phase B). This pass runs **after** ``solve_with_cert`` returns, over the
    solver's FINAL picks (``solution``) only — never the full enumerated
    stub/version space. That is what lets a *named* (registry-resolved) dep
    participate: a named dep is a lazy stub until the solver actually asks for
    its dependencies (``_Provider._materialize``), which happens for every
    package PubGrub includes in ``solution`` before it can be included. By the
    time this pass runs, every solved candidate — named or eager (git/tarball/
    local) — carries a real, VERIFIED fetched-bytes ``identity`` (never the
    unverified index-declared claim). This is exactly what §3.3's merge-on-
    proof bar requires: two DISTINCT source-ids (e.g. a ``RegistrySourceId``
    coordinate and a ``GitSourceId`` URL) that fetch byte-identical trees
    collapse to one canonical dep + one ``_deps/<slot>/`` view — milpa's edge
    over Cargo, realized here, at the solver's own boundary.

    Algorithm (Phase B, spec/resolver-semantics.md Phase B, extended by S4b):
    1. Group every solved (name, version) pair by content identity (``identity``).
    2. For each group of size ≥ 2: pick the canonical member as the one with the
       smallest index in ``discovery_order`` (BFS-insertion order, NOT lex).
    3. Invariant guard (requires-equality): for each dedup group, re-derive
       each member's requires from its sealed edge_cache entry and assert they
       are equal after alias-rewriting (identical content ⇒ identical tree ⇒
       identical requires; any mismatch is a bug, not a user error — raises
       ``MILPA_INTERNAL``, never silently picks one side).
    4. Rewrite every surviving (non-aliased) solved candidate's
       ``requires_names`` entries that reference a non-canonical name to the
       canonical name (so the lockfile's ``requires`` list never names a
       collapsed-away label). ``dep_terms`` is NOT rewritten here — PubGrub
       has already run; nothing reads ``dep_terms`` after ``solve_with_cert``
       returns.

    ``_build_graph`` uses ``aliases_map`` two ways: (a) it skips building a
    separate ``ResolvedDep`` for any non-canonical name (folded into its
    canonical peer), and (b) it appends each alias's OWN observed provenance
    to the canonical dep's ``provenances`` list — a cross-origin collapse
    keeps BOTH origins' full audit trail, never just the survivor's.
    """
    # Step 1: materialize (if needed — a named stub not yet queried by the
    # solver still can't happen here, since PubGrub must call dependencies()
    # for everything it puts in `solution`) every solved candidate and group
    # by identity.
    by_identity: dict[str, list[str]] = {}
    solved_candidates: dict[str, _Candidate] = {}
    for name, version in solution.items():
        if name == "__root__":
            continue
        try:
            c = provider.get(name, version)
        except KeyError:
            continue
        solved_candidates[name] = c
        if not c.identity:
            continue
        by_identity.setdefault(c.identity, []).append(name)

    aliases_map: dict[str, str] = {}  # non-canonical → canonical

    # Build a fast index for discovery_order lookup.
    discovery_index: dict[str, int] = {n: i for i, n in enumerate(discovery_order)}
    _LARGE = len(discovery_order)

    for identity, group in by_identity.items():
        if len(group) < 2:
            continue

        # Step 2: pick canonical = group member with smallest discovery_order index.
        # Names NOT in discovery_order get _LARGE (should not happen — every
        # BFS/root/transitive admission site records its solver_var into
        # discovery_order, including the mid-solve named-transitive callback).
        canonical = min(group, key=lambda n: discovery_index.get(n, _LARGE))

        non_canonicals = [n for n in group if n != canonical]

        # Step 3: invariant guard — re-derive requires from the sealed edge_cache.
        # Identical content ⇒ identical tree ⇒ identical requires. Any mismatch
        # is a bug, not a user error → MILPA-INTERNAL.
        # RFC origin-as-identity §4.5 (S4): edge_cache is keyed by
        # (source_id, version) — translate member_name through the SAME
        # BindingResolver the seal step used, and use THIS member's own solved
        # version (a named dep's real version, not the eager-dep sentinel —
        # ``solution[member_name]`` is correct uniformly for both kinds).
        all_requires: list[frozenset[str]] = []
        for member_name in group:
            _member_ver = solution[member_name]
            _member_sid = _source_id_for_edge_cache(provider._binding_resolver, member_name)  # type: ignore[attr-defined]
            cached_es = provider._edge_cache.get((_member_sid, _member_ver))  # type: ignore[attr-defined]
            raw_deps = edgeset_to_bfs_deps(cached_es, overrides_by_name) if cached_es is not None else []
            # Canonicalize dep names through the alias map (partially built so far
            # — for same-group members: no alias yet; across-group: alias may exist).
            req_names: frozenset[str] = frozenset(
                aliases_map.get(getattr(d, "name", ""), getattr(d, "name", ""))
                for d in raw_deps
                if hasattr(d, "name")
            )
            all_requires.append(req_names)

        # Check all members' requires sets equal the first (invariant guard).
        first_req = all_requires[0]
        for i, req in enumerate(all_requires[1:], 1):
            if req != first_req:
                member_name_i = group[i]
                raise MilpaError(
                    MILPA_INTERNAL,
                    f"dedup invariant violated: deps {group[0]!r} and "
                    f"{member_name_i!r} share identity {identity!r} but have "
                    f"different requires: {first_req!r} vs {req!r}. "
                    f"This is a bug — identical content must imply identical requires.",
                    identity=identity,
                    group=group,
                )

        for other in non_canonicals:
            aliases_map[other] = canonical

    if not aliases_map:
        return aliases_map

    # Step 4: rewrite requires_names in all surviving (non-aliased) solved
    # candidates so a downstream requirer of a collapsed label points at the
    # canonical name in the lockfile's ``requires`` list.
    for name, c in solved_candidates.items():
        if name in aliases_map:
            continue
        c.requires_names = [aliases_map.get(r, r) for r in c.requires_names]

    return aliases_map


# ---------------------------------------------------------------------------
# B-nimcfg: atomic _deps/ view rebuild (Phase B, rfc-content-addressed-identity.md)
# ---------------------------------------------------------------------------


def rebuild_deps_view(
    graph: ResolvedGraph,
    deps_dir: Path,
    store: object,  # CAStore — typed as object to avoid circular import
) -> None:
    """Rebuild ``_deps/`` as a pure function of ``graph`` (B-nimcfg slice).

    This is the SINGLE SOURCE OF TRUTH for ``_deps/`` contents in the Python
    impl. Called from both ``resolve()`` and ``resolve_frozen``/``resolve_workspace_frozen``
    (via frozen.py import).

    Algorithm:
    1. Compute the EXPECTED entry set: for each dep in ``graph.deps`` that has
       a CAS identity, record ``{canonical_name: identity}`` PLUS
       ``{alias: identity}`` for each alias.  Non-CAS deps (local, member) are
       excluded from the rebuild loop — their ``_deps/<name>`` are managed by
       the fetcher/frozen path directly (e.g. LocalFetcher creates a real dir).
    2. Remove any ``_deps/<x>`` NOT in the expected set:
       - symlinks → os.unlink  (shutil.rmtree refuses symlinks)
       - real dirs → shutil.rmtree
    3. Create/refresh each expected CAS entry as a relative symlink via
       ``store.link(identity, deps_dir / name)``.  ``link()`` is idempotent
       (it clears any existing entry before re-linking).

    "Atomic" here = the rebuild leaves ``_deps/`` in the fully-correct state
    with no partial/stale residue.  Cross-process transactional atomicity is
    NOT guaranteed (out of scope for B-nimcfg).
    """
    import os
    import shutil
    import stat as _stat

    from milpa.lockfile import MemberProvenanceRecord, LocalProvenanceRecord

    # Step 1: compute expected entry set (name → identity) for CAS entries only.
    # Also collect local dep names to PRESERVE in _deps/ (LocalFetcher created
    # their symlinks; rebuild_deps_view must not remove them as stale).
    expected: dict[str, str] = {}
    local_names: set[str] = set()
    for dep in graph.deps:
        # Skip member deps — their dirs are not in _deps/ (they live in the ws tree).
        if any(isinstance(p, MemberProvenanceRecord) for p in dep.provenances):
            continue
        # Local deps have no CAS identity (cas_admissible=False); LocalFetcher
        # creates their _deps/<name> symlink.  Add to local_names so Step 2
        # does NOT remove them as stale entries.
        if any(isinstance(p, LocalProvenanceRecord) for p in dep.provenances):
            local_names.add(dep.name)
            continue
        # Skip deps without a CAS identity (should not occur for non-local/member).
        if not dep.identity:
            continue
        # C1: use dep_dir_name so qualified deps go to ``@<ns>/<name>``
        # (not ``ns::name`` with a Windows-illegal ``:``).
        _dir_entry = dep_dir_name(dep.name, dep.namespace)
        expected[_dir_entry] = dep.identity
        for alias in dep.aliases:
            expected[alias] = dep.identity

    if not deps_dir.is_dir():
        return  # nothing to rebuild

    # Step 2: remove stale entries (not in expected set, and not a preserved local dep).
    # C1: namespace dirs (``@<ns>/``) may contain multiple entries; check their
    # children rather than the dir itself.
    for child in list(deps_dir.iterdir()):
        child_key = child.name
        if child.name.startswith("@") and child.is_dir():
            # Namespace directory: check each child independently.
            for grandchild in list(child.iterdir()):
                gc_key = f"{child.name}/{grandchild.name}"
                if gc_key not in expected:
                    try:
                        st = os.lstat(grandchild)
                        if _stat.S_ISLNK(st.st_mode):
                            os.unlink(grandchild)
                        else:
                            shutil.rmtree(grandchild, ignore_errors=True)
                    except FileNotFoundError:
                        pass
            # Remove the namespace dir itself if now empty.
            try:
                if child.is_dir() and not any(child.iterdir()):
                    child.rmdir()
            except (OSError, StopIteration):
                pass
        elif child_key not in expected and child_key not in local_names:
            try:
                st = os.lstat(child)
                if _stat.S_ISLNK(st.st_mode):
                    os.unlink(child)
                else:
                    shutil.rmtree(child, ignore_errors=True)
            except FileNotFoundError:
                pass

    # Step 3: create/refresh expected CAS symlinks.
    # store.link(identity, target) creates a relative symlink; it is idempotent
    # (clears any existing entry first).
    _store = store  # type: ignore[assignment]
    for dir_entry, identity in expected.items():
        target = deps_dir / dir_entry
        # Ensure the parent directory exists for qualified deps (``@<ns>/``).
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            _store.link(identity, target)
        except Exception:
            # CAS entry missing for this identity — the resolver already validated
            # presence (FROZEN-IDENTITY-NOT-IN-STORE); treat as non-fatal here.
            pass


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------


def _depkey_for_solved_name(name: str) -> DepKey:
    """The display ``DepKey`` for a solved PubGrub variable.

    DE1 (RFC origin-as-identity §4.4, genericized key): a bound origin's solver
    variable is a ``SolverKey`` — a ``str`` whose value is
    ``canonical(source_id)``, carrying its BFS-first ``.display`` DepKey inline —
    so decoding is a direct ``.display`` read, with no ``canonical → DepKey``
    reverse map and no ``binding_resolver`` threading (both deleted).

    The only non-``SolverKey`` variables that reach here are ones whose origin
    string IS already their label — a bare name, an ``ns::name`` qualified name,
    or the ``__root__`` sentinel — where ``DepKey.from_solver_var`` is exact by
    construction. A prefixed canonical string (``git+``/``pkg+``/…) never
    arrives as a plain ``str``: every such variable is minted as a ``SolverKey``
    at ``BindingResolver.canonical_for`` / ``canonical_key_for_requirement``.
    """
    if isinstance(name, SolverKey):
        return name.display
    return DepKey.from_solver_var(name)


def _project_solve_success(result: "SolveSuccess") -> "SolveSuccess":
    """Project every PubGrub package string in a §5.1 success certificate
    back to the display "ns::name"/bare form (RFC origin-as-identity §4.4).

    ``certificate_to_json`` (solver.py) is a generic PubGrub serializer that
    prints the raw solver variable — for a named/registry dep that is the
    SOLVER-INTERNAL ``canonical(source_id)`` string (mirrors why the lockfile's
    ``requires`` list needs the same projection, ``_build_graph``'s
    ``requires=`` construction), never meant to leak into the user-facing
    certificate. DE1: each variable is a ``SolverKey`` carrying its display
    inline, so the projection is a direct ``.display`` read (no
    ``binding_resolver``). Rebuilt via ``dataclasses.replace`` since every
    solver dataclass here is frozen.
    """
    import dataclasses
    from milpa.solver import SolveSuccess as _SolveSuccess, WitnessEntry as _WitnessEntry

    def _proj(pkg: str) -> str:
        return _depkey_for_solved_name(pkg).solver_var()

    new_resolved = tuple((_proj(pkg), ver) for pkg, ver in result.resolved)
    new_witness = tuple(
        dataclasses.replace(w, package=_proj(w.package), satisfied_by=_proj(w.satisfied_by))
        for w in result.witness
    )
    return dataclasses.replace(result, resolved=new_resolved, witness=new_witness)  # type: ignore[return-value]


def _project_solver_error(exc: "SolverError") -> "SolverError":
    """Project every PubGrub package string in a §5.2 failure certificate
    back to the display "ns::name"/bare form (RFC origin-as-identity §4.4) —
    the failure-path counterpart to ``_project_solve_success`` (DE1: reads each
    ``SolverKey``'s ``.display``, no ``binding_resolver``).

    Rebuilds ``exc.chain``/``exc._all_incompats`` (both frozen dataclasses,
    walked bottom-up via ``dataclasses.replace``) and constructs a NEW
    ``SolverError`` from them — ``SolverError.__init__`` regenerates its
    prose ``message`` from the (now-projected) chain automatically.
    ``cause_tag``/``consequent_description`` are left untouched: they are
    internal diagnostics, not part of the §5.2 refutation's ``package``/
    ``constraint`` fields ``certificate_to_json`` actually serializes, and
    the certificate's ``message`` field is explicitly NOT byte-normative
    (``certificate_to_json``'s own docstring).
    """
    import dataclasses
    from milpa.solver import SolverError as _SolverError, Term as _Term

    def _proj(pkg: str) -> str:
        return _depkey_for_solved_name(pkg).solver_var()

    def _proj_term(t: "_Term") -> "_Term":
        return dataclasses.replace(t, package=_proj(t.package))

    new_steps = tuple(
        dataclasses.replace(
            step,
            consequent_package=_proj(step.consequent_package),
            antecedents=tuple(_proj_term(t) for t in step.antecedents),
            antecedent_constraints=tuple(_proj_term(t) for t in step.antecedent_constraints),
        )
        for step in exc.chain.steps
    )
    new_chain = dataclasses.replace(exc.chain, steps=new_steps)
    new_incompats = [
        dataclasses.replace(ic, terms=tuple(_proj_term(t) for t in ic.terms))
        for ic in exc._all_incompats
    ]
    return _SolverError(new_chain, new_incompats)


def _build_graph(
    solution: dict[str, Version],
    provider: _Provider,
    deps_dir: Path,
    strategy: Strategy,
    aliases_map: dict[str, str] | None = None,
    entry_trust: "EntryTrustConfig | None" = None,
    binding_resolver: "BindingResolver | None" = None,
) -> ResolvedGraph:
    """Map ``solve()``'s solution dict to a ``ResolvedGraph``.

    ``aliases_map`` maps non-canonical name → canonical name (populated by
    the Phase B dedup pass).  Used to populate ``ResolvedDep.aliases`` on
    the surviving canonical dep.

    ``entry_trust`` (P3a, RFC per-entry-attestation.md §3): when not ``None``,
    the entry-trust gate runs HERE, per selected registry-resolved dep — this
    is the "post-solve, per selected dep" point the RFC specs: ``solution``
    is already the solver's FINAL pick (backtracking is done), and this loop
    iterates exactly the selected set, never a rejected/enumerated candidate.
    A ``strict``-policy failure raises and aborts graph construction (RFC §3:
    "a failing selected version is a hard, late resolve failure with no
    automatic fallback"). RFC origin-as-identity §3.3/§4.5 (S4b): the gate
    also runs for a registry candidate that S4b's dedup folded into a
    canonical peer (see the alias branch below) — merging away a dep's own
    ResolvedDep must never merge away its attestation obligation too.
    """
    GP = GitProvenance
    MP = MemberProvenanceRecord

    # Build reverse map: canonical → sorted list of aliases.
    canonical_to_aliases: dict[str, list[str]] = {}
    _aliases_map: dict[str, str] = aliases_map or {}
    if aliases_map:
        for alias, canonical in aliases_map.items():
            canonical_to_aliases.setdefault(canonical, []).append(alias)
        for lst in canonical_to_aliases.values():
            lst.sort()

    deps: list[ResolvedDep] = []
    for name, version in solution.items():
        if name == "__root__":
            continue
        try:
            cand = provider.get(name, version)
        except KeyError:
            continue

        # RFC origin-as-identity §3.3/§4.5 (S4b): a solution entry that the
        # post-solve content-hash collapse folded into a canonical peer never
        # gets its own ResolvedDep (its provenance is merged into the
        # canonical's below, from the canonical branch) — but if it was
        # itself registry-resolved, ITS OWN attestation must still be
        # checked here, before the skip, so a cross-origin collapse can
        # never be used to bypass strict entry-trust policy merely because
        # a differently-sourced peer happened to win the BFS canonical
        # tie-break.
        if name in _aliases_map:
            _alias_dk = _depkey_for_solved_name(name)
            _run_entry_trust_gate(
                cand,
                _alias_dk.name,
                _version_str_for_candidate(cand, version),
                entry_trust,
            )
            continue

        # C1 (rfc-resolver-correctness.md): ``name`` here is the PubGrub solver
        # variable — RFC origin-as-identity §4.4: for a named/registry dep its
        # string value is the BOUND source-id's canonical form, not a
        # ``"ns1::bar"`` string, so it is decoded via
        # ``_depkey_for_solved_name`` (the ``SolverKey``'s ``.display``, DE1;
        # ``DepKey.from_solver_var`` for the identity==label git/tarball/local/
        # member case). Decompose into bare name + namespace for
        # ``ResolvedDep`` so the lockfile receives the bare name as the dep
        # arg and namespace as a separate child node (never the canonical
        # string, and never ``::``, on disk).
        _cand_dk = _depkey_for_solved_name(name)
        _bare_name = _cand_dk.name        # e.g. "bar"
        _namespace = _cand_dk.namespace   # e.g. "ns1" or None

        # Map fetcher provenance → lockfile ProvenanceRecord (observed).
        observed_record = _observed_provenance_record_for_candidate(cand)

        # D-lifecycle: build declared provenance records for each mirror URL that
        # was NOT the observed candidate. Declared = unverified (no commit_sha,
        # ref preserved from the manifest dep). Mirrors are always git provenances.
        # Use the ref from the observed GitProvenance (which carries dep.ref).
        declared_ref: str | None = cand.provenance.ref if isinstance(cand.provenance, GP) else None
        declared_records: list[GitProvenanceRecord] = [
            GitProvenanceRecord(
                url=mirror_url,
                ref=declared_ref,
                commit_sha=None,
                origin="declared",
            )
            for mirror_url in cand.declared_mirror_urls
        ]

        # Assemble the full provenances tuple: observed first (before sorting), then
        # declared. The emitter sorts them canonically (declared < observed by rank).
        _all_provs: list[ProvenanceRecord] = []
        if observed_record is not None:
            _all_provs.append(observed_record)
        _all_provs.extend(declared_records)

        # RFC origin-as-identity §3.3/§4.5 (S4b): a cross-origin collapse
        # keeps BOTH origins' full audit trail — append each folded alias's
        # OWN observed provenance (never just the survivor's). Each alias is
        # itself a solved candidate (it was materialized to compute its
        # identity in _dedup_candidates), so its own version is exactly
        # ``solution[alias]``.
        for _alias_name in canonical_to_aliases.get(name, []):
            _alias_ver = solution.get(_alias_name)
            if _alias_ver is None:
                continue
            try:
                _alias_cand = provider.get(_alias_name, _alias_ver)
            except KeyError:
                continue
            _alias_prov = _observed_provenance_record_for_candidate(_alias_cand)
            if _alias_prov is not None:
                _all_provs.append(_alias_prov)

        all_provenances: tuple[ProvenanceRecord, ...] = tuple(_all_provs)

        version_str = _version_str_for_candidate(cand, version)

        # P3a (RFC per-entry-attestation.md §3, §5): the entry-trust gate —
        # post-solve, per selected registry-resolved dep. Runs BEFORE the
        # ResolvedDep is assembled so a strict-policy failure aborts graph
        # construction outright (no partially-built graph escapes).
        _run_entry_trust_gate(cand, _bare_name, version_str, entry_trust)

        # S4: build cond_requires from the candidate's requires_predicates dict.
        # requires_predicates maps name → list[predicate_tuple]; a dep in ≥2
        # when-branches yields ≥2 entries per name, each becoming one CondRequire.
        # Sort delegates to cond_require_sort_key (lockfile SSOT) so the sort
        # key uses the same escaping as the emitter — cannot drift (C1 fix).
        from milpa.lockfile import CondRequire as _CondRequire, cond_require_sort_key

        # S5-rekey (RFC origin-as-identity §4.4): requires_predicates is
        # keyed by the PubGrub solver-variable string — project back to the
        # legacy "ns::name"/bare form, same as `requires=` above (lockfile.py
        # applies no separate conversion to CondRequire.name).
        _raw_cond: list[_CondRequire] = [
            _CondRequire(name=_depkey_for_solved_name(rname).solver_var(), predicates=preds)
            for rname, pred_list in cand.requires_predicates.items()
            for preds in pred_list
            if preds
        ]
        _cond_requires: tuple[_CondRequire, ...] = tuple(
            sorted(_raw_cond, key=cond_require_sort_key)
        )

        # S5 (RFC #23 §4): populate active_flags from the converged dep_active_flags
        # map, keyed by resolved identity.  Lexicographically sorted (normative).
        # dep_active_flags is seeded only when the dep has consumer flag requests
        # (S3/S4a).  For deps with no requests but default=#true flags, derive the
        # defaults-only active set from the dep's manifest (same fallback as S4c).
        #
        # Workspace members are excluded: their active_flags are an internal
        # resolver concern (used to fire cross-pkg enables on external deps)
        # and MUST NOT appear in the lockfile.  Members carry no pinnable
        # flag state — every consumer already knows the member's flags by
        # reading the member's milpa.kdl directly.
        _is_member = isinstance(cand.provenance, MP)
        _active_map = (
            {}
            if _is_member
            else provider.dep_active_flags.get(cand.identity if cand.identity else "", {})
        )
        if not _active_map and cand.identity and not _is_member:
            # No consumer requests — derive defaults only.
            # C1: use dep_dir_name to find the dep's milpa.kdl at the correct
            # on-disk location (``_deps/@ns/bar/milpa.kdl`` for qualified deps).
            _dir_entry = dep_dir_name(_bare_name, _namespace)
            _kdl_path = deps_dir / _dir_entry / "milpa.kdl"
            if _kdl_path.exists():
                try:
                    from milpa.manifest import parse_manifest as _pm_s5
                    _dm_s5 = _pm_s5(_kdl_path.read_text(encoding="utf-8"))
                    _active_map = compute_dep_active_flags(_dm_s5.flags, ())
                except Exception:
                    pass  # non-fatal: manifest unreadable → empty active_flags
        _active_flags_sorted: tuple[str, ...] = tuple(sorted(_active_map.keys()))

        resolved = ResolvedDep(
            name=_bare_name,    # C1: bare name (never solver_var "ns::bar")
            identity=cand.identity,
            version=version_str,
            src_dir=cand.src_dir,
            # S5-rekey (RFC origin-as-identity §4.4): cand.requires_names holds
            # PubGrub solver-variable strings — a BOUND source-id's canonical
            # form for a named dep, never lockfile-safe on its own (mirrors
            # why `name=` above needs `_bare_name`, not the raw solver var).
            # Project each entry back to the legacy "ns::name" form via the
            # same canonical-or-legacy decode, so lockfile.py's SOLE
            # ``_req_name_to_lockfile`` conversion site (solver_var "ns::name"
            # -> lockfile "ns/name") keeps working unchanged.
            requires=tuple(
                _depkey_for_solved_name(r).solver_var()
                for r in cand.requires_names
            ),
            # D-lifecycle: full provenances tuple (observed + declared mirrors).
            provenances=all_provenances,
            # S5: unified per-dep active flag set, lex-sorted (RFC #23 §4).
            active_flags=_active_flags_sorted,
            # S6: dep_decl pin — carries the DepDecl hash from _Candidate (set in
            # _materialize when DepDeclEdgeSource fired) to the lockfile record.
            dep_decl=cand.dep_decl,
            # S4: conditional require annotations (sorted by (name, canonical-predicate-string)).
            cond_requires=_cond_requires,
            # Phase B: aliases — lex-sorted list of non-canonical names that share
            # this dep's content identity.  Empty for non-deduped deps.
            # RFC §4.4.1 (S5-rekey): canonical_to_aliases holds RAW PubGrub
            # solver-variable strings (canonical for every kind, uniformly)
            # — project each back to the bare name (matching ``name=``
            # above; the lockfile's ``aliases`` field, unlike ``requires=``,
            # has no separate "::"->"/" conversion step in lockfile.py, so
            # it has only ever carried bare names) before it reaches the
            # lockfile; re-sort after projection since canonical-string
            # lexicographic order need not match bare-name lexicographic
            # order.
            aliases=tuple(sorted(
                _depkey_for_solved_name(a).name
                for a in canonical_to_aliases.get(name, [])
            )),
            # C1: carry namespace for qualified named deps.
            namespace=_namespace,
            # RFC per-entry-attestation.md P2: carry the attestation claim from
            # the candidate (None for non-named deps and unattested entries).
            attestation=cand.attestation,
            # RFC origin-as-identity §4.4 (B2/G10 field-duplication audit):
            # ``registry_namespace`` is DELETED from ResolvedDep — it
            # duplicated ``source_id.namespace`` for a ``RegistrySourceId``.
            # ``milpa verify``'s offline re-verification and the lockfile's
            # ``LockAttestation.namespace`` now read ``source_id.namespace``
            # directly (see ``_locked_from_resolved``).
            # A5: sibling source for the declared version (None for
            # version-unknown and for named/index candidates, which never
            # populate it — see the field's doc comment on _Candidate).
            # RFC origin-as-identity §4.4 (S3a): the binding phase's own
            # accepted SourceId for this dep's DepKey — carried onto the
            # on-disk lockfile's structured ``source { … }`` node as of S5
            # (§4.1/§7). ``None`` when no ``binding_resolver`` was passed
            # (defensive; both live entry points always pass one).
            source_id=(
                binding_resolver.source_id_for(_cand_dk)
                if binding_resolver is not None
                else None
            ),
            declared_version_source=(
                cand.declared_version_source.value
                if cand.declared_version_source is not None
                else None
            ),
        )
        deps.append(resolved)

    return ResolvedGraph(deps=tuple(deps))


# ---------------------------------------------------------------------------
# _Candidate-builder for workspace members (slice 9d)
# ---------------------------------------------------------------------------


def _build_member_candidate(
    manifest: Manifest,
    abs_dir: Path,
    overrides_by_name: dict[str, Override],
    member_versions: dict[str, Version],
    member_version_sources: dict[str, VersionSource | None],
    binding_resolver: "BindingResolver",
) -> tuple[_Candidate, list[object]]:
    """Build a _Candidate for a workspace member (never fetched, cas_admissible=False).

    Returns ``(_Candidate, [])`` — members have no external transitive deps to
    enqueue (their deps are seeded explicitly in resolve_workspace).

    ``member_versions`` maps every workspace member's name to its own
    candidate-label version (A2c: ``_member_candidate_version`` — the
    member's declared ``milpa.kdl``/``.nimble`` version, else the sentinel),
    precomputed once for ALL members by the caller so this function can
    validate a same-name reference against the *referenced* member's real
    version, not just its own.
    """
    identity = compute_content_hash(abs_dir)

    # Build solver terms from ALL member deps (regular + dev-deps, per §11).
    # Member-named refs and named deps matching a member name (auto-coerce)
    # both get a full() self-term (D-A2: a member has exactly one candidate,
    # like a git/url/local/tarball dep — justified by "one candidate, must
    # satisfy floors", NOT by the fetched-kinds' pre-fetch/post-fetch
    # causality argument, since a member has no fetch).
    dep_terms: list[Term] = []
    requires_names: list[str] = []

    all_member_deps = list(manifest.deps) + list(manifest.dev_deps)

    for dep in all_member_deps:
        name = dep.name
        # Auto-coerce: MemberDep or named dep matching a member name → full().
        if isinstance(dep, MemberDep) or name in member_versions:
            # Breadth-P1c (S5) + A2c: when a NamedDep auto-coerces to a member,
            # check that the member's OWN declared (or sentinel, if undeclared)
            # version satisfies the declared constraint. Silently discarding
            # the constraint is a correctness hole — the consumer said
            # ">= 2.0.0" and the member must actually be at a version that
            # satisfies it. This is a real semantic check, independent of the
            # full() self-term below (which exists so PubGrub never
            # pre-commits to a version label the one-candidate member might
            # not carry — the check above is where real conflicts surface).
            if isinstance(dep, NamedDep) and dep.constraint_set is not None:
                target_version = member_versions[name]
                if not dep.constraint_set.contains(target_version):
                    raise MilpaError(
                        RES_WS_MEMBER_VERSION_CONSTRAINT,
                        f"named dep {name!r} auto-coerces to workspace member "
                        f"{name!r} but the declared constraint "
                        f"{dep.constraint!r} is not satisfied by the member's "
                        f"version {target_version} "
                        f"(member {name!r} is at version {target_version}; "
                        f"declared constraint must match)",
                        dep=name,
                        constraint=dep.constraint,
                        member=manifest.name,
                    )
            # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key —
            # the referenced member's OWN candidate is registered under its
            # canonical (MemberSourceId) form (below), so this auto-coerced
            # self-term must key the SAME string. The member's own claim is
            # already bound (member self-registration Claims, at
            # BindingResolver construction, above).
            _svar_coerce = binding_resolver.canonical_for(DepKey(name=name))
            dep_terms.append(Term.require(_svar_coerce, VersionSet.full()))
            requires_names.append(_svar_coerce)
            continue
        # Override: named dep with override → URL-like full() self-term (D-A2).
        if name in overrides_by_name:
            _svar_ov_mc = binding_resolver.canonical_for(DepKey(name=name))
            dep_terms.append(Term.require(_svar_ov_mc, VersionSet.full()))
            requires_names.append(_svar_ov_mc)
            continue
        # Regular dep: same logic as _dep_to_term.
        t, r = _dep_to_term(dep, overrides_by_name, binding_resolver)
        if t is not None and r is not None:
            dep_terms.append(t)
            requires_names.append(r)

    return _Candidate(
        # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — a
        # member's own candidate is keyed by its bound MemberSourceId's
        # canonical form, matching any consumer's reference to this SAME
        # member name (auto-coerce above, a MemberTarget override target, or
        # a transitive git/named require that turns out to BE this member).
        name=binding_resolver.canonical_for(DepKey(name=manifest.name)),
        version=member_versions[manifest.name],
        identity=identity,
        src_dir=manifest.src_dir or "",
        dep_terms=dep_terms,
        requires_names=requires_names,
        provenance=MemberProvenanceRecord(name=manifest.name),
        # A5: sibling source for the member's own version label (D-A2's
        # existing precomputed-once-for-all-members pattern, extended).
        declared_version_source=member_version_sources[manifest.name],
    ), []


# ---------------------------------------------------------------------------
# resolve_workspace — slice 9d
# ---------------------------------------------------------------------------


def resolve_workspace(
    workspace: LoadedWorkspace,
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
) -> ResolvedGraph:
    """Full live resolve for a workspace.

    Unions all member dep-sets into one solve; cross-member named constraints
    are accumulated and intersected (resolver-semantics.md §11).

    Parameters
    ----------
    workspace:
        Loaded workspace with member manifests and root directory.
    deps_dir:
        Where fetched external dep trees are placed (typically ``_deps/``).
    env:
        Injectable seams: ``fetcher``, ``index``, ``store``.
    params:
        Per-call parameters: ``strategy``, ``max_parallel``, ``profile``,
        ``prior``, ``require_attested_metadata``.

    Returns
    -------
    ResolvedGraph
        The complete set of resolved deps (members + external deps).

    Raises
    ------
    MilpaError
        RES-WS-OVERRIDE-MEMBER-COLLISION, RES-WS-MEMBER-REF-UNKNOWN,
        RES-WS-NO-INDEX, or any other MAN-*/TNG-*/FETCH-*/SOLVE-*/RES-* slug.
    """
    # §13.1 workspace attestation policy: effective strict = OR of
    # params.require_attested_metadata (flag/env) OR any member's
    # attestation-policy == "strict".
    from milpa.trust import effective_trust_policy as _eff_trust
    _ws_is_strict = params.require_attested_metadata or any(
        _eff_trust(m.manifest.attestation_policy, False) == "strict"
        for m in workspace.members
    )
    deps_dir.mkdir(parents=True, exist_ok=True)

    # S2 (RFC: workspace-completion §3.A): compute workspace-root CLI seed.
    # Uses _compute_workspace_cli_seed (SSOT wrapper) with workspace_manifest.flags.
    # The seed is passed per-member to FilterContext.build, which runs
    # flag_enables_closure against the *member's own* flags — that's why
    # build() takes the member manifest.
    # None = no CLI feature selection (passthrough for the flag gate).
    _ws_cli_seed: frozenset[str] | None = _compute_workspace_cli_seed(
        workspace.workspace_manifest,
        features=params.features,
        no_default_features=params.no_default_features,
        all_features=params.all_features,
    )

    # ------------------------------------------------------------------
    # Workspace-level checks before any resolution
    # ------------------------------------------------------------------
    overrides_by_name: dict[str, Override] = {
        ov.name: ov for ov in workspace.workspace_manifest.overrides
    }
    members_by_name: frozenset[str] = frozenset(
        m.manifest.name for m in workspace.members
    )

    # A2c: each member's own candidate-label version, computed once up front
    # so both the member's own candidate AND any other member's same-name
    # auto-coerce reference (which needs the *referenced* member's real
    # version, not its own) read the same value (§3 Axis A member block, D-A2).
    # A5: also capture the sibling source per member (same precomputed-once
    # call — no second, potentially file-re-reading, lookup).
    _member_version_pairs: dict[str, tuple[Version, VersionSource | None]] = {
        m.manifest.name: _member_candidate_version(m.manifest, m.abs_dir)
        for m in workspace.members
    }
    member_versions: dict[str, Version] = {
        name: v for name, (v, _src) in _member_version_pairs.items()
    }
    member_version_sources: dict[str, VersionSource | None] = {
        name: src for name, (_v, src) in _member_version_pairs.items()
    }

    # RES-WS-OVERRIDE-MEMBER-COLLISION: a non-member-target override name cannot
    # also be a member name.  MemberTarget overrides (pkg "X" { member "X" }) are
    # the INTENDED form of S8b patch and are explicitly exempted — they redirect a
    # transitive dep to the pre-registered member candidate.
    collisions = sorted(
        n for n in overrides_by_name
        if n in members_by_name
        and not isinstance(overrides_by_name[n].target, MemberTarget)
    )
    if collisions:
        raise MilpaError(
            RES_WS_OVERRIDE_MEMBER_COLLISION,
            f"workspace override name(s) {collisions!r} also appear as workspace "
            f"member(s) — remove either the override or the member; cannot have both",
            names=collisions,
        )

    # RES-WS-MEMBER-REF-UNKNOWN: a member "X" dep with no such workspace member.
    # Must check BOTH deps AND dev_deps — a dangling member ref in dev_deps is
    # equally invalid (Depth-F3, S5 fix).
    for member in workspace.members:
        for dep in list(member.manifest.deps) + list(member.manifest.dev_deps):
            if isinstance(dep, MemberDep) and dep.name not in members_by_name:
                raise MilpaError(
                    RES_WS_MEMBER_REF_UNKNOWN,
                    f"workspace member {member.manifest.name!r} references "
                    f"`member {dep.name!r}` but no such member exists",
                    member=member.manifest.name,
                    name=dep.name,
                )

    # RES-WS-NO-INDEX: a member's named dep with no index, no override, no
    # matching member is unresolvable.
    if env.index is None:
        unresolvable = sorted({
            dep.name
            for m in workspace.members
            for dep in list(m.manifest.deps) + list(m.manifest.dev_deps)
            if isinstance(dep, NamedDep)
            and dep.name != "nim"
            and dep.name not in overrides_by_name
            and dep.name not in members_by_name
        })
        if unresolvable:
            raise MilpaError(
                RES_WS_NO_INDEX,
                f"workspace has named dep(s) {unresolvable!r} but no tianguis "
                f"index was provided",
                names=unresolvable,
            )

    index: Index = env.index if env.index is not None else Index()

    # ------------------------------------------------------------------
    # Build provider with workspace root authority
    # ------------------------------------------------------------------
    # RR2 (R6 dual-set cleanup): build the namespace-aware set ONCE
    # (members + overrides + every member dep), then derive the bare-name
    # authority set as a pure name-projection of it — replacing two
    # independently hand-built + independently mutated collections with one
    # populated collection + one projection.
    #
    # R6: namespace-aware set — used ONLY by is_root_direct (the
    # lowest-direct precompute). Member names and overrides have no
    # namespace concept; each member dep's ACTUAL namespace is threaded
    # through the same way as the single-package resolve() path.
    root_direct_keys: set[DepKey] = {DepKey(name=n) for n in members_by_name} | {
        DepKey(name=n) for n in overrides_by_name
    }
    for m in workspace.members:
        all_deps = list(m.manifest.deps) + list(m.manifest.dev_deps)
        for dep in all_deps:
            root_direct_keys.add(
                DepKey(name=dep.name, namespace=getattr(dep, "namespace", None))
            )

    # Root authority = all member names + override names + every member dep's
    # name (§10 NORMATIVE) — provably byte-identical to the old
    # independently-built set: both are sourced from exactly
    # `members_by_name` + `overrides_by_name` + every member's own
    # deps/dev-deps names — the SAME sources — so projecting
    # `root_direct_keys` down to just its `.name` field yields the exact
    # same set of bare names.
    #
    # RFC origin-as-identity §6 "Kept": see resolve()'s identical comment —
    # ``root_authority`` survives post-S3b for ``_version_unknown_constrained_err``
    # and the registry-shadow tripwire gate only; source admission/arbitration
    # (including a MemberTarget override suppressing a transitive's stale
    # claim on the same name — the old provenance-gate pre-seed this block
    # used to carry) is entirely ``BindingResolver``'s job below.
    root_authority: set[str] = {k.name for k in root_direct_keys}

    seen_url: set[tuple[str, str, str | None]] = set()
    seen_named: set[DepKey] = set()  # S5a: qualified key (namespace+name)
    seen_local: set[str] = set()
    seen_tarball: set[str] = set()
    seen_oci: set[str] = set()  # S8b: keyed by "registry/repository@digest"

    # Phase B dedup: BFS-insertion discovery order (mirrors resolve()).
    # Members are pre-registered and NOT in discovery_order (they are
    # workspace-local, not external deps subject to content-hash dedup).
    ws_discovery_order: list[str] = []
    _ws_discovery_seen: set[str] = set()

    def _ws_record_discovery(name: str) -> None:
        """Record a name in BFS-insertion discovery order (idempotent)."""
        if name not in _ws_discovery_seen:
            _ws_discovery_seen.add(name)
            ws_discovery_order.append(name)

    # Resolver-scoped edge memo (§4.2.1 resolve_edges clause a).
    ws_edge_cache: dict[tuple[SourceId, Version], EdgeSet] = {}

    # RFC origin-as-identity §4.3 (S3a): the binding phase, workspace form.
    # Root claims are every member's OWN self-registration (MemberSourceId,
    # conflict-free by W1-W5 name uniqueness) PLUS every member's declared
    # deps/dev-deps, reconciled against the workspace overrides (a
    # MemberTarget override is meaningful here — unlike the standalone
    # resolve() path — since it redirects to an actually pre-registered
    # member).
    #
    # Member auto-coerce (§11.5, mirrors ``_build_member_candidate``'s own
    # ``name in member_versions`` check): a dep — ``MemberDep`` OR a bare
    # ``NamedDep`` — whose name matches ANOTHER workspace member's name
    # never makes its own claim; it resolves directly to that member's
    # candidate (a ``full()`` self-term, handled entirely in
    # ``_build_member_candidate``, never via BFS/binding). Excluded here so
    # it doesn't collide with that member's own self-registration Claim
    # above (same name, would otherwise look like a disagreeing registry
    # claim to ``BindingResolver.__init__``).
    #
    # Constructed BEFORE ``_Provider`` (S4): ``_Provider._materialize`` needs
    # ``binding_resolver.source_id_for`` to key the edge_cache by source_id
    # rather than name (RFC §4.5) — neither construction depends on the
    # other's output, so this is a pure reorder, not a behavior change.
    _ws_all_member_deps: list[object] = []
    for m in workspace.members:
        for _wsd in list(m.manifest.deps) + list(m.manifest.dev_deps):
            if _wsd.name in members_by_name:
                continue
            _ws_all_member_deps.append(_wsd)
    binding_resolver = BindingResolver(
        [
            Claim(
                name=m.manifest.name,
                source_id=MemberSourceId(member_name=m.manifest.name),
                is_root=True,
                claimant="member",
            )
            for m in workspace.members
        ]
        + reconcile_root_claims(
            _ws_all_member_deps,
            workspace.workspace_manifest.overrides,
            index=index,
        )
    )

    provider = _Provider(
        env=env,
        deps_dir=deps_dir,
        params=params,
        overrides_by_name=overrides_by_name,
        root_direct_keys=root_direct_keys,
        seen_named=seen_named,
        seen_url=seen_url,
        binding_resolver=binding_resolver,
        edge_cache=ws_edge_cache,
        strict_attestation=_ws_is_strict,
    )

    # ------------------------------------------------------------------
    # Pre-register each member as a candidate (never fetched)
    # ------------------------------------------------------------------
    for member in workspace.members:
        # S2 (RFC: workspace-completion §3.A): apply FilterContext to the member
        # manifest before building dep_terms for the solver.  Filtering at this
        # site ensures flag-gated deps are pruned from solver terms, preventing
        # spurious SOLVE-CONFLICT when a gated dep version-clashes.
        # FilterContext.build runs flag_enables_closure against the MEMBER's own
        # flags (not the workspace root's) — this is the invariant Design-F1.
        _member_ctx = FilterContext.build(
            member.manifest, params.profile, cli_seed=_ws_cli_seed
        )
        member_manifest = filter_manifest(member.manifest, _member_ctx)

        cand, _ = _build_member_candidate(
            member_manifest,
            member.abs_dir,
            overrides_by_name,
            member_versions,
            member_version_sources,
            binding_resolver,
        )
        provider.add(cand)

    # ------------------------------------------------------------------
    # Build root candidate requiring all members
    # ------------------------------------------------------------------
    # A2c/D-A2: full() self-term — the root always requires all members
    # regardless of their (real or sentinel) version label; a member has
    # exactly one candidate, so pre-committing to a version here would
    # spuriously conflict with a versioned member.
    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key — must
    # agree with _build_member_candidate's own canonical registration key
    # (above). Each member's own MemberSourceId claim is already bound
    # (member self-registration Claims, at BindingResolver construction).
    _member_svars: list[str] = [
        binding_resolver.canonical_for(DepKey(name=m.manifest.name))
        for m in workspace.members
    ]
    root_terms: list[Term] = [
        Term.require(_svar_m, VersionSet.full())
        for _svar_m in _member_svars
    ]
    root_requires: list[str] = list(_member_svars)

    root_cand = _Candidate(
        name="__root__",
        version=Version(0, 0, 0),
        identity=None,
        src_dir="",
        dep_terms=root_terms,
        requires_names=root_requires,
        provenance=None,
    )
    provider.add(root_cand)

    # ------------------------------------------------------------------
    # Seed BFS queue with each member's external deps
    #
    # ORDERING INVARIANT (§4.2.1 / §11): declaration order across members
    # (member 0 deps first, then member 1 deps, etc.) is the canonical P.
    # Members themselves are pre-registered above.
    # ------------------------------------------------------------------
    bfs_queue: list[object] = []

    # S11 (RFC #23 §3.8): workspace-root flags {} — seed workspace-wide active
    # flags from workspace-root default-true flags.  Compute the enables-closure
    # (same-package closure via _flag_enables_closure) then extract cross-pkg
    # enables and pre-seed provider._flag_requests_by_name.
    if workspace.workspace_manifest.flags:
        _ws_root_flags = workspace.workspace_manifest.flags
        # Compute which workspace-root flags are default-active (or always-active).
        _ws_root_active_seed: frozenset[str] = frozenset(
            f.name for f in _ws_root_flags if f.default
        )
        _ws_root_active: frozenset[str] = flag_enables_closure(
            _ws_root_flags, _ws_root_active_seed
        )
        # Build a flag-name → FlagDecl lookup.
        _ws_flag_by_name = {fd.name: fd for fd in _ws_root_flags}
        # Extract cross-pkg enables from root-active flags.
        for _ws_flag_name in _ws_root_active:
            _ws_fd = _ws_flag_by_name.get(_ws_flag_name)
            if _ws_fd is None:
                continue
            for _cpe in _ws_fd.enables_cross_pkg:  # CrossPkgEnable(dep, flag_requests)
                # S5-rekey (RFC origin-as-identity §4.4): _cpe.dep is the bare
                # target name from the workspace-root `enables{}` block —
                # project to whatever key the target's ALREADY-admitted
                # candidate is actually registered under (bare for an eager
                # git/tarball/local target, canonical for a named/registry
                # one — the target is one of the members' own deps, already
                # root-bound via reconcile_root_claims above, so
                # canonical_key_for_requirement's binding_resolver-first
                # branch always fires) so this accumulation lands under the
                # SAME key _materialize reads.
                from milpa.binding import canonical_key_for_requirement as _ckfr_ws_root
                _target = _ckfr_ws_root(
                    name=_cpe.dep,
                    namespace=None,
                    url=None,
                    overrides_by_name=overrides_by_name,
                    index=index,
                    binding_resolver=binding_resolver,
                )
                # Accumulate (union) into provider._flag_requests_by_name.
                existing = provider._flag_requests_by_name.get(_target, ())
                provider._flag_requests_by_name[_target] = existing + _cpe.flag_requests

    for member in workspace.members:
        # S2 (RFC: workspace-completion §3.A): apply FilterContext to the member
        # manifest before seeding the BFS queue.  This is the second of two
        # application sites (the first is in the candidate pre-registration loop
        # above) — filtering at BOTH sites ensures the solver sees no flag-gated
        # solver terms AND the BFS queue contains no flag-gated deps.
        # Re-using FilterContext.build ensures the flag-only arm is identical to
        # the single-package path (shared SSOT, no divergence).
        _bfs_ctx = FilterContext.build(
            member.manifest, params.profile, cli_seed=_ws_cli_seed
        )
        member_manifest = filter_manifest(member.manifest, _bfs_ctx)

        all_member_deps = list(member_manifest.deps) + list(member_manifest.dev_deps)

        for dep in all_member_deps:
            name = dep.name
            # Members and member-named refs are pre-registered → skip queueing.
            if isinstance(dep, MemberDep) or name in members_by_name:
                continue
            # Override: named → URL, local (S8a), or member (S8b) override.
            if name in overrides_by_name:
                ov = overrides_by_name[name]
                # S8a: LocalTarget override → route to local BFS slot.
                if isinstance(ov.target, LocalTarget):
                    # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical
                    # solver key — matches what _build_member_candidate's
                    # _dep_to_term call independently computes for this SAME
                    # dep (this loop only seeds the BFS fetch queue/
                    # discovery bookkeeping; _dep_to_term builds the actual
                    # Term). Root claim already bound.
                    _svar_wslt = binding_resolver.canonical_for(DepKey(name=name))
                    bfs_queue.append(("local", LocalDep(name=name, path=ov.target.path, version=ov.version)))
                    _ws_record_discovery(_svar_wslt)  # Phase B: overridden dep in seed order
                elif isinstance(ov.target, MemberTarget):
                    # S8b: MemberTarget override — member already pre-registered.
                    # No external queue entry needed; provenance gate was pre-seeded
                    # above.  Don't call _ws_record_discovery — the member candidate
                    # is not an external dep and is never in ws_discovery_order.
                    pass
                else:
                    # S8b: GitTarget → UrlDep; LocalTarget already handled
                    # above; TarballTarget/OciTarget/RegistryTarget → their
                    # own BFS slot (mirrors _extended_override_bfs_item's
                    # dispatch, but this call site already needs
                    # _apply_override's result for the UrlDep/LocalDep case
                    # too, so the full dispatch is inlined here rather than
                    # calling both helpers).
                    effective_dep = _apply_override(name, ov)
                    _svar_wsov = binding_resolver.canonical_for(DepKey(name=name))
                    if isinstance(effective_dep, UrlDep):
                        bfs_queue.append(("url", effective_dep))
                    elif isinstance(effective_dep, TarballDep):
                        bfs_queue.append(("tarball", effective_dep))
                    elif isinstance(effective_dep, _OciOverrideDep):
                        bfs_queue.append(("oci", effective_dep))
                    elif isinstance(effective_dep, NamedDep):
                        bfs_queue.append((
                            "named",
                            DepKey(name=effective_dep.name, namespace=effective_dep.namespace),
                            effective_dep.constraint,
                        ))
                    else:
                        # Unreachable: LocalTarget/MemberTarget are already
                        # handled above; every other kind is enumerated
                        # explicitly above.
                        raise AssertionError(
                            f"unexpected _apply_override result for {name!r}: "
                            f"{type(effective_dep)!r}"
                        )
                    _ws_record_discovery(_svar_wsov)  # Phase B: overridden dep in seed order
                continue
            # Queue external deps.
            if isinstance(dep, UrlDep):
                # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
                _svar_wsu = binding_resolver.canonical_for(DepKey(name=name))
                bfs_queue.append(("url", dep))
                _ws_record_discovery(_svar_wsu)  # Phase B: URL dep in seed order
            elif isinstance(dep, NamedDep):
                if name == "nim":
                    continue
                # S5b: carry namespace from manifest dep.
                _dk_ws = DepKey(name=name, namespace=dep.namespace)
                # S5-rekey (RFC origin-as-identity §4.4): solver variable =
                # BOUND source-id canonical form. This member dep's root
                # claim is already bound (reconcile_root_claims, at
                # BindingResolver construction, above).
                _svar_ws = binding_resolver.canonical_for(_dk_ws)
                bfs_queue.append(("named", _dk_ws, dep.constraint))
                _ws_record_discovery(_svar_ws)  # Phase B: named dep in seed order
                # S11 (RFC #23 §3.8): accumulate flag_requests from ALL members
                # (workspace-wide union).  Keyed by solver_var to agree with _materialize.
                if dep.flag_requests:
                    existing_named = provider._flag_requests_by_name.get(_svar_ws, ())
                    provider._flag_requests_by_name[_svar_ws] = existing_named + dep.flag_requests
            elif isinstance(dep, TarballDep):
                # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
                _svar_wstb = binding_resolver.canonical_for(DepKey(name=name))
                bfs_queue.append(("tarball", dep))
                _ws_record_discovery(_svar_wstb)  # Phase B: tarball dep in seed order
            elif isinstance(dep, LocalDep):
                # RFC §4.4.1 (S5-rekey, phase 2): uniform canonical solver key.
                _svar_wslo = binding_resolver.canonical_for(DepKey(name=name))
                bfs_queue.append(("local", dep))
                _ws_record_discovery(_svar_wslo)  # Phase B: local dep in seed order

    # ------------------------------------------------------------------
    # S4a (workspace): pre-seed member dep_active_flags and build the
    # extra_manifests dict so the fixpoint can fire member-flag enables.
    #
    # Workspace members live in their source dirs (member.abs_dir), NOT
    # in deps_dir.  The standard S4a fixpoint reads manifests from
    # deps_dir/<name>/milpa.kdl — members are invisible to it.  To fix:
    #
    # 1. Compute each member's default-active flag seed (default=true
    #    flags + same-pkg enables-closure, same algorithm as the
    #    workspace-root-flags seeding above).
    # 2. Seed provider.dep_active_flags[member_identity] with those
    #    active flags so the fixpoint's step 2 can fire their
    #    enables_cross_pkg rules.
    # 3. Pass the member manifests as extra_manifests to the fixpoint so
    #    they appear in dep_manifests alongside fetched URL deps.
    #
    # This mirrors what process_url (line ~1522-1546) does for URL deps:
    # unconditionally seed dep_active_flags so default-true flags are
    # visible to the fixpoint even without an explicit flag_request.
    # ------------------------------------------------------------------
    _member_manifests_for_fixpoint: dict[str, object] = {}
    for _seed_member in workspace.members:
        _seed_manifest = _seed_member.manifest
        if not _seed_manifest.flags:
            continue
        # Compute the member's default-active flags (same-pkg closure).
        _seed_active: frozenset[str] = frozenset(
            f.name for f in _seed_manifest.flags if f.default
        )
        _seed_active = flag_enables_closure(_seed_manifest.flags, _seed_active)
        if not _seed_active:
            continue
        # Get the member's identity from its candidate.
        # RFC §4.4.1 (S5-rekey, phase 2): provider._candidates is keyed by
        # the UNIFORM canonical solver variable (a member's own
        # MemberSourceId canonical form, matching _build_member_candidate's
        # registration) — never the bare manifest name.
        _seed_svar = binding_resolver.canonical_for(DepKey(name=_seed_manifest.name))
        _seed_cand_map = provider._candidates.get(_seed_svar, {})
        _seed_identity: str | None = None
        for _sc in _seed_cand_map.values():
            if _sc.identity:
                _seed_identity = _sc.identity
                break
        if _seed_identity is None:
            continue
        # Seed dep_active_flags for this member (monotone union with any existing).
        _seed_existing = provider.dep_active_flags.get(_seed_identity, {})
        _seed_merged: dict[str, set[ActivationSource]] = dict(_seed_existing)
        for _sfn in _seed_active:
            if _sfn not in _seed_merged:
                _seed_merged[_sfn] = set()
            _seed_merged[_sfn].add(ActivationSource.DEFAULT)
        provider.dep_active_flags[_seed_identity] = _seed_merged
        # Include this member's manifest in the fixpoint's dep_manifests,
        # keyed by the SAME canonical solver variable so _s4a_run_fixpoint's
        # own identity_for_dep re-lookup (provider._candidates.get(dep_name_k))
        # finds this SAME candidate on each fixpoint iteration.
        _member_manifests_for_fixpoint[_seed_svar] = _seed_manifest

    # ------------------------------------------------------------------
    # BFS materialisation loop (parallel) — shared helper, see resolve()
    # for full ordering-invariant commentary.
    # ------------------------------------------------------------------
    workers = max(1, params.max_parallel)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        _run_bfs_wave_loop(
            bfs_queue=bfs_queue,
            executor=executor,
            seen_named=seen_named,
            seen_url=seen_url,
            seen_tarball=seen_tarball,
            seen_local=seen_local,
            seen_oci=seen_oci,
            edge_cache=ws_edge_cache,
            provider=provider,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            root_authority=root_authority,
            record_discovery=_ws_record_discovery,
            binding_resolver=binding_resolver,
            is_strict=_ws_is_strict,
        )

        # ------------------------------------------------------------------
        # Step 6a (workspace): S4a dep×flag fixpoint (RFC #23 §3.1.2 + §7 S4a)
        #
        # Mirrors resolve() step 6a.  After the initial BFS wave, iterate
        # until neither the admitted dep set nor the active-flag set grows.
        # The executor remains open so newly-admitted deps can be fetched.
        #
        # extra_manifests supplies workspace member manifests (not in deps_dir)
        # so member-flag enables_cross_pkg rules fire during the fixpoint.
        # Member dep_active_flags were pre-seeded above so the fixpoint's
        # step 2 sees each member's default-active flags on the first iteration.
        # ------------------------------------------------------------------
        _s4a_run_fixpoint(
            provider=provider,
            bfs_queue=bfs_queue,
            executor=executor,
            seen_named=seen_named,
            seen_url=seen_url,
            seen_tarball=seen_tarball,
            seen_local=seen_local,
            seen_oci=seen_oci,
            edge_cache=ws_edge_cache,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            root_authority=root_authority,
            record_discovery=_ws_record_discovery,
            binding_resolver=binding_resolver,
            is_strict=_ws_is_strict,
            extra_manifests=_member_manifests_for_fixpoint,
        )

    # ------------------------------------------------------------------
    # Wire Phase B transitive callback BEFORE solve
    # ------------------------------------------------------------------
    def _on_transitive_named(dep_key: DepKey) -> None:
        # S5-rekey (RFC origin-as-identity §4.4): caller passes the ORIGINAL
        # ``DepKey`` directly (see ``_edgeset_named_requires``) — no
        # ``DepKey.from_solver_var`` reverse-decode; mirrors the
        # single-package ``_on_transitive_named`` (resolve() step 7).
        if dep_key in seen_named or dep_key.name == "nim":
            return
        seen_named.add(dep_key)
        # RFC origin-as-identity §4.3 (S3a): this callback fires OUTSIDE the
        # BFS wave loop (mid-solve, Phase B lazy materialisation) — mirrors
        # the single-package ``_on_transitive_named`` (resolve() step 7): an
        # independent admission site that must route through
        # ``BindingResolver`` too, not just the BFS "named" arm.
        _named_claim_wt = Claim(
            name=dep_key.solver_var(),
            source_id=normalize_source(
                RegistrySourceId(
                    registry=DEFAULT_REGISTRY_ALIAS,
                    namespace=resolved_registry_namespace(
                        dep_key.name, dep_key.namespace, index,
                    ),
                    name=dep_key.name,
                )
            ),
            is_root=False,
            claimant="transitive",
        )
        _named_decision_wt = binding_resolver.submit(_named_claim_wt)
        if _named_decision_wt.outcome is BindOutcome.LOST_TO_ROOT:
            return
        # S5-rekey: record_discovery AFTER the claim is bound (canonical_for
        # requires it) — see resolve()'s equivalent callback for why moving
        # past the LOST_TO_ROOT return is a no-op, not a behavior change.
        _ws_record_discovery(binding_resolver.canonical_for(dep_key))  # Phase B: lazy-materialized named dep
        _enumerate_named_stubs(
            dep_key, None, index, provider, deps_dir, env,
            exclude_newer=params.exclude_newer,
        )

    provider.set_transitive_callback(_on_transitive_named)

    # ------------------------------------------------------------------
    # Step 6b-pre (workspace): S4c post-fixpoint flag-conflict validation
    #
    # Mirrors resolve() step 6b-pre: runs AFTER the dep×flag fixpoint
    # converges across ALL members (the union is already in dep_active_flags),
    # BEFORE solver entry.  The cross-member union is subject to the same
    # flag-conflict validation as a single-package resolve — a dep with
    # conflicting flags co-active from different members raises
    # RESOLVE-FLAG-CONFLICT (resolver-semantics §3.8-conflict).
    # ------------------------------------------------------------------
    _s4c_check_flag_conflicts(provider, deps_dir)

    # ------------------------------------------------------------------
    # Solve (+ build §5.1 certificate for --certificate flag)
    # ------------------------------------------------------------------
    try:
        solution, cert = solve_with_cert(
            provider,
            "__root__",
            Version(0, 0, 0),
            strategy=params.strategy,
        )
        # S5-rekey (RFC origin-as-identity §4.4): project the certificate's
        # PubGrub package strings back to the legacy "ns::name"/bare form —
        # certificate_to_json (solver.py) has no BindingResolver access.
        cert = _project_solve_success(cert)
    except VersionUnknownConstrained as exc:
        raise _version_unknown_constrained_err(exc, root_authority, binding_resolver) from exc
    except SolverError as exc:
        from milpa.errors import SOLVE_CONFLICT
        _projected_exc = _project_solver_error(exc)
        raise MilpaError(
            SOLVE_CONFLICT,
            f"dependency conflict: {_projected_exc}",
            chain=_projected_exc.chain,
            solver_error=_projected_exc,
        ) from exc

    # ------------------------------------------------------------------
    # Step 6b (workspace): Phase B content-hash dedup/alias (RFC origin-as-
    # identity §3.3/§4.5, S4b — cross-origin reconciliation)
    #
    # Mirrors resolve() step 8b: runs on the SOLVED graph (post-solve, pre-
    # build), grouping `solution`'s chosen candidates by identity.  Member
    # candidates are never in ws_discovery_order, so a member never wins a
    # canonical tie-break against a genuinely-external dep (members are never
    # expected to coincide in content with a fetched dep in practice).
    # ------------------------------------------------------------------
    ws_aliases_map: dict[str, str] = _dedup_candidates(
        provider, deps_dir, ws_discovery_order, overrides_by_name, solution
    )

    # ------------------------------------------------------------------
    # Build graph (attach cert for CLI §2.5)
    # ------------------------------------------------------------------
    graph = _build_graph(
        solution, provider, deps_dir, params.strategy,
        aliases_map=ws_aliases_map, entry_trust=params.entry_trust,
        binding_resolver=binding_resolver,
    )

    # §13 attestation policy enforcement — mirrors single-package resolve().
    # Effective policy: OR of flag/env (via _ws_is_strict computed above) and
    # each member's attestation-policy "strict" declaration (§13.1 workspace rule).
    from milpa.attestation import enforce_attestation_policy
    # RFC origin-as-identity §4.5 (S4): ws_edge_cache is keyed by
    # (source_id, version) — reverse-map via ws_discovery_order, mirroring
    # resolve()'s Step 10 (see its comment for the full rationale).
    _ws_name_by_source_id: dict[SourceId, str] = {}
    for _n in ws_discovery_order:
        # S5-rekey: ws_discovery_order holds canonical solver-variable
        # strings for named deps — decode for both the lookup key and the
        # stored DISPLAY name (attestation-policy warning text).
        _ws_dk_disp = _depkey_for_solved_name(_n)
        _sid = binding_resolver.source_id_for(_ws_dk_disp)
        if _sid is not None and _sid not in _ws_name_by_source_id:
            _ws_name_by_source_id[_sid] = _ws_dk_disp.solver_var()
    resolved_edge_map: dict[str, "EdgeSet"] = {
        _ws_name_by_source_id[sid]: es
        for (sid, _ver), es in ws_edge_cache.items()
        if sid in _ws_name_by_source_id
    }
    enforce_attestation_policy(resolved_edge_map, _ws_is_strict)

    from dataclasses import replace as _replace
    graph = _replace(graph, cert=cert)

    # M6 / RES-DEAD-OVERRIDE (rfc-origin-as-identity.md §10 item 12 / B10,
    # S5b): workspace mirror of resolve()'s identical check — a workspace
    # root `overrides {}` entry naming a dep absent from the resolved graph
    # is dead config (a typo, or a stale override left behind after the dep
    # it targeted was removed). Non-fatal — resolution still succeeds.
    import warnings as _ws_warnings
    _ws_resolved_dep_names = {dep.name for dep in graph.deps}
    _ws_dead_override_names = sorted(
        ov.name for ov in workspace.workspace_manifest.overrides
        if ov.name not in _ws_resolved_dep_names
    )
    if _ws_dead_override_names:
        _ws_warnings.warn(
            f"override(s) {', '.join(_ws_dead_override_names)!r} name dep(s) not present in the "
            f"resolved graph — check for typos in override names",
            UserWarning,
            stacklevel=4,
        )

    # RFC origin-as-identity.md §4.7/B3 (S3a-req): see resolve()'s identical
    # hook — the slot-projection collapse must be VISIBLE, never silent.
    from milpa.lockfile import collapse_notes as _collapse_notes
    for _note in _collapse_notes(list(graph.deps)):
        print(f"[milpa] note: {_note}", file=sys.stderr)

    # RFC origin-as-identity.md §4.6 (S6 + S7): the complete import-slot
    # check — post-solve, post-dedup, before anything is written under
    # _deps/. Runs the S6 directory-slot floor first, then the symbol-level
    # scan over the same CAS store rebuild_deps_view materializes from
    # below. live_symbol_provider() is manifest_declared fidelity ONLY —
    # see its docstring for the evidence-based reason tree_scanned fidelity
    # is not (yet) part of the zero-config hard-fail default.
    from milpa.import_slot import check_import_slot_collisions, live_symbol_provider
    check_import_slot_collisions(graph, live_symbol_provider(), store=env.store)

    # B-nimcfg: rebuild _deps/ view (alias symlinks + stale removal).
    rebuild_deps_view(graph, deps_dir, env.store)

    return graph
