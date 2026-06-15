"""Resolver — live dependency resolution.

Implements ``resolve(manifest, deps_dir, env, params) -> ResolvedGraph`` per
``spec/resolver-semantics.md`` (the authoritative contract).

Architecture
------------
``resolve()`` drives a BFS over the dep graph:

1. **Profile filtering** (§6, slice 9b-2): ``_filter_manifest_by_profile``
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import (
    FETCH_ALL_FAILED,
    FETCH_PROVENANCE_DIVERGENCE,
    MILPA_INTERNAL,
    RES_NO_INDEX,
    RES_PROVENANCE_CONFLICT,
    RES_WS_MEMBER_REF_UNKNOWN,
    RES_WS_NO_INDEX,
    RES_WS_OVERRIDE_MEMBER_COLLISION,
    TNG_NO_IDENTITY,
    MilpaError,
)
from milpa.fetchers.git import GitProvenance
from milpa.fetchers.local import LocalProvenance
from milpa.fetchers.tarball import TarballProvenance
from milpa.fetchers.types import Provenance
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    GitProvenanceRecord,
    LocalProvenanceRecord,
    MemberProvenanceRecord,
    ProvenanceRecord,
    ResolvedDep,
    ResolvedGraph,
    TarballProvenanceRecord,
)
from milpa.manifest import (
    Dep,
    LocalDep,
    Manifest,
    MemberDep,
    NamedDep,
    Override,
    Predicate,
    TarballDep,
    UrlDep,
)
from milpa.edge_sources import (
    DepDeclEdgeSource,
    EdgeSourceCtx,
    MilpaKdlEdgeSource,
    NimbleEdgeSource,
    edgeset_to_terms,
    resolve_edges,
)
from milpa.dep_decl import EdgeSet
from milpa.nimble import parse_nimble
from milpa.profile import Profile
from milpa.registry import GitIndexProvenance, Index, IndexVersion
from milpa.solver import SolverError, Term, solve_with_cert
from milpa.version import Strategy, Version, VersionSet, format_version_str, parse_version
from milpa.workspace import LoadedWorkspace

if TYPE_CHECKING:
    from milpa.lockfile import Lockfile


# ---------------------------------------------------------------------------
# Sentinel version for URL/local/tarball/member deps (resolver-semantics §3)
# ---------------------------------------------------------------------------

# URL deps, local deps, and member deps have exactly one canonical version.
# The exact sentinel value is an incidental implementation detail (§3 NOTE).
_URL_DEP_VERSION: Version = Version(0, 0, 1)


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
    identity: str | None        # sha256:<hex>; None for root/__root__ only
    src_dir: str
    dep_terms: list[Term]       # solver terms for this dep's declared requires
    requires_names: list[str]   # dep names (parallel to dep_terms, for graph)
    # typed; None only for __root__
    provenance: (
        Provenance | _LocalDepProvenance | MemberProvenanceRecord | None
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
        root_authority: set[str],
        seen_named: set[str],
        seen_url: set[tuple[str, str]],
        provenance_gate: dict[str, tuple[tuple[object, ...], bool]],
        edge_cache: dict[tuple[str, Version], EdgeSet] | None = None,
        strict_attestation: bool = False,
    ) -> None:
        # name → {version → _Candidate}
        self._candidates: dict[str, dict[Version, _Candidate]] = {}
        # name → {version → _NamedStub}
        self._stubs: dict[str, dict[Version, _NamedStub]] = {}

        # Injected seams
        self._env = env
        self._deps_dir = deps_dir
        self._params = params
        self._overrides_by_name = overrides_by_name

        # Shared dedup sets (owned by resolve(), borrowed here for callbacks)
        self._root_authority = root_authority
        self._seen_named = seen_named
        self._seen_url = seen_url
        self._provenance_gate = provenance_gate

        # Resolver-scoped edge memo (§4.2.1 resolve_edges, clause a).
        # Owned by resolve() and shared here so _materialize can seal it.
        self._edge_cache: dict[tuple[str, Version], EdgeSet] = (
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

    def add(self, c: _Candidate) -> None:
        """Add a candidate unconditionally (for __root__ and pre-built deps)."""
        self._candidates.setdefault(c.name, {})[c.version] = c

    def register_named_stubs(self, name: str, stubs: list[_NamedStub]) -> None:
        """Phase A: register all satisfying IndexVersion stubs for ``name``."""
        stub_map = self._stubs.setdefault(name, {})
        for stub in stubs:
            ver = stub.version
            # Don't revert a materialised candidate back to a stub.
            if ver in self._candidates.get(name, {}):
                continue
            stub_map[ver] = stub

    def _materialize(self, stub: _NamedStub) -> _Candidate:
        """Phase B: fetch + parse the named dep for the selected version."""
        name = stub.name
        iv = stub.index_version

        # Check identity gate (TNG-NO-IDENTITY).
        if not iv.content_hash:
            raise MilpaError(
                TNG_NO_IDENTITY,
                f"package {name!r} version {iv.version!r} has no identity "
                f"(content_hash is absent) — cannot fetch",
                name=name,
                version=iv.version,
            )

        # Phase B fetch: pick the first provenance from the index.
        prov_record = iv.provenances[0]  # preference-ordered, element 0 is canonical
        if isinstance(prov_record, GitIndexProvenance):
            prov = GitProvenance(
                url=prov_record.url,
                ref=prov_record.ref,
                commit_sha=prov_record.commit_sha,
            )
        else:
            # OCI not yet implemented for Phase B; raise loudly.
            raise MilpaError(
                TNG_NO_IDENTITY,
                f"package {name!r}: OCI provenance not yet supported in Phase B",
                name=name,
            )

        dest = self._deps_dir / name
        result = self._env.fetcher.fetch(name, prov, dest=dest)

        # Resolve the commit_sha from the receipt (may differ from index if
        # the index had a symbolic ref; the receipt reflects the actual commit).
        fetched_commit_sha: str | None = result.receipt.transport_fields().get(
            "commit_sha"
        )

        # Resolve edges via the coordinator (§4.2.1 resolve_edges, NORMATIVE).
        # ctx.dep_decl comes from IndexVersion.dep_decl (S2 field — may be None
        # for old index entries).  ctx.is_overridden = False for named deps that
        # reach materialisation (overridden named deps are coerced to URL deps
        # before Phase A; they never become stubs).
        has_milpa_kdl = (result.path / "milpa.kdl").exists()
        ctx = EdgeSourceCtx(
            dep_path=result.path,
            dep_name=name,
            dep_decl=iv.dep_decl,  # S2 field; None when absent
            dep_decl_schema_version=iv.dep_decl_schema_version,  # S3b schema check
            is_overridden=False,   # overridden named → URL coercion before Phase A
            has_milpa_kdl=has_milpa_kdl,
            overrides_by_name=self._overrides_by_name,
        )
        es = resolve_edges(
            name,
            stub.version,
            ctx,
            self._edge_cache,
            nimble_source=self._nimble_source,
            milpakdl_source=self._milpakdl_source,
            dep_decl_source=self._dep_decl_source,  # S3b: wired from MilpaEnv.dep_decl_store
            strict_attestation=self._strict_attestation,  # S5: policy-gated FETCH-FAILED fallback
        )
        dep_terms, requires_names, requires_predicates = edgeset_to_terms(
            es, self._overrides_by_name, _URL_DEP_VERSION
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
            name=name,
            version=stub.version,
            identity=result.identity,
            src_dir=src_dir,
            dep_terms=dep_terms,
            requires_names=requires_names,
            provenance=GitProvenance(
                url=prov_record.url,
                ref=prov_record.ref,
                commit_sha=fetched_commit_sha or prov_record.commit_sha,
            ),
            dep_decl=_dep_decl_pin,
            requires_predicates=requires_predicates,
        )

        # Register and clear stub.
        self._candidates.setdefault(name, {})[stub.version] = candidate
        self._stubs.get(name, {}).pop(stub.version, None)

        # Enroll any newly-discovered transitive named deps.
        if self._on_transitive_named is not None:
            for req_name, _vs in _terms_to_named_reqs(dep_terms, name):
                self._on_transitive_named(req_name)

        return candidate

    # Callback wired by resolve() after initial BFS; fires during solve.
    _on_transitive_named: None = None  # will be set to Callable[[str], None]

    def set_transitive_callback(
        self, on_named: object  # Callable[[str], None]
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
    """Phase A stub — lightweight placeholder before fetch."""

    name: str
    version: Version
    index_version: IndexVersion


# ---------------------------------------------------------------------------
# Predicate filtering (resolver-semantics §6, slice 9b-2)
# ---------------------------------------------------------------------------


def _filter_manifest_by_profile(
    manifest: Manifest,
    profile: Profile,
) -> Manifest:
    """Return a ``Manifest`` with only the deps whose predicates match ``profile``.

    Called at the start of ``resolve()`` BEFORE any BFS or solver input.
    When ``profile`` is ``None``, filtering is disabled and all deps are
    included (§6 NORMATIVE: absent profile ≠ profile that matches nothing).
    """
    active_flags: frozenset[str] = frozenset(
        fd.name for fd in manifest.flags if fd.default
    )
    kept = tuple(
        d for d in manifest.deps
        if _dep_matches_profile(d, profile, active_flags)
    )
    kept_dev = tuple(
        d for d in manifest.dev_deps
        if _dep_matches_profile(d, profile, active_flags)
    )
    if len(kept) == len(manifest.deps) and len(kept_dev) == len(manifest.dev_deps):
        return manifest
    from dataclasses import replace as dc_replace
    return dc_replace(manifest, deps=kept, dev_deps=kept_dev)


def _dep_matches_profile(
    dep: Dep,
    profile: Profile,
    active_flags: frozenset[str],
) -> bool:
    """True iff ALL predicates on ``dep`` match the profile (conjunction)."""
    preds: tuple[Predicate, ...] = getattr(dep, "predicates", ())
    return all(_predicate_satisfied(pred, profile, active_flags) for pred in preds)


def _predicate_satisfied(
    pred: Predicate,
    profile: Profile,
    active_flags: frozenset[str],
) -> bool:
    """Evaluate a single predicate against profile + active flags.

    OR semantics within a predicate's values (§6 NORMATIVE).
    Negation inverts the OR result.
    """
    if pred.name == "flag":
        any_match = any(v in active_flags for v in pred.values)
        return (not any_match) if pred.negated else any_match

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


def _dep_to_term(
    dep: Dep,
    overrides_by_name: dict[str, Override],
) -> tuple[Term | None, str | None]:
    """Convert a dep to a solver Term + require name.

    Returns ``(None, None)`` for dep kinds that are not solver-visible
    (MemberDep — member resolution is a workspace concern, slice 9d).
    """
    if isinstance(dep, UrlDep):
        # Override may redirect the URL.
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            # Still sentinel version — override changes the URL, not the version.
            _ = ov  # override consumed by the fetch step; term is the same
        return (Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)), dep.name)

    if isinstance(dep, NamedDep):
        if dep.name == "nim":
            return (None, None)
        vs = dep.constraint_set if dep.constraint_set is not None else VersionSet.full()
        # Check if this named dep is overridden (becomes a URL dep at sentinel).
        if dep.name in overrides_by_name:
            return (Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)), dep.name)
        return (Term.require(dep.name, vs), dep.name)

    if isinstance(dep, TarballDep):
        return (Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)), dep.name)

    if isinstance(dep, LocalDep):
        return (Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)), dep.name)

    if isinstance(dep, MemberDep):
        # Member resolution is a workspace concern (slice 9d).
        return (None, None)

    return (None, None)


# ---------------------------------------------------------------------------
# Named dep enumeration (Phase A) — resolver-semantics §4.2.1
# ---------------------------------------------------------------------------


def _enumerate_named_stubs(
    name: str,
    constraint: VersionSet | None,
    index: Index,
    provider: _Provider,
    deps_dir: Path,
    env: MilpaEnv,
) -> None:
    """Phase A: enumerate all satisfying IndexVersions as stubs (no fetch).

    Passes ``constraint=None`` to ``resolve_named_all`` so the solver sees
    the full candidate space — constraint accumulation is the solver's job.
    The dep_terms (registered in Phase B materialisation) will carry the
    actual constraint as incompatibility terms.
    """
    # Always enumerate all versions regardless of constraint; the solver's
    # incompatibility terms encode the constraint (P3.3 S2 diamond correctness).
    all_versions = index.resolve_named_all(name, constraint=None)
    stubs: list[_NamedStub] = []
    for iv in all_versions:
        ver = _parse_version_strict(iv.version)
        if ver is not None:
            stubs.append(_NamedStub(name=name, version=ver, index_version=iv))
    provider.register_named_stubs(name, stubs)


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
        return ("url", ov.git, ov.ref)
    return ("url", dep.git, dep.ref)


def _provenance_key_for_named(name: str) -> tuple[object, ...]:
    return ("named", name)


def _provenance_key_for_tarball(dep: TarballDep) -> tuple[object, ...]:
    return ("tarball", dep.url)


def _provenance_key_for_local(dep: LocalDep) -> tuple[object, ...]:
    return ("local", dep.path)


# ---------------------------------------------------------------------------
# Helper: extract named req names from dep_terms (for transitive callback)
# ---------------------------------------------------------------------------


def _terms_to_named_reqs(
    dep_terms: list[Term],
    owner_name: str,
) -> list[tuple[str, VersionSet]]:
    """Extract (name, VersionSet) pairs from positive dep_terms."""
    result: list[tuple[str, VersionSet]] = []
    for t in dep_terms:
        if t.positive and t.package != owner_name:
            result.append((t.package, t.versions))
    return result


# ---------------------------------------------------------------------------
# BFS wave-drain loop — shared by resolve() and resolve_workspace()
# ---------------------------------------------------------------------------


def _run_bfs_wave_loop(
    bfs_queue: list[object],
    executor: object,
    seen_named: set[str],
    seen_url: set[tuple[str, str]],
    seen_tarball: set[str],
    seen_local: set[str],
    edge_cache: "dict[tuple[str, Version], EdgeSet]",
    provider: "_Provider",
    overrides_by_name: "dict[str, Override]",
    deps_dir: Path,
    env: "MilpaEnv",
    params: "ResolveParams",
    index: "Index",
    provenance_gate: "dict[str, tuple[tuple[object, ...], bool]]",
    root_authority: "set[str]",
    record_discovery: "Callable[[str], None]",
) -> None:
    """BFS wave-drain loop — runs in-place on *bfs_queue*.

    Processes the queue in waves of parallel I/O-bound items (URL / tarball /
    local) interleaved with synchronous named-dep enumeration.  All mutable
    state (seen_* sets, edge_cache, provider, bfs_queue) is updated in-place.

    Parameters mirror the closed-over locals in the old per-function copies
    except ``record_discovery``, which is the only thing that differed between
    the single-package and workspace copies.
    """
    from concurrent.futures import Future as _Future
    from typing import cast as _cast

    i = 0
    while i < len(bfs_queue):
        # --- Collect the next wave of I/O-bound items -------------------
        # A wave ends when we hit a "named" item (synchronous) or the
        # queue runs out of new I/O items (all remaining are named or
        # already-seen URL/tarball/local).
        wave_futures: list[object] = []

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
                name_str: str = item[1]
                constraint_str: str | None = item[2] if len(item) > 2 else None
                if name_str not in seen_named and name_str != "nim":
                    seen_named.add(name_str)
                    record_discovery(name_str)  # Phase B: transitive named dep
                    # Satisfiability pre-check (TNG-NO-SATISFYING-VERSION):
                    # verify at least one index version satisfies the
                    # declared constraint BEFORE enrolling stubs.  This
                    # surfaces TNG-NO-SATISFYING-VERSION eagerly rather
                    # than letting the solver raise SOLVE-CONFLICT.
                    # resolver-semantics §4.2.1 + registry-protocol §5.5.
                    if constraint_str is not None:
                        index.resolve_named_all(name_str, constraint_str)
                    _enumerate_named_stubs(name_str, None, index, provider, deps_dir, env)
                # Named items are always processed inline, not as futures.
                continue

            # URL/tarball/local — determine if this item is new (not seen).
            if kind == "url":
                dep_u: UrlDep = item[1]
                if dep_u.name in overrides_by_name:
                    ov = overrides_by_name[dep_u.name]
                    dep_u = UrlDep(name=dep_u.name, git=ov.git, ref=ov.ref)
                pkey_u = ("url", dep_u.git, dep_u.ref)
                if not _check_provenance_gate(
                    dep_u.name, pkey_u, provenance_gate, root_authority
                ):
                    continue
                url_key_u = (dep_u.git, dep_u.ref)
                if url_key_u in seen_url:
                    continue
                seen_url.add(url_key_u)
                record_discovery(dep_u.name)  # Phase B: transitive URL dep first-enqueue
                # Submit to thread pool — captures dep_u by value (closure).
                def _url_worker(
                    _dep: UrlDep = dep_u,
                ) -> tuple[str, object]:  # (kind, result)
                    return ("url", _process_url_worker(
                        _dep,
                        deps_dir=deps_dir,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                    ))
                wave_futures.append(executor.submit(_url_worker))  # type: ignore[union-attr]

            elif kind == "tarball":
                dep_t: TarballDep = item[1]
                if dep_t.url in seen_tarball:
                    continue
                seen_tarball.add(dep_t.url)
                record_discovery(dep_t.name)  # Phase B: transitive tarball dep first-enqueue
                def _tarball_worker(
                    _dep: TarballDep = dep_t,
                ) -> tuple[str, object]:
                    return ("tarball", _process_tarball_worker(
                        _dep,
                        deps_dir=deps_dir,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                    ))
                wave_futures.append(executor.submit(_tarball_worker))  # type: ignore[union-attr]

            elif kind == "local":
                dep_l: LocalDep = item[1]
                if dep_l.path in seen_local:
                    continue
                seen_local.add(dep_l.path)
                record_discovery(dep_l.name)  # Phase B: transitive local dep first-enqueue
                def _local_worker(
                    _dep: LocalDep = dep_l,
                ) -> tuple[str, object]:
                    return ("local", _process_local_worker(
                        _dep,
                        deps_dir=deps_dir,
                        env=env,
                        params=params,
                        overrides_by_name=overrides_by_name,
                    ))
                wave_futures.append(executor.submit(_local_worker))  # type: ignore[union-attr]

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
            if kind_result in ("url", "tarball", "local"):
                cand_and_deps: tuple[_Candidate, list[object], EdgeSet] = _cast(
                    "tuple[_Candidate, list[object], EdgeSet]", fetch_result
                )
                cand_r, transitive_deps_r, es_r = cand_and_deps
                provider.add(cand_r)
                # Seal the edge_cache for this (name, version) — clause (a).
                # First-encounter wins; no overwrite (worker produced the EdgeSet
                # deterministically from the fetched tree).
                cache_key_r = (cand_r.name, cand_r.version)
                if cache_key_r not in edge_cache:
                    edge_cache[cache_key_r] = es_r
                for sub_dep in transitive_deps_r:
                    _enqueue_dep(sub_dep, overrides_by_name, bfs_queue)


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
    # ------------------------------------------------------------------
    if params.profile is not None:
        manifest = _filter_manifest_by_profile(manifest, params.profile)

    # ------------------------------------------------------------------
    # Step 2: check index availability for named deps
    # ------------------------------------------------------------------
    overrides_by_name: dict[str, Override] = {ov.name: ov for ov in manifest.overrides}

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
    root_authority: set[str] = {
        d.name for d in all_root_deps
    } | {ov.name for ov in manifest.overrides}

    # provenance_gate: name → (prov_key, is_root_authority)
    #
    # NOT pre-seeded: root deps register themselves as they are processed
    # in the BFS loop.  The gate is used for TRANSITIVE conflict detection:
    # when a transitive dep tries to claim a name that root authority already
    # registered with a DIFFERENT pkey, the transitive claim is suppressed.
    # ``root_authority`` (the name set above) is the check for suppression —
    # the gate stores which pkey a root dep actually used.
    provenance_gate: dict[str, tuple[tuple[object, ...], bool]] = {}

    # ------------------------------------------------------------------
    # Step 4: build the provider and dedup sets
    # ------------------------------------------------------------------
    seen_url: set[tuple[str, str]] = set()
    seen_named: set[str] = set()
    seen_local: set[str] = set()
    seen_tarball: set[str] = set()

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
    edge_cache: dict[tuple[str, Version], EdgeSet] = {}

    from milpa.attestation import effective_strict_policy as _eff_strict
    _is_strict_early = _eff_strict(manifest.attestation_policy, params.require_attested_metadata)

    provider = _Provider(
        env=env,
        deps_dir=deps_dir,
        params=params,
        overrides_by_name=overrides_by_name,
        root_authority=root_authority,
        seen_named=seen_named,
        seen_url=seen_url,
        provenance_gate=provenance_gate,
        edge_cache=edge_cache,
        strict_attestation=_is_strict_early,
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
    # Format: ("url", UrlDep) | ("named", str, str|None)
    #        | ("tarball", TarballDep) | ("local", LocalDep)
    bfs_queue: list[object] = []

    for dep in all_root_deps:
        # Apply overrides: a named dep whose name is in overrides_by_name
        # is treated as a URL dep at the sentinel version.
        if isinstance(dep, UrlDep):
            if dep.name in overrides_by_name:
                ov = overrides_by_name[dep.name]
                effective_dep = UrlDep(name=dep.name, git=ov.git, ref=ov.ref)
            else:
                effective_dep = dep
            root_terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
            root_requires.append(dep.name)
            bfs_queue.append(("url", effective_dep))
            _record_discovery(dep.name)  # Phase B: root URL deps in declaration order

        elif isinstance(dep, NamedDep):
            if dep.name == "nim":
                continue
            if dep.name in overrides_by_name:
                # Named dep with override → URL fetch at sentinel version.
                ov = overrides_by_name[dep.name]
                effective_dep = UrlDep(name=dep.name, git=ov.git, ref=ov.ref)
                root_terms.append(
                    Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION))
                )
                root_requires.append(dep.name)
                bfs_queue.append(("url", effective_dep))
                _record_discovery(dep.name)  # Phase B: overridden named → URL
            else:
                vs = dep.constraint_set if dep.constraint_set is not None else VersionSet.full()
                root_terms.append(Term.require(dep.name, vs))
                root_requires.append(dep.name)
                bfs_queue.append(("named", dep.name, dep.constraint))
                _record_discovery(dep.name)  # Phase B: named deps in declaration order

        elif isinstance(dep, TarballDep):
            root_terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
            root_requires.append(dep.name)
            bfs_queue.append(("tarball", dep))
            _record_discovery(dep.name)  # Phase B: root tarball deps in declaration order

        elif isinstance(dep, LocalDep):
            root_terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
            root_requires.append(dep.name)
            bfs_queue.append(("local", dep))
            _record_discovery(dep.name)  # Phase B: root local deps in declaration order

        elif isinstance(dep, MemberDep):
            # Member deps in a single-package manifest are out of scope (slice 9d).
            pass

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
            edge_cache=edge_cache,
            provider=provider,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            provenance_gate=provenance_gate,
            root_authority=root_authority,
            record_discovery=_record_discovery,
        )

    # ------------------------------------------------------------------
    # Step 6b: Phase B content-hash dedup/alias
    #
    # After all eager deps are fetched, group candidates by identity.
    # Groups of size ≥ 2 share a content hash → collapse to one canonical
    # candidate.  Canonical = group member earliest in BFS-insertion order
    # (discovery_order list).  Non-canonical candidates are removed from
    # the provider's candidate set and their _deps/<name> dirs are removed.
    # All dep_terms / requires_names in surviving candidates pointing to a
    # non-canonical name are rewritten to the canonical name.
    # The canonical candidate gains an 'aliases' set for _build_graph.
    # ------------------------------------------------------------------
    aliases_map: dict[str, str] = _dedup_candidates(
        provider, deps_dir, discovery_order, overrides_by_name
    )

    # ------------------------------------------------------------------
    # Step 7: wire Phase B transitive callback BEFORE solve
    #
    # When the solver calls ``provider.dependencies()`` for a named stub,
    # any newly-discovered transitive named deps must be enrolled
    # immediately so the solver can see them.
    # ------------------------------------------------------------------
    def _on_transitive_named(name: str) -> None:
        if name in seen_named or name == "nim":
            return
        seen_named.add(name)
        _enumerate_named_stubs(name, None, index, provider, deps_dir, env)

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
    except SolverError as exc:
        from milpa.errors import SOLVE_CONFLICT
        raise MilpaError(
            SOLVE_CONFLICT,
            f"dependency conflict: {exc}",
            chain=exc.chain,
            solver_error=exc,
        ) from exc

    # ------------------------------------------------------------------
    # Step 9: build the ResolvedGraph (attach cert for CLI §2.5)
    # ------------------------------------------------------------------
    graph = _build_graph(solution, provider, deps_dir, params.strategy, aliases_map=aliases_map)

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
    # edge_cache holds (name, version) → EdgeSet for all deps seen during BFS.
    # We exclude __root__ (it has no EdgeSet in the cache).
    resolved_edge_map: dict[str, EdgeSet] = {
        name: es
        for (name, _ver), es in edge_cache.items()
        if name != "__root__"
    }
    enforce_attestation_policy(resolved_edge_map, is_strict)

    from dataclasses import replace as _replace
    graph = _replace(graph, cert=cert)

    # B-nimcfg: rebuild the _deps/ view as a pure function of the resolved graph.
    # This creates alias symlinks and removes stale entries from prior resolves.
    # SSOT: rebuild_deps_view is the single place that decides _deps/ contents.
    # MilpaEnv.store is typed CAStore (non-Optional); the None guard was dead code.
    rebuild_deps_view(graph, deps_dir, env.store)

    return graph


# ---------------------------------------------------------------------------
# URL dep processing
# ---------------------------------------------------------------------------


def _check_provenance_gate(
    name: str,
    pkey: tuple[object, ...],
    provenance_gate: dict[str, tuple[tuple[object, ...], bool]],
    root_authority: set[str],
) -> bool:
    """Check the provenance gate for ``name`` with key ``pkey``.

    Returns True if the dep should be fetched; False if suppressed.
    Raises MilpaError(RES-PROVENANCE-CONFLICT) on irresolvable transitive conflict.

    Gate semantics (resolver-semantics.md §10):
    - First claim for a name: register + proceed.
    - Same pkey as prior claim: dedup → suppress (already fetching or fetched).
    - Different pkey + prior was a root-authority claim: root wins → suppress.
    - Different pkey + both transitive: conflict → raise.
    """
    is_root = name in root_authority
    prior = provenance_gate.get(name)
    if prior is None:
        # First time we see this name — register and proceed.
        provenance_gate[name] = (pkey, is_root)
        return True
    if prior[0] == pkey:
        # Same provenance — already fetching/fetched; dedup.
        return False
    # Different provenance for the same name.
    if prior[1] or is_root:
        # Root authority (either the prior or this call is root) — suppress.
        return False
    # Non-root disagreement: two transitives want different provenances.
    raise MilpaError(
        RES_PROVENANCE_CONFLICT,
        f"provenance conflict for package {name!r}: "
        f"one transitive dep claims {prior[0]!r} "
        f"and another claims {pkey!r}. "
        f"The root manifest does not override {name!r}. "
        f"Add an override in your milpa.kdl to resolve which source to use.",
        name=name,
    )


def _pick_edges(
    dep_name: str,
    version: "Version",
    ctx: EdgeSourceCtx,
    milpakdl_source: MilpaKdlEdgeSource,
    nimble_source: NimbleEdgeSource,
) -> EdgeSet:
    """Dispatch to the correct EdgeSource for a single (dep, version) — no cache.

    Single source of truth for the ``has_milpa_kdl`` branching used by the
    three per-transport worker functions (_process_url_worker,
    _process_tarball_worker, _process_local_worker).  Workers call this instead
    of duplicating the two-branch ``if has_milpa_kdl`` block inline.

    Workers do NOT use the ``resolve_edges`` coordinator here because they run
    on worker threads before the edge_cache is available; the main thread seals
    the cache from the returned EdgeSet after the worker returns.
    """
    if ctx.has_milpa_kdl:
        return milpakdl_source.edges_for(dep_name, version, ctx)
    return nimble_source.edges_for(dep_name, version, ctx)


def _process_url_worker(
    dep: UrlDep,
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
    overrides_by_name: dict[str, Override],
) -> tuple[_Candidate, list[object], EdgeSet]:
    """Fetch one URL dep (worker: pure I/O, no shared-state mutation).

    Returns ``(_Candidate, transitive_dep_list, edge_set)`` where:
    - ``transitive_dep_list`` are raw dep objects for BFS enqueuing.
    - ``edge_set`` is the EdgeSet produced by the appropriate source (MilpaKdl
      or Nimble); the caller seals this into the resolver-scoped ``edge_cache``.

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

    dest = deps_dir / dep.name
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
    ctx = EdgeSourceCtx(
        dep_path=result.path,
        dep_name=dep.name,
        dep_decl=None,   # URL deps are not index-registered → no DepDecl
        is_overridden=dep.name in overrides_by_name,
        has_milpa_kdl=has_milpa_kdl,
        overrides_by_name=overrides_by_name,
    )
    # Call the source directly (worker thread — no shared edge_cache yet).
    # The main thread seals edge_cache from the returned EdgeSet.
    es = _pick_edges(dep.name, _URL_DEP_VERSION, ctx, MilpaKdlEdgeSource(), NimbleEdgeSource())

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, overrides_by_name, _URL_DEP_VERSION)
    src_dir = es.src_dir

    commit_sha: str | None = result.receipt.transport_fields().get("commit_sha")

    candidate = _Candidate(
        name=dep.name,
        version=_URL_DEP_VERSION,
        identity=result.identity,
        src_dir=src_dir,
        dep_terms=dep_terms,
        requires_names=requires_names,
        # D-lifecycle: provenance is the OBSERVED candidate (the one that succeeded).
        provenance=GitProvenance(url=observed_url, ref=dep.ref, commit_sha=commit_sha),
        # D-lifecycle: declared mirrors (all manifest+prior declared URLs != observed).
        declared_mirror_urls=declared_mirror_urls,
        requires_predicates=requires_predicates,
    )

    # Collect transitive deps for the BFS queue (returned to caller for enqueuing).
    transitive_deps = _collect_transitive_deps(result.path, dep.name, overrides_by_name)
    return candidate, transitive_deps, es


def _collect_transitive_deps(
    dep_path: Path,
    dep_name: str,
    overrides_by_name: dict[str, Override],
) -> list[object]:
    """Collect transitive deps from a fetched tree as raw dep objects.

    Returns a list of raw dep objects (UrlDep, NamedDep, TarballDep, LocalDep)
    from the fetched tree.  These are returned to the caller (BFS loop) for
    enqueuing into bfs_queue — this function does NOT touch bfs_queue directly,
    making it safe to call from worker threads.

    NORMATIVE §9: reads ONLY ``m.deps``, NEVER ``m.dev_deps`` — a transitive
    dep's dev-deps MUST NOT enter the resolved graph.
    """
    milpa_kdl = dep_path / "milpa.kdl"
    if milpa_kdl.exists():
        from milpa.manifest import parse_manifest
        try:
            m = parse_manifest(milpa_kdl.read_text(encoding="utf-8"))
        except MilpaError:
            m = None

        if m is not None:
            # NORMATIVE §9: transitive deps read ONLY m.deps, never m.dev_deps.
            return list(m.deps)

    # Fallback: nimble parse.
    try:
        nimble_path = _find_nimble_file(dep_path, dep_name)
        nm = parse_nimble(nimble_path.read_text(encoding="utf-8"))
        return list(nm.deps)
    except FileNotFoundError:
        return []


def _enqueue_dep(
    dep: object,
    overrides_by_name: dict[str, Override],
    bfs_queue: list[object],
) -> None:
    """Append a dep to the BFS queue (FIFO)."""
    if isinstance(dep, UrlDep):
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            dep = UrlDep(name=dep.name, git=ov.git, ref=ov.ref)
        bfs_queue.append(("url", dep))
    elif isinstance(dep, NamedDep):
        if dep.name == "nim":
            return
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            bfs_queue.append(("url", UrlDep(name=dep.name, git=ov.git, ref=ov.ref)))
        else:
            bfs_queue.append(("named", dep.name, dep.constraint))
    elif isinstance(dep, TarballDep):
        bfs_queue.append(("tarball", dep))
    elif isinstance(dep, LocalDep):
        bfs_queue.append(("local", dep))


# ---------------------------------------------------------------------------
# Tarball dep processing
# ---------------------------------------------------------------------------


def _process_tarball_worker(
    dep: TarballDep,
    deps_dir: Path,
    env: MilpaEnv,
    params: ResolveParams,
    overrides_by_name: dict[str, Override],
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
    )
    es = _pick_edges(dep.name, _URL_DEP_VERSION, ctx, MilpaKdlEdgeSource(), NimbleEdgeSource())

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, overrides_by_name, _URL_DEP_VERSION)
    src_dir = es.src_dir
    recorded_sha256 = dep.sha256 or archive_sha256 or locked_sha256

    candidate = _Candidate(
        name=dep.name,
        version=_URL_DEP_VERSION,
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
    )
    transitive_deps = _collect_transitive_deps(result.path, dep.name, overrides_by_name)
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
    )
    es = _pick_edges(dep.name, _URL_DEP_VERSION, ctx, MilpaKdlEdgeSource(), NimbleEdgeSource())

    dep_terms, requires_names, requires_predicates = edgeset_to_terms(es, overrides_by_name, _URL_DEP_VERSION)
    src_dir = es.src_dir

    candidate = _Candidate(
        name=dep.name,
        version=_URL_DEP_VERSION,
        identity=result.identity,
        src_dir=src_dir,
        dep_terms=dep_terms,
        requires_names=requires_names,
        provenance=_LocalDepProvenance(declared_path=declared_path_str),
        requires_predicates=requires_predicates,
    )
    transitive_deps = _collect_transitive_deps(result.path, dep.name, overrides_by_name)
    return candidate, transitive_deps, es


# ---------------------------------------------------------------------------
# Phase B: content-hash dedup/alias
# ---------------------------------------------------------------------------


def _dedup_candidates(
    provider: _Provider,
    deps_dir: Path,
    discovery_order: list[str],
    overrides_by_name: dict[str, Override],
) -> dict[str, str]:
    """Collapse eagerly-fetched candidates that share a content identity.

    Returns ``aliases_map``: a dict mapping non-canonical name → canonical name.
    Empty when no dedup occurred.

    Algorithm (Phase B, spec/resolver-semantics.md Phase B):
    1. Group all non-root candidates by their content identity (``identity`` field).
    2. For each group of size ≥ 2: pick the canonical member as the one with the
       smallest index in ``discovery_order`` (BFS-insertion order, NOT lex).
    3. For non-canonical members: remove from provider._candidates and remove
       their ``_deps/<name>`` dir (B-nimcfg will later replace this with the
       proper atomic alias-symlink view).
    4. Rewrite all surviving candidates' ``dep_terms[i].package`` and
       ``requires_names`` entries that reference a non-canonical name to the
       canonical name.
    5. Invariant guard (requires-equality): for each dedup group, re-derive
       each member's requires from its fetched tree and assert they are equal
       after alias-rewriting (identical content ⇒ identical tree ⇒ identical
       requires; any mismatch is a bug, not a user error).

    Named candidates (stubs, not fetched yet) are NOT deduped — they are
    materialized lazily by the solver after this pass.
    """
    candidates = provider._candidates  # type: ignore[attr-defined]  # dict[str, dict[Version, _Candidate]]

    # Step 1: group by identity.
    by_identity: dict[str, list[str]] = {}
    for name, versions in candidates.items():
        if name == "__root__":
            continue
        for c in versions.values():
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
        # Names NOT in discovery_order get _LARGE (should not happen for non-root
        # URL/tarball/local deps, but guard defensively).
        canonical = min(group, key=lambda n: discovery_index.get(n, _LARGE))

        non_canonicals = [n for n in group if n != canonical]

        # Step 5: invariant guard — re-derive requires from fetched tree.
        # Identical content ⇒ identical tree ⇒ identical requires. Any mismatch
        # is a bug, not a user error → MILPA-INTERNAL.
        all_requires: list[frozenset[str]] = []
        for member_name in group:
            dep_path = deps_dir / member_name
            raw_deps = _collect_transitive_deps(dep_path, member_name, overrides_by_name)
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

        # Step 3: remove non-canonical candidates from the provider.
        # NOTE: _deps/<other> dir removal is intentionally OMITTED here —
        # rebuild_deps_view (B-nimcfg SSOT) owns _deps/ contents and will
        # remove stale non-canonical dirs and create alias symlinks atomically
        # after the graph is assembled. The stopgap inline removal is gone.
        for other in non_canonicals:
            candidates.pop(other, None)
            aliases_map[other] = canonical

    if not aliases_map:
        return aliases_map

    # Step 4: rewrite dep_terms and requires_names in all surviving candidates.
    for versions in candidates.values():
        for c in versions.values():
            # Rewrite requires_names (parallel to dep_terms).
            c.requires_names = [
                aliases_map.get(r, r) for r in c.requires_names
            ]
            # Rewrite solver dep_terms (frozen Terms — create new instances).
            from milpa.solver import Term as _Term
            new_dep_terms = []
            for term in c.dep_terms:
                can = aliases_map.get(term.package)
                if can is not None:
                    # Preserve positive/negative polarity.
                    new_dep_terms.append(
                        _Term(package=can, positive=term.positive, versions=term.versions)
                    )
                else:
                    new_dep_terms.append(term)
            c.dep_terms = new_dep_terms

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
        expected[dep.name] = dep.identity
        for alias in dep.aliases:
            expected[alias] = dep.identity

    if not deps_dir.is_dir():
        return  # nothing to rebuild

    # Step 2: remove stale entries (not in expected set, and not a preserved local dep).
    for child in list(deps_dir.iterdir()):
        if child.name not in expected and child.name not in local_names:
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
    for name, identity in expected.items():
        try:
            _store.link(identity, deps_dir / name)
        except Exception:
            # CAS entry missing for this identity — the resolver already validated
            # presence (FROZEN-IDENTITY-NOT-IN-STORE); treat as non-fatal here.
            pass


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------


def _build_graph(
    solution: dict[str, Version],
    provider: _Provider,
    deps_dir: Path,
    strategy: Strategy,
    aliases_map: dict[str, str] | None = None,
) -> ResolvedGraph:
    """Map ``solve()``'s solution dict to a ``ResolvedGraph``.

    ``aliases_map`` maps non-canonical name → canonical name (populated by
    the Phase B dedup pass).  Used to populate ``ResolvedDep.aliases`` on
    the surviving canonical dep.
    """
    GP = GitProvenance
    LP = LocalProvenance
    TP = TarballProvenance
    MP = MemberProvenanceRecord

    # Build reverse map: canonical → sorted list of aliases.
    canonical_to_aliases: dict[str, list[str]] = {}
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

        # Map fetcher provenance → lockfile ProvenanceRecord (observed).
        observed_record: (
            GitProvenanceRecord
            | LocalProvenanceRecord
            | TarballProvenanceRecord
            | MemberProvenanceRecord
            | None
        ) = None
        if isinstance(cand.provenance, GP):
            observed_record = GitProvenanceRecord(
                url=cand.provenance.url,
                ref=cand.provenance.ref,
                commit_sha=cand.provenance.commit_sha,
                origin="observed",
            )
        elif isinstance(cand.provenance, LP):
            # Dead branch: _process_local_worker always wraps local deps in
            # _LocalDepProvenance (the declared relative path) before storing
            # them in _Candidate.provenance, so a raw LocalProvenance (which
            # carries the ABSOLUTE resolved path) is never stored here.
            # If this fires, the caller wired a LocalProvenance directly into
            # _Candidate — that would silently write an absolute path to the
            # lockfile, violating lockfile-schema §4.3.  Raise hard.
            raise AssertionError(
                f"_build_graph: _Candidate for {cand.name!r} carries a raw "
                f"LocalProvenance (absolute path={cand.provenance.path!r}); "
                f"local deps must use _LocalDepProvenance so the declared "
                f"relative path is written to the lockfile (§4.3)."
            )
        elif isinstance(cand.provenance, _LocalDepProvenance):
            # _LocalDepProvenance stores the DECLARED (relative) path — correct for lockfile.
            observed_record = LocalProvenanceRecord(path=cand.provenance.declared_path, origin="observed")
        elif isinstance(cand.provenance, TP):
            observed_record = TarballProvenanceRecord(
                url=cand.provenance.url,
                sha256=cand.provenance.expected_sha256,
                origin="observed",
            )
        elif isinstance(cand.provenance, MP):
            # Member candidate — provenance record already typed correctly.
            observed_record = cand.provenance

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
        all_provenances: tuple[ProvenanceRecord, ...] = tuple(_all_provs)

        version_str = format_version_str(version)

        # S4: build cond_requires from the candidate's requires_predicates dict.
        # requires_predicates maps name → list[predicate_tuple]; a dep in ≥2
        # when-branches yields ≥2 entries per name, each becoming one CondRequire.
        # Sort delegates to cond_require_sort_key (lockfile SSOT) so the sort
        # key uses the same escaping as the emitter — cannot drift (C1 fix).
        from milpa.lockfile import CondRequire as _CondRequire, cond_require_sort_key

        _raw_cond: list[_CondRequire] = [
            _CondRequire(name=rname, predicates=preds)
            for rname, pred_list in cand.requires_predicates.items()
            for preds in pred_list
            if preds
        ]
        _cond_requires: tuple[_CondRequire, ...] = tuple(
            sorted(_raw_cond, key=cond_require_sort_key)
        )

        resolved = ResolvedDep(
            name=name,
            identity=cand.identity,
            version=version_str,
            src_dir=cand.src_dir,
            requires=tuple(cand.requires_names),
            # D-lifecycle: full provenances tuple (observed + declared mirrors).
            provenances=all_provenances,
            # S6: dep_decl pin — carries the DepDecl hash from _Candidate (set in
            # _materialize when DepDeclEdgeSource fired) to the lockfile record.
            dep_decl=cand.dep_decl,
            # S4: conditional require annotations (sorted by (name, canonical-predicate-string)).
            cond_requires=_cond_requires,
            # Phase B: aliases — lex-sorted list of non-canonical names that share
            # this dep's content identity.  Empty for non-deduped deps.
            aliases=tuple(canonical_to_aliases.get(name, [])),
        )
        deps.append(resolved)

    return ResolvedGraph(deps=tuple(deps))


# ---------------------------------------------------------------------------
# _Candidate-builder for workspace members (slice 9d)
# ---------------------------------------------------------------------------


def _build_member_candidate(
    member: object,  # LoadedMember — typed at runtime to avoid early import
    overrides_by_name: dict[str, Override],
    members_by_name: frozenset[str],
) -> tuple[_Candidate, list[object]]:
    """Build a _Candidate for a workspace member (never fetched, cas_admissible=False).

    Returns ``(_Candidate, [])`` — members have no external transitive deps to
    enqueue (their deps are seeded explicitly in resolve_workspace).
    """
    # member is a LoadedMember — access fields dynamically to avoid circular import.
    manifest = member.manifest  # type: ignore[attr-defined]
    abs_dir: Path = member.abs_dir  # type: ignore[attr-defined]

    identity = compute_content_hash(abs_dir)

    # Build solver terms from ALL member deps (regular + dev-deps, per §11).
    # Member-named refs → sentinel version (in-tree candidate).
    # Named deps that match a workspace member → sentinel (auto-coerce).
    dep_terms: list[Term] = []
    requires_names: list[str] = []

    all_member_deps = list(manifest.deps) + list(manifest.dev_deps)

    for dep in all_member_deps:
        name = dep.name
        # Auto-coerce: MemberDep or named dep matching a member name → sentinel.
        if isinstance(dep, MemberDep) or name in members_by_name:
            dep_terms.append(Term.require(name, VersionSet.eq(_URL_DEP_VERSION)))
            requires_names.append(name)
            continue
        # Override: named dep with override → URL at sentinel.
        if name in overrides_by_name:
            dep_terms.append(Term.require(name, VersionSet.eq(_URL_DEP_VERSION)))
            requires_names.append(name)
            continue
        # Regular dep: same logic as _dep_to_term.
        t, r = _dep_to_term(dep, overrides_by_name)
        if t is not None and r is not None:
            dep_terms.append(t)
            requires_names.append(r)

    return _Candidate(
        name=manifest.name,
        version=_URL_DEP_VERSION,
        identity=identity,
        src_dir=manifest.src_dir or "",
        dep_terms=dep_terms,
        requires_names=requires_names,
        provenance=MemberProvenanceRecord(name=manifest.name),
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
    from milpa.attestation import effective_strict_policy as _eff_strict
    _ws_is_strict = params.require_attested_metadata or any(
        _eff_strict(m.manifest.attestation_policy, False)
        for m in workspace.members
    )
    deps_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Workspace-level checks before any resolution
    # ------------------------------------------------------------------
    overrides_by_name: dict[str, Override] = {
        ov.name: ov for ov in workspace.workspace_manifest.overrides
    }
    members_by_name: frozenset[str] = frozenset(
        m.manifest.name for m in workspace.members
    )

    # RES-WS-OVERRIDE-MEMBER-COLLISION: name cannot be both override and member.
    collisions = sorted(
        n for n in overrides_by_name if n in members_by_name
    )
    if collisions:
        raise MilpaError(
            RES_WS_OVERRIDE_MEMBER_COLLISION,
            f"workspace override name(s) {collisions!r} also appear as workspace "
            f"member(s) — remove either the override or the member; cannot have both",
            names=collisions,
        )

    # RES-WS-MEMBER-REF-UNKNOWN: a member "X" dep with no such workspace member.
    for member in workspace.members:
        for dep in member.manifest.deps:
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
    # Root authority = all member names + override names (§10 NORMATIVE).
    root_authority: set[str] = set(members_by_name) | set(overrides_by_name)
    for m in workspace.members:
        all_deps = list(m.manifest.deps) + list(m.manifest.dev_deps)
        for dep in all_deps:
            root_authority.add(dep.name)

    provenance_gate: dict[str, tuple[tuple[object, ...], bool]] = {}
    seen_url: set[tuple[str, str]] = set()
    seen_named: set[str] = set()
    seen_local: set[str] = set()
    seen_tarball: set[str] = set()

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
    ws_edge_cache: dict[tuple[str, Version], EdgeSet] = {}

    provider = _Provider(
        env=env,
        deps_dir=deps_dir,
        params=params,
        overrides_by_name=overrides_by_name,
        root_authority=root_authority,
        seen_named=seen_named,
        seen_url=seen_url,
        provenance_gate=provenance_gate,
        edge_cache=ws_edge_cache,
        strict_attestation=_ws_is_strict,
    )

    # ------------------------------------------------------------------
    # Pre-register each member as a candidate (never fetched)
    # ------------------------------------------------------------------
    for member in workspace.members:
        if params.profile is not None:
            member_manifest = _filter_manifest_by_profile(
                member.manifest, params.profile
            )
            # Use a temporary LoadedMember-like object with the filtered manifest.
            class _FilteredMember:
                def __init__(self, orig: object, manifest: Manifest) -> None:
                    self.manifest = manifest
                    self.abs_dir = orig.abs_dir  # type: ignore[attr-defined]
                    self.rel_path = orig.rel_path  # type: ignore[attr-defined]
            effective = _FilteredMember(member, member_manifest)
        else:
            effective = member  # type: ignore[assignment]

        cand, _ = _build_member_candidate(
            effective, overrides_by_name, members_by_name
        )
        provider.add(cand)

    # ------------------------------------------------------------------
    # Build root candidate requiring all members
    # ------------------------------------------------------------------
    root_terms: list[Term] = [
        Term.require(m.manifest.name, VersionSet.eq(_URL_DEP_VERSION))
        for m in workspace.members
    ]
    root_requires: list[str] = [m.manifest.name for m in workspace.members]

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

    for member in workspace.members:
        if params.profile is not None:
            member_manifest = _filter_manifest_by_profile(
                member.manifest, params.profile
            )
        else:
            member_manifest = member.manifest

        all_member_deps = list(member_manifest.deps) + list(member_manifest.dev_deps)

        for dep in all_member_deps:
            name = dep.name
            # Members and member-named refs are pre-registered → skip queueing.
            if isinstance(dep, MemberDep) or name in members_by_name:
                continue
            # Override: named → URL override.
            if name in overrides_by_name:
                ov = overrides_by_name[name]
                effective_dep = UrlDep(name=name, git=ov.git, ref=ov.ref)
                bfs_queue.append(("url", effective_dep))
                _ws_record_discovery(name)  # Phase B: overridden dep in seed order
                continue
            # Queue external deps.
            if isinstance(dep, UrlDep):
                bfs_queue.append(("url", dep))
                _ws_record_discovery(name)  # Phase B: URL dep in seed order
            elif isinstance(dep, NamedDep):
                if name == "nim":
                    continue
                bfs_queue.append(("named", name, dep.constraint))
                _ws_record_discovery(name)  # Phase B: named dep in seed order
            elif isinstance(dep, TarballDep):
                bfs_queue.append(("tarball", dep))
                _ws_record_discovery(name)  # Phase B: tarball dep in seed order
            elif isinstance(dep, LocalDep):
                bfs_queue.append(("local", dep))
                _ws_record_discovery(name)  # Phase B: local dep in seed order

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
            edge_cache=ws_edge_cache,
            provider=provider,
            overrides_by_name=overrides_by_name,
            deps_dir=deps_dir,
            env=env,
            params=params,
            index=index,
            provenance_gate=provenance_gate,
            root_authority=root_authority,
            record_discovery=_ws_record_discovery,
        )

    # ------------------------------------------------------------------
    # Wire Phase B transitive callback BEFORE solve
    # ------------------------------------------------------------------
    def _on_transitive_named(name: str) -> None:
        if name in seen_named or name == "nim":
            return
        seen_named.add(name)
        _ws_record_discovery(name)  # Phase B: lazy-materialized named dep
        _enumerate_named_stubs(name, None, index, provider, deps_dir, env)

    provider.set_transitive_callback(_on_transitive_named)

    # ------------------------------------------------------------------
    # Step 6b (workspace): Phase B content-hash dedup/alias
    #
    # Mirrors resolve() step 6b: group external candidates by identity,
    # collapse groups of size ≥ 2 to ONE canonical node.  Member candidates
    # are never in ws_discovery_order so they are never deduplicated.
    # ------------------------------------------------------------------
    ws_aliases_map: dict[str, str] = _dedup_candidates(
        provider, deps_dir, ws_discovery_order, overrides_by_name
    )

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
    except SolverError as exc:
        from milpa.errors import SOLVE_CONFLICT
        raise MilpaError(
            SOLVE_CONFLICT,
            f"dependency conflict: {exc}",
            chain=exc.chain,
            solver_error=exc,
        ) from exc

    # ------------------------------------------------------------------
    # Build graph (attach cert for CLI §2.5)
    # ------------------------------------------------------------------
    graph = _build_graph(solution, provider, deps_dir, params.strategy, aliases_map=ws_aliases_map)

    # §13 attestation policy enforcement — mirrors single-package resolve().
    # Effective policy: OR of flag/env (via _ws_is_strict computed above) and
    # each member's attestation-policy "strict" declaration (§13.1 workspace rule).
    from milpa.attestation import enforce_attestation_policy
    resolved_edge_map: dict[str, "EdgeSet"] = {
        name: es
        for (name, _ver), es in ws_edge_cache.items()
        if name != "__root__"
    }
    enforce_attestation_policy(resolved_edge_map, _ws_is_strict)

    from dataclasses import replace as _replace
    graph = _replace(graph, cert=cert)

    # B-nimcfg: rebuild _deps/ view (alias symlinks + stale removal).
    rebuild_deps_view(graph, deps_dir, env.store)

    return graph
