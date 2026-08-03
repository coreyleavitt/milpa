"""``BindingResolver`` — the deterministic, in-memory binding phase (S2), per
``docs/rfc-origin-as-identity.md`` §4.3.

This is the first-class **binding phase** that produces the solver's source-id
variables, replacing the fragile ``provenance_gate``/``TIER_*`` side-table
(``resolver.py``'s ``_check_provenance_gate``/``_validate_transitive_url_against_registry``,
~lines 1990/2118/2150/3790-3880). This module does NOT delete or wire into
that machinery — S2 is a standalone, in-memory class only; wiring lands in
S3a, deletion in S3b.

**Root-first is structural, not a convention.** Root/override ``Claim``s are
reconciled by the CALLER (override pre-empts the root dep declaration —
mirroring today's ``_apply_git_override_to_url_dep`` transform) before they
ever reach ``BindingResolver``. All root claims are bound in ``__init__``;
``submit()`` is reachable only afterward and accepts only non-root claims. So
"root submitted first" is enforced by the API shape, not caller discipline
the Rust mirror could independently get wrong.

**Authority is a two-valued fact, not a lattice.** ``Claim.is_root: bool`` is
the entire authority model — arbitration only ever asks "is this root?",
never compares a priority integer. There is deliberately no ``ClaimAuthority``
``IntEnum`` (that would be the deleted ``TIER_*`` lattice smuggled back in).

**Keyed by ``DepKey`` (``(name, namespace)``), never a bare name (§4.3
B1/G1).** A bare-name store is the LITERAL #193 root cause: it is what let
``ns1::foo`` and ``ns2::foo`` cross-bind. ``Claim.name`` carries the
manifest/solver qualified-name form (``spec/resolver-semantics.md`` §6b's
``"ns::name"`` convention — the same string ``DepKey.solver_var()`` produces
and ``DepKey.from_solver_var()`` consumes); the grouping key is derived from
that field alone via ``DepKey.from_solver_var``, never from the accepted
``SourceId``'s own fields. This is what makes the "override to a different
registry coordinate" case (RFC §5 row) work: the grouping key stays the
*overridden* coordinate even when the accepted ``SourceId`` is a
``RegistrySourceId`` in a completely different ``(namespace, name)`` —
deriving the key from ``source_id.namespace`` instead would silently mix the
overridden name with the override target's own namespace.
"""

from __future__ import annotations

import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

from milpa.errors import MILPA_INTERNAL, RES_BINDING_CONFLICT, RES_REGISTRY_SHADOW, MilpaError
from milpa.source_id import (
    GitSourceId,
    LocalSourceId,
    MemberSourceId,
    OciSourceId,
    RegistrySourceId,
    SourceId,
    TarballSourceId,
    canonical,
    format_source_id,
    normalize_source,
)
from milpa.version import DepKey, SolverKey

if TYPE_CHECKING:
    from milpa.manifest import Override
    from milpa.registry import Index, Package


@dataclass(frozen=True)
class Claim:
    """One declaration site's claim on a dep's origin.

    ``name`` is the label THIS declaration used — the manifest/solver
    qualified-name form (``"foo"`` or ``"ns::foo"``; see module docstring),
    used both for diagnostics/slot projection and to derive the grouping
    ``DepKey``.

    ``claimant`` is message text ONLY (``"root"`` / ``"override:<name>"`` /
    ``"<parent>@<version>"``) — never parsed, never compared.
    """

    name: str
    source_id: SourceId
    is_root: bool
    claimant: str


class BindOutcome(Enum):
    """The 3-way outcome of a claim submission (RFC §4.3 G2 — NOT a bool).

    Flattening ``DUPLICATE``/``LOST_TO_ROOT`` into one ``suppressed: bool``
    would reproduce the exact opacity the RFC's §2.2 condemns in the old
    side-table: a user asking "why didn't my transitive git fork get picked
    up?" deserves a typed answer, not a log grep.
    """

    NEW = auto()  #: first claim for this key — caller enqueues/fetches
    DUPLICATE = auto()  #: matched the existing binding — harmless no-op
    LOST_TO_ROOT = auto()  #: disagreed with a root binding — discarded (Cargo `[patch]`)


@dataclass(frozen=True)
class BindingDecision:
    accepted: SourceId
    outcome: BindOutcome  #: caller enqueues iff outcome is NEW


def _key_for(claim: Claim) -> DepKey:
    """The grouping key — derived from ``claim.name`` alone (never from
    ``claim.source_id``'s own fields; see module docstring)."""
    return DepKey.from_solver_var(claim.name)


class BindingResolver:
    """One instance per ``resolve()``. Deterministic, in-memory-only: it
    never fetches a package tree.

    Root/override claims are bound at construction; only transitive claims
    arrive via ``submit()``.
    """

    def __init__(self, root_claims: Sequence[Claim]) -> None:
        self._bindings: dict[DepKey, SourceId] = {}
        self._root_keys: set[DepKey] = set()
        # origin-as-identity §4.4 (DE1, genericized key): the intern table for
        # SolverKeys — canonical(source_id) → the ONE SolverKey the solver uses
        # for that origin, whose `.display` is the FIRST DepKey ever bound to it
        # (insertion order == BFS-first, mirroring Phase B's alias-selection
        # convention). Kept INSIDE BindingResolver (not a separate side-table)
        # so it stays exactly in sync with `_bindings` — populated atomically in
        # `__init__`/`submit`, and read by `canonical_for`. Interning here means
        # every SolverKey the solver ever sees for a given origin is the SAME
        # object, so `.display` is deterministic: a second, different DepKey
        # later bound to the SAME source_id (the "two labels, one origin" case)
        # does not change it — this is the pre-fetch collapse the re-key
        # realizes. Replaces the old canonical→DepKey reverse map.
        self._solverkey_index: dict[str, SolverKey] = {}
        for claim in root_claims:
            if not claim.is_root:
                raise ValueError(
                    "BindingResolver.__init__ received a non-root claim "
                    f"(name={claim.name!r}, claimant={claim.claimant!r}); "
                    "only root/override claims may be passed to __init__ — "
                    "transitive claims go through submit()"
                )
            key = _key_for(claim)
            existing = self._bindings.get(key)
            if existing is not None and existing != claim.source_id:
                # Root vs. root, same name, different source is unreachable
                # by construction: the caller must pre-empt a base root dep
                # declaration with its override BEFORE building root_claims
                # (RFC §4.3 — mirroring today's `_apply_git_override_to_url_dep`
                # transform). Two disagreeing root claims arriving here is an
                # internal invariant violation, never RES-BINDING-CONFLICT.
                raise AssertionError(
                    "BindingResolver received two disagreeing root claims for "
                    f"{key!r}: {format_source_id(existing)} vs "
                    f"{format_source_id(claim.source_id)} — root claims must "
                    "be reconciled (override pre-empts the base dep "
                    "declaration) before BindingResolver is constructed"
                )
            self._bindings[key] = claim.source_id
            self._root_keys.add(key)
            self._intern(canonical(claim.source_id), key)

    def submit(self, claim: Claim) -> BindingDecision:
        """Submit a non-root (transitive) claim. Raises ``ValueError`` if
        handed a root claim — those are bound at ``__init__`` only."""
        if claim.is_root:
            raise ValueError(
                "BindingResolver.submit() received a root claim "
                f"(name={claim.name!r}, claimant={claim.claimant!r}); root "
                "claims are bound at __init__, not submit()"
            )
        key = _key_for(claim)
        existing = self._bindings.get(key)

        if existing is None:
            self._bindings[key] = claim.source_id
            self._intern(canonical(claim.source_id), key)
            return BindingDecision(accepted=claim.source_id, outcome=BindOutcome.NEW)

        if existing == claim.source_id:
            return BindingDecision(accepted=existing, outcome=BindOutcome.DUPLICATE)

        if key in self._root_keys:
            # Transitive disagrees with a ROOT binding: loses to root
            # silently — Cargo-`[patch]` semantics.
            return BindingDecision(accepted=existing, outcome=BindOutcome.LOST_TO_ROOT)

        # Transitive disagrees with another TRANSITIVE binding, and no root
        # claim exists for this name: unresolvable without human input.
        raise MilpaError(
            RES_BINDING_CONFLICT,
            f"conflicting sources for {claim.name!r}: "
            f"{format_source_id(existing)} vs {format_source_id(claim.source_id)}; "
            "declare it at the root via `overrides {}` to resolve",
            name=claim.name,
            existing=format_source_id(existing),
            conflicting=format_source_id(claim.source_id),
        )

    def source_id_for(self, key: DepKey) -> SourceId | None:
        return self._bindings.get(key)

    def is_root_authority(self, key: DepKey) -> bool:
        """Is *key* bound by a ROOT/override claim? The registry-shadow
        tripwire uses this to decide whether to second-guess a transitive
        claim: root owns a source only over the EXACT ``DepKey`` it declared,
        never over a bare name — a root ``foo namespace="ns1"`` gives NO
        authority over a bare ``foo`` a transitive tries to source elsewhere
        (that would let an unrelated namespaced root dep silently disable the
        dependency-confusion check for a different coordinate)."""
        return key in self._root_keys

    def _intern(self, canonical_key: str, key: DepKey) -> SolverKey:
        """Intern the ``SolverKey`` for an origin string, first-``DepKey``-wins.

        The single mint point for the ``canonical(source_id) → SolverKey`` map:
        the first ``DepKey`` bound to a given origin fixes that origin's
        ``.display`` for the whole solve (BFS-first). Idempotent — a later,
        different ``DepKey`` for the same origin returns the already-interned
        SolverKey unchanged (the "two labels, one origin" collapse)."""
        existing = self._solverkey_index.get(canonical_key)
        if existing is None:
            existing = SolverKey(canonical_key, key)
            self._solverkey_index[canonical_key] = existing
        return existing

    def canonical_for(self, key: DepKey) -> SolverKey:
        """The ``SolverKey`` the solver sees for an ALREADY-BOUND ``DepKey``
        (RFC §4.4 deliverable #1). Its string value is
        ``canonical(source_id_for(key))``; its ``.display`` is the BFS-first
        label for that origin (the interned first-bound DepKey, which may differ
        from ``key`` when two labels collapse to one origin). Raises
        ``MilpaError('MILPA-INTERNAL', …)`` if ``key`` has never been bound —
        every caller reaches this only after a root claim (bound at
        ``__init__``) or an accepted ``submit()`` (``NEW``/``DUPLICATE``), so
        an unbound key here is an internal invariant violation, not a
        user-facing condition.
        """
        sid = self._bindings.get(key)
        if sid is None:
            raise MilpaError(
                MILPA_INTERNAL,
                f"canonical_for({key!r}) has no binding — this is an internal "
                "milpa bug; please report it",
            )
        return self._intern(canonical(sid), key)


# ---------------------------------------------------------------------------
# Root-claim reconciliation (S3a) — override-preempts-root-dep, RFC §4.3
# ---------------------------------------------------------------------------

#: The registry alias every ``RegistrySourceId`` uses today (RFC §4.1 — the
#: registry component is a CONFIGURED ALIAS slug, never a base URL). milpa
#: does not yet support multiple configured registries/aliases (that is
#: future work, tracked alongside ``FROZEN-REGISTRY-ALIAS-UNRESOLVED``); one
#: hardcoded alias is the minimal-viable choice until a second registry is a
#: proven need ([[feedback_minimal_over_completeness]]).
DEFAULT_REGISTRY_ALIAS = "tianguis"


def resolved_registry_namespace(
    name: str, namespace: str | None, index: "Index | None"
) -> str | None:
    """The REAL resolved index namespace for a registry coordinate (RFC §4.3
    B1/G1 — ``RegistrySourceId.namespace`` is always the real resolved index
    namespace, never the manifest qualifier; the two CAN differ).

    An explicit manifest qualifier is used as-is — already unambiguous, no
    lookup needed. A bare (unqualified) name is looked up; an unambiguous
    match uses the index's own recorded namespace. An absent or ambiguous
    bare name falls back to ``None`` — the ordinary enumeration path
    (``_enumerate_named_stubs`` / ``index.resolve_named_all``) raises the
    appropriate ``TNG-NOT-FOUND``/``TNG-AMBIGUOUS-NAME`` immediately
    afterward regardless, so the transient value here never drives anything
    but that same error path.

    ``index is None`` (no registry configured — ``MilpaEnv.index``, S5-rekey
    callers like ``canonical_key_for_requirement`` reach this even for a
    manifest with no actual named/registry deps, e.g. a NamedRequire that
    turns out to reference the root's own name, §14) is treated the same as
    an absent bare-name match: falls back to ``None`` — never a crash. The
    ordinary enumeration path still owns raising ``TNG-NOT-FOUND`` etc. for
    any case that genuinely needed a real index.
    """
    if namespace is not None:
        return namespace
    if index is None:
        return None
    from milpa.registry import Package as _Package

    looked_up = index.lookup_bare(name)
    if isinstance(looked_up, _Package):
        return looked_up.namespace or None
    return None


def _override_target_to_raw_origin(ov: "Override", index: "Index | None" = None) -> SourceId:
    """The ``SourceId`` an override's target denotes (pre-normalization).

    ``index`` (S8b, rfc-origin-as-identity.md §7 B5) is consulted ONLY for a
    ``RegistryTarget`` whose ``namespace`` is unset — a bare-name index
    lookup, mirroring ``_dep_declared_raw_origin``'s ``NamedDep`` branch,
    so the ROOT CLAIM built here (at ``BindingResolver.__init__`` time)
    agrees with whatever the "named" BFS arm will independently compute for
    the SAME coordinate later. ``None`` is accepted (falls back to the bare
    ``namespace=None`` — the ordinary "no index configured" case already
    handled by ``resolved_registry_namespace``).
    """
    from milpa.manifest import GitTarget, LocalTarget, MemberTarget, OciTarget, RegistryTarget, TarballTarget

    if isinstance(ov.target, GitTarget):
        return GitSourceId(url=ov.target.git, subpath=ov.target.subpath)
    if isinstance(ov.target, LocalTarget):
        return LocalSourceId(path=ov.target.path)
    if isinstance(ov.target, MemberTarget):
        return MemberSourceId(member_name=ov.target.member_name)
    if isinstance(ov.target, OciTarget):
        return OciSourceId(
            registry=ov.target.registry, repository=ov.target.repository, subpath=ov.target.subpath,
        )
    if isinstance(ov.target, TarballTarget):
        return TarballSourceId(url=ov.target.url, subpath=ov.target.subpath)
    if isinstance(ov.target, RegistryTarget):
        ns = resolved_registry_namespace(ov.target.name, ov.target.namespace, index)
        return RegistrySourceId(registry=DEFAULT_REGISTRY_ALIAS, namespace=ns, name=ov.target.name)
    raise TypeError(f"unrecognized override target kind: {type(ov.target)!r}")  # pragma: no cover


def _dep_declared_raw_origin(dep: object, index: "Index") -> SourceId | None:
    """The ``SourceId`` a dep's OWN declaration denotes (pre-normalization,
    pre-override), or ``None`` for a dep kind that makes no claim of its own
    (``MemberDep`` — a workspace-only concern; the caller registers a
    ``MemberSourceId`` claim per workspace member independently, not via a
    dep declaration)."""
    from milpa.manifest import LocalDep, MemberDep, NamedDep, TarballDep, UrlDep

    if isinstance(dep, UrlDep):
        return GitSourceId(url=dep.git, subpath=dep.subpath)
    if isinstance(dep, NamedDep):
        ns = resolved_registry_namespace(dep.name, dep.namespace, index)
        return RegistrySourceId(registry=DEFAULT_REGISTRY_ALIAS, namespace=ns, name=dep.name)
    if isinstance(dep, TarballDep):
        return TarballSourceId(url=dep.url, subpath=dep.subpath)
    if isinstance(dep, LocalDep):
        return LocalSourceId(path=dep.path)
    if isinstance(dep, MemberDep):
        return None
    raise TypeError(f"unrecognized dep kind: {type(dep)!r}")  # pragma: no cover


def canonical_key_for_requirement(
    *,
    name: str,
    namespace: str | None = None,
    url: str | None = None,
    overrides_by_name: dict[str, "Override"],
    index: "Index | None",
    root_self_name: str | None = None,
    binding_resolver: "BindingResolver | None" = None,
) -> SolverKey:
    """The PubGrub solver-variable string a ``requires`` occurrence resolves
    to (RFC §4.4.1 — the normative two-phase design). Used to feed the
    solver ``Term``/provider-dict key BEFORE the corresponding claim is
    actually ``submit()``ted (submission happens later, at BFS dispatch,
    batched so a sibling conflict is caught before any fetch — RFC §3a).

    **The solver variable is UNIFORMLY ``canonical(source_id)`` for EVERY
    dep kind** — git, tarball, local, member, and registry alike. There is
    no "eager kinds stay bare" carve-out: that would be two regimes glued
    together, not one seam. Two questions, kept separate:

    Phase 1 — name-resolution (``reference → source_id``), BINDING-AWARE:

    1. *name*'s ``DepKey`` already bound? → ``binding_resolver.
       source_id_for(dep_key)`` wins, REGARDLESS of source-id kind. Root/
       override claims bind at ``BindingResolver.__init__``; earlier
       accepted transitive claims (the "named" BFS arm, ``_on_transitive_
       named``, and the "url" BFS arm's own ``binding_resolver.submit()``
       — RFC origin-as-identity §4.3 S3a — ALL kinds submit a claim on
       first transitive admission) bind during BFS. A later disagreeing
       claim for an already-bound ref is ``RES-BINDING-CONFLICT`` (root) or
       silently ``LOST_TO_ROOT`` (transitive vs. root) — unchanged, handled
       entirely by ``BindingResolver.submit``/``__init__``, not here.
    2. Else (genuinely unbound — first-ever encounter, no root claim, no
       prior transitive claim): a KIND DEFAULT — ``url`` present → that
       git declaration's own ``GitSourceId``; ``root_self_name`` match →
       the root-self ``MemberSourceId`` sentinel (§14, checked first — a
       structural identity, never redirected by ``overrides{}``);
       ``overrides_by_name`` match → the override's target ``SourceId``;
       otherwise → an ordinary registry coordinate.

    Phase 2 — canonicalization (``source_id → canonical``): uniform,
    kind-free — ``canonical()`` (source_id.py), always.

    Why this unifies root ``bearssl git=<url>`` with a transitive bare
    ``requires "bearssl >= 0.2.8"``: both resolve to the SAME ``DepKey
    (name="bearssl", namespace=None)``. Phase 1 step 1 finds the root's
    BOUND ``GitSourceId`` for that key BEFORE the registry default would
    ever apply — the transitive's own guess is never even computed. One
    ``canonical(url)`` solver variable, unified pre-fetch — no fictional
    registry coordinate, because the binding is consulted before the kind
    default. A direct ``git=``/``local=``/``tarball=``/``oci=`` declaration
    is semantically an implicit override of that name (Cargo ``[patch]`` /
    nimble federation) — which is exactly what phase-1 step 1 encodes.

    Only when *name*'s ``DepKey`` is NOT YET bound (genuinely first
    encounter — no root claim, no prior transitive claim) does this fall
    through to the KIND-DEFAULT GUESS below: assume it will become a NEW
    claim of the kind its OWN occurrence declares — which is exactly what
    the "named"/"url" BFS arms (or ``_on_transitive_named``) will submit
    once this occurrence is formally processed, so the guess and the
    eventual real binding always agree.

    The guess itself mirrors ``_dep_declared_raw_origin``/
    ``_override_target_to_raw_origin`` (same primitives, no new dispatch
    logic): ``root_self_name`` (§14, checked first — root-self is a
    structural identity, never redirected by ``overrides{}``), then
    ``overrides_by_name`` (an override on this name wins), then ``url is
    not None`` (the git branch, mirrors ``_dep_declared_raw_origin``'s
    ``UrlDep`` case), then an ordinary registry-coordinate guess (mirrors
    its ``NamedDep`` case) — the only two kinds ``edgeset_to_terms`` ever
    builds terms for (Local/Tarball transitive requires are dropped
    upstream, M2 security gate; they only ever reach this function via an
    ALREADY-bound root claim, phase-1 step 1, never the guess).
    """
    _dk = DepKey(name=name, namespace=namespace)
    if binding_resolver is not None:
        _sid = binding_resolver.source_id_for(_dk)
        if _sid is not None:
            # Bound: return the interned SolverKey (BFS-first display).
            return binding_resolver.canonical_for(_dk)
    # Unbound (first encounter): the kind-default guess. This requirement's
    # own DepKey IS the first (BFS-first) label for the guessed origin, so it
    # is the display. When the corresponding claim is later submitted,
    # canonical_for interns the same origin with the same first-seen display.
    if namespace is None and url is None and root_self_name is not None and name == root_self_name:
        return SolverKey(canonical(MemberSourceId(member_name=name)), _dk)
    ov = overrides_by_name.get(name)
    if ov is not None:
        raw = _override_target_to_raw_origin(ov, index)
    elif url is not None:
        raw = GitSourceId(url=url)
    else:
        ns = resolved_registry_namespace(name, namespace, index)
        raw = RegistrySourceId(registry=DEFAULT_REGISTRY_ALIAS, namespace=ns, name=name)
    return SolverKey(canonical(normalize_source(raw)), _dk)


def reconcile_root_claims(
    deps: Sequence[object],
    overrides: Sequence["Override"],
    *,
    index: "Index",
) -> list[Claim]:
    """Build the reconciled root ``Claim`` set for ``BindingResolver.__init__``
    (RFC §4.3: "the override pre-empts the root dep declaration before
    binding" — mirroring today's ``_apply_git_override_to_url_dep``
    transform).

    *deps* is every root-authoritative dep declaration — a single manifest's
    ``deps + dev_deps`` for a standalone ``resolve()``; every workspace
    member's ``deps + dev_deps`` for ``resolve_workspace()``; the caller
    assembles the right list. This function is deliberately dep-source-
    agnostic so ``resolve()``, ``resolve_workspace()``, and a later
    ``frozen.py`` slice all reuse the identical override-reconciliation
    transform (CLAUDE.md single-source-of-truth discipline), rather than
    three independent copies.

    Reconciliation: for each dep, an override on the SAME name wins —
    its target (not the dep's own declaration) determines the claim's
    ``SourceId`` — so two disagreeing root claims for one name are
    unreachable by construction (``BindingResolver.__init__`` treats that
    as an internal invariant violation, never ``RES-BINDING-CONFLICT``).
    An override with NO corresponding dep declaration (RFC §5 "Overrides"
    row — patching a transitive-only name) still produces its own root
    ``Claim``, bound regardless of whether the name is ever declared as a
    root dep. ``MemberDep`` entries produce no claim (see
    ``_dep_declared_raw_origin``).

    ``Claim.name`` (the string ``_key_for`` derives the grouping ``DepKey``
    from) carries the dep's own qualified identity — ``DepKey(name,
    namespace).solver_var()`` — for a plain (non-overridden) declaration, so
    a namespace-qualified root ``NamedDep`` (e.g. ``foo namespace="ns1"``)
    binds under ``DepKey(name="foo", namespace="ns1")``, never the bare
    ``DepKey(name="foo", namespace=None)``. An OVERRIDDEN dep's claim stays
    bare (``name`` only, ignoring the dep's own namespace): ``Override`` has
    no namespace concept, ``overrides_by_name`` matches by bare name
    regardless of the matched dep's namespace, and the override-only claims
    built below (no corresponding dep) are unconditionally bare — every
    override-driven claim for one name must bind under the SAME grouping
    key regardless of which branch produced it.

    Dedup is by the FULL ``(name, namespace)`` pair, not bare name — two
    root deps sharing a bare name under DIFFERENT namespaces are DIFFERENT
    deps (S5b B1/G1: qualified vs. bare never cross-bind) and each needs its
    own claim; only a bare-name-tracking set (``seen_names``, retained
    separately) drives the override catch-up loop below, since overrides
    themselves have no namespace axis.
    """
    overrides_by_name = {ov.name: ov for ov in overrides}
    claims: list[Claim] = []
    seen_names: set[str] = set()  # bare names — drives the override catch-up loop below
    seen_keys: set[tuple[str, str | None]] = set()  # qualified (name, namespace) dedup
    # The source bound to each already-seen key. A SECOND root declaration of
    # the same (name, namespace) that disagrees on source is a hard
    # RES-BINDING-CONFLICT, not a silent drop: the old first-wins skip hid
    # `deps { foo local="./a" }` + `dev-deps { foo local="./b" }`, producing a
    # lockfile whose recorded `source` disagreed with the materialized bytes
    # (the two blocks carry independent duplicate-name guards, so the collision
    # is invisible until reconciliation). RFC §4.3: root claims bind cleanly or
    # raise — never a silent condition.
    seen_key_source: dict[tuple[str, str | None], SourceId] = {}
    for dep in deps:
        name: str = dep.name  # type: ignore[attr-defined]
        namespace: str | None = getattr(dep, "namespace", None)
        key = (name, namespace)
        first_time = key not in seen_keys
        seen_keys.add(key)
        seen_names.add(name)
        ov = overrides_by_name.get(name)
        if ov is not None:
            raw = _override_target_to_raw_origin(ov, index)
            claimant = f"override:{name}"
            claim_name = name  # override's grouping key is always bare
        else:
            raw = _dep_declared_raw_origin(dep, index)
            claimant = "root"
            claim_name = DepKey(name=name, namespace=namespace).solver_var()
        if raw is None:
            continue
        source_id = normalize_source(raw)
        if not first_time:
            prior = seen_key_source.get(key)
            if prior is not None and prior != source_id:
                raise MilpaError(
                    RES_BINDING_CONFLICT,
                    f"package {claim_name!r} is declared at the root more than "
                    "once with disagreeing sources: "
                    f"{format_source_id(prior)} vs {format_source_id(source_id)}; "
                    "a package may be declared at the root (across deps and "
                    "dev-deps) only once",
                    name=claim_name,
                    existing=format_source_id(prior),
                    conflicting=format_source_id(source_id),
                )
            # Same source (or the first sighting produced no claim) — the
            # first-seen claim stands; this is an idempotent duplicate.
            continue
        seen_key_source[key] = source_id
        claims.append(
            Claim(name=claim_name, source_id=source_id, is_root=True, claimant=claimant)
        )
    for ov in overrides:
        if ov.name in seen_names:
            continue
        seen_names.add(ov.name)
        raw = _override_target_to_raw_origin(ov, index)
        claims.append(
            Claim(
                name=ov.name,
                source_id=normalize_source(raw),
                is_root=True,
                claimant=f"override:{ov.name}",
            )
        )
    return claims


# ---------------------------------------------------------------------------
# Registry-shadow tripwire (S3c) — RFC §6.1/§11 D-Fork1
# ---------------------------------------------------------------------------


def check_registry_shadow(
    claim: Claim,
    index: "Index",
    *,
    is_strict: bool,
) -> None:
    """The pre-fetch dependency-confusion tripwire (RFC §6.1/§11 D-Fork1,
    S3c — the security-critical companion that must land atomically with
    ``BindingResolver`` becoming authoritative, S3a).

    Deleting the old ``_validate_transitive_url_against_registry`` gate
    removes milpa's pre-fetch defense against a transitive claim silently
    name-squatting a registry-owned coordinate. This is NOT a source-
    selection mechanism (coordinate-is-origin already settled that — RFC
    §3.2) — it is an orthogonal, additive TRUST check consulted before a
    NEW (previously-unbound) transitive ``git=``/``tarball=``/``oci=``
    claim is admitted:

    - **Trigger**: the claim's bare name is ALSO a name the registry owns,
      in ANY namespace (an ambiguous bare name checks every namespace it
      resolves to).
    - **Refine**: if the registry records a comparable upstream source
      (a ``GitIndexProvenance.url`` or an ``OciIndexProvenance.source_url``,
      across every version of every owning package) that matches the
      claim's own normalized source — silent accept (a legitimate pin of
      the registry's own repository).
    - Otherwise (the URL disagrees, or NOTHING comparable is recorded —
      e.g. an OCI-only entry with no ``source_url``) — this is a silent
      name-shadow: **warn by default** (a git fork of a registry package
      is legitimate and common), **hard-fail under
      ``attestation-policy strict``** (secure-by-default for consumers who
      opt in).

    Deliberately does NOT reconcile via post-fetch ``content_hash``
    comparison (the retired mechanism's fallback) — this is a STATIC,
    pre-fetch, URL-only check; ``content_hash`` still verifies fetched
    bytes independently at materialization, orthogonal to this admission
    decision (RFC §11 D-Fork1: "NO post-fetch content-hash comparison —
    deleted entirely").

    Never mutates ``BindingResolver`` state and never touches its own
    multi-claim arbitration (``RES-BINDING-CONFLICT`` governs disagreements
    between two EXPLICIT claims independently of this check).
    """
    from milpa.registry import AmbiguousName, GitIndexProvenance, OciIndexProvenance, Package
    from milpa.source_id import _normalize_git_url

    sid = claim.source_id
    if not isinstance(sid, (GitSourceId, TarballSourceId, OciSourceId)):
        return  # not a fetchable self-declared-source claim — nothing to shadow-check

    bare_name = DepKey.from_solver_var(claim.name).name
    looked_up = index.lookup_bare(bare_name)
    packages: list["Package"] = []
    if isinstance(looked_up, Package):
        packages = [looked_up]
    elif isinstance(looked_up, AmbiguousName):
        for ns in looked_up.namespaces:
            pkg = index.lookup_qualified(ns, bare_name)
            if pkg is not None:
                packages.append(pkg)
    if not packages:
        return  # the name is not registry-owned at all — an ordinary self-source

    claim_url = sid.url if isinstance(sid, (GitSourceId, TarballSourceId)) else None
    if claim_url is not None:
        claim_norm = _normalize_git_url(claim_url)
        for pkg in packages:
            for iv in pkg.versions:
                for prov in iv.provenances:
                    upstream: str | None = None
                    if isinstance(prov, GitIndexProvenance):
                        upstream = prov.url
                    elif isinstance(prov, OciIndexProvenance) and prov.source_url:
                        upstream = prov.source_url
                    if upstream is not None and _normalize_git_url(upstream) == claim_norm:
                        return  # legitimate same-repository pin — silent accept

    owning = sorted(
        f"{pkg.namespace}/{pkg.name}" if pkg.namespace else pkg.name for pkg in packages
    )
    message = (
        f"{format_source_id(sid)} shares the name {bare_name!r} with a tianguis "
        f"registry package ({owning!r}), but its source does not match any "
        f"upstream URL the registry records for it — this could be a "
        f"legitimate fork, or a dependency-confusion attempt. Pin it "
        f"explicitly at the root (deps/overrides) to silence this warning."
    )
    if is_strict:
        raise MilpaError(
            RES_REGISTRY_SHADOW,
            message,
            name=bare_name,
            source=canonical(sid),
        )
    warnings.warn(message, UserWarning, stacklevel=3)
