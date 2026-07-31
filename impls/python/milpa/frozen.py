"""Frozen resolver — lockfile-backed graph reconstruction (NO fetcher invocation).

Implements ``resolve_frozen`` and ``resolve_workspace_frozen`` per
``spec/resolver-semantics.md`` §7 and §7.1.

The frozen path NEVER invokes a fetcher.  It reconstructs a ``ResolvedGraph``
from the lockfile and the CAS alone.  This is enforced by signature:
``resolve_frozen`` takes ``MilpaEnv`` but NOT ``ResolveParams`` — there is no
``strategy`` / ``max_parallel`` / ``prior`` available here (RFC §4.4 NORMATIVE).

The resolver-level ``FROZEN-*`` preconditions (§7.1) are:

1. ``FROZEN-STRATEGY-MISMATCH`` — lockfile.strategy != default requested strategy.
2. ``FROZEN-MANIFEST-DEP-NOT-IN-LOCK`` — manifest dep has no lockfile entry.
3. ``FROZEN-LOCKED-VERSION-UNPARSEABLE`` — locked version not parseable.
4. ``FROZEN-CONSTRAINT-UNSATISFIED`` — locked version doesn't satisfy named constraint.
5. ``FROZEN-IDENTITY-NOT-IN-STORE`` — dep identity absent from CAS.
6. ``FROZEN-LOCAL-DEP`` — dep has local provenance (single-package path only).
7. ``FROZEN-MEMBER-DEP`` — locked dep has member provenance (single-package raises).
8. ``FROZEN-MEMBER-NOT-IN-WORKSPACE`` — lockfile member not in workspace members.
9. ``FROZEN-MEMBER-IDENTITY-DRIFT`` — member on-disk hash ≠ lockfile pin.
10. ``FROZEN-EXCLUDE-NEWER-MISMATCH`` (D5) — lockfile.exclude_newer != the
    manifest's effective ``resolution { exclude-newer }``.

The 2 CLI-level guards (``FROZEN-NO-LOCKFILE``, ``FROZEN-NO-CAS``) are raised in
``cli.py`` BEFORE the resolve path is entered (RFC §8 scope clarification).

Public surface
--------------
``resolve_frozen(manifest, lockfile, env, deps_dir) -> ResolvedGraph``
    Reconstruct the graph for a single-package project from a lockfile.
    No solver, no network.

``resolve_workspace_frozen(workspace, lockfile, env, deps_dir) -> ResolvedGraph``
    Reconstruct the graph for a workspace from a shared lockfile.

Spec: spec/resolver-semantics.md §7 and §7.1 (the closed list of 9 preconditions).
"""

from __future__ import annotations

from pathlib import Path

from milpa.context import MilpaEnv
from milpa.errors import (
    FROZEN_CONSTRAINT_UNSATISFIED,
    FROZEN_EXCLUDE_NEWER_MISMATCH,
    FROZEN_IDENTITY_NOT_IN_STORE,
    FROZEN_LOCAL_DEP,
    FROZEN_LOCKED_VERSION_UNPARSEABLE,
    FROZEN_MANIFEST_DEP_NOT_IN_LOCK,
    FROZEN_MEMBER_DEP,
    FROZEN_MEMBER_IDENTITY_DRIFT,
    FROZEN_MEMBER_NOT_IN_WORKSPACE,
    FROZEN_STRATEGY_MISMATCH,
    MilpaError,
)
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    LocalProvenanceRecord,
    LockedDep,
    Lockfile,
    MemberProvenanceRecord,
    ResolvedDep,
    ResolvedGraph,
)
from milpa.manifest import Manifest, MemberDep, NamedDep
from milpa.registry import EntryAttestation
from milpa.version import DepKey, Strategy, VersionSet, parse_version
from milpa.workspace import LoadedWorkspace


def _frozen_baseline_strategy(manifest: "Manifest | object") -> Strategy:
    """C3b (resolution-semantics RFC §3 Axis C / §6 D-C2, §7 C3b): the
    ``FROZEN-STRATEGY-MISMATCH`` baseline.

    NOT a hardcoded ``"maxver"`` literal — the manifest's *effective*
    ``resolution { strategy }`` (default ``maxver`` when the block is
    absent or declared without a ``strategy`` child). Reuses
    ``resolver._resolve_effective_strategy`` (the C3 SSOT for strategy
    precedence) with ``cli_strategy=None`` (the frozen path has no CLI
    ``--strategy`` surface). R9: the function has no lockfile-prior tier at
    all anymore (the lockfile-recorded strategy is diagnostic-only, never a
    live input) — it collapses to tiers 2 (manifest) + 3 (global default)
    only, which is exactly what this baseline needs (the frozen path's
    ``lockfile`` IS the very value this baseline gets compared against;
    a lockfile-prior tier would have made the mismatch check compare the
    lockfile's strategy to itself and never fire).

    Returns a ``Strategy`` (a ``StrEnum``), which compares equal to the
    lockfile's plain ``str`` ``strategy`` field directly — no ``str()``
    conversion needed at the call site.
    """
    from milpa.resolver import _resolve_effective_strategy  # avoid circular import

    decl = _resolve_effective_strategy(None, manifest)
    return decl if decl is not None else Strategy.MAXVER


def _frozen_baseline_exclude_newer(manifest: "Manifest | object") -> "object | None":
    """D5 (resolution-semantics RFC §3 Axis D / §7 D5): the
    ``FROZEN-EXCLUDE-NEWER-MISMATCH`` baseline.

    Built manifest-sourced from the start (mirrors ``_frozen_baseline_
    strategy`` / C3b EXACTLY) — the manifest's *effective*
    ``resolution { exclude-newer }`` (default ``None`` when the block is
    absent or declared without an ``exclude-newer`` child). Reuses
    ``resolver._resolve_effective_exclude_newer`` (the D2/D5 SSOT for
    exclude-newer precedence) with ``cli_exclude_newer=None`` (the frozen
    path has no CLI ``--exclude-newer`` surface) and ``prior=None`` —
    deliberately, since the frozen path's lockfile IS the very value this
    baseline gets compared against; threading it through as tier 3 would
    make the mismatch check compare the lockfile's value to itself and
    never fire. Collapses to tier 2 (manifest) + the ``None`` default only.

    Returns a ``datetime | None``, comparable directly against the
    lockfile's ``exclude_newer`` field.
    """
    from milpa.resolver import _resolve_effective_exclude_newer  # avoid circular import

    return _resolve_effective_exclude_newer(None, manifest, None)


def _locked_index(deps: object) -> "dict[DepKey, LockedDep]":
    """Build an alias-aware lookup map from lockfile deps.

    Maps EVERY canonical name AND every alias to its canonical ``LockedDep``.
    This is the SSOT for all "is this manifest dep in the lockfile?" checks
    (condition 2: FROZEN-MANIFEST-DEP-NOT-IN-LOCK) — both ``resolve_frozen``
    and ``resolve_workspace_frozen`` use it in place of the bare
    ``{d.name: d for d in lockfile.deps}`` pattern.

    S1 (rfc-resolver-correctness.md #142): fixes the false-positive where a
    manifest dep known only as an alias fired FROZEN-MANIFEST-DEP-NOT-IN-LOCK
    because the old dict keyed on canonical names only.

    C1 (rfc-resolver-correctness.md): key by ``DepKey(name=dep.name,
    namespace=dep.namespace)`` so a manifest dep ``"ns1/bar"`` (which parses
    to ``DepKey(name="bar", namespace="ns1")``) matches the lockfile dep with
    bare name ``"bar"`` and namespace ``"ns1"``.  Aliases are always bare
    (no namespace) — alias DepKeys use ``namespace=None``.
    """
    index: dict[DepKey, LockedDep] = {}
    for dep in deps:  # type: ignore[union-attr]
        index[DepKey(name=dep.name, namespace=getattr(dep, "namespace", None))] = dep
        for alias in dep.aliases:
            index[DepKey(name=alias)] = dep
    return index


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_local_provenance(locked: LockedDep) -> None:
    """Condition 6 (single-package path only): FROZEN-LOCAL-DEP.

    Raises if any provenance record has kind ``local``.
    """
    for prov in locked.provenances:
        if isinstance(prov, LocalProvenanceRecord):
            raise MilpaError(
                FROZEN_LOCAL_DEP,
                f"dep {locked.name!r} has a local-path provenance; "
                f"local deps cannot use the frozen path — run 'milpa fetch' instead",
                name=locked.name,
            )


def _check_member_provenance_in_single_package(locked: LockedDep) -> None:
    """Condition 7 (single-package path only): FROZEN-MEMBER-DEP.

    Raises if any provenance record has kind ``member`` in single-package context.
    """
    for prov in locked.provenances:
        if isinstance(prov, MemberProvenanceRecord):
            raise MilpaError(
                FROZEN_MEMBER_DEP,
                f"dep {locked.name!r} has a workspace-member provenance; "
                f"workspace member deps cannot use the single-package frozen path",
                name=locked.name,
            )


def _reconstruct_from_locked(locked: LockedDep) -> ResolvedDep:
    """Reconstruct a ResolvedDep from a LockedDep (frozen path reconstruction).

    D-lifecycle: carry all provenances through (observed + declared mirrors).
    The frozen path reads the lockfile's full tuple so D-frozen can later use
    the plural model without a data-model change.
    """
    return ResolvedDep(
        name=locked.name,
        identity=locked.identity,
        version=locked.version,
        src_dir=locked.src_dir,
        requires=locked.requires,
        provenances=locked.provenances,
        active_flags=locked.active_flags,
        dep_decl=locked.dep_decl,
        # cond_requires intentionally empty: frozen path reconstructs from
        # lockfile; cond_requires are lockfile annotations only — not needed
        # for frozen graph reconstruction (mirrors Rust: Vec::new()).
        cond_requires=(),
        aliases=locked.aliases,
        # C1: carry namespace for qualified named deps (None for all others).
        namespace=getattr(locked, "namespace", None),
        # RFC per-entry-attestation.md P2 (§8 Command Coverage): the frozen
        # path carries the lockfile's attestation CLAIM through, nothing
        # re-checked (no gate runs here — §8 command-coverage table). Widen
        # LockAttestation back to the EntryAttestation shape ResolvedDep
        # carries; bundle_pin round-trips too (P3a addition, lockfile-schema
        # §3.9) since P4's offline verify needs it downstream of a frozen
        # resolve too.
        attestation=(
            EntryAttestation(
                kind=locked.attestation.kind,
                rekor=locked.attestation.rekor,
                bundle_pin=locked.attestation.bundle_pin,
            )
            if locked.attestation is not None
            else None
        ),
        # CR13/4: carry LockAttestation.namespace back onto registry_namespace
        # — it is populated precisely so milpa verify's offline re-verification
        # (RFC per-entry-attestation.md §7) can rebuild the exact
        # pkg:tianguis/<namespace>/<name>@<version> subject coordinate from a
        # frozen-reconstructed graph with no index available.
        registry_namespace=(
            locked.attestation.namespace or None if locked.attestation is not None else None
        ),
        # A5: carry the sibling declared-version source straight through —
        # frozen reconstruction re-derives nothing (no solve, no re-fetch).
        declared_version_source=locked.declared_version_source,
    )


# ---------------------------------------------------------------------------
# Public: resolve_frozen
# ---------------------------------------------------------------------------


def resolve_frozen(
    manifest: Manifest,
    lockfile: Lockfile,
    env: MilpaEnv,
    deps_dir: Path,
) -> ResolvedGraph:
    """Reconstruct a ``ResolvedGraph`` from a lockfile (no fetch, no solve).

    Checks the resolver-level ``FROZEN-*`` preconditions from
    ``resolver-semantics.md`` §7.1 for the single-package path:
    conditions 1–7.

    Parameters
    ----------
    manifest:
        The parsed package manifest (for constraint-check, §7.1 #2 and #4).
    lockfile:
        The previously-recorded lockfile.
    env:
        Injectable seams: ``store`` is used to verify CAS presence (§7.1 #5).
        ``fetcher`` and ``index`` are NOT used — the frozen path never fetches.
    deps_dir:
        Where to symlink the CAS entries for this project's ``_deps/``.

    Raises
    ------
    MilpaError
        Any of the 10 ``FROZEN-*`` precondition codes.
    """
    # Condition 1: FROZEN-STRATEGY-MISMATCH (C3b: baseline = manifest's
    # effective ``resolution { strategy }``, not the hardcoded literal).
    _baseline_strategy = _frozen_baseline_strategy(manifest)
    if lockfile.strategy != _baseline_strategy:
        raise MilpaError(
            FROZEN_STRATEGY_MISMATCH,
            f"lockfile strategy {lockfile.strategy!r} does not match "
            f"the requested strategy {_baseline_strategy!r}; re-run 'milpa fetch' "
            f"with the desired strategy to regenerate the lockfile",
            lockfile_strategy=lockfile.strategy,
            requested_strategy=_baseline_strategy,
        )

    # D5: FROZEN-EXCLUDE-NEWER-MISMATCH (baseline = manifest's effective
    # ``resolution { exclude-newer }``, built the same way as the strategy
    # baseline above — manifest-sourced from the start, C3b's own fix).
    _baseline_exclude_newer = _frozen_baseline_exclude_newer(manifest)
    if lockfile.exclude_newer != _baseline_exclude_newer:
        raise MilpaError(
            FROZEN_EXCLUDE_NEWER_MISMATCH,
            f"lockfile exclude-newer {lockfile.exclude_newer!r} does not match "
            f"the requested exclude-newer {_baseline_exclude_newer!r}; re-run "
            f"'milpa fetch' with the desired exclude-newer to regenerate the lockfile",
            lockfile_exclude_newer=lockfile.exclude_newer,
            requested_exclude_newer=_baseline_exclude_newer,
        )

    # S1 (#142): alias-aware lookup — maps canonical name AND every alias to
    # the canonical LockedDep.  Replaces the bare {d.name: d} dict.
    locked_index = _locked_index(lockfile.deps)

    # Condition 2: FROZEN-MANIFEST-DEP-NOT-IN-LOCK (for each manifest dep)
    # §7.1 #2: check both ``deps`` and ``dev_deps`` (spec/resolver-semantics.md).
    all_deps = list(manifest.deps) + list(manifest.dev_deps)
    for dep in all_deps:
        # C1: use DepKey(name, namespace) so qualified deps (``"ns/bar"`` →
        # namespace="ns", name="bar") match the lockfile entry with the same
        # bare name + namespace pair — not just the bare name.
        _ns = getattr(dep, "namespace", None)
        if DepKey(name=dep.name, namespace=_ns) not in locked_index:
            raise MilpaError(
                FROZEN_MANIFEST_DEP_NOT_IN_LOCK,
                f"manifest dep {dep.name!r} has no entry in the lockfile; "
                f"run 'milpa fetch' to regenerate the lockfile",
                name=dep.name,
            )

    # Per-dep checks (3–8) for each locked dep
    for locked in lockfile.deps:
        # Condition 6: FROZEN-LOCAL-DEP (single-package only)
        _check_local_provenance(locked)

        # Condition 7: FROZEN-MEMBER-DEP (single-package only)
        _check_member_provenance_in_single_package(locked)

        # Condition 3: FROZEN-LOCKED-VERSION-UNPARSEABLE
        parsed = parse_version(locked.version)
        if parsed is None:
            raise MilpaError(
                FROZEN_LOCKED_VERSION_UNPARSEABLE,
                f"dep {locked.name!r}: locked version {locked.version!r} is not "
                f"a valid semver string; re-run 'milpa fetch' to regenerate",
                name=locked.name,
                version=locked.version,
            )

        # Condition 4: FROZEN-CONSTRAINT-UNSATISFIED (for named deps)
        # S1 (#142): also find the manifest dep via alias (d.name in locked.aliases).
        manifest_dep = next(
            (d for d in all_deps if d.name == locked.name or d.name in locked.aliases),
            None,
        )
        if manifest_dep is not None and isinstance(manifest_dep, NamedDep):
            vs = (
                manifest_dep.constraint_set
                if manifest_dep.constraint_set is not None
                else VersionSet.full()
            )
            if not vs.contains(parsed):
                raise MilpaError(
                    FROZEN_CONSTRAINT_UNSATISFIED,
                    f"dep {locked.name!r}: locked version {locked.version!r} does not "
                    f"satisfy manifest constraint {manifest_dep.constraint!r}; "
                    f"re-run 'milpa fetch' to regenerate the lockfile",
                    name=locked.name,
                    version=locked.version,
                    constraint=manifest_dep.constraint,
                )

        # Condition 5: FROZEN-IDENTITY-NOT-IN-STORE
        if locked.identity is not None and not env.store.contains(locked.identity):
            raise MilpaError(
                FROZEN_IDENTITY_NOT_IN_STORE,
                f"dep {locked.name!r}: identity {locked.identity!r} is not in "
                f"the CAS; run 'milpa fetch' to re-download",
                name=locked.name,
                identity=locked.identity,
            )

    # All preconditions passed — reconstruct the graph.
    # B-nimcfg: use rebuild_deps_view (SSOT) to create canonical + alias symlinks
    # and remove stale entries.  The old per-dep link() calls are replaced by the
    # atomic rebuild (no partial/stale residue after this point).
    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        resolved.append(_reconstruct_from_locked(locked))

    graph = ResolvedGraph(deps=tuple(resolved))
    from milpa.resolver import rebuild_deps_view
    rebuild_deps_view(graph, deps_dir, env.store)
    return graph


# ---------------------------------------------------------------------------
# Public: resolve_workspace_frozen
# ---------------------------------------------------------------------------


def resolve_workspace_frozen(
    workspace: LoadedWorkspace,
    lockfile: Lockfile,
    env: MilpaEnv,
    deps_dir: Path,
    *,
    profile: object = None,
    cli_seed: frozenset[str] | None = None,
) -> ResolvedGraph:
    """Reconstruct a workspace ``ResolvedGraph`` from a shared lockfile (no fetch).

    Checks the workspace-specific ``FROZEN-*`` preconditions from
    ``resolver-semantics.md`` §7.1:

    - Condition 1: FROZEN-STRATEGY-MISMATCH (BOTH paths).
    - Condition 8: FROZEN-MEMBER-NOT-IN-WORKSPACE.
    - Condition 9: FROZEN-MEMBER-IDENTITY-DRIFT.

    (Conditions 2–5 apply to non-member deps. Conditions 6–7 do not apply
    to the workspace path — local and member provenance are valid here.)

    Parameters
    ----------
    workspace:
        The loaded workspace with members.
    lockfile:
        The previously-recorded shared lockfile.
    env:
        Injectable seams: ``store`` for CAS presence checks.
    deps_dir:
        Where to place external dep symlinks (``<root>/_deps/``).
    profile:
        Optional profile for platform/arch/nim/milpa predicate filtering.
    cli_seed:
        Optional workspace-root CLI active-flag seed.  When non-``None``,
        flag-gated member deps that are not active under this seed are
        silently skipped in the manifest-vs-lock alignment check — a flag-
        excluded dep should not trigger ``FROZEN-MANIFEST-DEP-NOT-IN-LOCK``.
        The ``FROZEN-ACTIVE-FLAGS-MISMATCH`` check (which runs BEFORE this
        function is called from the frozen CLI path) handles the mismatch
        case; this filter prevents the wrong slug from firing.
    """
    from milpa.resolver import FilterContext, filter_manifest  # avoid circular import

    # Condition 1: FROZEN-STRATEGY-MISMATCH (C3b: baseline = the workspace
    # root manifest's effective ``resolution { strategy }``, not the
    # hardcoded literal — root-only, same root-authority model as
    # index-trust/entry-trust).
    _baseline_strategy = _frozen_baseline_strategy(workspace.workspace_manifest)
    if lockfile.strategy != _baseline_strategy:
        raise MilpaError(
            FROZEN_STRATEGY_MISMATCH,
            f"lockfile strategy {lockfile.strategy!r} does not match "
            f"the requested strategy {_baseline_strategy!r}; re-run 'milpa fetch' "
            f"with the desired strategy to regenerate the lockfile",
            lockfile_strategy=lockfile.strategy,
            requested_strategy=_baseline_strategy,
        )

    # D5: FROZEN-EXCLUDE-NEWER-MISMATCH (baseline = the workspace root
    # manifest's effective ``resolution { exclude-newer }`` — root-only,
    # same root-authority model as strategy above).
    _baseline_exclude_newer = _frozen_baseline_exclude_newer(workspace.workspace_manifest)
    if lockfile.exclude_newer != _baseline_exclude_newer:
        raise MilpaError(
            FROZEN_EXCLUDE_NEWER_MISMATCH,
            f"lockfile exclude-newer {lockfile.exclude_newer!r} does not match "
            f"the requested exclude-newer {_baseline_exclude_newer!r}; re-run "
            f"'milpa fetch' with the desired exclude-newer to regenerate the lockfile",
            lockfile_exclude_newer=lockfile.exclude_newer,
            requested_exclude_newer=_baseline_exclude_newer,
        )

    # S1 (#142): alias-aware lookup — maps canonical name AND every alias to
    # the canonical LockedDep.  Replaces the bare {d.name: d} dict.
    locked_index = _locked_index(lockfile.deps)

    # Conditions 2-4: per-member manifest alignment (mirrors Rust check_manifest_alignment).
    # S2 (RFC: workspace-completion §3.A): filter member deps via FilterContext BEFORE
    # the "dep not in lock" check.  A flag-excluded dep must not fire
    # FROZEN-MANIFEST-DEP-NOT-IN-LOCK — only FROZEN-ACTIVE-FLAGS-MISMATCH (raised by
    # the caller) is the correct slug for a features-vs-lock disagreement.
    for member in workspace.members:
        _frozen_ctx = FilterContext.build(
            member.manifest, profile, cli_seed=cli_seed
        )
        filtered_member_manifest = filter_manifest(member.manifest, _frozen_ctx)
        all_member_deps = list(filtered_member_manifest.deps) + list(filtered_member_manifest.dev_deps)
        for dep in all_member_deps:
            # MemberDep entries are workspace-topology edges validated by
            # conditions 9 (FROZEN-MEMBER-NOT-IN-WORKSPACE) and 10
            # (FROZEN-MEMBER-IDENTITY-DRIFT) on the lockfile side.  Including
            # them here would fire FROZEN-MANIFEST-DEP-NOT-IN-LOCK with a
            # misleading "dep '<name>' has no entry in lockfile" message that
            # looks like a missing external dep (F6 fix).
            if isinstance(dep, MemberDep):
                continue
            # Condition 2: FROZEN-MANIFEST-DEP-NOT-IN-LOCK
            # S1 (#142): alias-aware lookup.
            # C1: include namespace in DepKey for qualified deps.
            _dep_ns = getattr(dep, "namespace", None)
            _dep_key_ws = DepKey(name=dep.name, namespace=_dep_ns)
            if _dep_key_ws not in locked_index:
                raise MilpaError(
                    FROZEN_MANIFEST_DEP_NOT_IN_LOCK,
                    f"member {member.manifest.name!r}: dep {dep.name!r} has no entry "
                    f"in the lockfile; run 'milpa fetch' to regenerate the lockfile",
                    name=dep.name,
                )
            locked = locked_index[_dep_key_ws]
            # Condition 3: FROZEN-LOCKED-VERSION-UNPARSEABLE
            parsed = parse_version(locked.version)
            if parsed is None:
                raise MilpaError(
                    FROZEN_LOCKED_VERSION_UNPARSEABLE,
                    f"dep {dep.name!r}: locked version {locked.version!r} is not "
                    f"a valid semver string; re-run 'milpa fetch' to regenerate",
                    name=dep.name,
                    version=locked.version,
                )
            # Condition 4: FROZEN-CONSTRAINT-UNSATISFIED (named deps only)
            if isinstance(dep, NamedDep):
                vs = (
                    dep.constraint_set
                    if dep.constraint_set is not None
                    else VersionSet.full()
                )
                if not vs.contains(parsed):
                    raise MilpaError(
                        FROZEN_CONSTRAINT_UNSATISFIED,
                        f"dep {dep.name!r}: locked version {locked.version!r} does not "
                        f"satisfy manifest constraint {dep.constraint!r}; "
                        f"re-run 'milpa fetch' to regenerate the lockfile",
                        name=dep.name,
                        version=locked.version,
                        constraint=dep.constraint,
                    )

    members_by_name = {m.manifest.name: m for m in workspace.members}

    # Per-dep checks
    for locked in lockfile.deps:
        # Determine if this locked dep is a member or an external dep.
        is_member = any(
            isinstance(p, MemberProvenanceRecord) for p in locked.provenances
        )

        if is_member:
            # Condition 8: FROZEN-MEMBER-NOT-IN-WORKSPACE
            if locked.name not in members_by_name:
                raise MilpaError(
                    FROZEN_MEMBER_NOT_IN_WORKSPACE,
                    f"lockfile references workspace member {locked.name!r} but "
                    f"the workspace does not declare such a member; "
                    f"re-run 'milpa fetch' to regenerate the lockfile",
                    name=locked.name,
                )

            # Condition 9: FROZEN-MEMBER-IDENTITY-DRIFT
            member = members_by_name[locked.name]
            actual_identity = compute_content_hash(member.abs_dir)
            if locked.identity is not None and locked.identity != actual_identity:
                raise MilpaError(
                    FROZEN_MEMBER_IDENTITY_DRIFT,
                    f"workspace member {locked.name!r}: on-disk identity "
                    f"{actual_identity!r} does not match lockfile pin "
                    f"{locked.identity!r}; re-run 'milpa fetch' to regenerate",
                    name=locked.name,
                    locked_identity=locked.identity,
                    actual_identity=actual_identity,
                )
        else:
            # External dep: check identity-in-store (condition 5).
            if locked.identity is not None and not env.store.contains(locked.identity):
                raise MilpaError(
                    FROZEN_IDENTITY_NOT_IN_STORE,
                    f"dep {locked.name!r}: identity {locked.identity!r} is not in "
                    f"the CAS; run 'milpa fetch' to re-download",
                    name=locked.name,
                    identity=locked.identity,
                )

    # All preconditions passed — reconstruct the graph.
    # B-nimcfg: use rebuild_deps_view (SSOT) for atomic _deps/ rebuild
    # (canonical + alias symlinks, stale removal).
    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        resolved.append(_reconstruct_from_locked(locked))

    graph = ResolvedGraph(deps=tuple(resolved))
    from milpa.resolver import rebuild_deps_view
    rebuild_deps_view(graph, deps_dir, env.store)
    return graph
