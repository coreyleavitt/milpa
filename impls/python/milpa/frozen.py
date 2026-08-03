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

from milpa.binding import DEFAULT_REGISTRY_ALIAS, Claim, reconcile_root_claims
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
    FROZEN_REGISTRY_ALIAS_UNRESOLVED,
    FROZEN_SOURCE_ID_MISMATCH,
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
from milpa.manifest import Manifest, MemberDep, MemberTarget, NamedDep
from milpa.registry import EntryAttestation, Index
from milpa.source_id import RegistrySourceId, SourceId, format_source_id
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


def _source_id_matches_declared(declared: SourceId, locked: SourceId) -> bool:
    """Field-wise comparison for ``FROZEN-SOURCE-ID-MISMATCH`` (RFC
    origin-as-identity.md §7.1 D2).

    Plain frozen-dataclass equality for every kind EXCEPT ``RegistrySourceId``
    with an unqualified (bare) manifest declaration: the frozen path has no
    live tianguis index to resolve a bare name's real namespace (unlike a
    live ``resolve()``, which calls ``resolved_registry_namespace``), so the
    *namespace* component is not compared when the manifest declaration
    itself carried no explicit qualifier — only the registry alias and name
    (both knowable without an index). An EXPLICITLY-qualified declaration
    (``ns/name``) still gets a full three-field comparison.
    """
    if isinstance(declared, RegistrySourceId) and isinstance(locked, RegistrySourceId):
        if declared.registry != locked.registry or declared.name != locked.name:
            return False
        if declared.namespace is not None and declared.namespace != locked.namespace:
            return False
        return True
    return declared == locked


def _check_source_id_preconditions(
    declared_deps: "list[object]",
    overrides: "object",
    lockfile_deps: "tuple[LockedDep, ...]",
) -> None:
    """``FROZEN-REGISTRY-ALIAS-UNRESOLVED`` (checked FIRST, short-circuits)
    + ``FROZEN-SOURCE-ID-MISMATCH`` (declared-AFTER-override) — RFC
    origin-as-identity.md §7.1 D2/D3.

    Scope (normative): only locked deps that correspond to a ROOT-
    authoritative claim (an ordinary manifest dep declaration, or an
    ``overrides {}`` target) are checked — a purely transitive dep's "real"
    declaration lives inside another dep's fetched manifest, which the
    frozen path never re-reads (it never fetches), so there is nothing to
    compare it against here. Workspace-member and standalone-root-self
    entries (``MemberSourceId``) are likewise skipped — W1-W5 conflict-free-
    by-construction, no manifest "declared origin" concept applies.

    Reuses ``binding.reconcile_root_claims`` — the SAME override-application
    helper ``BindingResolver.__init__`` uses — so an ``overrides {}``-
    redirected dep is compared against its override TARGET, never its raw
    declaration (a naive check would false-positive on every project using
    ``overrides {}``, the very bridge the RFC promotes). No live tianguis
    index is needed (or used) here: registry-namespace resolution for a bare
    name would require one, so ``_source_id_matches_declared`` skips that
    ONE component for an unqualified declaration rather than passing a real
    index through the frozen path (which never fetches / never loads one).
    """
    declared_claims: "list[Claim]" = reconcile_root_claims(
        declared_deps, list(overrides), index=Index()  # type: ignore[arg-type]
    )
    declared_by_key: "dict[DepKey, SourceId]" = {
        DepKey.from_solver_var(c.name): c.source_id for c in declared_claims
    }

    for locked in lockfile_deps:
        locked_sid = locked.source_id
        if locked_sid is None:
            continue  # pre-S5 lockfile — nothing to check (forward-compat)

        # D3: FROZEN-REGISTRY-ALIAS-UNRESOLVED is checked FIRST and
        # short-circuits — an unresolved alias must never be misreported as
        # a coordinate mismatch (the comparison below is not even attempted).
        if (
            isinstance(locked_sid, RegistrySourceId)
            and locked_sid.registry != DEFAULT_REGISTRY_ALIAS
        ):
            raise MilpaError(
                FROZEN_REGISTRY_ALIAS_UNRESOLVED,
                f"dep {locked.name!r}: lockfile references registry alias "
                f"{locked_sid.registry!r}, which is not configured on this "
                f"machine (known: {DEFAULT_REGISTRY_ALIAS!r}); the source-id "
                f"coordinate cannot be verified — configure the alias or "
                f"re-run 'milpa fetch'",
                name=locked.name,
                alias=locked_sid.registry,
            )

        key = DepKey(name=locked.name, namespace=locked.namespace)
        declared_sid = declared_by_key.get(key)
        if declared_sid is None:
            continue  # not a root-authoritative claim at this scope — skip

        if not _source_id_matches_declared(declared_sid, locked_sid):
            raise MilpaError(
                FROZEN_SOURCE_ID_MISMATCH,
                f"dep {locked.name!r}: manifest declares "
                f"{format_source_id(declared_sid)} but the lockfile records "
                f"{format_source_id(locked_sid)} — the declared origin was "
                f"edited without re-fetching; run 'milpa fetch' to "
                f"regenerate the lockfile",
                name=locked.name,
                declared=format_source_id(declared_sid),
                locked=format_source_id(locked_sid),
            )

    # A ``RegistryTarget`` override (`pkg "old-fork" named="widget"
    # namespace="acme"`) redirects the subject to a DIFFERENT coordinate, so
    # the locked dep is stored under the TARGET coordinate (widget/acme), not
    # the subject — the subject-keyed loop above can never match it, and the
    # FROZEN-SOURCE-ID-MISMATCH check was structurally unreachable for this one
    # target kind. Detect an edited-without-refetch RegistryTarget override
    # from the DECLARED side: the coordinate the override CURRENTLY resolves to
    # MUST appear among the locked source-ids; if it doesn't, the target was
    # changed since the lockfile was generated. (Git/Local/Tarball/Oci override
    # targets keep the subject's own name on the locked dep, so the loop above
    # already covers them; only RegistryTarget renames the dep.)
    locked_reg_coords = {
        (d.source_id.namespace, d.source_id.name)
        for d in lockfile_deps
        if isinstance(d.source_id, RegistrySourceId)
    }
    for claim in declared_claims:
        if not claim.claimant.startswith("override:"):
            continue
        csid = claim.source_id
        if not isinstance(csid, RegistrySourceId):
            continue  # Git/Local/Tarball/Oci override → covered by the loop above
        if (csid.namespace, csid.name) not in locked_reg_coords:
            raise MilpaError(
                FROZEN_SOURCE_ID_MISMATCH,
                f"override redirects to {format_source_id(csid)}, which is not "
                f"present in the lockfile — the `overrides {{}}` target was "
                f"edited without re-fetching; run 'milpa fetch' to regenerate "
                f"the lockfile",
                name=csid.name,
                declared=format_source_id(csid),
            )


def check_source_id_preconditions_standalone(
    manifest: Manifest, lockfile_deps: "tuple[LockedDep, ...]"
) -> None:
    """Public SSOT wrapper for a standalone (single-package) project — used
    by both ``resolve_frozen`` and ``milpa verify`` (``cli.cmd_verify``), so
    the two entry points cannot structurally drift on this check.
    """
    all_deps = list(manifest.deps) + list(manifest.dev_deps)
    _check_source_id_preconditions(
        all_deps,
        [ov for ov in manifest.overrides if not isinstance(ov.target, MemberTarget)],
        lockfile_deps,
    )


def check_source_id_preconditions_workspace(
    workspace: LoadedWorkspace, lockfile_deps: "tuple[LockedDep, ...]"
) -> None:
    """Public SSOT wrapper for a workspace — used by both
    ``resolve_workspace_frozen`` and ``milpa verify`` (``cli.cmd_verify``).
    """
    members_by_name = {m.manifest.name: m for m in workspace.members}
    ws_declared_deps: list[object] = []
    for member in workspace.members:
        for wsd in list(member.manifest.deps) + list(member.manifest.dev_deps):
            if wsd.name in members_by_name or isinstance(wsd, MemberDep):
                continue
            ws_declared_deps.append(wsd)
    _check_source_id_preconditions(
        ws_declared_deps, workspace.workspace_manifest.overrides, lockfile_deps
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
        # A5: carry the sibling declared-version source straight through —
        # frozen reconstruction re-derives nothing (no solve, no re-fetch).
        declared_version_source=locked.declared_version_source,
        # RFC origin-as-identity.md §4.1/§4.4/§7 (S5): the frozen path now
        # threads the lockfile's own structured ``source_id`` straight onto
        # the reconstructed ResolvedDep — no re-derivation, no parsing, just
        # a direct passthrough of the typed struct already on LockedDep.
        # This is what lets check_directory_slot_collisions and milpa verify's
        # offline attestation-subject reconstruction use format_source_id
        # (the typed formatter) on the frozen path too, not just fresh
        # resolves (closes the "until a later slice populates it there too"
        # gap the S3a docstring on ResolvedDep.source_id flagged).
        source_id=locked.source_id,
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

    # RFC origin-as-identity.md §7.1 D2/D3 (S5): FROZEN-REGISTRY-ALIAS-
    # UNRESOLVED (checked first) + FROZEN-SOURCE-ID-MISMATCH (declared-
    # AFTER-override). SSOT wrapper also used by `milpa verify` (cli.py).
    check_source_id_preconditions_standalone(manifest, lockfile.deps)

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

    # RFC origin-as-identity.md §4.6 (S6 "F4" frozen-path reachability + S7):
    # the import-slot check runs here too — no BindingResolver protects a
    # lockfile reconstructed straight off disk, so this check must not wait
    # for S5's structured on-disk source. check_import_slot_collisions runs
    # the S6 directory-slot floor first (see lockfile.py's
    # check_directory_slot_collisions docstring for why it needs no new
    # source_id plumbing to cover this path), then the manifest_declared-
    # fidelity symbol-level scan over the SAME CAS store rebuild_deps_view
    # materializes from — see live_symbol_provider()'s docstring for why
    # tree_scanned fidelity is not (yet) in the zero-config default.
    from milpa.import_slot import check_import_slot_collisions, live_symbol_provider
    check_import_slot_collisions(graph, live_symbol_provider(), store=env.store)

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

    # RFC origin-as-identity.md §7.1 D2/D3 (S5): FROZEN-REGISTRY-ALIAS-
    # UNRESOLVED (checked first) + FROZEN-SOURCE-ID-MISMATCH (declared-
    # AFTER-override). SSOT wrapper also used by `milpa verify` (cli.py).
    check_source_id_preconditions_workspace(workspace, lockfile.deps)

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

    # RFC origin-as-identity.md §4.6 (S6 "F4" + S7): see resolve_frozen's
    # identical hook above (manifest_declared fidelity only, live_symbol_
    # provider()'s docstring has the why).
    from milpa.import_slot import check_import_slot_collisions, live_symbol_provider
    check_import_slot_collisions(graph, live_symbol_provider(), store=env.store)

    from milpa.resolver import rebuild_deps_view
    rebuild_deps_view(graph, deps_dir, env.store)
    return graph
