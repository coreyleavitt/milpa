"""Frozen resolver — lockfile-backed graph reconstruction (NO fetcher invocation).

Implements ``resolve_frozen`` and ``resolve_workspace_frozen`` per
``spec/resolver-semantics.md`` §7 and §7.1.

The frozen path NEVER invokes a fetcher.  It reconstructs a ``ResolvedGraph``
from the lockfile and the CAS alone.  This is enforced by signature:
``resolve_frozen`` takes ``MilpaEnv`` but NOT ``ResolveParams`` — there is no
``strategy`` / ``max_parallel`` / ``prior`` available here (RFC §4.4 NORMATIVE).

The 10 resolver-level ``FROZEN-*`` preconditions (§7.1) are:

1. ``FROZEN-STRATEGY-MISMATCH`` — lockfile.strategy != default requested strategy.
2. ``FROZEN-MANIFEST-DEP-NOT-IN-LOCK`` — manifest dep has no lockfile entry.
3. ``FROZEN-LOCKED-VERSION-UNPARSEABLE`` — locked version not parseable.
4. ``FROZEN-CONSTRAINT-UNSATISFIED`` — locked version doesn't satisfy named constraint.
5. ``FROZEN-IDENTITY-NOT-IN-STORE`` — dep identity absent from CAS.
6. ``FROZEN-LEGACY-REGISTRY-PROVENANCE`` — dep has ``kind "registry"`` (BOTH paths).
7. ``FROZEN-LOCAL-DEP`` — dep has local provenance (single-package path only).
8. ``FROZEN-MEMBER-DEP`` — locked dep has member provenance (single-package raises).
9. ``FROZEN-MEMBER-NOT-IN-WORKSPACE`` — lockfile member not in workspace members.
10. ``FROZEN-MEMBER-IDENTITY-DRIFT`` — member on-disk hash ≠ lockfile pin.

The 2 CLI-level guards (``FROZEN-NO-LOCKFILE``, ``FROZEN-NO-CAS``) are raised in
``cli.py`` BEFORE the resolve path is entered (RFC §8 scope clarification).

Public surface
--------------
``resolve_frozen(manifest, lockfile, env, deps_dir) -> ResolvedGraph``
    Reconstruct the graph for a single-package project from a lockfile.
    No solver, no network.

``resolve_workspace_frozen(workspace, lockfile, env, deps_dir) -> ResolvedGraph``
    Reconstruct the graph for a workspace from a shared lockfile.

Spec: spec/resolver-semantics.md §7 and §7.1 (the closed list of 10 preconditions).
"""

from __future__ import annotations

from pathlib import Path

from milpa.context import MilpaEnv
from milpa.errors import (
    FROZEN_CONSTRAINT_UNSATISFIED,
    FROZEN_IDENTITY_NOT_IN_STORE,
    FROZEN_LEGACY_REGISTRY_PROVENANCE,
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
    RegistryProvenanceRecord,
    ResolvedDep,
    ResolvedGraph,
)
from milpa.manifest import Manifest, NamedDep
from milpa.version import VersionSet, parse_version
from milpa.workspace import LoadedWorkspace

# The default strategy string used when no explicit strategy is passed.
# Frozen path checks: lockfile.strategy must match "maxver" (the default for
# the frozen command — no strategy param is available to override it).
_DEFAULT_STRATEGY = "maxver"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _check_legacy_registry_provenance(locked: LockedDep) -> None:
    """Condition 6 (BOTH paths): FROZEN-LEGACY-REGISTRY-PROVENANCE.

    Raises if any provenance record has kind ``registry`` (pre-#97 provenance).
    """
    for prov in locked.provenances:
        if isinstance(prov, RegistryProvenanceRecord):
            raise MilpaError(
                FROZEN_LEGACY_REGISTRY_PROVENANCE,
                f"dep {locked.name!r} uses legacy 'registry' provenance; "
                f"re-resolve via tianguis to regenerate the lockfile",
                name=locked.name,
            )


def _check_local_provenance(locked: LockedDep) -> None:
    """Condition 7 (single-package path only): FROZEN-LOCAL-DEP.

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
    """Condition 8 (single-package path only): FROZEN-MEMBER-DEP.

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
    """Reconstruct a ResolvedDep from a LockedDep (frozen path reconstruction)."""
    prov_record = locked.provenances[0] if locked.provenances else None
    return ResolvedDep(
        name=locked.name,
        identity=locked.identity,
        version=locked.version,
        src_dir=locked.src_dir,
        requires=locked.requires,
        provenance=prov_record,
        active_flags=locked.active_flags,
        self_mirrors=locked.self_mirrors,
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
    conditions 1–5, 6 (BOTH paths), 7, 8.

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
    # Condition 1: FROZEN-STRATEGY-MISMATCH
    if lockfile.strategy != _DEFAULT_STRATEGY:
        raise MilpaError(
            FROZEN_STRATEGY_MISMATCH,
            f"lockfile strategy {lockfile.strategy!r} does not match "
            f"the requested strategy {_DEFAULT_STRATEGY!r}; re-run 'milpa fetch' "
            f"with the desired strategy to regenerate the lockfile",
            lockfile_strategy=lockfile.strategy,
            requested_strategy=_DEFAULT_STRATEGY,
        )

    locked_by_name = {d.name: d for d in lockfile.deps}

    # Condition 2: FROZEN-MANIFEST-DEP-NOT-IN-LOCK (for each manifest dep)
    all_deps = list(manifest.deps) + list(manifest.dev_deps)
    for dep in all_deps:
        if dep.name not in locked_by_name:
            raise MilpaError(
                FROZEN_MANIFEST_DEP_NOT_IN_LOCK,
                f"manifest dep {dep.name!r} has no entry in the lockfile; "
                f"run 'milpa fetch' to regenerate the lockfile",
                name=dep.name,
            )

    # Per-dep checks (3–8) for each locked dep
    for locked in lockfile.deps:
        # Condition 6: FROZEN-LEGACY-REGISTRY-PROVENANCE (BOTH paths)
        _check_legacy_registry_provenance(locked)

        # Condition 7: FROZEN-LOCAL-DEP (single-package only)
        _check_local_provenance(locked)

        # Condition 8: FROZEN-MEMBER-DEP (single-package only)
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
        manifest_dep = next(
            (d for d in all_deps if d.name == locked.name),
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
    # Symlink CAS entries into deps_dir.
    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        if locked.identity is not None:
            link_target = deps_dir / locked.name
            if not link_target.exists():
                env.store.link(locked.identity, link_target)
        resolved.append(_reconstruct_from_locked(locked))

    return ResolvedGraph(deps=tuple(resolved))


# ---------------------------------------------------------------------------
# Public: resolve_workspace_frozen
# ---------------------------------------------------------------------------


def resolve_workspace_frozen(
    workspace: LoadedWorkspace,
    lockfile: Lockfile,
    env: MilpaEnv,
    deps_dir: Path,
) -> ResolvedGraph:
    """Reconstruct a workspace ``ResolvedGraph`` from a shared lockfile (no fetch).

    Checks the workspace-specific ``FROZEN-*`` preconditions from
    ``resolver-semantics.md`` §7.1:

    - Condition 1: FROZEN-STRATEGY-MISMATCH (BOTH paths).
    - Condition 6: FROZEN-LEGACY-REGISTRY-PROVENANCE (BOTH paths).
    - Condition 9: FROZEN-MEMBER-NOT-IN-WORKSPACE.
    - Condition 10: FROZEN-MEMBER-IDENTITY-DRIFT.

    (Conditions 2–5 apply to non-member deps. Conditions 7–8 do not apply
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
    """
    # Condition 1: FROZEN-STRATEGY-MISMATCH
    if lockfile.strategy != _DEFAULT_STRATEGY:
        raise MilpaError(
            FROZEN_STRATEGY_MISMATCH,
            f"lockfile strategy {lockfile.strategy!r} does not match "
            f"the requested strategy {_DEFAULT_STRATEGY!r}; re-run 'milpa fetch' "
            f"with the desired strategy to regenerate the lockfile",
            lockfile_strategy=lockfile.strategy,
            requested_strategy=_DEFAULT_STRATEGY,
        )

    members_by_name = {m.manifest.name: m for m in workspace.members}

    # Per-dep checks
    for locked in lockfile.deps:
        # Condition 6: FROZEN-LEGACY-REGISTRY-PROVENANCE (BOTH paths)
        _check_legacy_registry_provenance(locked)

        # Determine if this locked dep is a member or an external dep.
        is_member = any(
            isinstance(p, MemberProvenanceRecord) for p in locked.provenances
        )

        if is_member:
            # Condition 9: FROZEN-MEMBER-NOT-IN-WORKSPACE
            if locked.name not in members_by_name:
                raise MilpaError(
                    FROZEN_MEMBER_NOT_IN_WORKSPACE,
                    f"lockfile references workspace member {locked.name!r} but "
                    f"the workspace does not declare such a member; "
                    f"re-run 'milpa fetch' to regenerate the lockfile",
                    name=locked.name,
                )

            # Condition 10: FROZEN-MEMBER-IDENTITY-DRIFT
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
    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        is_member = any(
            isinstance(p, MemberProvenanceRecord) for p in locked.provenances
        )
        if not is_member and locked.identity is not None:
            link_target = deps_dir / locked.name
            if not link_target.exists():
                env.store.link(locked.identity, link_target)
        resolved.append(_reconstruct_from_locked(locked))

    return ResolvedGraph(deps=tuple(resolved))
