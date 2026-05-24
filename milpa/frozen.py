"""Lockfile-driven frozen resolve (#36).

When milpa.lock pins every dep's identity and the global CAS already
holds those bytes, we can skip the entire fetch + parse + solve cycle:
just symlink _deps/<name>/ into the CAS and rebuild a ResolvedGraph
from the lockfile's records.

Falls back via NotFrozen on any precondition failure.
"""

from pathlib import Path

from .cas import CAStore
from .lockfile import (
    LocalProvenanceRecord,
    Lockfile,
    MemberProvenanceRecord,
)
from .manifest import Manifest, NamedDep
from .resolver import ResolvedDep, ResolvedGraph
from .solver import Strategy, VersionSet


class NotFrozen(Exception):
    """The frozen fast path can't be used. The message carries a
    specific reason; the resolver falls through to the slow path
    unless --frozen was set."""


def resolve_frozen(
    manifest: Manifest,
    *,
    lockfile: Lockfile,
    deps_dir: Path,
    store: CAStore,
    strategy: Strategy = Strategy.MAXVER,
) -> ResolvedGraph:
    """Reconstruct a ResolvedGraph from manifest + lockfile + CAS.

    No network, no fetcher invocation. Raises NotFrozen with a
    specific reason if any precondition fails.
    """
    _check_strategy(strategy, lockfile)
    locked_by_name = {d.name: d for d in lockfile.deps}
    _check_manifest_alignment(
        manifest, locked_by_name, context_prefix="",
    )

    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        # In single-package mode, MemberProvenance / LocalProvenance are
        # both "editable, always re-resolve."
        first = locked.provenances[0] if locked.provenances else None
        if isinstance(first, MemberProvenanceRecord):
            raise NotFrozen(
                f"dep {locked.name!r} is a workspace member — "
                f"members always re-resolve"
            )
        if isinstance(first, LocalProvenanceRecord):
            raise NotFrozen(
                f"dep {locked.name!r} has a local provenance — "
                f"editable trees always re-resolve"
            )
        _link_external(locked, deps_dir, store)
        resolved.append(_resolved_from_locked(locked))
    return ResolvedGraph(deps=tuple(resolved))


def resolve_workspace_frozen(
    workspace,
    *,
    lockfile: Lockfile,
    deps_dir: Path,
    store: CAStore,
    strategy: Strategy = Strategy.MAXVER,
) -> ResolvedGraph:
    """Workspace analog of resolve_frozen (#78).

    External deps come from the CAS (symlinked into deps_dir/<name>);
    members are verified against their on-disk content_hash and stay
    in their declared workspace locations (no symlink under _deps/).

    NotFrozen reasons: strategy mismatch, member identity drift,
    member-removed-from-workspace, manifest-vs-lockfile drift,
    external CAS miss, or any non-member LocalProvenanceRecord (those
    are always editable and re-resolve)."""
    from .identity import compute_content_hash as _compute_hash

    _check_strategy(strategy, lockfile)
    locked_by_name = {d.name: d for d in lockfile.deps}
    members_by_name = {m.name: m for m in workspace.members}

    for member in workspace.members:
        _check_manifest_alignment(
            member.manifest, locked_by_name,
            context_prefix=f"member {member.name!r}: ",
        )

    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        first = locked.provenances[0] if locked.provenances else None

        if isinstance(first, MemberProvenanceRecord):
            member = members_by_name.get(first.name)
            if member is None:
                raise NotFrozen(
                    f"lockfile references workspace member "
                    f"{first.name!r} that is not in the current "
                    f"workspace"
                )
            actual = _compute_hash(member.directory)
            if actual != locked.identity:
                raise NotFrozen(
                    f"member {first.name!r}: on-disk identity "
                    f"{actual[:23]}... differs from lockfile pin "
                    f"{(locked.identity or '<none>')[:23]}..."
                )
            resolved.append(_resolved_from_locked(locked))
            continue

        if isinstance(first, LocalProvenanceRecord):
            raise NotFrozen(
                f"dep {locked.name!r} has a local provenance — "
                f"editable trees always re-resolve"
            )

        _link_external(locked, deps_dir, store)
        resolved.append(_resolved_from_locked(locked))

    return ResolvedGraph(deps=tuple(resolved))


# ---------------------------------------------------------------------------
# Shared frozen-precondition helpers
# ---------------------------------------------------------------------------


def _check_strategy(strategy: Strategy, lockfile: Lockfile) -> None:
    if str(strategy) != lockfile.strategy:
        raise NotFrozen(
            f"strategy mismatch: lockfile built with "
            f"{lockfile.strategy!r}, requested {str(strategy)!r}"
        )


def _check_manifest_alignment(
    manifest: Manifest,
    locked_by_name: dict,
    *,
    context_prefix: str,
) -> None:
    """Every manifest dep must have a lockfile entry; NamedDep
    constraints must still be satisfied by the locked version.
    `context_prefix` is prepended to error messages so workspace
    failures name the offending member."""
    for mdep in manifest.deps:
        if mdep.name not in locked_by_name:
            raise NotFrozen(
                f"{context_prefix}manifest dep {mdep.name!r} has no "
                f"lockfile entry (re-run `milpa fetch`)"
            )
        if isinstance(mdep, NamedDep) and mdep.constraint:
            locked = locked_by_name[mdep.name]
            locked_version = _parse_version(locked.version)
            vset = VersionSet.from_constraint(mdep.constraint)
            if not vset.contains(locked_version):
                raise NotFrozen(
                    f"{context_prefix}dep {mdep.name!r}: locked "
                    f"version {locked.version} no longer satisfies "
                    f"manifest constraint {mdep.constraint!r}"
                )


def _link_external(locked, deps_dir: Path, store: CAStore) -> None:
    """Link an external (CAS-resident) dep into deps_dir. Raises
    NotFrozen if its identity isn't in the store."""
    if not locked.identity or not store.contains(locked.identity):
        raise NotFrozen(
            f"dep {locked.name!r} identity "
            f"{(locked.identity or '<none>')[:23]}... not in store"
        )
    store.link(locked.identity, deps_dir / locked.name)


def _resolved_from_locked(locked) -> ResolvedDep:
    """Convert a LockedDep into a ResolvedDep, deriving source / ref /
    sha / tag from the first provenance."""
    return ResolvedDep(
        name=locked.name,
        source=_source_from_provenance(locked.provenances[0]),
        ref=getattr(locked.provenances[0], "ref", None),
        tag=getattr(locked.provenances[0], "tag", None),
        sha=getattr(locked.provenances[0], "commit_sha", None),
        version=_parse_version(locked.version),
        identity=locked.identity,
        src_dir=locked.src_dir,
        requires=locked.requires,
    )


def _source_from_provenance(p) -> str:
    from .lockfile import (
        GitProvenanceRecord,
        LocalProvenanceRecord,
        MemberProvenanceRecord,
        RegistryProvenanceRecord,
        TarballProvenanceRecord,
    )
    if isinstance(p, GitProvenanceRecord):
        return p.url
    if isinstance(p, TarballProvenanceRecord):
        return f"tarball:{p.url}"
    if isinstance(p, LocalProvenanceRecord):
        return f"local:{p.path}"
    if isinstance(p, MemberProvenanceRecord):
        return f"member:{p.name}"
    if isinstance(p, RegistryProvenanceRecord):
        return f"registry:{p.name}"
    raise ValueError(f"unknown provenance kind {type(p).__name__}")


def _parse_version(s: str):
    parts = s.split(".")
    return tuple(int(x) for x in parts[:3]) + (0,) * (3 - len(parts[:3]))
