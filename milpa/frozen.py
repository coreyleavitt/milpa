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
    if str(strategy) != lockfile.strategy:
        raise NotFrozen(
            f"strategy mismatch: lockfile built with "
            f"{lockfile.strategy!r}, requested {str(strategy)!r}"
        )
    # Every manifest dep must have a lockfile entry — else the user
    # added something they haven't locked yet.
    locked_by_name = {d.name: d for d in lockfile.deps}
    for mdep in manifest.deps:
        if mdep.name not in locked_by_name:
            raise NotFrozen(
                f"manifest dep {mdep.name!r} has no lockfile entry "
                f"(re-run `milpa lock`)"
            )
        # Strict constraint re-check: if the manifest tightened a
        # NamedDep constraint, the locked version may no longer satisfy
        # it. Forcing a re-resolve preserves correctness when the user
        # edits constraints without re-locking.
        if isinstance(mdep, NamedDep) and mdep.constraint:
            locked = locked_by_name[mdep.name]
            locked_version = _parse_version(locked.version)
            vset = VersionSet.from_constraint(mdep.constraint)
            if not vset.contains(locked_version):
                raise NotFrozen(
                    f"dep {mdep.name!r}: locked version "
                    f"{locked.version} no longer satisfies manifest "
                    f"constraint {mdep.constraint!r}"
                )

    deps_dir.mkdir(parents=True, exist_ok=True)
    resolved: list[ResolvedDep] = []
    for locked in lockfile.deps:
        # Editable sources (local paths, workspace members) can change
        # between runs — never serve them from CAS even if identity hits.
        for p in locked.provenances:
            if isinstance(p, LocalProvenanceRecord):
                raise NotFrozen(
                    f"dep {locked.name!r} has a local provenance — "
                    f"editable trees always re-resolve"
                )
            if isinstance(p, MemberProvenanceRecord):
                raise NotFrozen(
                    f"dep {locked.name!r} is a workspace member — "
                    f"members always re-resolve"
                )
        if not locked.identity or not store.contains(locked.identity):
            raise NotFrozen(
                f"dep {locked.name!r} identity "
                f"{(locked.identity or '<none>')[:23]}... not in store"
            )
        store.link(locked.identity, deps_dir / locked.name)
        resolved.append(_resolved_from_locked(locked))
    return ResolvedGraph(deps=tuple(resolved))


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
