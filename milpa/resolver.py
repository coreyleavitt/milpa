"""Top-level resolver — manifest → fetch + parse + solve → ResolvedGraph.

The resolver eagerly walks the manifest's URL deps, fetches each into
`_deps/<name>/`, parses its `.nimble` for transitive requires, recurses
on URL transitive deps and resolves named transitive deps via the
registry. Once the candidate space is materialized, it hands a
`PackageProvider` to the solver and maps the solver's `{name: version}`
output back into a `ResolvedGraph` of `ResolvedDep` records.

Each `ResolvedDep` carries both identity (`content_hash`) and provenance
(`source`, `ref`, `tag`, `sha`) — see docs/identity-and-provenance.md.
For v0.x, the resolver dedups by `(URL, ref)` for efficiency; content-
hash-keyed dedup is Phase B work (#32).

Tests inject a fake fetcher so the integration runs without network or
git operations.
"""

from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
import shutil
import sys

from .fetchers import FetcherRegistry, default_registry
from .fetchers.git import GitProvenance, GitReceipt
from .fetchers.local import LocalProvenance
from .fetchers.tarball import TarballProvenance
from .identity import compute_content_hash
from .manifest import (
    LocalDep, Manifest, MemberDep, NamedDep, Override, TarballDep, UrlDep,
)
from .nimble_parse import NamedRequirement, UrlRequirement, parse_nimble
from .registry import (
    RegistryEntry,
    ResolvedRegistryDep,
    list_remote_tags,
    resolve_named,
)
from .solver import (
    PackageProvider,
    Strategy,
    Term,
    Version,
    VersionSet,
    solve,
)


class ResolverError(Exception):
    """Raised by resolve() / resolve_workspace() for structural problems
    surfaced during candidate-set construction (e.g. a `member "X"`
    reference to a name with no matching workspace member). Solver-
    level failures (unsatisfiable constraints) raise SolverError."""


@dataclass(frozen=True)
class ResolvedDep:
    name: str
    source: str           # URL or "registry:<name>"
    ref: str | None       # git ref originally requested (branch / tag / sha)
    tag: str | None       # tag name (registry deps only)
    sha: str | None       # resolved commit SHA
    version: Version
    identity: str | None   # multihash-encoded content hash (#34); was content_hash (#33)
    src_dir: str           # for nim.cfg --path emission
    requires: tuple[str, ...]  # names of direct deps
    active_flags: tuple[str, ...] = ()  # feature flags active on this dep (#23)
    # Per-flag explicit -d: overrides. Each entry: (flag_name, tuple of
    # -d: strings to emit). Flags not listed here use the convention
    # `-d:<dep_name>_<flag_name>`. Stored as a tuple of pairs so the
    # dataclass stays hashable and immutable (#23).
    flag_defines: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class ResolvedGraph:
    deps: tuple[ResolvedDep, ...]


# Sentinel version used for URL deps. URL deps have exactly one version
# (the resolved commit/content); the solver doesn't reason about their
# version space.
_URL_DEP_VERSION: Version = (0, 0, 1)


@dataclass
class _Candidate:
    """One concrete candidate the resolver discovered.

    Keyed by (package_name, version) in the resolver's internal map.
    Production resolver fills these by walking the manifest; tests can
    construct them directly.
    """
    name: str
    version: Version
    source: str                # URL or "registry:<name>"
    ref: str | None
    sha: str | None
    tag: str | None
    identity: str | None       # multihash-encoded (#34); was content_hash
    src_dir: str
    dep_terms: list[Term]      # for the solver
    requires_names: list[str]  # for ResolvedDep.requires


class _MaterializedProvider:
    """PackageProvider backed by the resolver's materialized candidate set.

    Two-phase population for content-hash dedup (#32):

    1. During BFS, workers produce candidates which are buffered via
       `record(c)`. The provider's `candidates` map is NOT populated
       during BFS — only after all candidates are collected.

    2. After BFS completes, `finalize(deps_dir)` partitions buffered
       candidates by content_hash, picks a deterministic canonical
       name (lexicographically earliest) per group, registers only
       canonicals in `candidates`, builds the alias map, and removes
       duplicate _deps/<name>/ directories from disk.

    Pre-existing synthetic candidates (__root__, workspace members)
    are added via `add()` directly — they bypass dedup and are in
    the provider from the start.

    Workspace members (source prefix 'member:') are exempt from
    content-hash dedup — workspace identity is by-name within the
    workspace, not interchangeable with external deps even if bytes
    happen to coincide.
    """

    def __init__(self) -> None:
        # name -> {version: _Candidate}
        self.candidates: dict[str, dict[Version, _Candidate]] = {}
        # Pending candidates collected during BFS; canonicalized in finalize()
        self._pending: list[_Candidate] = []
        # alias name → canonical name (populated by finalize())
        self.aliases: dict[str, str] = {}

    def add(self, c: _Candidate) -> None:
        """Add unconditionally — used for synthetic candidates (__root__,
        pre-registered workspace members). Production worker results
        go through `record()` + `finalize()`."""
        self.candidates.setdefault(c.name, {})[c.version] = c

    def record(self, c: _Candidate) -> None:
        """Buffer a fetched candidate; canonical-vs-alias decision is
        deferred to finalize() so it can be deterministic (lex-min
        name across all candidates sharing a content_hash) regardless
        of BFS arrival order."""
        self._pending.append(c)

    def finalize(self, deps_dir: Path) -> None:
        """Resolve all buffered candidates into the canonical provider
        state. Deterministic — same set of buffered candidates always
        produces the same canonical/alias mapping.

        Cleans up duplicate _deps/<name>/ directories on disk; only
        the canonical's directory survives.
        """
        by_hash: dict[str, list[_Candidate]] = {}
        no_hash: list[_Candidate] = []
        for c in self._pending:
            if c.identity is None or c.source.startswith("member:"):
                no_hash.append(c)
                continue
            by_hash.setdefault(c.identity, []).append(c)

        # Pass-through: no-hash + member candidates land as-is.
        for c in no_hash:
            self.candidates.setdefault(c.name, {})[c.version] = c

        # Content-hash groups: canonical is lex-min name (deterministic).
        for content_hash, group in by_hash.items():
            canonical = min(group, key=lambda c: c.name)
            self.candidates.setdefault(
                canonical.name, {}
            )[canonical.version] = canonical
            for c in group:
                if c is canonical:
                    continue
                self.aliases[c.name] = canonical.name
                # Clean up the duplicate's _deps directory; the canonical's
                # stays. (rmtree on a missing dir would already raise; the
                # ignore_errors covers concurrent removal edge cases.)
                dup_path = deps_dir / c.name
                if dup_path.exists():
                    shutil.rmtree(dup_path, ignore_errors=True)

        self._pending.clear()

        # Rewrite all candidates' dep_terms + requires_names to use
        # canonical names. The solver sees a clean graph where each
        # package has exactly one name.
        if self.aliases:
            for cands in self.candidates.values():
                for c in cands.values():
                    c.dep_terms[:] = [
                        Term(
                            package=self.aliases.get(t.package, t.package),
                            positive=t.positive,
                            versions=t.versions,
                        )
                        for t in c.dep_terms
                    ]
                    c.requires_names[:] = [
                        self.aliases.get(n, n) for n in c.requires_names
                    ]

    def get(self, name: str, version: Version) -> _Candidate:
        return self.candidates[name][version]

    def versions(self, package: str) -> list[Version]:
        return sorted(self.candidates.get(package, {}).keys())

    def dependencies(self, package: str, version: Version) -> list[Term]:
        return list(self.candidates[package][version].dep_terms)


def resolve(
    manifest: Manifest,
    *,
    deps_dir: Path,
    registry: dict[str, RegistryEntry],
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
    prior_lockfile=None,    # Lockfile | None — pins fetched identities per-dep (#82)
    profile=None,           # Profile | None — conditional predicate context (#26)
) -> ResolvedGraph:
    """Resolve `manifest` into a topologically-sorted ResolvedGraph.

    Eager fetch model: walk URL deps + transitive deps in BFS order,
    materializing every candidate, then run PubGrub over the result.

    `max_parallel` controls how many concurrent fetches may be in
    flight. Output is deterministic regardless of value — the resolved
    graph, lockfile, and nim.cfg are byte-identical for any value.
    Only the fetch ORDER varies. Use 1 for serial execution; the
    default 8 is conservative for typical Nim dep graphs.
    """
    deps_dir.mkdir(parents=True, exist_ok=True)
    provider = _MaterializedProvider()

    # Filter conditional manifest deps by profile up-front. Deps whose
    # predicates don't match the current Profile are dropped before
    # BFS — they're never fetched or considered by the solver (#26).
    if profile is not None:
        manifest = _filter_manifest_by_profile(manifest, profile)

    # Build a synthetic "root" candidate that requires each manifest dep.
    root_terms: list[Term] = []
    root_requires: list[str] = []
    queue: list[tuple[str, UrlDep] | tuple[str, str, str | None]] = []

    # Index overrides up front so root-term construction knows when
    # a NamedDep gets transformed into a URL fetch (which produces a
    # singleton version, not a registry-constrained range).
    _overrides_by_name: dict[str, Override] = {
        ov.name: ov for ov in manifest.overrides
    }

    # Manifest deps go first. UrlDep produces a fixed-singleton version
    # in solver space; NamedDep gets its constraint mapped to a VersionSet
    # and is resolved via the registry path (same code path as transitive
    # named deps from a fetched .nimble). NamedDeps whose name appears in
    # overrides become URL fetches at the sentinel version — the
    # constraint is irrelevant because the override IS the spec.
    for dep in manifest.deps:
        if isinstance(dep, TarballDep):
            # Tarball deps are fixed-singleton (like URL/Local), routed
            # through TarballFetcher with pre-fetch sha256 verification.
            # Overrides don't apply — the user wrote a specific URL +
            # hash; that's itself an explicit specification.
            root_terms.append(
                Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION))
            )
            root_requires.append(dep.name)
            queue.append(("tarball", dep))
            continue
        if isinstance(dep, LocalDep):
            # Local deps are fixed-singleton in solver space (like URL),
            # but routed through the local-fetch path. Overrides do NOT
            # apply to local deps — the user wrote `local="..."` to mean
            # "use this exact tree", which is itself an explicit override.
            root_terms.append(
                Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION))
            )
            root_requires.append(dep.name)
            queue.append(("local", dep))
        elif isinstance(dep, UrlDep) or dep.name in _overrides_by_name:
            root_terms.append(
                Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION))
            )
            root_requires.append(dep.name)
            if isinstance(dep, UrlDep):
                queue.append(("url", dep))
            else:
                # NamedDep + override → fetched as URL via the
                # submit() override path
                queue.append(("named", dep.name, dep.constraint))
        else:  # NamedDep (no override applies)
            root_terms.append(Term.require(
                dep.name, VersionSet.from_constraint(dep.constraint)
            ))
            root_requires.append(dep.name)
            queue.append(("named", dep.name, dep.constraint))

    # The synthetic root candidate at version (0,0,0):
    root_cand = _Candidate(
        name="__root__", version=(0, 0, 0),
        source="root", ref=None, sha=None, tag=None, identity=None,
        src_dir="", dep_terms=root_terms,
        requires_names=root_requires,
    )
    provider.add(root_cand)

    # Single source of truth (already built above for root-term construction)
    overrides_by_name = _overrides_by_name

    # BFS over the dep graph, materializing candidates. The main thread
    # owns `provider`, `seen_url`, `seen_named`, and the queue. Worker
    # threads only execute self-contained fetch+parse work and return
    # results — no shared mutable state.
    seen_url: set[tuple[str, str]] = set()       # (git, ref)
    seen_named: set[str] = set()
    seen_local: set[str] = set()                  # by declared path string
    seen_tarball: set[str] = set()                # by URL

    # Project root for resolving local-dep paths declared relative to it.
    project_root = deps_dir.parent

    with ThreadPoolExecutor(max_workers=max(1, max_parallel)) as ex:
        in_flight: dict = {}   # Future → queue item (for error context)

        def submit(item):
            # Override application — checked uniformly for URL + named
            # items. An override for `name` replaces the original
            # provenance with the override's URL+ref. Named-dep deps
            # become URL deps (skipping the registry lookup entirely).
            if item[0] == "local":
                ldep: LocalDep = item[1]
                if ldep.path in seen_local:
                    return
                seen_local.add(ldep.path)
                print(f"fetching {ldep.name} (local)...", file=sys.stderr)
                fut = ex.submit(
                    _process_local, ldep, project_root, deps_dir, fetcher,
                    registry, list_tags, None, prior_lockfile,
                )
            elif item[0] == "tarball":
                tdep: TarballDep = item[1]
                if tdep.url in seen_tarball:
                    return
                seen_tarball.add(tdep.url)
                print(f"fetching {tdep.name} (tarball)...", file=sys.stderr)
                fut = ex.submit(
                    _process_tarball, tdep, deps_dir, fetcher,
                    registry, list_tags, overrides_by_name,
                    prior_lockfile,
                )
            else:
                # url or named — both share the override-then-dispatch
                # shape with resolve_workspace's submit(). Single
                # _apply_override pass eliminates the previous
                # url-then-named duplication.
                item = _apply_override(item, overrides_by_name)
                if item[0] == "url":
                    dep = item[1]
                    key = (dep.git, dep.ref)
                    if key in seen_url:
                        return
                    seen_url.add(key)
                    print(f"fetching {dep.name}...", file=sys.stderr)
                    fut = ex.submit(
                        _process_url, dep, deps_dir, fetcher,
                        registry, list_tags, overrides_by_name,
                        prior_lockfile,
                    )
                else:  # named
                    name, constraint = item[1], item[2]
                    if name in seen_named:
                        return
                    if name == "nim":
                        seen_named.add(name)
                        return
                    seen_named.add(name)
                    print(f"fetching {name}...", file=sys.stderr)
                    fut = ex.submit(
                        _process_named, name, constraint, deps_dir, fetcher,
                        registry, list_tags, strategy, overrides_by_name,
                        prior_lockfile,
                    )
            in_flight[fut] = item

        for item in queue:
            submit(item)

        while in_flight:
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for fut in done:
                item = in_flight.pop(fut)
                try:
                    candidate, new_items = fut.result()
                except Exception as e:
                    # Cancel outstanding work and surface the error.
                    for outstanding in in_flight:
                        outstanding.cancel()
                    raise
                provider.record(candidate)
                print(f"✓ {candidate.name}", file=sys.stderr)
                # Transitive deps still flow through BFS — they're real
                # edges in the dep graph regardless of whether this
                # candidate ends up canonical or aliased.
                for new_item in new_items:
                    submit(new_item)

    # Resolve content-hash duplicates into canonical/alias form and
    # rewrite all terms to use canonical names. Deterministic
    # regardless of BFS arrival order.
    provider.finalize(deps_dir)

    # Solve.
    solution = solve(provider, "__root__", (0, 0, 0), strategy=strategy)
    # Map solution → ResolvedGraph (topologically sorted).
    return _build_graph(solution, provider)


def resolve_workspace(
    workspace,  # Workspace from milpa.workspace
    *,
    deps_dir: Path,
    registry: dict[str, RegistryEntry],
    fetcher: FetcherRegistry = default_registry,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
    prior_lockfile=None,    # threaded to workers for identity-pin enforcement (#82)
    profile=None,           # conditional-predicate context (#26) — per-member filtering
) -> ResolvedGraph:
    """Resolve every member's deps into one shared global graph.

    Workspace members appear as ResolvedDep entries with
    source='member:<name>', content_hash computed from each member's
    on-disk directory (no fetcher invocation). External deps (URL,
    named, local) appear once each — one version per package across
    the whole workspace.

    NamedDeps (direct or transitive) whose name matches a workspace
    member auto-coerce to member resolution. This handles the common
    case where a member's .nimble file transitively requires another
    workspace member by bare name (the .nimble syntax has no `member`
    keyword expressible).

    See #25 + W3 (#75) for design rationale.
    """
    deps_dir.mkdir(parents=True, exist_ok=True)
    provider = _MaterializedProvider()

    # Index members by name for fast lookup + auto-coercion.
    members_by_name = {m.name: m for m in workspace.members}
    overrides_by_name = {ov.name: ov for ov in workspace.overrides}

    # Reject the structurally contradictory case: a workspace override
    # whose name matches a workspace member. The user is asking for X
    # to come from both an external URL (override) AND the in-tree
    # member — these can't both be true. Surface the ambiguity loudly
    # so the user resolves it explicitly (remove one).
    collisions = sorted(set(overrides_by_name) & set(members_by_name))
    if collisions:
        names_str = ", ".join(repr(n) for n in collisions)
        raise ResolverError(
            f"workspace override name(s) {names_str} also appear as "
            f"workspace member(s) — remove either the override or the "
            f"member; cannot have both"
        )

    # Pre-register each member as a Candidate. Members have no fetch
    # step — their bytes are already on disk at member.directory.
    # Each member's manifest deps become solver terms for that member.
    root_terms: list[Term] = []
    root_requires: list[str] = []
    queue: list = []

    # Validate member-to-member references before building anything —
    # surfacing structural problems early beats letting the solver
    # complain about a phantom term.
    for member in workspace.members:
        for dep in member.manifest.deps:
            if isinstance(dep, MemberDep) and dep.name not in members_by_name:
                raise ResolverError(
                    f"workspace member {member.name!r} references "
                    f"`member \"{dep.name}\"` but no member named "
                    f"{dep.name!r} exists in the workspace"
                )

    for member in workspace.members:
        # Apply profile-based predicate filtering per member (#89) so
        # member-declared conditional deps respect the active profile.
        # Members lacking matching predicates simply don't contribute
        # their gated deps to the workspace's resolution.
        member_manifest = member.manifest
        if profile is not None:
            member_manifest = _filter_manifest_by_profile(
                member_manifest, profile,
            )
        terms, requires_names, sub_items = _terms_from_member_manifest(
            member_manifest, members_by_name, overrides_by_name,
        )
        candidate = _Candidate(
            name=member.name,
            version=_URL_DEP_VERSION,
            source=f"member:{member.name}",
            ref=None, sha=None, tag=None,
            identity=compute_content_hash(member.directory),
            src_dir=_extract_src_dir(member.manifest),
            dep_terms=terms,
            requires_names=requires_names,
        )
        provider.add(candidate)
        root_terms.append(
            Term.require(member.name, VersionSet.eq(_URL_DEP_VERSION))
        )
        root_requires.append(member.name)
        queue.extend(sub_items)

    root_cand = _Candidate(
        name="__root__", version=(0, 0, 0),
        source="root", ref=None, sha=None, tag=None, identity=None,
        src_dir="", dep_terms=root_terms,
        requires_names=root_requires,
    )
    provider.add(root_cand)

    # BFS over external deps reachable from members. Same shape as
    # resolve() — URL/named/local items get fetched in parallel; the
    # main thread owns provider + seen sets.
    seen_url: set[tuple[str, str]] = set()
    seen_named: set[str] = set()
    seen_local: set[str] = set()
    seen_member: set[str] = set(members_by_name.keys())  # all pre-registered

    project_root = deps_dir.parent

    with ThreadPoolExecutor(max_workers=max(1, max_parallel)) as ex:
        in_flight: dict = {}

        def submit(item):
            # Apply workspace overrides BEFORE dispatch. An override on
            # a name replaces URL spec or routes a named dep to a URL
            # fetch (same semantics as single-project resolve()).
            item = _apply_override(item, overrides_by_name)
            if item[0] == "url":
                dep = item[1]
                key = (dep.git, dep.ref)
                if key in seen_url:
                    return
                seen_url.add(key)
                print(f"fetching {dep.name}...", file=sys.stderr)
                fut = ex.submit(
                    _process_url, dep, deps_dir, fetcher,
                    registry, list_tags, overrides_by_name,
                    prior_lockfile,
                )
            elif item[0] == "local":
                ldep = item[1]
                if ldep.path in seen_local:
                    return
                seen_local.add(ldep.path)
                print(f"fetching {ldep.name} (local)...", file=sys.stderr)
                fut = ex.submit(
                    _process_local, ldep, project_root, deps_dir, fetcher,
                    registry, list_tags, overrides_by_name,
                    prior_lockfile,
                )
            else:  # named
                name, constraint = item[1], item[2]
                if name in seen_named or name in seen_member:
                    return
                if name == "nim":
                    seen_named.add(name)
                    return
                seen_named.add(name)
                print(f"fetching {name}...", file=sys.stderr)
                fut = ex.submit(
                    _process_named, name, constraint, deps_dir, fetcher,
                    registry, list_tags, strategy, overrides_by_name,
                    prior_lockfile,
                )
            in_flight[fut] = item

        for item in queue:
            submit(item)

        while in_flight:
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
            for fut in done:
                item = in_flight.pop(fut)
                try:
                    candidate, new_items = fut.result()
                except Exception:
                    for outstanding in in_flight:
                        outstanding.cancel()
                    raise
                provider.record(candidate)
                print(f"✓ {candidate.name}", file=sys.stderr)
                # Auto-coerce: filter out new_items whose name matches
                # a workspace member — they're already pre-registered.
                for new_item in new_items:
                    if _item_targets_member(new_item, members_by_name):
                        continue
                    submit(new_item)

    # Same finalize+solve sequence as resolve(): canonical/alias
    # resolution then PubGrub. Workspace members were pre-registered
    # via add() and are exempt from content-hash dedup.
    provider.finalize(deps_dir)

    solution = solve(provider, "__root__", (0, 0, 0), strategy=strategy)
    return _build_graph(solution, provider)


def _terms_from_member_manifest(
    manifest: Manifest,
    members_by_name: dict,
    overrides_by_name: dict,
) -> tuple[list[Term], list[str], list]:
    """Convert a member's milpa.kdl deps into solver terms + queue items
    for external deps. MemberDep entries become solver terms targeting
    the pre-registered member candidate (no queue item — no fetch).
    NamedDeps whose name matches a member auto-coerce the same way.
    NamedDeps whose name matches a workspace override get a sentinel-
    version root term because the override turns them into a URL fetch
    (same shape as resolve()'s NamedDep+Override path)."""
    terms: list[Term] = []
    names: list[str] = []
    queue: list = []
    for dep in manifest.deps:
        if isinstance(dep, MemberDep):
            terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
            names.append(dep.name)
        elif isinstance(dep, UrlDep):
            terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
            names.append(dep.name)
            queue.append(("url", dep))
        elif isinstance(dep, LocalDep):
            terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
            names.append(dep.name)
            queue.append(("local", dep))
        else:  # NamedDep
            if dep.name in members_by_name or dep.name in overrides_by_name:
                # Auto-coerce (member) OR override-routed → sentinel.
                terms.append(Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION)))
                names.append(dep.name)
                if dep.name not in members_by_name:
                    # Goes through the named-queue path; override
                    # substitution happens in submit().
                    queue.append(("named", dep.name, dep.constraint))
            else:
                terms.append(Term.require(
                    dep.name, VersionSet.from_constraint(dep.constraint),
                ))
                names.append(dep.name)
                queue.append(("named", dep.name, dep.constraint))
    return terms, names, queue


def _extract_src_dir(manifest: Manifest) -> str:
    """Read the member's intrinsic src_dir from its milpa.kdl. Empty
    string when not declared — consumers' nim.cfg lines then point at
    the member's directory itself (no /src suffix)."""
    return manifest.src_dir or ""


def _apply_override(item, overrides_by_name: dict):
    """Transform a queue item per the override table. Pure function:

    - URL item with name in overrides → URL item whose git/ref are the
      override's spec (the name stays; only the provenance changes).
    - Named item with name in overrides → URL item targeting the
      override's spec (skips the registry path entirely).
    - Local item: unchanged. `local` is itself an explicit override of
      the transport; workspace/manifest overrides don't apply to it.
    - No matching override: item unchanged.

    Used by both resolve() and resolve_workspace() at every enqueue
    point so override application is uniform regardless of which
    resolver path is active.
    """
    if item[0] == "url":
        dep = item[1]
        if dep.name in overrides_by_name:
            ov = overrides_by_name[dep.name]
            return ("url", UrlDep(name=dep.name, git=ov.git, ref=ov.ref))
        return item
    if item[0] == "named":
        name = item[1]
        if name in overrides_by_name:
            ov = overrides_by_name[name]
            return ("url", UrlDep(name=name, git=ov.git, ref=ov.ref))
        return item
    return item


def _item_targets_member(item, members_by_name: dict) -> bool:
    """Auto-coerce: a sub-item (from a fetched dep's transitive
    requires) targeting a workspace-member name is dropped — the
    member is already pre-registered with its own dep edges."""
    if item[0] == "named":
        return item[1] in members_by_name
    if item[0] == "url":
        return item[1].name in members_by_name
    return False


def _filter_manifest_by_profile(
    manifest: Manifest, profile, active_flags: frozenset | None = None,
) -> Manifest:
    """Drop deps whose predicates don't match `profile` (#26) or the
    given `active_flags` set (#23). Returns a new Manifest with the
    filtered deps tuple.

    `active_flags` defaults to the set of declared flags whose
    `default=True` (the natural choice for top-level resolution).
    """
    from dataclasses import replace as dc_replace
    if active_flags is None:
        active_flags = frozenset(
            fd.name for fd in manifest.flags if fd.default
        )
    kept = tuple(
        d for d in manifest.deps
        if _dep_matches_profile(d, profile, active_flags)
    )
    if len(kept) == len(manifest.deps):
        return manifest
    return dc_replace(manifest, deps=kept)


def _dep_matches_profile(dep, profile, active_flags: frozenset) -> bool:
    """True if every predicate on the dep matches the profile + flags."""
    preds = getattr(dep, "predicates", ())
    for p in preds:
        if not _predicate_satisfied(p, profile, active_flags):
            return False
    return True


def _predicate_satisfied(pred, profile, active_flags: frozenset) -> bool:
    """Evaluate a single Predicate against the profile + active flags.

    For `flag` predicates: satisfied iff any (none, if negated) of the
    values is in `active_flags`. For other predicates: evaluate against
    the global Profile as in #26.

    `pred.values` is a non-empty tuple of literal values. With
    `negated=False`: satisfied if matches ANY value. With
    `negated=True`: satisfied if matches NONE."""
    if pred.name == "flag":
        any_match = any(v in active_flags for v in pred.values)
        return (not any_match) if pred.negated else any_match
    actual = getattr(profile, pred.name, None)
    if actual is None:
        return False
    any_match = any(_value_matches(pred.name, actual, v) for v in pred.values)
    return (not any_match) if pred.negated else any_match


def _value_matches(predicate_name: str, actual: str, declared: str) -> bool:
    if predicate_name in ("nim", "milpa") and _looks_like_constraint(declared):
        return _version_satisfies(actual, declared)
    return actual == declared


def _looks_like_constraint(s: str) -> bool:
    """A constraint string starts with a comparison operator."""
    return s.startswith((">=", "<=", ">", "<", "==", "!=", "~", "^"))


def _version_satisfies(actual: str, constraint: str) -> bool:
    """Check `actual` (a semver string) against a constraint like
    \">=2.0\" using the existing VersionSet algebra. Short versions
    (\"2.0\") in the constraint are normalized to full triples
    (\"2.0.0\") since VersionSet only accepts complete versions."""
    parts = actual.split(".")
    triple = tuple(int(x) for x in parts[:3]) + (0,) * (3 - len(parts[:3]))
    try:
        vset = VersionSet.from_constraint(_normalize_constraint(constraint))
    except Exception:
        return False
    return vset.contains(triple)


def _normalize_constraint(s: str) -> str:
    """Normalize a user-written predicate constraint for VersionSet:
      - insert a space after the comparison operator
      - expand short version literals to full triples
    \">=2.0\" → \">= 2.0.0\"."""
    import re
    # Operator + immediately-attached version → operator + space + version
    s = re.sub(r"^(>=|<=|==|!=|>|<|~|\^)\s*", r"\1 ", s)
    # Expand short versions
    def expand(m):
        digits = [int(x) for x in m.group(0).split(".")]
        while len(digits) < 3:
            digits.append(0)
        return ".".join(str(x) for x in digits)
    return re.sub(r"\d+(?:\.\d+){0,2}", expand, s)


def _pin_for_url_dep(dep: UrlDep, prior_lockfile) -> str | None:
    """Return the locked identity for `dep` iff the manifest's git+ref
    still matches the lockfile's recorded GitProvenanceRecord. Drops
    the pin on any user-visible change (different URL, different ref)
    so an intentional manifest edit doesn't get rejected as a
    'hostile mirror'."""
    if prior_lockfile is None:
        return None
    from .lockfile import GitProvenanceRecord
    locked = next(
        (d for d in prior_lockfile.deps if d.name == dep.name),
        None,
    )
    if locked is None or not locked.identity:
        return None
    # Primary git provenance — first GitProvenanceRecord, if any
    primary = next(
        (p for p in locked.provenances if isinstance(p, GitProvenanceRecord)),
        None,
    )
    if primary is None:
        return None
    if primary.url == dep.git and primary.ref == dep.ref:
        return locked.identity
    return None


def _pin_for_tarball_dep(dep: TarballDep, prior_lockfile) -> str | None:
    """Return the locked identity for a TarballDep iff the manifest's
    url matches the lockfile's recorded TarballProvenanceRecord url."""
    if prior_lockfile is None:
        return None
    from .lockfile import TarballProvenanceRecord
    locked = next(
        (d for d in prior_lockfile.deps if d.name == dep.name),
        None,
    )
    if locked is None or not locked.identity:
        return None
    for p in locked.provenances:
        if isinstance(p, TarballProvenanceRecord) and p.url == dep.url:
            return locked.identity
    return None


def _pin_for_named_dep(name: str, resolved, prior_lockfile) -> str | None:
    """Return the locked identity for a NamedDep iff the registry's
    just-resolved (tag, url) matches the lockfile's recorded
    RegistryProvenanceRecord (or GitProvenanceRecord for the same tag).
    When the constraint allows a newer tag than was locked, the pin
    drops — that's the user's constraint working as intended."""
    if prior_lockfile is None:
        return None
    from .lockfile import GitProvenanceRecord, RegistryProvenanceRecord
    locked = next(
        (d for d in prior_lockfile.deps if d.name == name),
        None,
    )
    if locked is None or not locked.identity:
        return None
    # The registry-resolved provenance is stored as a Git or Registry
    # record. Either form must reference the same tag we just resolved.
    for p in locked.provenances:
        if isinstance(p, RegistryProvenanceRecord) and p.tag == resolved.tag:
            return locked.identity
        if isinstance(p, GitProvenanceRecord) and p.ref == resolved.tag:
            return locked.identity
    return None


def _process_url(
    dep: UrlDep,
    deps_dir: Path,
    fetcher: FetcherRegistry,
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
    overrides_by_name: dict | None = None,
    prior_lockfile=None,
) -> tuple["_Candidate", list]:
    """Worker function: fetch + parse one URL dep. Returns the candidate
    plus the queue items its requires introduce. Thread-safe: touches no
    shared mutable state outside its own subtree of `deps_dir`.

    When `prior_lockfile` is supplied and its recorded GitProvenanceRecord
    for `dep.name` matches the manifest's git+ref, the locked identity
    is enforced via fetch_any's expected_identity guard (#82). A
    hostile mirror or rewritten tag is rejected at fetch time."""
    candidates = [GitProvenance(url=dep.git, ref=dep.ref)]
    for mirror_url in dep.mirrors:
        candidates.append(GitProvenance(url=mirror_url, ref=dep.ref))
    expected_identity = _pin_for_url_dep(dep, prior_lockfile)
    result = fetcher.fetch_any(
        dep.name,
        candidates,
        dest=deps_dir / dep.name,
        expected_identity=expected_identity,
    )
    sha = _commit_sha_or_none(result.receipt)
    nimble_path = _find_nimble_file(result.path, dep.name)
    nm = parse_nimble(nimble_path.read_text())
    terms, requires_names, sub_url_deps, sub_named = _build_terms(
        nm, registry, list_tags, overrides_by_name,
    )
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=dep.git, ref=dep.ref, sha=sha, tag=None,
        identity=result.identity,
        src_dir=nm.src_dir or "",
        dep_terms=terms, requires_names=requires_names,
    )
    new_items: list = []
    for u in sub_url_deps:
        new_items.append(("url", u))
    for n in sub_named:
        new_items.append(("named", n.name, n.constraint))
    return candidate, new_items


def _process_tarball(
    dep: TarballDep,
    deps_dir: Path,
    fetcher: FetcherRegistry,
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
    overrides_by_name: dict | None = None,
    prior_lockfile=None,
) -> tuple["_Candidate", list]:
    """Worker: download + verify + extract a TarballDep via the
    TarballFetcher. Reads the extracted .nimble for transitive
    requires. Source recorded as 'tarball:<url>' for the lockfile."""
    expected_identity = _pin_for_tarball_dep(dep, prior_lockfile)
    result = fetcher.fetch_any(
        dep.name,
        [TarballProvenance(
            url=dep.url,
            expected_sha256=dep.sha256,
            strip_components=dep.strip_components,
        )],
        dest=deps_dir / dep.name,
        expected_identity=expected_identity,
    )
    nimble_path = _find_nimble_file(result.path, dep.name)
    nm = parse_nimble(nimble_path.read_text()) if nimble_path.exists() else None
    terms, requires_names, sub_url_deps, sub_named = (
        _build_terms(nm, registry, list_tags, overrides_by_name)
        if nm else ([], [], [], [])
    )
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=f"tarball:{dep.url}", ref=None, sha=None, tag=None,
        identity=result.identity,
        src_dir=(nm.src_dir or "") if nm else "",
        dep_terms=terms, requires_names=requires_names,
    )
    new_items: list = []
    for u in sub_url_deps:
        new_items.append(("url", u))
    for n in sub_named:
        new_items.append(("named", n.name, n.constraint))
    return candidate, new_items


def _process_local(
    dep: LocalDep,
    project_root: Path,
    deps_dir: Path,
    fetcher: FetcherRegistry,
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
    overrides_by_name: dict | None = None,
    prior_lockfile=None,    # never enforced for local (cas_admissible=False)
) -> tuple["_Candidate", list]:
    """Worker: copy a LocalDep's source tree into _deps/, parse its
    nimble for transitive requires.

    The declared path string (dep.path) is preserved on the candidate's
    `source` field (`local:<as-declared>`) so the lockfile records the
    user's intent — portable across machines within the same workspace
    layout. The absolute path used for the actual copy is only on the
    LocalReceipt."""
    abs_path = (project_root / dep.path).resolve()
    result = fetcher.fetch(
        dep.name,
        LocalProvenance(path=abs_path),
        dest=deps_dir / dep.name,
    )
    nimble_path = _find_nimble_file(result.path, dep.name)
    nm = parse_nimble(nimble_path.read_text()) if nimble_path.exists() else None
    terms, requires_names, sub_url_deps, sub_named = (
        _build_terms(nm, registry, list_tags, overrides_by_name)
        if nm else ([], [], [], [])
    )
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=f"local:{dep.path}", ref=None, sha=None, tag=None,
        identity=result.identity,
        src_dir=(nm.src_dir or "") if nm else "",
        dep_terms=terms, requires_names=requires_names,
    )
    new_items: list = []
    for u in sub_url_deps:
        new_items.append(("url", u))
    for n in sub_named:
        new_items.append(("named", n.name, n.constraint))
    return candidate, new_items


def _process_named(
    name: str,
    constraint: str | None,
    deps_dir: Path,
    fetcher: FetcherRegistry,
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
    strategy: Strategy = Strategy.MAXVER,
    overrides_by_name: dict | None = None,
    prior_lockfile=None,
) -> tuple["_Candidate", list]:
    """Worker function: resolve a named dep through the registry, fetch
    it, parse its nimble. Network ops (resolve_named's list_remote_tags
    + fetcher's git clone) both happen here so they can parallelize."""
    r = resolve_named(name, constraint,
                      registry=registry, list_tags=list_tags,
                      strategy=str(strategy))
    expected_identity = _pin_for_named_dep(name, r, prior_lockfile)
    result = fetcher.fetch_any(
        name,
        [GitProvenance(url=r.url, ref=r.tag)],
        dest=deps_dir / name,
        expected_identity=expected_identity,
    )
    sha = _commit_sha_or_none(result.receipt)
    nimble_path = _find_nimble_file(result.path, name)
    nm = parse_nimble(nimble_path.read_text()) if nimble_path.exists() else None
    terms, requires_names, sub_url_deps, sub_named = (
        _build_terms(nm, registry, list_tags, overrides_by_name)
        if nm else ([], [], [], [])
    )
    parts = r.version.split(".")
    ver = (int(parts[0]), int(parts[1]), int(parts[2]))
    candidate = _Candidate(
        name=name, version=ver,
        source=f"registry:{name}", ref=r.tag,
        sha=sha, tag=r.tag,
        identity=result.identity,
        src_dir=(nm.src_dir or "") if nm else "",
        dep_terms=terms, requires_names=requires_names,
    )
    new_items: list = []
    for u in sub_url_deps:
        new_items.append(("url", u))
    for n in sub_named:
        new_items.append(("named", n.name, n.constraint))
    return candidate, new_items


def _build_terms(
    nm,
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
    overrides_by_name: dict | None = None,
) -> tuple[list[Term], list[str], list[UrlDep], list[NamedRequirement]]:
    """Convert a NimbleManifest's requires into solver Terms + the queues
    of sub-deps to fetch.

    Override-aware: when overrides_by_name is provided and a transitive
    NamedRequirement's name matches an override, the produced Term uses
    the URL-dep sentinel version (because the override turns it into a
    URL fetch downstream). This keeps the term shape consistent with
    the candidate the override path actually produces."""
    overrides_by_name = overrides_by_name or {}
    terms: list[Term] = []
    names: list[str] = []
    sub_url: list[UrlDep] = []
    sub_named: list[NamedRequirement] = []
    for req in nm.requires:
        if isinstance(req, UrlRequirement):
            if req.url.startswith("nim "):
                # `nim X.Y.Z` shouldn't appear as a URL, but defensively skip
                continue
            # Derive a dep name from the URL (last path segment without .git)
            name = _name_from_url(req.url)
            terms.append(Term.require(name, VersionSet.eq(_URL_DEP_VERSION)))
            names.append(name)
            sub_url.append(UrlDep(name=name, git=req.url, ref=req.ref or "main"))
        elif isinstance(req, NamedRequirement):
            if req.name == "nim":
                # Skip the compiler version requirement.
                continue
            if req.name in overrides_by_name:
                # Override will route this through a URL fetch (sentinel
                # version candidate). Use sentinel here so the term
                # shape matches the candidate.
                terms.append(Term.require(
                    req.name, VersionSet.eq(_URL_DEP_VERSION)
                ))
            else:
                terms.append(Term.require(
                    req.name, VersionSet.from_constraint(req.constraint)
                ))
            names.append(req.name)
            sub_named.append(req)
    return terms, names, sub_url, sub_named


def _commit_sha_or_none(receipt) -> str | None:
    """Extract commit_sha from a fetcher receipt if it's a GitReceipt.

    The ResolvedDep model carries `sha` as a flat optional field for
    historical reasons; future provenance kinds (tarball, hg, etc.)
    will populate this slot with their own receipt's primary id, or
    `None` once ResolvedDep migrates to carry typed receipts directly
    (rfc-content-addressed-identity Phase D).
    """
    if isinstance(receipt, GitReceipt):
        return receipt.commit_sha
    return None


def _name_from_url(url: str) -> str:
    """Derive a package name from a git URL.

    `https://github.com/x/foo.git` → `foo`
    """
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail


def _find_nimble_file(path: Path, hint: str) -> Path:
    """Find the .nimble file in a cloned package. Convention: <name>.nimble
    at the package root. Falls back to any *.nimble if the hinted name
    doesn't exist."""
    candidate = path / f"{hint}.nimble"
    if candidate.exists():
        return candidate
    found = list(path.glob("*.nimble"))
    if found:
        return found[0]
    return candidate  # nonexistent — caller may .exists() check


def _build_graph(
    solution: dict[str, Version],
    provider: _MaterializedProvider,
) -> ResolvedGraph:
    """Map solver output → ResolvedGraph (excluding the synthetic root)."""
    # Toposort by dependency order: deps come before dependents.
    name_to_cand: dict[str, _Candidate] = {}
    for name, version in solution.items():
        if name == "__root__":
            continue
        name_to_cand[name] = provider.get(name, version)

    ordered: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited or name not in name_to_cand:
            return
        if name in visiting:
            return   # cycle — break here; final order isn't strict topo, but consistent
        visiting.add(name)
        for req_name in name_to_cand[name].requires_names:
            visit(req_name)
        visiting.discard(name)
        visited.add(name)
        ordered.append(name)

    for name in name_to_cand:
        visit(name)

    out: list[ResolvedDep] = []
    for name in ordered:
        c = name_to_cand[name]
        out.append(ResolvedDep(
            name=c.name, source=c.source,
            ref=c.ref, tag=c.tag, sha=c.sha,
            version=c.version,
            identity=c.identity,
            src_dir=c.src_dir,
            requires=tuple(c.requires_names),
        ))
    return ResolvedGraph(deps=tuple(out))
