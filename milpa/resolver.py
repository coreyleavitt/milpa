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
import sys

from .fetcher import FetchResult, fetch_url_dep
from .manifest import Manifest, NamedDep, UrlDep
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


@dataclass(frozen=True)
class ResolvedDep:
    name: str
    source: str           # URL or "registry:<name>"
    ref: str | None       # git ref originally requested (branch / tag / sha)
    tag: str | None       # tag name (registry deps only)
    sha: str | None       # resolved commit SHA
    version: Version
    content_hash: str | None
    src_dir: str          # for nim.cfg --path emission
    requires: tuple[str, ...]  # names of direct deps


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
    content_hash: str | None
    src_dir: str
    dep_terms: list[Term]      # for the solver
    requires_names: list[str]  # for ResolvedDep.requires


class _MaterializedProvider:
    """PackageProvider backed by the resolver's materialized candidate set."""

    def __init__(self) -> None:
        # name -> {version: _Candidate}
        self.candidates: dict[str, dict[Version, _Candidate]] = {}

    def add(self, c: _Candidate) -> None:
        self.candidates.setdefault(c.name, {})[c.version] = c

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
    fetcher: Callable[..., FetchResult] = fetch_url_dep,
    list_tags: Callable[[str], list[str]] = list_remote_tags,
    max_parallel: int = 8,
    strategy: Strategy = Strategy.MAXVER,
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

    # Build a synthetic "root" candidate that requires each manifest dep.
    root_terms: list[Term] = []
    root_requires: list[str] = []
    queue: list[tuple[str, UrlDep] | tuple[str, str, str | None]] = []

    # Manifest deps go first. UrlDep produces a fixed-singleton version
    # in solver space; NamedDep gets its constraint mapped to a VersionSet
    # and is resolved via the registry path (same code path as transitive
    # named deps from a fetched .nimble).
    for dep in manifest.deps:
        if isinstance(dep, UrlDep):
            root_terms.append(
                Term.require(dep.name, VersionSet.eq(_URL_DEP_VERSION))
            )
            root_requires.append(dep.name)
            queue.append(("url", dep))
        else:  # NamedDep
            root_terms.append(Term.require(
                dep.name, VersionSet.from_constraint(dep.constraint)
            ))
            root_requires.append(dep.name)
            queue.append(("named", dep.name, dep.constraint))

    # The synthetic root candidate at version (0,0,0):
    root_cand = _Candidate(
        name="__root__", version=(0, 0, 0),
        source="root", ref=None, sha=None, tag=None, content_hash=None,
        src_dir="", dep_terms=root_terms,
        requires_names=root_requires,
    )
    provider.add(root_cand)

    # BFS over the dep graph, materializing candidates. The main thread
    # owns `provider`, `seen_url`, `seen_named`, and the queue. Worker
    # threads only execute self-contained fetch+parse work and return
    # results — no shared mutable state.
    seen_url: set[tuple[str, str]] = set()       # (git, ref)
    seen_named: set[str] = set()

    with ThreadPoolExecutor(max_workers=max(1, max_parallel)) as ex:
        in_flight: dict = {}   # Future → queue item (for error context)

        def submit(item):
            if item[0] == "url":
                dep = item[1]
                key = (dep.git, dep.ref)
                if key in seen_url:
                    return
                seen_url.add(key)
                print(f"fetching {dep.name}...", file=sys.stderr)
                fut = ex.submit(
                    _process_url, dep, deps_dir, fetcher,
                    registry, list_tags,
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
                    registry, list_tags, strategy,
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
                provider.add(candidate)
                name = candidate.name
                print(f"✓ {name}", file=sys.stderr)
                for new_item in new_items:
                    submit(new_item)

    # Solve.
    solution = solve(provider, "__root__", (0, 0, 0), strategy=strategy)
    # Map solution → ResolvedGraph (topologically sorted).
    return _build_graph(solution, provider)


def _process_url(
    dep: UrlDep,
    deps_dir: Path,
    fetcher: Callable[..., FetchResult],
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
) -> tuple["_Candidate", list]:
    """Worker function: fetch + parse one URL dep. Returns the candidate
    plus the queue items its requires introduce. Thread-safe: touches no
    shared mutable state outside its own subtree of `deps_dir`."""
    result = fetcher(dep.name, dep.git, dep.ref, deps_dir=deps_dir)
    nimble_path = _find_nimble_file(result.path, dep.name)
    nm = parse_nimble(nimble_path.read_text())
    terms, requires_names, sub_url_deps, sub_named = _build_terms(
        nm, registry, list_tags,
    )
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=dep.git, ref=dep.ref, sha=result.sha, tag=None,
        content_hash=result.content_hash,
        src_dir=nm.src_dir or "",
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
    fetcher: Callable[..., FetchResult],
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]],
    strategy: Strategy = Strategy.MAXVER,
) -> tuple["_Candidate", list]:
    """Worker function: resolve a named dep through the registry, fetch
    it, parse its nimble. Network ops (resolve_named's list_remote_tags
    + fetcher's git clone) both happen here so they can parallelize."""
    r = resolve_named(name, constraint,
                      registry=registry, list_tags=list_tags,
                      strategy=str(strategy))
    result = fetcher(name, r.url, r.tag, deps_dir=deps_dir)
    nimble_path = _find_nimble_file(result.path, name)
    nm = parse_nimble(nimble_path.read_text()) if nimble_path.exists() else None
    terms, requires_names, sub_url_deps, sub_named = (
        _build_terms(nm, registry, list_tags) if nm else ([], [], [], [])
    )
    parts = r.version.split(".")
    ver = (int(parts[0]), int(parts[1]), int(parts[2]))
    candidate = _Candidate(
        name=name, version=ver,
        source=f"registry:{name}", ref=r.tag,
        sha=result.sha, tag=r.tag,
        content_hash=result.content_hash,
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
) -> tuple[list[Term], list[str], list[UrlDep], list[NamedRequirement]]:
    """Convert a NimbleManifest's requires into solver Terms + the queues
    of sub-deps to fetch."""
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
            terms.append(Term.require(
                req.name, VersionSet.from_constraint(req.constraint)
            ))
            names.append(req.name)
            sub_named.append(req)
    return terms, names, sub_url, sub_named


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
            content_hash=c.content_hash,
            src_dir=c.src_dir,
            requires=tuple(c.requires_names),
        ))
    return ResolvedGraph(deps=tuple(out))
