"""Top-level resolver — manifest → fetch + parse + solve → ResolvedGraph.

The resolver eagerly walks the manifest's URL deps, fetches each into
`_deps/<name>/`, parses its `.nimble` for transitive requires, recurses
on URL transitive deps and resolves named transitive deps via the
tianguis index (milpa#97). Once the candidate space is materialized, it hands a
`PackageProvider` to the solver and maps the solver's `{name: version}`
output back into a `ResolvedGraph` of `ResolvedDep` records.

Each `ResolvedDep` carries both identity (`content_hash`) and provenance
(typed `provenance` + `source`/`ref`/`sha`) — see docs/identity-and-provenance.md.
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

from .error_codes import resolver_codes as _RC  # noqa: F401 — populates catalog
from .fetchers import FetcherRegistry, default_registry
from .fetchers.git import GitProvenance, GitReceipt
from .fetchers.local import LocalProvenance
from .fetchers.oci import OciProvenance
from .fetchers.tarball import TarballProvenance
from .fetchers.types import Provenance
from .identity import compute_content_hash
from .manifest import (
    LocalDep, Manifest, MemberDep, NamedDep, Override, TarballDep, UrlDep,
    ManifestError,
)
from .nimble_parse import NamedRequirement, UrlRequirement, parse_nimble
from . import tianguis_client
from .tianguis_client import Index
from .solver import (
    PackageProvider,
    Strategy,
    Term,
    Version,
    VersionSet,
    parse_version,
    solve,
)


class ResolverError(Exception):
    """Raised by resolve() / resolve_workspace() for structural problems
    surfaced during candidate-set construction (e.g. a `member "X"`
    reference to a name with no matching workspace member). Solver-
    level failures (unsatisfiable constraints) raise SolverError.

    Carries a stable `code` (a `RES-*` slug from the error catalog)."""

    def __init__(self, message: str, *, code: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class ResolvedDep:
    name: str
    source: str           # display marker: git URL / "oci:<registry>/<repo>" / "local:" / "member:"
    ref: str | None       # git ref originally requested (branch / tag / sha)
    sha: str | None       # resolved commit SHA
    version: Version
    identity: str | None   # multihash-encoded content hash (#34); was content_hash (#33)
    src_dir: str           # for nim.cfg --path emission
    requires: tuple[str, ...]  # names of direct deps
    # Authoritative provenance-reconstruction input (#97 / Option A). The
    # lockfile boundary dispatches on its type to build the *Record — no
    # source-string parsing. None only for the synthetic root + workspace
    # members (never fetched); `source` then carries the member marker.
    provenance: Provenance | None = None
    active_flags: tuple[str, ...] = ()  # feature flags active on this dep (#23)
    self_mirrors: tuple[str, ...] = ()  # alternative URLs declared by this dep (#79)
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
_URL_DEP_VERSION: Version = Version(0, 0, 1)


@dataclass
class _Candidate:
    """One concrete candidate the resolver discovered.

    Keyed by (package_name, version) in the resolver's internal map.
    Production resolver fills these by walking the manifest; tests can
    construct them directly.
    """
    name: str
    version: Version
    source: str                # display marker (see ResolvedDep.source)
    ref: str | None
    sha: str | None
    identity: str | None       # multihash-encoded (#34); was content_hash
    src_dir: str
    dep_terms: list[Term]      # for the solver
    requires_names: list[str]  # for ResolvedDep.requires
    # Typed provenance carried onto the candidate (#97 / Option A) — the
    # authoritative lockfile-reconstruction input. None is legitimate ONLY
    # for: (1) the synthetic __root__ candidate, (2) workspace member
    # candidates (source prefix "member:"), and (3) local deps (source
    # prefix "local:") — see _process_local's comment for why local stays
    # on the string-fallback path. All other fetched deps carry a typed
    # GitProvenance / OciProvenance / TarballProvenance.
    provenance: Provenance | None = None
    # Feature-flag state on this candidate (#90).
    active_flags: tuple[str, ...] = ()
    flag_defines: tuple[tuple[str, tuple[str, ...]], ...] = ()
    # Self-mirrors harvested from this dep's milpa.kdl (#79). Used
    # as fall-back candidates in subsequent resolves via the lockfile
    # cache.
    self_mirrors: tuple[str, ...] = ()


@dataclass
class _NamedDepStub:
    """Lightweight stub for a named-dep candidate before fetch (Phase A).

    Registered in `_MaterializedProvider._stubs` during BFS enumeration.
    When the solver selects this (name, version) and calls
    `provider.dependencies()`, the stub is materialized: fetched, nimble-
    parsed, and replaced by a real `_Candidate` in the provider.

    The fetcher context (deps_dir, fetcher, overrides_by_name) is captured
    at enumeration time so Phase B is self-contained.
    """
    name: str
    version: Version
    index_version: "tianguis_client.IndexVersion"  # version metadata + provenance
    deps_dir: Path
    fetcher: "FetcherRegistry"
    overrides_by_name: dict


class _MaterializedProvider:
    """PackageProvider backed by the resolver's materialized candidate set.

    Two-phase population:

    Phase A (BFS enumeration — no fetch):
      Named deps are registered as `_NamedDepStub` objects via
      `register_named_stubs()`. URL/local/tarball deps are buffered via
      `record()` as before (they continue to be fetched eagerly in BFS).

    Phase B (lazy materialization — fetch on demand):
      When the solver calls `dependencies(pkg, version)` for a stub, the
      stub is fetched + nimble-parsed inline. Any newly-discovered
      transitive named deps are enrolled as additional stubs immediately,
      so the solver can continue without a restart (P3.2 fixpoint).

    Dedup (content-hash, #32 — unchanged for URL/tarball):
      URL-dep workers produce candidates which are buffered via `record(c)`.
      After BFS completes, `finalize(deps_dir)` partitions buffered
      candidates by content_hash, picks a deterministic canonical name, and
      registers only canonicals in `candidates`. Named-dep stubs bypass this
      path — they are materialized directly into `candidates` during solve.

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
        # Phase A stubs: name -> {version: _NamedDepStub}
        # Cleared on materialization (one stub per (name, version) at most).
        self._stubs: dict[str, dict[Version, _NamedDepStub]] = {}
        # Phase B transitive callbacks — None until start_solve() is called.
        # Callers must call start_solve() AFTER finalize() and BEFORE solve()
        # to ensure the callbacks are set before the solver can call
        # dependencies(). Use start_solve() to set both atomically.
        self._on_new_named: "Callable[[str, str | None], None] | None" = None
        self._on_new_url: "Callable[[UrlDep], None] | None" = None

    def start_solve(
        self,
        on_new_named: "Callable[[str, str | None], None]",
        on_new_url: "Callable[[UrlDep], None]",
    ) -> None:
        """Wire up Phase B transitive callbacks before the solver starts.

        Must be called after finalize() and before solve() to eliminate the
        half-built window where dependencies() could be called without the
        callbacks set (M4). Both callbacks are set atomically so there is no
        intermediate state where one is set but not the other."""
        self._on_new_named = on_new_named
        self._on_new_url = on_new_url

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

    def update_pending(
        self,
        *,
        git_url: str,
        ref: str | None,
        dep_terms=None,
        requires_names=None,
        active_flags=None,
        flag_defines=None,
    ) -> bool:
        """Find a not-yet-finalized candidate by (git_url, ref) and
        mutate the provided fields. Used by the #90 fixpoint sweep to
        update a candidate's transitive deps after later consumer
        flag requests union in. Returns True iff a candidate matched.

        URL-dep-only: the sole caller keys by (dep_url.git, dep_url.ref),
        and a URL candidate's `source` IS its git URL (see `_process_url`),
        so matching on `source` here is matching on the git URL — not a
        general use of the display-oriented `source` field."""
        for c in self._pending:
            if c.source == git_url and c.ref == ref:
                if dep_terms is not None:
                    c.dep_terms = list(dep_terms)
                if requires_names is not None:
                    c.requires_names = list(requires_names)
                if active_flags is not None:
                    c.active_flags = active_flags
                if flag_defines is not None:
                    c.flag_defines = flag_defines
                return True
        return False

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

    def register_named_stubs(
        self,
        name: str,
        stubs: list["_NamedDepStub"],
    ) -> None:
        """Phase A: register lightweight version stubs for a named dep.

        All satisfying IndexVersions are registered as stubs so the solver
        can see the full candidate set and backtrack. No fetch happens here.
        Does NOT overwrite an existing materialized candidate — if a version
        is already in `candidates` (e.g. re-enumeration from a fixpoint),
        we skip that stub (it's already concrete)."""
        stub_versions = self._stubs.setdefault(name, {})
        for stub in stubs:
            if stub.version in self.candidates.get(name, {}):
                continue  # already materialized — don't revert to stub
            stub_versions[stub.version] = stub

    def _materialize_stub(self, stub: "_NamedDepStub") -> "_Candidate":
        """Phase B: fetch + parse the named dep for the selected version.

        Called lazily from `dependencies()` the first time the solver
        selects this (name, version). Produces a real _Candidate with
        dep_terms + requires_names populated from the nimble file.

        Any transitive named deps discovered here are immediately enrolled
        as stubs (Phase A for transitive deps) so the solver can see them
        in subsequent `versions()` calls without requiring a full restart.
        """
        idx_ver = stub.index_version
        name = stub.name

        # Delegate to the shared fetch+parse core (M3 — SSOT).
        candidate, sub_url_deps, sub_named = _fetch_and_build_named_candidate(
            name, idx_ver, stub.version, stub.deps_dir, stub.fetcher,
            stub.overrides_by_name,
        )
        # Register into the live candidates map so subsequent calls to
        # get() / dependencies() see the materialized candidate.
        self.candidates.setdefault(name, {})[stub.version] = candidate
        # Drop the stub — it's now concrete.
        self._stubs.get(name, {}).pop(stub.version, None)

        # Enroll transitive named deps as Phase A stubs so the solver can
        # immediately see them. Named transitive deps that are already stubs
        # or materialized are skipped.
        if self._on_new_named:
            for n in sub_named:
                self._on_new_named(n.name, n.constraint)
        # Enroll transitive URL deps discovered in this named dep's nimble.
        # These were previously silently ignored during Phase B, causing a
        # spurious no-versions SolverError (H4). The callback synchronously
        # fetches + enrolls each URL dep so the solver can satisfy it.
        if self._on_new_url:
            for u in sub_url_deps:
                self._on_new_url(u)

        print(f"✓ {name} {idx_ver.version}", file=sys.stderr)
        return candidate

    def get(self, name: str, version: Version) -> _Candidate:
        # If the solver selected a stub version, it has been materialized
        # by `dependencies()` before `_build_graph` calls `get()`.
        # But be defensive — materialize inline if somehow get() is called
        # before dependencies().
        if name not in self.candidates or version not in self.candidates.get(name, {}):
            stub = self._stubs.get(name, {}).get(version)
            if stub is not None:
                return self._materialize_stub(stub)
        return self.candidates[name][version]

    def versions(self, package: str) -> list[Version]:
        """Return all known versions for package — both materialized
        candidates and Phase A stubs (sorted ascending for the solver)."""
        known: set[Version] = set(self.candidates.get(package, {}).keys())
        known.update(self._stubs.get(package, {}).keys())
        return sorted(known)

    def dependencies(self, package: str, version: Version) -> list[Term]:
        # Fast path: already materialized.
        if version in self.candidates.get(package, {}):
            return list(self.candidates[package][version].dep_terms)
        # Lazy materialization: this is a Phase A stub being selected for
        # the first time by the solver.
        stub = self._stubs.get(package, {}).get(version)
        if stub is not None:
            candidate = self._materialize_stub(stub)
            return list(candidate.dep_terms)
        # Should not happen — the solver only calls dependencies() for
        # versions that appeared in versions(), which covers both.
        raise KeyError(f"no candidate for {package!r} @ {version}")


def resolve(
    manifest: Manifest,
    *,
    deps_dir: Path,
    index: Index | None = None,
    fetcher: FetcherRegistry = default_registry,
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

    Named deps resolve through the injected tianguis `index` (milpa#97);
    `index=None` defaults to an empty index — fine for manifests with no
    named deps (URL/local/tarball/member only).
    """
    if index is None:
        _overrides = {ov.name for ov in manifest.overrides}
        unresolvable = [
            d.name for d in manifest.deps
            if isinstance(d, NamedDep) and d.name not in _overrides
        ]
        if unresolvable:
            raise ResolverError(
                f"manifest has named dep(s) {unresolvable} but no tianguis "
                f"index was provided — pass index= to resolve named deps",
                code="RES-NO-INDEX",
            )
    index = index if index is not None else Index({})
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
    #
    # dev_deps for the ROOT package are enrolled here alongside regular
    # deps — they are requirements when this package is the root. Only the
    # root's dev_deps ever appear here; transitive deps' dev_deps are
    # silently ignored (see _extract_from_milpa_kdl).
    for dep in list(manifest.deps) + list(manifest.dev_deps):
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
                dep.name,
                dep.constraint_set if dep.constraint_set is not None
                else VersionSet.full(),
            ))
            root_requires.append(dep.name)
            queue.append(("named", dep.name, dep.constraint))

    # The synthetic root candidate at version (0,0,0):
    root_cand = _Candidate(
        name="__root__", version=Version(0, 0, 0),
        source="root", ref=None, sha=None, identity=None,
        src_dir="", dep_terms=root_terms,
        requires_names=root_requires,
    )
    provider.add(root_cand)

    # Single source of truth (already built above for root-term construction)
    overrides_by_name = _overrides_by_name

    # Root authority set: every package name the root controls.  Covers all
    # deps, dev-deps, and overrides declared directly in the root manifest.
    # A transitive dep claiming a name in this set is SUPPRESSED — the root's
    # provenance wins (Cargo [patch] / npm overrides semantics).
    root_authority: set[str] = {
        dep.name
        for dep in list(manifest.deps) + list(manifest.dev_deps)
    } | {ov.name for ov in manifest.overrides}

    # Cross-name provenance gate.  Tracks the first provenance key that claimed
    # each package name (from any transport).  Root-authority deps are enrolled
    # during queue seeding below; transitive deps are enrolled in submit().
    # Format: name → (item_provenance_key, is_root_authority_claim).
    _seen_by_name: dict[str, tuple[tuple, bool]] = {}

    # Seed the name map with root-declared deps so root provenance wins the
    # first-seen race regardless of BFS arrival order.  For deps whose name
    # appears in overrides_by_name, use the OVERRIDE's provenance (because
    # _apply_override will rewrite those items before the gate runs — the
    # gate must compare post-override keys, not pre-override keys).
    for dep in list(manifest.deps) + list(manifest.dev_deps):
        if isinstance(dep, LocalDep):
            # Local deps: overrides don't apply; seed with local path.
            _seen_by_name[dep.name] = (("local", dep.path), True)
        elif isinstance(dep, TarballDep):
            # Tarball deps: overrides don't apply.
            _seen_by_name[dep.name] = (("tarball", dep.url), True)
        elif isinstance(dep, UrlDep):
            # URL dep: _apply_override may redirect to a different URL+ref.
            # Seed with the effective (post-override) provenance.
            if dep.name in _overrides_by_name:
                ov = _overrides_by_name[dep.name]
                _seen_by_name[dep.name] = (("url", ov.git, ov.ref), True)
            else:
                _seen_by_name[dep.name] = (("url", dep.git, dep.ref), True)
        else:  # NamedDep: may be redirected to URL via override, or stay named.
            if dep.name in _overrides_by_name:
                ov = _overrides_by_name[dep.name]
                _seen_by_name[dep.name] = (("url", ov.git, ov.ref), True)
            else:
                _seen_by_name[dep.name] = (("named", dep.name), True)
    for ov in manifest.overrides:
        # Overrides not already covered by a direct dep also carry root authority.
        if ov.name not in _seen_by_name:
            _seen_by_name[ov.name] = (("url", ov.git, ov.ref), True)

    # BFS over the dep graph, materializing candidates. The main thread
    # owns `provider`, `seen_url`, `seen_named`, and the queue. Worker
    # threads only execute self-contained fetch+parse work and return
    # results — no shared mutable state.
    seen_url: set[tuple[str, str]] = set()       # (git, ref)
    seen_named: set[str] = set()
    seen_local: set[str] = set()                  # by declared path string
    seen_tarball: set[str] = set()                # by URL

    # Cross-graph flag-request accumulation (#90). Every UrlDep that
    # references a transitive dep contributes its FlagRequests to that
    # dep's bucket — even if the dep was already fetched (so consumer
    # flag requests from later consumers aren't lost to BFS dedup).
    from collections import defaultdict as _dd
    dep_flag_requests: dict[tuple[str, str], list] = _dd(list)
    dep_milpa_kdl_path: dict[tuple[str, str], Path] = {}
    # Track sub-deps already queued from each milpa.kdl dep, so the
    # fixpoint re-evaluation only queues NEWLY-included transitives.
    dep_queued_sub_keys: dict[tuple[str, str], set] = _dd(set)

    # Project root for resolving local-dep paths declared relative to it.
    project_root = deps_dir.parent

    with ThreadPoolExecutor(max_workers=max(1, max_parallel)) as ex:
        in_flight: dict = {}   # Future → queue item (for error context)

        def submit(item):
            # Override application — checked uniformly for URL + named
            # items. An override for `name` replaces the original
            # provenance with the override's URL+ref. Named-dep deps
            # become URL deps (skipping the registry lookup entirely).
            #
            # Root-provenance gate: apply BEFORE transport-specific dedup.
            # When a package name was already claimed by a root-authority dep
            # (or earlier dep of any kind), a transitive dep requesting the
            # same name via a DIFFERENT provenance key is either suppressed
            # (root-authority) or raised as a conflict (non-root).
            # Apply override first so the gate compares resolved provenance.
            if item[0] not in ("local", "tarball"):
                item = _apply_override(item, overrides_by_name)

            name = _item_name(item)
            if name is not None and name != "nim":
                pkey = _item_provenance_key(item)
                prior = _seen_by_name.get(name)
                if prior is None:
                    # First claim on this name — record it.
                    _seen_by_name[name] = (pkey, False)
                elif prior[0] != pkey:
                    # Different provenance for the same name.
                    if prior[1] or name in root_authority:
                        # Root authority wins: suppress the transitive claim.
                        return
                    # Non-root disagreement: two transitives want different
                    # provenance for the same name.
                    raise ResolverError(
                        f"provenance conflict for package {name!r}: "
                        f"one transitive dep claims provenance {prior[0]!r} "
                        f"and another claims {pkey!r}. "
                        f"The root manifest does not override {name!r}. "
                        f"Add an override in your milpa.kdl to resolve "
                        f"which source to use.",
                        code="RES-PROVENANCE-CONFLICT",
                    )
                else:
                    # Same provenance key — the transport-specific dedup
                    # below will suppress; nothing more to do here.
                    pass

            if item[0] == "local":
                ldep: LocalDep = item[1]
                if ldep.path in seen_local:
                    return
                seen_local.add(ldep.path)
                print(f"fetching {ldep.name} (local)...", file=sys.stderr)
                fut = ex.submit(
                    _process_local, ldep, project_root, deps_dir, fetcher,
                    None, prior_lockfile,
                )
            elif item[0] == "tarball":
                tdep: TarballDep = item[1]
                if tdep.url in seen_tarball:
                    return
                seen_tarball.add(tdep.url)
                print(f"fetching {tdep.name} (tarball)...", file=sys.stderr)
                fut = ex.submit(
                    _process_tarball, tdep, deps_dir, fetcher,
                    overrides_by_name,
                    prior_lockfile,
                )
            elif item[0] == "url":
                dep = item[1]
                key = (dep.git, dep.ref)
                # ALWAYS accumulate per-consumer flag requests
                # even on dup so cross-graph union works (#90).
                # Each consumer contributes a tuple of FlagRequests.
                if dep.flag_requests:
                    dep_flag_requests[key].append(dep.flag_requests)
                if key in seen_url:
                    return
                seen_url.add(key)
                print(f"fetching {dep.name}...", file=sys.stderr)
                fut = ex.submit(
                    _process_url, dep, deps_dir, fetcher,
                    overrides_by_name,
                    prior_lockfile,
                )
            else:  # named — Phase A: enumerate stubs synchronously (no fetch)
                name, constraint = item[1], item[2]
                if name in seen_named:
                    return
                if name == "nim":
                    seen_named.add(name)
                    return
                seen_named.add(name)
                # Phase A: enumerate all satisfying IndexVersions as
                # lightweight stubs. The solver will trigger Phase B
                # (fetch) lazily via dependencies() for the chosen version.
                _enumerate_named(
                    name, constraint, deps_dir, fetcher,
                    index, overrides_by_name, provider,
                )
                return  # no future — synchronous, nothing to track
            in_flight[fut] = item

        def drain_inflight():
            """Drain all currently in-flight futures, recording results
            and queueing any sub-items they introduce. Tracks per-dep
            milpa.kdl path + initial sub-deps so the fixpoint sweep
            below can identify newly-needed transitives (#90)."""
            while in_flight:
                done, _ = wait(in_flight, return_when=FIRST_COMPLETED)
                for fut in done:
                    item = in_flight.pop(fut)
                    try:
                        candidate, new_items = fut.result()
                    except Exception as e:
                        for outstanding in in_flight:
                            outstanding.cancel()
                        raise
                    provider.record(candidate)
                    print(f"✓ {candidate.name}", file=sys.stderr)
                    if item[0] == "url":
                        dep_url = item[1]
                        key = (dep_url.git, dep_url.ref)
                        mp = deps_dir / dep_url.name / "milpa.kdl"
                        if mp.exists():
                            dep_milpa_kdl_path[key] = mp
                        # Track the names we've already queued from
                        # this dep so the fixpoint pass doesn't
                        # re-queue them.
                        for sub in new_items:
                            dep_queued_sub_keys[key].add(_sub_item_key(sub))
                    for new_item in new_items:
                        submit(new_item)

        for item in queue:
            submit(item)
        drain_inflight()

        # Fixpoint sweep: re-evaluate each fetched milpa.kdl dep with
        # the FULL accumulated FlagRequest set from across the graph.
        # If new flags became active (because a later consumer's
        # request was unioned in), submit any newly-included
        # transitives. Monotonic — active sets only grow, so iteration
        # terminates (bounded by total flag count across all deps).
        while True:
            new_submits = 0
            for key, milpa_kdl_path in list(dep_milpa_kdl_path.items()):
                all_requests = dep_flag_requests.get(key)
                if not all_requests:
                    continue
                (new_terms, new_requires, _, sub_items,
                 new_active, new_flag_defines,
                 _self_mirrors) = _extract_from_milpa_kdl(
                    milpa_kdl_path, "<re-eval>",
                    overrides_by_name,
                    consumer_flag_requests=tuple(all_requests),
                )
                added_this_round = False
                for sub in sub_items:
                    sk = _sub_item_key(sub)
                    if sk not in dep_queued_sub_keys[key]:
                        dep_queued_sub_keys[key].add(sk)
                        submit(sub)
                        new_submits += 1
                        added_this_round = True
                if added_this_round:
                    # Update the existing candidate's requires_names +
                    # dep_terms + active_flags so the solver sees the
                    # newly-activated transitives as real edges from
                    # this dep, and ResolvedDep carries the correct
                    # flag state for nim.cfg emission.
                    _update_candidate_requires(
                        provider, key, new_terms, new_requires,
                        new_active, new_flag_defines,
                    )
            if new_submits == 0:
                break
            drain_inflight()

    # Resolve content-hash duplicates into canonical/alias form and
    # rewrite all terms to use canonical names. Deterministic
    # regardless of BFS arrival order.
    provider.finalize(deps_dir)

    # Wire up the Phase B transitive callback. When the solver triggers
    # lazy materialization of a named stub, any newly-discovered transitive
    # named deps are enrolled as stubs immediately (in-solve Phase A).
    # `seen_named` is still in scope here and acts as the dedup gate.
    def _on_new_named(name: str, constraint: str | None) -> None:
        if name in seen_named or name == "nim":
            return
        seen_named.add(name)
        item = _apply_override(("named", name, constraint), overrides_by_name)
        if item[0] == "named":
            # Enumerate ALL versions of the transitive dep (no constraint
            # pre-filter). The constraint from the nimble is already encoded in
            # `dep_terms` as a solver incompatibility — pre-filtering here would
            # shrink the candidate set to only those satisfying THIS dep's view
            # of the constraint, which is wrong when the solver may backtrack to
            # a parent that no longer imposes the same constraint. Passing None
            # lets the solver see the full candidate space and handle constraint
            # accumulation correctly (including backtracking through the parent
            # that introduced this transitive dep). See P3.3 S2 diamond test.
            _enumerate_named(
                name, None, deps_dir, fetcher,
                index, overrides_by_name, provider,
            )
        # If override turns it into a URL dep, we can't fetch synchronously
        # during solve — that case is rare (a named dep from a nimble that
        # is overridden to a URL), and is a pre-existing edge-case limitation
        # that predates P3.2. Silently skip so no regression is introduced.

    # Wire up the Phase B URL-transitive callback. When _materialize_stub
    # finds a URL require in a named dep's nimble, this callback synchronously
    # fetches + enrolls the URL dep into the provider so the solver can
    # satisfy it. `seen_url` deduplicates so the same URL is only fetched once.
    def _on_new_url(dep: "UrlDep") -> None:
        key = (dep.git, dep.ref)
        if key in seen_url:
            return
        seen_url.add(key)
        print(f"fetching {dep.name} (transitive from named dep)...", file=sys.stderr)
        candidate, new_items = _process_url(dep, deps_dir, fetcher,
                                             overrides_by_name, prior_lockfile)
        # Phase B happens after finalize() — add directly to candidates
        # (not pending) so the solver sees this dep immediately.
        provider.add(candidate)
        # Recurse: the URL dep's own transitives may introduce more URL or
        # named deps. Route them through the same Phase B enrollment path.
        for new_item in new_items:
            if new_item[0] == "url":
                _on_new_url(new_item[1])
            elif new_item[0] == "named":
                _on_new_named(new_item[1], new_item[2])

    # Atomically wire up both Phase B callbacks before the solver starts
    # (M4: eliminates the half-built window where dependencies() could fire
    # before both callbacks are set).
    provider.start_solve(_on_new_named, _on_new_url)

    # Solve.
    solution = solve(provider, "__root__", Version(0, 0, 0), strategy=strategy)
    # Map solution → ResolvedGraph (topologically sorted).
    return _build_graph(solution, provider)


def resolve_workspace(
    workspace,  # Workspace from milpa.workspace
    *,
    deps_dir: Path,
    index: Index | None = None,
    fetcher: FetcherRegistry = default_registry,
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
    if index is None:
        _ws_overrides = {ov.name for ov in workspace.overrides}
        _member_names = {m.name for m in workspace.members}
        _unresolvable = [
            d.name
            for member in workspace.members
            for d in member.manifest.deps
            if isinstance(d, NamedDep)
            and d.name not in _ws_overrides
            and d.name not in _member_names
        ]
        if _unresolvable:
            raise ResolverError(
                f"workspace has named dep(s) {_unresolvable} but no tianguis "
                f"index was provided — pass index= to resolve named deps",
                code="RES-WS-NO-INDEX",
            )
    index = index if index is not None else Index({})
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
            f"member; cannot have both",
            code="RES-WS-OVERRIDE-MEMBER-COLLISION",
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
                    f"{dep.name!r} exists in the workspace",
                    code="RES-WS-MEMBER-REF-UNKNOWN",
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
            ref=None, sha=None,
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
        name="__root__", version=Version(0, 0, 0),
        source="root", ref=None, sha=None, identity=None,
        src_dir="", dep_terms=root_terms,
        requires_names=root_requires,
    )
    provider.add(root_cand)

    # Root authority for the workspace: all names declared in any member's
    # deps/dev-deps plus workspace-level overrides.  A transitive dep
    # claiming a name already in root authority is suppressed (root wins).
    ws_root_authority: set[str] = {
        dep.name
        for member in workspace.members
        for dep in list(member.manifest.deps) + list(member.manifest.dev_deps)
        if hasattr(dep, "name")
    } | set(overrides_by_name.keys()) | set(members_by_name.keys())

    # Cross-name provenance gate for the workspace resolver.  Same semantics
    # as resolve()'s _seen_by_name: first provenance claim on a name wins when
    # it has root authority; two non-root claims with different provenance →
    # RES-PROVENANCE-CONFLICT.
    _ws_seen_by_name: dict[str, tuple[tuple, bool]] = {}

    # Seed with all root-authority external deps from all members.
    # As in resolve(), seed with POST-override provenance for URL deps
    # that have a workspace override — _apply_override rewrites before
    # the gate runs.
    for member in workspace.members:
        for dep in list(member.manifest.deps) + list(member.manifest.dev_deps):
            if not hasattr(dep, "name"):
                continue
            n = dep.name
            if n in members_by_name or isinstance(dep, MemberDep):
                continue  # member-to-member handled separately
            if n not in _ws_seen_by_name:
                if isinstance(dep, LocalDep):
                    _ws_seen_by_name[n] = (("local", dep.path), True)
                elif isinstance(dep, TarballDep):
                    _ws_seen_by_name[n] = (("tarball", dep.url), True)
                elif isinstance(dep, UrlDep):
                    # Use override URL+ref if this dep is overridden.
                    if n in overrides_by_name:
                        ov = overrides_by_name[n]
                        _ws_seen_by_name[n] = (("url", ov.git, ov.ref), True)
                    else:
                        _ws_seen_by_name[n] = (("url", dep.git, dep.ref), True)
                else:  # NamedDep
                    if n in overrides_by_name:
                        ov = overrides_by_name[n]
                        _ws_seen_by_name[n] = (("url", ov.git, ov.ref), True)
                    else:
                        _ws_seen_by_name[n] = (("named", n), True)
    for ov_name, ov in overrides_by_name.items():
        if ov_name not in _ws_seen_by_name:
            _ws_seen_by_name[ov_name] = (("url", ov.git, ov.ref), True)

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

            # Root-provenance gate (same semantics as resolve()'s gate).
            ws_name = _item_name(item)
            if ws_name is not None and ws_name != "nim" and ws_name not in seen_member:
                ws_pkey = _item_provenance_key(item)
                ws_prior = _ws_seen_by_name.get(ws_name)
                if ws_prior is None:
                    _ws_seen_by_name[ws_name] = (ws_pkey, False)
                elif ws_prior[0] != ws_pkey:
                    if ws_prior[1] or ws_name in ws_root_authority:
                        return  # root authority wins; suppress transitive
                    raise ResolverError(
                        f"provenance conflict for package {ws_name!r}: "
                        f"one transitive dep claims provenance {ws_prior[0]!r} "
                        f"and another claims {ws_pkey!r}. "
                        f"No workspace member overrides {ws_name!r}. "
                        f"Add an override in your workspace milpa.kdl to resolve "
                        f"which source to use.",
                        code="RES-PROVENANCE-CONFLICT",
                    )

            if item[0] == "url":
                dep = item[1]
                key = (dep.git, dep.ref)
                if key in seen_url:
                    return
                seen_url.add(key)
                print(f"fetching {dep.name}...", file=sys.stderr)
                fut = ex.submit(
                    _process_url, dep, deps_dir, fetcher,
                    overrides_by_name,
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
                    overrides_by_name,
                    prior_lockfile,
                )
            else:  # named — Phase A: enumerate stubs synchronously (no fetch)
                name, constraint = item[1], item[2]
                if name in seen_named or name in seen_member:
                    return
                if name == "nim":
                    seen_named.add(name)
                    return
                seen_named.add(name)
                # Phase A: enumerate ALL versions from the index (no constraint
                # pre-filter — pass None so the full candidate space is visible to
                # the solver). The member-declared constraints are already encoded
                # as solver terms in dep_terms; pre-filtering here would shrink the
                # candidate set to only those satisfying the first-arrival member's
                # view, which is wrong when a second member has a tighter bound.
                _enumerate_named(
                    name, None, deps_dir, fetcher,
                    index, overrides_by_name, provider,
                )
                return  # synchronous — no future to track

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

    # Wire up Phase B transitive callbacks. When _materialize_stub fires
    # during solve for a named dep, any transitives it discovers must be
    # enrolled immediately. `seen_named` / `seen_url` are still in scope
    # and act as dedup gates — mirrors resolve()'s start_solve() wiring.
    def _ws_on_new_named(name: str, constraint: str | None) -> None:
        if name in seen_named or name in seen_member or name == "nim":
            return
        seen_named.add(name)
        item = _apply_override(("named", name, constraint), overrides_by_name)
        if item[0] == "named":
            # Enumerate ALL versions of the transitive dep (no constraint
            # pre-filter) — same reasoning as the BFS submit() path above.
            _enumerate_named(
                name, None, deps_dir, fetcher,
                index, overrides_by_name, provider,
            )

    def _ws_on_new_url(dep: "UrlDep") -> None:
        key = (dep.git, dep.ref)
        if key in seen_url:
            return
        seen_url.add(key)
        print(f"fetching {dep.name} (transitive from named dep)...", file=sys.stderr)
        candidate, new_items = _process_url(dep, deps_dir, fetcher,
                                             overrides_by_name, prior_lockfile)
        provider.add(candidate)
        for new_item in new_items:
            if new_item[0] == "url":
                _ws_on_new_url(new_item[1])
            elif new_item[0] == "named":
                _ws_on_new_named(new_item[1], new_item[2])

    provider.start_solve(_ws_on_new_named, _ws_on_new_url)

    solution = solve(provider, "__root__", Version(0, 0, 0), strategy=strategy)
    return _build_graph(solution, provider)


def _terms_from_member_manifest(
    manifest: Manifest,
    members_by_name: dict,
    overrides_by_name: dict,
) -> tuple[list[Term], list[str], list]:
    """Convert a member's milpa.kdl deps (AND dev_deps) into solver terms +
    queue items for external deps. MemberDep entries become solver terms
    targeting the pre-registered member candidate (no queue item — no fetch).
    NamedDeps whose name matches a member auto-coerce the same way.
    NamedDeps whose name matches a workspace override get a sentinel-
    version root term because the override turns them into a URL fetch
    (same shape as resolve()'s NamedDep+Override path).

    A workspace member is a package being primarily developed; its own
    dev_deps are therefore enrolled here alongside regular deps. The
    transitive-exclusion rule still applies to any external dep's milpa.kdl
    that this member transitively reaches (enforced in _extract_from_milpa_kdl)."""
    terms: list[Term] = []
    names: list[str] = []
    queue: list = []
    for dep in list(manifest.deps) + list(manifest.dev_deps):
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
                    dep.name,
                    dep.constraint_set if dep.constraint_set is not None
                    else VersionSet.full(),
                ))
                names.append(dep.name)
                queue.append(("named", dep.name, dep.constraint))
    return terms, names, queue


def _extract_src_dir(manifest: Manifest) -> str:
    """Read the member's intrinsic src_dir from its milpa.kdl. Empty
    string when not declared — consumers' nim.cfg lines then point at
    the member's directory itself (no /src suffix)."""
    return manifest.src_dir or ""


def _item_name(item) -> str | None:
    """Extract the package name from a queue item, or None for unknown kinds."""
    kind = item[0]
    if kind == "url":
        return item[1].name
    if kind == "named":
        return item[1]
    if kind == "local":
        return item[1].name
    if kind == "tarball":
        return item[1].name
    return None


def _item_provenance_key(item) -> tuple:
    """A canonical key that identifies the provenance of a queue item.

    Used to detect when two items claim the same package name from different
    sources. Two items with the same key are compatible (dedup); different
    keys for the same name are a potential provenance conflict.

    Returns a tuple whose first element is the transport kind string so keys
    from different transports are always distinct."""
    kind = item[0]
    if kind == "url":
        dep = item[1]
        return ("url", dep.git, dep.ref)
    if kind == "named":
        # Named deps are keyed by name alone — the index is the single
        # source of truth; constraint differences are resolved by the solver.
        return ("named", item[1])
    if kind == "local":
        return ("local", item[1].path)
    if kind == "tarball":
        return ("tarball", item[1].url)
    return (kind,)


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


def _update_candidate_requires(
    provider, key: tuple[str, str], new_terms, new_requires,
    new_active=None, new_flag_defines=None,
) -> None:
    """Thin wrapper around _MaterializedProvider.update_pending —
    locates a buffered candidate by (URL, ref) and updates its
    transitive-dep state to reflect post-fixpoint flag activation
    (#90)."""
    provider.update_pending(
        git_url=key[0], ref=key[1],
        dep_terms=new_terms, requires_names=new_requires,
        active_flags=new_active, flag_defines=new_flag_defines,
    )


def _sub_item_key(item):
    """Stable identifier for a sub-dep queue item, used for fixpoint
    dedup (#90). Different KINDS of dep go through different submit
    branches; the key includes the kind to keep them disjoint."""
    kind = item[0]
    if kind == "url":
        return ("url", item[1].name)
    if kind == "named":
        return ("named", item[1])
    if kind == "local":
        return ("local", item[1].name)
    if kind == "tarball":
        return ("tarball", item[1].name)
    return (kind, str(item))


def _filter_manifest_by_profile(
    manifest: Manifest, profile, active_flags: frozenset | None = None,
) -> Manifest:
    """Drop deps whose predicates don't match `profile` (#26) or the
    given `active_flags` set (#23). Returns a new Manifest with the
    filtered deps and dev_deps tuples.

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
    kept_dev = tuple(
        d for d in manifest.dev_deps
        if _dep_matches_profile(d, profile, active_flags)
    )
    if len(kept) == len(manifest.deps) and len(kept_dev) == len(manifest.dev_deps):
        return manifest
    return dc_replace(manifest, deps=kept, dev_deps=kept_dev)


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
    digits = [int(x) for x in parts[:3]]
    while len(digits) < 3:
        digits.append(0)
    triple = Version(*digits)
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


def _prior_self_mirrors_for(name: str, prior_lockfile) -> tuple[str, ...]:
    """Return self-mirrors cached in the prior lockfile for `name`
    (#79). Empty tuple when no prior or no entry."""
    if prior_lockfile is None:
        return ()
    for d in prior_lockfile.deps:
        if d.name == name:
            return d.self_mirrors
    return ()


def _git_pin_for_url_dep(
    dep: UrlDep, prior_lockfile
) -> tuple[str, str | None] | None:
    """Return ``(locked_identity, locked_commit_sha)`` for ``dep`` iff the
    manifest's git+ref still matches the lockfile's recorded
    GitProvenanceRecord.  Drops the pin on any user-visible change (different
    URL, different ref) so an intentional manifest edit is never rejected as a
    'hostile mirror'.

    Both identity AND commit_sha come from the same matched record — single
    source of truth.  The commit_sha may be None for old lockfiles that
    pre-date the field; in that case callers fall back to ref-tip checkout
    (legacy behaviour).

    Returns None when there is no prior lockfile, no matching entry, or the
    provenance has changed."""
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
        return (locked.identity, primary.commit_sha)
    return None


def _pin_for_url_dep(dep: UrlDep, prior_lockfile) -> str | None:
    """Return the locked identity for `dep` iff the manifest's git+ref
    still matches the lockfile's recorded GitProvenanceRecord.

    Thin wrapper around ``_git_pin_for_url_dep`` for callers that only need
    the identity (kept for back-compat with existing call sites outside
    ``_process_url``)."""
    result = _git_pin_for_url_dep(dep, prior_lockfile)
    return result[0] if result is not None else None


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


def _named_source_display(name: str, prov: Provenance) -> str:
    """Human-readable `source` marker for a named dep's resolved
    provenance. Display / member-marker only — never parsed back; the
    lockfile reconstructs the record by dispatching on the typed
    `provenance` object (milpa#97 / Option A)."""
    if isinstance(prov, GitProvenance):
        return prov.url
    if isinstance(prov, OciProvenance):
        return f"oci:{prov.registry}/{prov.repository}"
    return name


def _process_url(
    dep: UrlDep,
    deps_dir: Path,
    fetcher: FetcherRegistry,
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
    # Single lookup: both identity pin AND commit_sha come from the same
    # matched lockfile record — no duplicated matching logic (#82).
    git_pin = _git_pin_for_url_dep(dep, prior_lockfile)
    expected_identity: str | None
    pinned_commit_sha: str | None
    if git_pin is not None:
        expected_identity, pinned_commit_sha = git_pin
    else:
        expected_identity, pinned_commit_sha = None, None
    # Primary candidate carries the pinned commit_sha so GitFetcher checks
    # out the immutable commit rather than the (mutable) ref tip.  When
    # commit_sha is None (no prior lockfile, or pre-pin old lock), the
    # existing ref-tip checkout behaviour is preserved (#82 + #97).
    candidates = [GitProvenance(url=dep.git, ref=dep.ref,
                                commit_sha=pinned_commit_sha)]
    # Consumer-declared dep-mirrors next (#37).  A git mirror of the same
    # content can also use the commit_sha — the same commit on a mirror is
    # the same bytes (immutable object hash).
    for mirror_url in dep.mirrors:
        candidates.append(GitProvenance(url=mirror_url, ref=dep.ref,
                                        commit_sha=pinned_commit_sha))
    # Self-mirrors cached from prior lockfile (#79): the dep's own
    # milpa.kdl declared them on a previous resolve; available now as
    # additional fall-back candidates even before this fetch succeeds.
    for sm_url in _prior_self_mirrors_for(dep.name, prior_lockfile):
        candidates.append(GitProvenance(url=sm_url, ref=dep.ref,
                                        commit_sha=pinned_commit_sha))
    result = fetcher.fetch_any(
        dep.name,
        candidates,
        dest=deps_dir / dep.name,
        expected_identity=expected_identity,
    )
    sha = _commit_sha_or_none(result.receipt)
    # Prefer milpa.kdl if present (#90); falls back to .nimble for
    # legacy Nim packages that don't yet ship a milpa manifest.
    milpa_kdl_path = result.path / "milpa.kdl"
    active_flags: tuple[str, ...] = ()
    flag_defines: tuple = ()
    self_mirrors: tuple[str, ...] = ()
    if milpa_kdl_path.exists():
        (terms, requires_names, src_dir_value, new_items,
         active_flags, flag_defines,
         self_mirrors) = _extract_from_milpa_kdl(
            milpa_kdl_path, dep.name,
            overrides_by_name,
            consumer_flag_requests=dep.flag_requests,
        )
    else:
        nimble_path = _find_nimble_file(result.path, dep.name)
        nm = parse_nimble(nimble_path.read_text())
        terms, requires_names, sub_url_deps, sub_named = _build_terms(
            nm, overrides_by_name,
        )
        src_dir_value = nm.src_dir or ""
        new_items = []
        for u in sub_url_deps:
            new_items.append(("url", u))
        for n in sub_named:
            new_items.append(("named", n.name, n.constraint))
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=dep.git, ref=dep.ref, sha=sha,
        identity=result.identity,
        src_dir=src_dir_value,
        dep_terms=terms, requires_names=requires_names,
        provenance=GitProvenance(url=dep.git, ref=dep.ref),
        active_flags=active_flags,
        flag_defines=flag_defines,
        self_mirrors=self_mirrors,
    )
    return candidate, new_items


def _extract_from_milpa_kdl(
    path,
    dep_name: str,
    overrides_by_name,
    consumer_flag_requests: tuple = (),
):
    """Parse a milpa.kdl manifest from a fetched transitive dep,
    compute the dep's active flag set, filter its `when flag=...`
    blocks, and return (dep_terms, requires_names, src_dir, queue_items).

    `consumer_flag_requests` is a tuple of per-consumer FlagRequest
    tuples: each inner tuple is one consumer's requests on this dep.
    Cargo-style additive union: per-consumer effective set =
    declared-defaults overridden by that consumer's explicit values;
    final active set = UNION across consumers.

    Unknown flag requests are silently ignored (resolve-time tolerance)."""
    from .manifest import load_manifest
    manifest = load_manifest(path)

    declared_flags = {fd.name for fd in manifest.flags}
    defaults = {fd.name for fd in manifest.flags if fd.default}

    # Normalize: accept a flat tuple of FlagRequests (legacy single-
    # consumer form) by wrapping it; otherwise expect tuple-of-tuples.
    if consumer_flag_requests and isinstance(
        consumer_flag_requests[0], tuple,
    ):
        per_consumer = consumer_flag_requests
    elif consumer_flag_requests:
        per_consumer = (consumer_flag_requests,)
    else:
        per_consumer = ()

    active: set = set()
    if not per_consumer:
        # No external consumer; defaults apply (top-level case)
        active = set(defaults)
    else:
        for consumer_reqs in per_consumer:
            consumer_mentions = {
                fr.name: fr.enabled for fr in consumer_reqs
                if fr.name in declared_flags
            }
            effective = set()
            for fd in manifest.flags:
                if fd.name in consumer_mentions:
                    if consumer_mentions[fd.name]:
                        effective.add(fd.name)
                else:
                    if fd.default:
                        effective.add(fd.name)
            active |= effective
    active_frozen = frozenset(active)

    # Filter manifest.deps by `when flag=...` predicates (other
    # predicates default-permissive for now — profile-aware
    # transitive filtering is a separate concern).
    # NORMATIVE: manifest.dev_deps is intentionally NOT included here.
    # A transitive dep's dev-deps MUST NEVER enter the resolved graph;
    # only the root package's (and workspace members') dev_deps are enrolled
    # (see resolve() / _terms_from_member_manifest). This is the single
    # structural guard that enforces the transitive-exclusion rule.
    kept_deps = tuple(
        d for d in manifest.deps
        if _dep_passes_flag_predicates(d, active_frozen)
    )

    sub_terms: list[Term] = []
    sub_requires: list[str] = []
    sub_items: list = []
    for d in kept_deps:
        if isinstance(d, UrlDep):
            sub_terms.append(
                Term.require(d.name, VersionSet.eq(_URL_DEP_VERSION))
            )
            sub_requires.append(d.name)
            sub_items.append(("url", d))
        elif isinstance(d, NamedDep):
            if d.name == "nim":
                continue
            constraint_set = d.constraint_set if d.constraint_set is not None else VersionSet.full()
            sub_terms.append(
                Term.require(d.name, constraint_set)
            )
            sub_requires.append(d.name)
            sub_items.append(("named", d.name, d.constraint))
        # LocalDep / TarballDep / MemberDep from a transitive milpa.kdl
        # are out of scope for #90's initial slice; defer.
    # Compute flag_defines for nim.cfg emission (#23 cycle 11 wiring).
    # Only flags with explicit `defines` get an entry; flags with empty
    # defines use the convention -d:<dep>_<flag> at emission time.
    flag_defines = tuple(
        (fd.name, fd.defines) for fd in manifest.flags
        if fd.name in active_frozen and fd.defines
    )
    return (
        tuple(sub_terms), tuple(sub_requires),
        manifest.src_dir, sub_items,
        tuple(sorted(active_frozen)), flag_defines,
        manifest.self_mirrors,
    )


def _dep_passes_flag_predicates(dep, active_flags: frozenset) -> bool:
    """Check only flag predicates (other predicates evaluated elsewhere
    via the profile-filter path)."""
    preds = getattr(dep, "predicates", ())
    for p in preds:
        if p.name != "flag":
            continue
        any_match = any(v in active_flags for v in p.values)
        satisfied = (not any_match) if p.negated else any_match
        if not satisfied:
            return False
    return True


def _process_tarball(
    dep: TarballDep,
    deps_dir: Path,
    fetcher: FetcherRegistry,
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
        _build_terms(nm, overrides_by_name)
        if nm else ([], [], [], [])
    )
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=f"tarball:{dep.url}", ref=None, sha=None,
        identity=result.identity,
        src_dir=(nm.src_dir or "") if nm else "",
        dep_terms=terms, requires_names=requires_names,
        provenance=TarballProvenance(
            url=dep.url,
            expected_sha256=dep.sha256,
            strip_components=dep.strip_components,
        ),
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
        _build_terms(nm, overrides_by_name)
        if nm else ([], [], [], [])
    )
    candidate = _Candidate(
        name=dep.name, version=_URL_DEP_VERSION,
        source=f"local:{dep.path}", ref=None, sha=None,
        identity=result.identity,
        src_dir=(nm.src_dir or "") if nm else "",
        dep_terms=terms, requires_names=requires_names,
        # NOTE: local deps deliberately stay on the source-string fallback
        # (`local:<declared>`). LocalProvenance.path is absolute-truthful,
        # but the lockfile records the *declared relative* path — carrying
        # the typed object would write the abs path (a behavior change).
        # The `local:` prefix is unambiguous, so no typed dispatch is
        # needed here; the OCI-ambiguity driver for Option A doesn't apply.
    )
    new_items: list = []
    for u in sub_url_deps:
        new_items.append(("url", u))
    for n in sub_named:
        new_items.append(("named", n.name, n.constraint))
    return candidate, new_items


def _enumerate_named(
    name: str,
    constraint: str | None,
    deps_dir: Path,
    fetcher: "FetcherRegistry",
    index: Index,
    overrides_by_name: dict | None,
    provider: "_MaterializedProvider",
) -> None:
    """Phase A: enumerate all satisfying IndexVersions for `name` as
    lightweight stubs and register them in `provider`. No fetch occurs.

    Each stub carries the IndexVersion metadata + fetch context so that
    Phase B (_materialize_stub) is self-contained when the solver selects
    a version.

    Called synchronously from the BFS submit() for named deps (no
    thread needed — no I/O). Also called from the _on_new_named callback
    during Phase B for transitives discovered inline during solve.
    """
    index_versions = tianguis_client.resolve_named_all(index, name, constraint)
    stubs: list[_NamedDepStub] = []
    for iv in index_versions:
        ver = parse_version(iv.version)
        # resolve_named_all only returns parseable versions; this assert
        # guards the invariant.
        assert ver is not None, (
            f"resolve_named_all returned unparseable version "
            f"{iv.version!r} for {name!r}"
        )
        stubs.append(_NamedDepStub(
            name=name,
            version=ver,
            index_version=iv,
            deps_dir=deps_dir,
            fetcher=fetcher,
            overrides_by_name=overrides_by_name or {},
        ))
    provider.register_named_stubs(name, stubs)
    print(f"indexed {name} ({len(stubs)} version(s))", file=sys.stderr)


def _fetch_and_build_named_candidate(
    name: str,
    idx_ver: "tianguis_client.IndexVersion",
    version: Version,
    deps_dir: Path,
    fetcher: "FetcherRegistry",
    overrides_by_name: dict | None = None,
) -> tuple["_Candidate", list["UrlDep"], list]:
    """Shared fetch + parse core for named deps (M3 — single source of truth).

    Given an already-resolved IndexVersion and its pre-parsed `version`,
    fetches the dep at the index-pinned provenance, parses its nimble for
    transitive deps, and returns:
      (candidate, sub_url_deps, sub_named)

    `_materialize_stub` (Phase B) delegates to this function so there is
    exactly one fetch+parse+_build_terms+_Candidate path.

    Identity gate (Invariant 1) is enforced here: the index content_hash
    is the trust root for named deps."""
    if not idx_ver.content_hash:
        raise tianguis_client.TianguisError(
            code="TNG-NO-IDENTITY",
            message=(
                f"index entry for {name!r} version {idx_ver.version!r} "
                f"carries no content_hash — cannot verify fetched bytes. "
                f"This index entry is malformed; file a bug at "
                f"coreyleavitt/tianguis."
            ),
        )
    result = fetcher.fetch_any(
        name,
        list(idx_ver.provenances),
        dest=deps_dir / name,
        expected_identity=idx_ver.content_hash,
    )
    sha = _commit_sha_or_none(result.receipt)
    nimble_path = _find_nimble_file(result.path, name)
    nm = parse_nimble(nimble_path.read_text()) if nimble_path.exists() else None
    terms, requires_names, sub_url_deps, sub_named = (
        _build_terms(nm, overrides_by_name)
        if nm else ([], [], [], [])
    )
    # The chosen provenance for record reconstruction (Option A). Mirrors
    # are byte-identical by the identity gate, so the canonical (index-
    # first) provenance is the authoritative one to record even when a
    # mirror served the bytes.
    chosen = idx_ver.canonical_provenance
    candidate = _Candidate(
        name=name, version=version,
        source=_named_source_display(name, chosen),
        ref=getattr(chosen, "ref", None),
        sha=sha,
        identity=result.identity,
        src_dir=(nm.src_dir or "") if nm else "",
        dep_terms=terms, requires_names=requires_names,
        provenance=chosen,
    )
    return candidate, sub_url_deps, sub_named


def _build_terms(
    nm,
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
                try:
                    vset = VersionSet.from_constraint(req.constraint)
                except ValueError as e:
                    raise ManifestError(
                        f"dep {req.name!r}: malformed version constraint "
                        f"{req.constraint!r} in .nimble requires — {e}",
                        code="MAN-NIMBLE-CONSTRAINT",
                    ) from e
                terms.append(Term.require(req.name, vset))
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

    Raises ValueError if the derived name is a path-traversal vector
    (H3: a crafted URL tail like `..` must not produce a name that
    escapes `_deps/`). Uses the same pattern as `tianguis_client`'s
    `_validate_safe_name` — single source of truth for what is unsafe.
    """
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    # Validate: reject `..`, `/`, `\\`, absolute paths. Delegates to the
    # public predicate in tianguis_client — single source of truth for the
    # safe-name rule. ValueError is intentional here (the name came from a
    # URL in a .nimble, not from the tianguis index, so a TNG- code would
    # be semantically wrong).
    if not tianguis_client.is_safe_name(tail):
        raise ValueError(
            f"unsafe package name {tail!r} derived from URL {url!r} — "
            f"path traversal via URL tail is not permitted"
        )
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
            ref=c.ref, sha=c.sha,
            version=c.version,
            identity=c.identity,
            src_dir=c.src_dir,
            requires=tuple(c.requires_names),
            provenance=c.provenance,
            active_flags=c.active_flags,
            flag_defines=c.flag_defines,
            self_mirrors=c.self_mirrors,
        ))
    return ResolvedGraph(deps=tuple(out))
