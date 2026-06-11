"""Tianguis index reader — `index.kdl` as the authoritative named-package
registry.

Per tianguis #7 (R4). Replaces the nim-lang/packages.json shape with
tianguis's richer model: per-version content_hash + OCI provenance +
attestation. No fallback to nim-lang — the vendor-en-absentia bot
guarantees coverage, and falling back would either be redundant or
actively wrong (e.g., bypassing an author's denylist opt-out).
"""

from __future__ import annotations

import hashlib
import re
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import kdl

from .error_catalog import ERROR_CATALOG
from .fetchers.git import GitProvenance
from .fetchers.oci import OciProvenance
from .fetchers.types import Provenance
from .solver import VersionSet, parse_version


# The only index schema version this milpa understands. A document
# declaring a *higher* version is refused (TNG-SCHEMA-UNKNOWN) rather than
# silently misread; a lower-or-equal version is read forward-compatibly.
TIANGUIS_INDEX_SCHEMA_VERSION: int = 1


# ---------------------------------------------------------------------------
# Format validators (single source of truth — called from index-parse path)
# These are pure helpers: they validate attacker-supplied strings from the
# index before those strings can reach subprocess argv or the filesystem.
# ---------------------------------------------------------------------------

_RE_40HEX = re.compile(r"^[0-9a-f]{40}$")
_RE_SHA256_64HEX = re.compile(r"^sha256:[0-9a-f]{64}$")
# Unsafe name components: `..`, any `/`, any `\`, or absolute paths.
_RE_UNSAFE_NAME = re.compile(r'[/\\]|\.\.')


def _validate_commit_sha(sha: str) -> None:
    """Reject commit_sha values that are not exactly 40 lowercase hex chars.

    This removes the flag-injection vector (`--upload-pack=rce`) and
    also the abbreviated-SHA ambiguity that the unshallow path exposed."""
    if not _RE_40HEX.fullmatch(sha):
        raise TianguisError(
            code="TNG-BAD-COMMIT-SHA",
            message=(
                f"commit_sha {sha!r} is not a valid 40-hex SHA1 — "
                f"expected exactly 40 lowercase hexadecimal characters"
            ),
        )


def _validate_no_leading_dash(value: str, field_name: str, code: str) -> None:
    """Reject values that begin with `-` — those would be interpreted as
    flags by git or oras when passed to a subprocess."""
    if value.startswith("-"):
        raise TianguisError(
            code=code,
            message=(
                f"{field_name} {value!r} begins with `-` and would be "
                f"interpreted as a command-line flag (flag injection)"
            ),
        )


def _validate_oci_digest(digest: str) -> None:
    """Reject OCI digests that are not `sha256:<64 lowercase hex>`.

    oras pins the pull to `@<digest>` so format correctness also prevents
    oras receiving a malformed reference string."""
    if not _RE_SHA256_64HEX.fullmatch(digest):
        raise TianguisError(
            code="TNG-BAD-OCI-DIGEST",
            message=(
                f"OCI digest {digest!r} is not in `sha256:<64 hex>` format"
            ),
        )


def is_safe_name(name: str) -> bool:
    """Return True iff `name` is safe to use as a filesystem path component
    under `_deps/`. Names containing `..`, `/`, `\\`, or that are absolute
    paths would escape the sandbox and are unsafe.

    Single source of truth for the safe-name rule — used by both the index
    parse path (via `_validate_safe_name`) and the URL-derived name check
    in the resolver (`_name_from_url`)."""
    return not (_RE_UNSAFE_NAME.search(name) or Path(name).is_absolute())


def _validate_safe_name(name: str) -> None:
    """Reject package names that are path-traversal vectors.

    Names flow directly into `deps_dir / name`, so `..`, `/`, `\\`, or
    an absolute path would escape the _deps/ sandbox."""
    if not is_safe_name(name):
        raise TianguisError(
            code="TNG-UNSAFE-NAME",
            message=(
                f"package name {name!r} contains path-traversal characters "
                f"(`..`, `/`, `\\`, or absolute path) — unsafe as a "
                f"filesystem path component under _deps/"
            ),
        )


class TianguisError(Exception):
    """Raised when tianguis lookup, parsing, or resolution fails.

    Carries a stable `code` (a TNG-* slug from the error catalog) so the
    CLI can print `code: message` per the error-catalog discipline and tests
    can assert on the code rather than brittle message substrings.

    The catalog is the single source of truth for valid TNG-* slugs
    (milpa/error_codes/tianguis_codes.py).  A typo in a code= raise site
    fails loudly at raise time via the catalog lookup below."""

    def __init__(self, *, code: str, message: str) -> None:
        if code not in ERROR_CATALOG:
            raise AssertionError(
                f"unknown tianguis error code {code!r} — add it to "
                f"milpa/error_codes/tianguis_codes.py"
            )
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class IndexVersion:
    """A single published version of a package, as recorded in tianguis.

    Named `IndexVersion` (not `Version`) to avoid colliding with
    `solver.Version` (a `tuple[int,int,int]` alias) in modules that import
    both concepts. "IndexVersion" reads as "a rich index record", not a
    version number.

    `content_hash` is what `milpa fetch` recomputes after unpacking the
    fetched source tree — divergence is a hard error per the identity
    invariant.

    `provenances` is **preference-ordered** (index node order): the first
    element is the index's canonical source, the rest are mirrors. Callers
    MUST NOT re-order — the identity gate (Invariant 1) makes any mirror
    yielding different bytes a hard error, so fall-through is safe. Mixed
    kinds (git + oci) are allowed; each is a fetcher `Provenance`.
    """
    version: str
    content_hash: str = ""
    provenances: tuple[Provenance, ...] = ()

    @property
    def canonical_provenance(self) -> Provenance:
        """The index's canonical (first) provenance. Raises if empty —
        an IndexVersion with no provenance is a malformed index entry and
        must be caught before any fetch is attempted (see resolve_named)."""
        if not self.provenances:
            raise TianguisError(
                code="TNG-NO-PROVENANCE",
                message=(
                    f"version {self.version!r} carries no provenance — "
                    f"malformed index entry (identity without a source)"
                ),
            )
        return self.provenances[0]


@dataclass(frozen=True)
class Package:
    """A package with one or more versions.

    `namespace` is the registry namespace (e.g. a GitHub org/user), forming
    the first half of the `(namespace, name)` identity key. Two packages may
    share a bare `name` under different namespaces (e.g. the nimkdl split:
    `greenm01/nimkdl` vs `coreyleavitt/nimkdl`) — this is the real identity.
    """
    name: str
    namespace: str
    versions: tuple[IndexVersion, ...]


@dataclass(frozen=True)
class AmbiguousName:
    """Returned by `Index.lookup_bare` when a bare `name` matches more than
    one namespace in the index. Callers decide the policy: resolve_named raises
    `TNG-AMBIGUOUS-NAME`; a future multi-version provider may enumerate all
    candidates for backtracking. This is a typed result, NOT an exception —
    keeping the registry primitive raise-free lets callers control flow.
    """
    name: str
    namespaces: list[str]


class Index:
    """Parsed tianguis index. Look up by (namespace, name) tuple key.

    The internal store is `dict[tuple[str, str], Package]` keyed on
    `(namespace, name)`. Two packages sharing a bare name under different
    namespaces are distinct entries — no silent drop.
    """

    def __init__(self, packages: dict[tuple[str, str], Package]) -> None:
        self._packages = packages

    def lookup(self, namespace: str, name: str) -> list[IndexVersion]:
        """Return the IndexVersion list for `(namespace, name)`, or [] if
        not found. The primary qualified entry point."""
        pkg = self._packages.get((namespace, name))
        return list(pkg.versions) if pkg is not None else []

    def lookup_bare(self, name: str) -> Package | AmbiguousName | None:
        """Look up by bare `name` without a namespace qualifier.

        - Unique match: returns the `Package`.
        - Collision (multiple namespaces): returns `AmbiguousName`; does NOT
          raise (the caller decides policy).
        - Not found: returns None.

        Load-bearing for P3.2/#100: the future multi-version provider
        enumerates candidates while backtracking — a raise inside this
        primitive would be a hard stop mid-solve.
        """
        matches = [pkg for (ns, n), pkg in self._packages.items() if n == name]
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        return AmbiguousName(
            name=name,
            namespaces=[pkg.namespace for pkg in matches],
        )


class IndexLoader(Protocol):
    """The seam for loading the tianguis index. Typed as a Protocol (not
    an untyped Callable alias) so a test fake with a misnamed kwarg fails
    at type-check time rather than at runtime (milpa#97).

    Canonical home in `tianguis_client` (next to `Index`/`load_index`)
    because "how to obtain an Index" is a tianguis-domain concern, not a
    CLI concern."""

    def __call__(self, *, cache_dir: Path) -> Index: ...


def _scalar_child(node: kdl.Node, name: str) -> str:
    """Return the first scalar-arg of `node`'s child named `name`, or "".

    Accepts both bare strings and `(url)`-annotated values: the tianguis
    index annotates every URL `(url)"https://..."` (the milpa KDL url
    convention), which the kdl lib parses into a urllib ParseResult, not a
    str. Without handling that, `url` fields silently read as "" and every
    git-vendored entry becomes unfetchable (caught by the S7 live test)."""
    from .kdl_util import url_value_to_str
    for c in node.nodes:
        if c.name == name and c.args:
            return url_value_to_str(c.args[0])
    return ""


def _scalar_int(node: kdl.Node) -> int | None:
    """Return the first argument of `node` as an int, or None if absent /
    non-integer. KDL emits `schema_version 1` as a bare int, so the
    str-only `_scalar_child` would silently miss it."""
    if not node.args:
        return None
    v = node.args[0]
    if isinstance(v, bool):  # bool is an int subclass — reject explicitly
        return None
    if isinstance(v, int):
        return v
    # The kdl lib parses bare KDL numbers (`schema_version 1`) as float.
    if isinstance(v, float):
        return int(v) if v.is_integer() else None
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return None
    return None


def _check_schema_version(doc: kdl.Document) -> None:
    """Refuse an index whose declared schema_version exceeds the one this
    milpa understands (TNG-SCHEMA-UNKNOWN). A lower-or-equal version reads
    normally — we are forward-compatible within a major. A missing node is
    tolerated (legacy/minimal indexes predate the field)."""
    for node in doc.nodes:
        if node.name == "schema_version":
            value = _scalar_int(node)
            if value is not None and value > TIANGUIS_INDEX_SCHEMA_VERSION:
                raise TianguisError(
                    code="TNG-SCHEMA-UNKNOWN",
                    message=(
                        f"index declares schema_version {value}, but this "
                        f"milpa understands at most "
                        f"{TIANGUIS_INDEX_SCHEMA_VERSION} — upgrade milpa"
                    ),
                )
            return


def _parse_version_node(ver_str: str, node: kdl.Node) -> IndexVersion:
    content_hash = _scalar_child(node, "content_hash")
    provenances: list[Provenance] = []
    for child in node.nodes:
        if child.name != "provenance":
            continue
        kind = _scalar_child(child, "kind")
        if kind == "git":
            url = _scalar_child(child, "url")
            ref = _scalar_child(child, "ref")
            commit_sha_raw = _scalar_child(child, "commit_sha") or None
            # Validate at the trust boundary: index-supplied values that
            # flow into git subprocess argv must be sanitized here so the
            # rest of the system can trust them (H2).
            _validate_no_leading_dash(url, "git url", "TNG-UNSAFE-URL")
            _validate_no_leading_dash(ref, "git ref", "TNG-UNSAFE-REF")
            if commit_sha_raw is not None:
                _validate_commit_sha(commit_sha_raw)
            provenances.append(GitProvenance(
                url=url,
                ref=ref,
                # commit_sha is the immutable pin (Invariant 2); absent on
                # legacy entries → None (GitFetcher falls back to ref tip).
                commit_sha=commit_sha_raw,
            ))
        elif kind == "oci":
            registry = _scalar_child(child, "registry")
            repository = _scalar_child(child, "repository")
            digest = _scalar_child(child, "digest")
            # Validate at the trust boundary: oci fields flow into oras
            # argv (M1). digest must be sha256:<64hex>.
            _validate_no_leading_dash(registry, "oci registry", "TNG-UNSAFE-OCI-FIELD")
            _validate_no_leading_dash(repository, "oci repository", "TNG-UNSAFE-OCI-FIELD")
            _validate_oci_digest(digest)
            provenances.append(OciProvenance(
                registry=registry,
                repository=repository,
                digest=digest,
            ))
        # Unknown kinds are skipped (forward-compat): a future transport
        # the index records but this milpa doesn't know how to fetch is
        # ignored rather than fatal — other provenances on the same
        # version may still be fetchable.
    return IndexVersion(
        version=ver_str,
        content_hash=content_hash,
        provenances=tuple(provenances),
    )


def _parse_namespace(node: kdl.Node) -> str:
    """Return the `namespace` child's first string arg, or "" if absent."""
    for child in node.nodes:
        if child.name == "namespace" and child.args and isinstance(child.args[0], str):
            return child.args[0]
    return ""


def parse_index(text: str) -> Index:
    """Parse an index.kdl document into a queryable Index.

    Internal store is keyed on `(namespace, name)` so two packages sharing
    a bare name under different namespaces are distinct entries (no silent
    drop). Use `Index.lookup(ns, name)` for qualified access or
    `Index.lookup_bare(name)` for a bare lookup that returns `AmbiguousName`
    on a collision rather than silently picking one.
    """
    try:
        doc = kdl.parse(text)
    except kdl.errors.ParseError as e:
        raise TianguisError(
            code="TNG-KDL-SYNTAX",
            message=f"KDL syntax error in index: {e}",
        ) from e
    _check_schema_version(doc)
    packages: dict[tuple[str, str], Package] = {}
    for node in doc.nodes:
        if node.name != "package":
            continue
        name = node.args[0] if node.args else None
        if not isinstance(name, str):
            # L12: malformed (non-string) package name — warn rather than
            # silently skip, consistent with the duplicate-version warn style.
            warnings.warn(
                f"package node with non-string name {name!r} skipped "
                f"(malformed index entry)",
                stacklevel=2,
            )
            continue
        # H3: reject path-traversal names at the trust boundary so they
        # never reach `deps_dir / name` (hard error, not warn — a crafted
        # `..`-name is an active attack vector, not just a formatting quirk).
        _validate_safe_name(name)
        namespace = _parse_namespace(node)
        versions: list[IndexVersion] = []
        seen: set[str] = set()
        for child in node.nodes:
            if child.name != "version":
                continue
            ver_str = child.args[0] if child.args else None
            if not isinstance(ver_str, str):
                continue
            # Duplicate-version tolerance: keep the first, warn, skip the
            # rest (forward-compat — a malformed double entry shouldn't be
            # fatal, consistent with the unknown-kind skip).
            if ver_str in seen:
                warnings.warn(
                    f"package {name!r} declares version {ver_str!r} more "
                    f"than once; keeping the first occurrence",
                    stacklevel=2,
                )
                continue
            seen.add(ver_str)
            versions.append(_parse_version_node(ver_str, child))
        # Sort newest-first by semver via a partition (no heterogeneous
        # sentinel): parseable versions descending, then the unparseable
        # ones in stable input order. Robust under any future sort change.
        parseable = [v for v in versions if parse_version(v.version) is not None]
        unparseable = [v for v in versions if parse_version(v.version) is None]
        parseable.sort(key=lambda v: parse_version(v.version), reverse=True)
        packages[(namespace, name)] = Package(
            name=name,
            namespace=namespace,
            versions=tuple(parseable + unparseable),
        )
    return Index(packages)


HttpGet = Callable[[str], str]
Clock = Callable[[], float]


# 24h — generous enough to avoid hammering tianguis on every CLI invocation
# during a normal dev day, short enough that vendor-en-absentia's daily
# pass is visible within the same cycle.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


# The live tianguis index. A single constant is the federation (#8) seam —
# one place to grow into a URL list later. The CLI imports this.
DEFAULT_INDEX_URL = (
    "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl"
)


def default_index_cache_dir() -> Path:
    """Global XDG index cache (`$XDG_CACHE_HOME/milpa/index/`, default
    `~/.cache/milpa/index/`). The index is the *registry* — shared across
    every project, not project state — so it lives outside any project's
    `_deps/` and is untouched by `milpa clean` (milpa#97). A single source
    of truth for the location, imported by the CLI and manifest writer."""
    import os
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "milpa" / "index"


def _real_http_get(url: str) -> str:
    import urllib.request
    # timeout so a wedged server can't hang the resolver forever.
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8")


def _real_clock() -> float:
    import time
    return time.time()


def _cache_path_for(url: str, cache_dir: Path) -> Path:
    """Stable per-URL cache filename. Hashing keeps it filesystem-safe
    across arbitrary URL shapes."""
    h = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return cache_dir / f"{h}.index.kdl"


def load_index(
    *,
    url: str,
    cache_dir: Path,
    http_get: HttpGet = _real_http_get,
    ttl_seconds: float = DEFAULT_TTL_SECONDS,
    clock: Clock = _real_clock,
) -> Index:
    """Fetch + cache + parse an index.kdl from `url`.

    Cache semantics:
      - fresh cache (age < ttl_seconds) → serve cached bytes, no network
      - stale cache (age >= ttl_seconds) → re-fetch, overwrite cache
      - missing cache → fetch, populate cache
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_path_for(url, cache_dir)

    now = clock()
    if cache_file.exists():
        age = now - cache_file.stat().st_mtime
        if age < ttl_seconds:
            return parse_index(cache_file.read_text())

    try:
        text = http_get(url)
    except Exception:
        # Offline fallback: if a cached copy exists (even if stale),
        # serve it rather than failing. The stale-but-available cache
        # is strictly more useful than a hard error for the common
        # "I'm on a plane / behind a flaky proxy" case.
        if cache_file.exists():
            return parse_index(cache_file.read_text())
        raise
    # Atomic write: two concurrent `milpa` invocations must never let one
    # read a half-written file the other is producing. Write a sibling temp
    # then os.replace (atomic rename on POSIX + Windows).
    import os
    tmp = cache_file.with_suffix(cache_file.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(text)
    os.replace(tmp, cache_file)
    # Stamp mtime explicitly so the injected clock controls cache age
    # in tests (otherwise the wall-clock mtime would race with the
    # injected clock and TTL math becomes meaningless).
    os.utime(cache_file, (now, now))
    return parse_index(text)


def resolve_named_all(idx: Index, name: str, constraint: str | None) -> list[IndexVersion]:
    """Resolve `name` against `idx` and return ALL satisfying IndexVersions,
    ordered descending by semver (newest first). This is the Phase-A enumerate
    step for P3.2's two-phase model: the caller registers the full candidate set
    into the provider so the solver can choose and backtrack.

    Same policy as `resolve_named` for structural errors (TNG-NOT-FOUND,
    TNG-AMBIGUOUS-NAME, TNG-NO-SATISFYING-VERSION, TNG-NO-PROVENANCE).
    Versions whose version string is unparseable are silently skipped
    (same behaviour as `resolve_named`).
    """
    result = idx.lookup_bare(name)
    if result is None:
        raise TianguisError(
            code="TNG-NOT-FOUND",
            message=(
                f"package {name!r} is not in tianguis "
                f"(every nim-lang/packages entry should be vendored — "
                f"if you've checked tianguis.dev and it's genuinely absent, "
                f"that's a vendor-bot bug; file at coreyleavitt/tianguis)"
            ),
        )
    if isinstance(result, AmbiguousName):
        raise TianguisError(
            code="TNG-AMBIGUOUS-NAME",
            message=(
                f"package {name!r} matches multiple namespaces: "
                f"{', '.join(sorted(result.namespaces))} — "
                f"use a namespace-qualified reference to disambiguate"
            ),
        )
    versions = list(result.versions)
    vs = VersionSet.from_constraint(constraint) if constraint else None

    satisfying: list[IndexVersion] = []
    provenance_less: list[str] = []   # version strings skipped due to no provenance
    for v in versions:
        parsed = parse_version(v.version)
        if parsed is None:
            continue
        if vs is None or vs.contains(parsed):
            if not v.provenances:
                # Skip provenance-less versions with a warning (forward-compat:
                # unknown or malformed entries should not block older valid
                # versions). Raise TNG-NO-PROVENANCE only if no satisfying
                # version with provenance remains (M12).
                provenance_less.append(v.version)
                import warnings
                warnings.warn(
                    f"{name!r} version {v.version!r} has no provenance in the "
                    f"index — skipping (malformed entry); older versions will be "
                    f"tried",
                    UserWarning,
                    stacklevel=2,
                )
                continue
            satisfying.append(v)

    if not satisfying:
        if provenance_less:
            # All satisfying versions lacked provenance — surface a coded error.
            raise TianguisError(
                code="TNG-NO-PROVENANCE",
                message=(
                    f"{name!r} has no fetchable version satisfying {constraint!r} "
                    f"— all satisfying versions lack provenance: "
                    f"{', '.join(provenance_less)}"
                ),
            )
        raise TianguisError(
            code="TNG-NO-SATISFYING-VERSION",
            message=(
                f"no version of {name!r} satisfies constraint {constraint!r} "
                f"(available: {', '.join(v.version for v in versions)})"
            ),
        )
    return satisfying


def resolve_named(idx: Index, name: str, constraint: str | None) -> IndexVersion:
    """Resolve `name` against `idx` and return the highest satisfying
    IndexVersion. Delegates to `resolve_named_all` and returns the first
    (highest-semver) result.

    Tianguis-only: a name not in the index is a hard error (no
    fallback). The vendor-en-absentia bot makes "missing from
    tianguis" a vendor-bot bug rather than a transient state worth
    routing around.

    Calls `lookup_bare` (the unqualified registry primitive). On a bare-name
    collision (AmbiguousName result), raises TNG-AMBIGUOUS-NAME at this policy
    layer — NOT inside the registry primitive, which stays raise-free for the
    multi-version provider's backtracking use (P3.2/#100).
    """
    # resolve_named_all returns versions in descending semver order; index 0
    # is the maximum satisfying version — the single-winner semantics.
    return resolve_named_all(idx, name, constraint)[0]
