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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import kdl

from .fetchers.git import GitProvenance
from .fetchers.oci import OciProvenance
from .fetchers.types import Provenance
from .solver import VersionSet, parse_version


# The only index schema version this milpa understands. A document
# declaring a *higher* version is refused (TNG-SCHEMA-UNKNOWN) rather than
# silently misread; a lower-or-equal version is read forward-compatibly.
TIANGUIS_INDEX_SCHEMA_VERSION: int = 1


# The single source of truth for tianguis-domain error codes. The
# error-catalog bijection lint greps this one set. `TianguisError.__init__`
# validates against it so a typo'd code fails loudly at raise time.
_TNG_CODES: frozenset[str] = frozenset({
    "TNG-NOT-FOUND",
    "TNG-NO-SATISFYING-VERSION",
    "TNG-NO-PROVENANCE",
    "TNG-SCHEMA-UNKNOWN",
    "TNG-BAD-VERSION",
})


class TianguisError(Exception):
    """Raised when tianguis lookup, parsing, or resolution fails.

    Carries a stable `code` (one of `_TNG_CODES`) so the CLI can print
    `code: message` per the error-catalog discipline and tests can assert
    on the code rather than brittle message substrings."""

    def __init__(self, *, code: str, message: str) -> None:
        if code not in _TNG_CODES:
            raise AssertionError(
                f"unknown tianguis error code {code!r} — add it to _TNG_CODES"
            )
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class Version:
    """A single published version of a package, as recorded in tianguis.

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
        a Version with no provenance is a malformed index entry and must
        be caught before any fetch is attempted (see resolve_named)."""
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
    """A package with one or more versions."""
    name: str
    versions: tuple[Version, ...]


class Index:
    """Parsed tianguis index. Look up by name."""

    def __init__(self, packages: dict[str, Package]) -> None:
        self._packages = packages

    def lookup(self, name: str) -> list[Version]:
        pkg = self._packages.get(name)
        return list(pkg.versions) if pkg is not None else []


def _scalar_child(node: kdl.Node, name: str) -> str:
    """Return the first string-arg of `node`'s child named `name`, or ""."""
    for c in node.nodes:
        if c.name == name and c.args:
            v = c.args[0]
            if isinstance(v, str):
                return v
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


def _parse_version_node(ver_str: str, node: kdl.Node) -> Version:
    content_hash = _scalar_child(node, "content_hash")
    provenances: list[Provenance] = []
    for child in node.nodes:
        if child.name != "provenance":
            continue
        kind = _scalar_child(child, "kind")
        if kind == "git":
            provenances.append(GitProvenance(
                url=_scalar_child(child, "url"),
                ref=_scalar_child(child, "ref"),
                # commit_sha is the immutable pin (Invariant 2); absent on
                # legacy entries → None (GitFetcher falls back to ref tip).
                commit_sha=_scalar_child(child, "commit_sha") or None,
            ))
        elif kind == "oci":
            provenances.append(OciProvenance(
                registry=_scalar_child(child, "registry"),
                repository=_scalar_child(child, "repository"),
                digest=_scalar_child(child, "digest"),
            ))
        # Unknown kinds are skipped (forward-compat): a future transport
        # the index records but this milpa doesn't know how to fetch is
        # ignored rather than fatal — other provenances on the same
        # version may still be fetchable.
    return Version(
        version=ver_str,
        content_hash=content_hash,
        provenances=tuple(provenances),
    )


def parse_index(text: str) -> Index:
    """Parse an index.kdl document into a queryable Index."""
    doc = kdl.parse(text)
    _check_schema_version(doc)
    packages: dict[str, Package] = {}
    for node in doc.nodes:
        if node.name != "package":
            continue
        name = node.args[0] if node.args else None
        if not isinstance(name, str):
            continue
        versions: list[Version] = []
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
                import warnings
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
        packages[name] = Package(
            name=name, versions=tuple(parseable + unparseable),
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


def resolve_named(idx: Index, name: str, constraint: str | None) -> Version:
    """Resolve `name` against `idx` and return the highest satisfying
    Version. Constraint matching routes through VersionSet — same
    semantics as URL deps and registry-pinned deps.

    Tianguis-only: a name not in the index is a hard error (no
    fallback). The vendor-en-absentia bot makes "missing from
    tianguis" a vendor-bot bug rather than a transient state worth
    routing around.
    """
    versions = idx.lookup(name)
    if not versions:
        raise TianguisError(
            code="TNG-NOT-FOUND",
            message=(
                f"package {name!r} is not in tianguis "
                f"(every nim-lang/packages entry should be vendored — "
                f"if you've checked tianguis.dev and it's genuinely absent, "
                f"that's a vendor-bot bug; file at coreyleavitt/tianguis)"
            ),
        )

    vs = VersionSet.from_constraint(constraint) if constraint else None
    # Versions arrive descending-semver; first match is the max satisfying.
    for v in versions:
        parsed = parse_version(v.version)
        if parsed is None:
            continue
        if vs is None or vs.contains(parsed):
            # An entry that carries identity but no fetchable provenance
            # is malformed — catch it here, naming the package + version,
            # rather than letting an empty tuple reach fetch_any (which
            # raises an opaque "no candidates provided").
            if not v.provenances:
                raise TianguisError(
                    code="TNG-NO-PROVENANCE",
                    message=(
                        f"{name!r} version {v.version!r} has no provenance "
                        f"in the index — unfetchable (malformed entry)"
                    ),
                )
            return v

    raise TianguisError(
        code="TNG-NO-SATISFYING-VERSION",
        message=(
            f"no version of {name!r} satisfies constraint {constraint!r} "
            f"(available: {', '.join(v.version for v in versions)})"
        ),
    )
