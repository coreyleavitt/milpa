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

from .fetchers.oci import OciProvenance
from .solver import VersionSet, parse_version


@dataclass(frozen=True)
class Version:
    """A single published version of a package, as recorded in tianguis.

    `content_hash` is what `milpa fetch` recomputes after unpacking the
    OCI artifact — divergence is a hard error per the identity invariant.
    `provenances` is a list so multi-mirror support (R4a's federation
    cousin) drops in without an interface change.
    """
    version: str
    content_hash: str = ""
    provenances: tuple[OciProvenance, ...] = ()


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


def _parse_version_node(ver_str: str, node: kdl.Node) -> Version:
    content_hash = _scalar_child(node, "content_hash")
    provenances: list[OciProvenance] = []
    for child in node.nodes:
        if child.name != "provenance":
            continue
        kind = _scalar_child(child, "kind")
        if kind != "oci":
            # Only OCI is supported today. Other kinds (#43-#46) get
            # routed through their own fetchers once those land.
            continue
        provenances.append(OciProvenance(
            registry=_scalar_child(child, "registry"),
            repository=_scalar_child(child, "repository"),
            digest=_scalar_child(child, "digest"),
        ))
    return Version(
        version=ver_str,
        content_hash=content_hash,
        provenances=tuple(provenances),
    )


def parse_index(text: str) -> Index:
    """Parse an index.kdl document into a queryable Index."""
    doc = kdl.parse(text)
    packages: dict[str, Package] = {}
    for node in doc.nodes:
        if node.name != "package":
            continue
        name = node.args[0] if node.args else None
        if not isinstance(name, str):
            continue
        versions: list[Version] = []
        for child in node.nodes:
            if child.name != "version":
                continue
            ver_str = child.args[0] if child.args else None
            if not isinstance(ver_str, str):
                continue
            versions.append(_parse_version_node(ver_str, child))
        # Sort newest-first by semver. Unparseable versions sort last
        # (treated as "pre-history" — resolver's maxver strategy then
        # naturally skips them in favor of the canonical-semver ones).
        versions.sort(
            key=lambda v: parse_version(v.version) or (-1,),
            reverse=True,
        )
        packages[name] = Package(name=name, versions=tuple(versions))
    return Index(packages)


HttpGet = Callable[[str], str]
Clock = Callable[[], float]


# 24h — generous enough to avoid hammering tianguis on every CLI invocation
# during a normal dev day, short enough that vendor-en-absentia's daily
# pass is visible within the same cycle.
DEFAULT_TTL_SECONDS = 24 * 60 * 60


def _real_http_get(url: str) -> str:
    import urllib.request
    with urllib.request.urlopen(url) as resp:
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
    cache_file.write_text(text)
    # Stamp mtime explicitly so the injected clock controls cache age
    # in tests (otherwise os.write's wall-clock mtime would race with
    # the injected clock and TTL math becomes meaningless).
    import os
    os.utime(cache_file, (now, now))
    return parse_index(text)


class TianguisError(Exception):
    """Raised when tianguis lookup or resolution fails."""


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
            f"package {name!r} is not in tianguis "
            f"(every nim-lang/packages entry should be vendored — "
            f"if you've checked tianguis.dev and it's genuinely absent, "
            f"that's a vendor-bot bug; file at coreyleavitt/tianguis)"
        )

    vs = VersionSet.from_constraint(constraint) if constraint else None
    # Versions arrive descending-semver; first match is the max satisfying.
    for v in versions:
        parsed = parse_version(v.version)
        if parsed is None:
            continue
        if vs is None or vs.contains(parsed):
            return v

    raise TianguisError(
        f"no version of {name!r} satisfies constraint {constraint!r} "
        f"(available: {', '.join(v.version for v in versions)})"
    )
