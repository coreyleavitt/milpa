"""Nim package registry resolver.

Resolves named-package dependencies via nim-lang/packages's
packages_official.json. Splits responsibility cleanly:

  - Pure decision logic: parse_version, resolve_version, parse_registry
    — testable with synthetic data, zero I/O. Constraint matching
    routes through VersionSet (solver layer) so there's one source of
    truth for 'does version v satisfy constraint c?' across milpa.
  - I/O wrappers: load_registry (fetch + cache + parse) and
    list_remote_tags (subprocess git ls-remote) — testable against
    local fixtures.
  - Glue: resolve_named threads everything together.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import json
import re
import subprocess

import requests

from .solver import VersionSet


DEFAULT_REGISTRY_URL = (
    "https://github.com/nim-lang/packages/raw/master/packages.json"
)


@dataclass(frozen=True)
class RegistryEntry:
    name: str
    url: str
    method: str   # "git" usually; some legacy entries use "hg"


@dataclass(frozen=True)
class ResolvedRegistryDep:
    name: str
    url: str
    tag: str        # verbatim tag (e.g. "v0.5.1") — for `git checkout`
    version: str    # normalized version (e.g. "0.5.1") — for the lockfile


class RegistryError(Exception):
    """Raised when a named dep cannot be resolved against the registry."""


def parse_registry(text: str) -> dict[str, RegistryEntry]:
    """Parse packages_official.json text into a name → RegistryEntry map.

    Skips entries that lack a name or url. method defaults to 'git' when
    absent (nim-lang/packages convention).
    """
    raw = json.loads(text)
    if not isinstance(raw, list):
        raise RegistryError(
            f"expected packages.json to be a JSON array, got {type(raw).__name__}"
        )
    registry: dict[str, RegistryEntry] = {}
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        url = entry.get("url")
        if not (isinstance(name, str) and isinstance(url, str)):
            continue
        method = entry.get("method", "git")
        if not isinstance(method, str):
            method = "git"
        registry[name] = RegistryEntry(name=name, url=url, method=method)
    return registry


Version = tuple[int, int, int]


def parse_version(tag: str) -> Version | None:
    """Parse a tag string into a (major, minor, patch) triple.

    Returns None for tags milpa v0 doesn't model (prereleases, build
    metadata, non-canonical prefixes). Skipped tags are filtered out of
    the candidate set before version matching.
    """
    m = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    if m is None:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def load_registry(
    *,
    cache_path: Path,
    source_url: str = DEFAULT_REGISTRY_URL,
) -> dict[str, RegistryEntry]:
    """Load the registry from `cache_path`, fetching from `source_url`
    if the cache is absent.

    On fetch failure, raises RegistryError. The cache is the source of
    truth across repeated invocations — refresh by deleting the file or
    calling load_registry with a different cache_path.
    """
    if cache_path.exists():
        return parse_registry(cache_path.read_text())
    try:
        response = requests.get(source_url, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        raise RegistryError(
            f"failed to fetch registry from {source_url}: {e}"
        ) from e
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(response.text)
    return parse_registry(response.text)


def resolve_named(
    name: str,
    constraint: str | None,
    *,
    registry: dict[str, RegistryEntry],
    list_tags: Callable[[str], list[str]] = None,  # type: ignore[assignment]
    strategy: str = "maxver",
) -> ResolvedRegistryDep:
    """Resolve a named dep against the registry, returning the best
    version that satisfies `constraint` under `strategy`.

    `list_tags` defaults to the network-touching list_remote_tags; tests
    inject a fake. Raises RegistryError if `name` isn't in the registry
    or no tag satisfies the constraint.
    """
    if list_tags is None:
        list_tags = list_remote_tags
    entry = registry.get(name)
    if entry is None:
        raise RegistryError(
            f"package {name!r} not found in registry "
            f"(available: {len(registry)} entries)"
        )
    tags = list_tags(entry.url)
    tag = resolve_version(constraint, tags, strategy=strategy)
    parsed = parse_version(tag)
    assert parsed is not None  # resolve_version only picks parseable tags
    version_str = ".".join(str(p) for p in parsed)
    return ResolvedRegistryDep(
        name=name, url=entry.url, tag=tag, version=version_str
    )


def list_remote_tags(url: str) -> list[str]:
    """Enumerate tags published on a remote git repository.

    Uses `git ls-remote --tags`. Returns the tag names (without the
    `refs/tags/` prefix and without dereferenced-tag `^{}` suffixes).
    Raises RegistryError on git failure (network, bad URL, etc.).
    """
    result = subprocess.run(
        ["git", "ls-remote", "--tags", url],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RegistryError(
            f"git ls-remote --tags {url} failed: "
            f"{result.stderr.strip() or 'non-zero exit'}"
        )
    tags: list[str] = []
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        ref = parts[1]
        if not ref.startswith("refs/tags/"):
            continue
        tag = ref[len("refs/tags/"):]
        # Skip the dereferenced-tag pointers (refs/tags/v1.0^{}) — those
        # point at the underlying commit, but the tag we want is the
        # plain refs/tags/v1.0 entry. Keep only the bare names.
        if tag.endswith("^{}"):
            continue
        tags.append(tag)
    return tags


def resolve_version(
    constraint: str | None,
    available: list[str],
    *,
    strategy: str = "maxver",
) -> str:
    """Pick a tag in `available` that satisfies `constraint`, per `strategy`.

    `strategy` may be "maxver" (default; highest), "minver" (lowest), or
    "semver" (highest within same major as the constraint's lower bound,
    falling back to highest when constraint has no lower bound).

    Returns the tag string (verbatim — keep the `v` prefix if present
    in the input). Tags milpa v0 doesn't model (prereleases, build
    metadata, non-canonical prefixes) are filtered out before matching.

    Raises RegistryError if no tag matches.
    """
    # Parse the constraint once into the canonical algebraic form; query
    # each candidate via .contains(). Same predicate semantics as the
    # solver — single source of truth (closes #67).
    vs = VersionSet.from_constraint(constraint)
    candidates: list[tuple[Version, str]] = []
    for tag in available:
        v = parse_version(tag)
        if v is None:
            continue
        if vs.contains(v):
            candidates.append((v, tag))
    if not candidates:
        raise RegistryError(
            f"no version satisfies {constraint!r} "
            f"(available: {available!r})"
        )
    candidates.sort(key=lambda x: x[0])
    if strategy == "minver":
        return candidates[0][1]
    if strategy == "semver":
        lower = _constraint_lower_bound(constraint)
        if lower is not None:
            same_major = [c for c in candidates if c[0][0] == lower[0]]
            if not same_major:
                raise RegistryError(
                    f"semver: no tag in same major as constraint "
                    f"lower bound (major={lower[0]}) — would require "
                    f"crossing a major boundary"
                )
            return same_major[-1][1]
        # No lower bound — fall back to maxver
    return candidates[-1][1]


def _constraint_lower_bound(constraint: str | None) -> Version | None:
    """Extract the lowest inclusive lower bound from a constraint string.
    Returns None if the constraint has no lower bound or is empty."""
    if constraint is None or constraint.strip() in ("", "any version"):
        return None
    for clause in constraint.split("&"):
        clause = clause.strip()
        parts = clause.split(None, 1)
        if len(parts) != 2:
            continue
        op, ver_str = parts[0], parts[1].strip()
        v = parse_version(ver_str)
        if v is None:
            continue
        if op in (">=", "=="):
            return v
    return None


