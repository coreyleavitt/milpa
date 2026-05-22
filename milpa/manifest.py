"""milpa.kdl parser.

Public surface: parse_manifest(text), load_manifest(path), and the
value types Manifest / UrlDep, plus ManifestError for malformed input.
kdl-py is an internal detail; callers see only the typed values.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

import kdl


Kind = Literal["library", "application"]


@dataclass(frozen=True)
class UrlDep:
    name: str
    git: str
    ref: str


@dataclass(frozen=True)
class Manifest:
    deps: tuple[UrlDep, ...]
    kind: Kind


class ManifestError(Exception):
    """Raised when milpa.kdl is malformed or violates the schema."""


# What the parser accepts. These are the source of truth for validation;
# the schema doc at milpa/schema/milpa.schema.kdl documents the same shape
# for humans. Drift between the two is checked indirectly via tests against
# example manifests.
_TOP_LEVEL_NODES = frozenset({"deps", "kind"})
_URL_DEP_PROPS = frozenset({"git", "ref"})
_VALID_KINDS: tuple[Kind, ...] = ("library", "application")
_VALID_GIT_SCHEMES = frozenset({"https", "http", "ssh", "git"})


def parse_manifest(text: str, *, source: str | None = None) -> Manifest:
    """Parse a milpa.kdl source string into a typed Manifest.

    `source` is the file path (or other identifier) used in error
    messages; presently reserved for future use (error catalog work,
    issue #14). Raises `ManifestError` on malformed input or schema
    violations.
    """
    try:
        doc = kdl.parse(text)
    except kdl.errors.ParseError as e:
        raise ManifestError(f"KDL syntax error: {e}") from e
    deps: list[UrlDep] = []
    kind: Kind = "library"
    seen_names: set[str] = set()
    for node in doc.nodes:
        if node.name == "deps":
            for child in node.nodes:
                if child.name in seen_names:
                    raise ManifestError(
                        f"duplicate dep {child.name!r} in manifest"
                    )
                seen_names.add(child.name)
                deps.append(_parse_url_dep(child))
        elif node.name == "kind":
            kind = _parse_kind(node)
        else:
            allowed = ", ".join(sorted(_TOP_LEVEL_NODES))
            raise ManifestError(
                f"unknown top-level node {node.name!r} "
                f"(allowed: {allowed})"
            )
    return Manifest(deps=tuple(deps), kind=kind)


def load_manifest(path: Path) -> Manifest:
    """Read milpa.kdl from `path` and parse it.

    Raises `ManifestError` if the file is missing, unreadable, or
    malformed. The error message includes the path so the user can
    locate the offending file quickly.
    """
    try:
        text = path.read_text()
    except FileNotFoundError as e:
        raise ManifestError(f"manifest file not found: {path}") from e
    except OSError as e:
        raise ManifestError(f"cannot read manifest {path}: {e}") from e
    return parse_manifest(text, source=str(path))


def _parse_url_dep(node: kdl.Node) -> UrlDep:
    """Validate and convert one child of the `deps` block into a UrlDep."""
    name = node.name
    extra = set(node.props.keys()) - _URL_DEP_PROPS
    if extra:
        unknown = ", ".join(repr(p) for p in sorted(extra))
        allowed = ", ".join(sorted(_URL_DEP_PROPS))
        raise ManifestError(
            f"dep {name!r}: unknown property/properties {unknown} "
            f"(allowed: {allowed})"
        )
    if "git" not in node.props:
        raise ManifestError(f"dep {name!r}: missing required property 'git'")
    if "ref" not in node.props:
        raise ManifestError(f"dep {name!r}: missing required property 'ref'")
    git = node.props["git"]
    _validate_git_url(name, git)
    return UrlDep(name=name, git=git, ref=node.props["ref"])


def _parse_kind(node: kdl.Node) -> Kind:
    if len(node.args) != 1:
        raise ManifestError(
            f"'kind' takes exactly one value (got {len(node.args)})"
        )
    value = node.args[0]
    if value not in _VALID_KINDS:
        allowed = ", ".join(repr(k) for k in _VALID_KINDS)
        raise ManifestError(f"invalid kind {value!r} (allowed: {allowed})")
    return value


def _validate_git_url(dep_name: str, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ManifestError(
            f"dep {dep_name!r}: git URL {url!r} has no scheme "
            f"(expected one of: {', '.join(sorted(_VALID_GIT_SCHEMES))})"
        )
    if parsed.scheme not in _VALID_GIT_SCHEMES:
        raise ManifestError(
            f"dep {dep_name!r}: git URL {url!r} has unsupported scheme "
            f"{parsed.scheme!r} "
            f"(expected one of: {', '.join(sorted(_VALID_GIT_SCHEMES))})"
        )
