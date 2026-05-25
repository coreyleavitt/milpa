"""milpa.kdl parser, formatter, and discovery.

Public surface, by intended use:
  - parse_manifest(text) / format_manifest(m) — pure text↔value pair
  - load_or_discover_manifest(project_dir) — entry point for the CLI;
    prefers milpa.kdl, falls back to <name>.nimble auto-promotion
  - load_manifest(path) — explicit-path loader (used internally by
    discover; exposed for tools that know exactly which file to read)
  - Value types: Manifest, UrlDep, NamedDep, Dep, ManifestError
  - manifest_from_nimble(nm) — convert a parsed NimbleManifest to a
    milpa Manifest (used by load_or_discover_manifest on the
    .nimble fallback path)

kdl-py is an internal detail; callers see only the typed values.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import ParseResult, urlparse

import kdl


Kind = Literal["library", "application"]


@dataclass(frozen=True)
class Predicate:
    """One conditional clause on a dep.

    `values` is the set of literal values the predicate is checked
    against. `negated=False` means the predicate is satisfied if the
    profile's value MATCHES any of `values` (OR semantics — #88).
    `negated=True` means the predicate is satisfied if the profile
    MATCHES NONE — equivalent to the (not) annotation applied to every
    value (De Morgan: NOT (a OR b) = NOT a AND NOT b).

    A mixed-negation clause (some args (not), some bare in a child
    node) is rejected at parse time as ambiguous."""
    name: str                    # one of: platform, arch, nim, milpa
    values: tuple[str, ...]
    negated: bool = False


@dataclass(frozen=True)
class FlagRequest:
    """A consumer's request for a specific flag state on a dep (#23).

    `enabled=True` turns the flag on; `enabled=False` explicitly opts
    out (overrides the dep's default-true)."""
    name: str
    enabled: bool = True


@dataclass(frozen=True)
class UrlDep:
    name: str
    git: str
    ref: str
    mirrors: tuple[str, ...] = ()    # fall-back URLs tried in order (#37)
    predicates: tuple[Predicate, ...] = ()    # conditional gates (#26)
    flag_requests: tuple[FlagRequest, ...] = ()    # consumer feature requests (#23)


@dataclass(frozen=True)
class MemberDep:
    """A dep declared as a workspace-internal reference.

    Resolved through the workspace's member table by `name` — not
    a fetch, not a filesystem path. Members live in their declared
    location within the workspace; they are NOT copied into `_deps/`.

    Grammar: `intonaco member` (bare keyword `member`, no value, no
    other properties). Valid only inside a workspace member's manifest;
    structural validation (member exists, name matches) happens at
    workspace-load time (W2).

    See #25 (umbrella) and W1 (#73).
    """
    name: str


@dataclass(frozen=True)
class TarballDep:
    """A dep declared by tarball URL (F2 / #41).

    `sha256` is optional — when set, the fetcher verifies the
    archive's hash BEFORE extraction (strictly stronger than git's
    "clone and hope"). When absent, the fetcher trusts the URL on
    first fetch and records the actual hash on the TarballReceipt
    so the lockfile can pin it for subsequent fetches (TOFU model).

    `strip_components` defaults to 0; the github-tarball idiom of
    "everything under <repo>-<sha>/" needs 1.

    See docs/rfc-pluggable-fetchers.md Phase F2.
    """
    name: str
    url: str
    sha256: str | None = None
    strip_components: int = 0


@dataclass(frozen=True)
class LocalDep:
    """A dep declared by local filesystem path.

    `path` is the literal user-supplied string (relative-to-project
    or absolute). The resolver lifts it to an absolute Path against
    the project root before constructing a LocalProvenance — keeping
    the string intent here means the lockfile can record portable
    workspace-relative provenance instead of machine-specific
    absolute paths.

    Grammar: `intonaco local="../intonaco"`.

    See docs/rfc-pluggable-fetchers.md Phase F3.
    """
    name: str
    path: str


@dataclass(frozen=True)
class NamedDep:
    """A dep declared by name (resolved via the registry).

    Appears in manifests promoted from .nimble files that have
    `requires "results"` or `requires "stew >= 0.5.0"` style lines.
    milpa.kdl-authored manifests use only UrlDep today; named deps
    would be added if/when KDL-level named-dep syntax is introduced.
    """
    name: str
    constraint: str | None   # e.g. ">= 0.5.0" or None for any version


Dep = UrlDep | NamedDep | LocalDep | TarballDep | MemberDep


@dataclass(frozen=True)
class Override:
    """A pkg-form override: any dep with this name resolves to this
    URL+ref instead of whatever the manifest or transitive resolution
    would otherwise produce.

    Project-wide scope: applies to manifest-direct deps, transitive
    URL deps, and named (registry-resolved) deps with the same name.
    Does not propagate to downstream consumers of this project.

    See docs/identity-and-provenance.md — overrides change provenance,
    identity follows whatever the override's content hashes to.
    """
    name: str
    git: str
    ref: str


@dataclass(frozen=True)
class FlagDecl:
    """A named feature flag declared by a package (#23).

    `default` is the flag's value when no consumer explicitly requests
    otherwise. `description` is human-facing documentation. `defines`
    are explicit `-d:` flags to pass to the Nim compiler when this
    flag is active; empty tuple means use the convention
    `-d:<package_name>_<flag_name>`."""
    name: str
    default: bool = False
    description: str = ""
    defines: tuple[str, ...] = ()


@dataclass(frozen=True)
class Manifest:
    deps: tuple[Dep, ...]
    kind: Kind
    name: str | None = None
    src_dir: str = ""
    overrides: tuple[Override, ...] = ()
    flags: tuple[FlagDecl, ...] = ()
    self_mirrors: tuple[str, ...] = ()    # alternative URLs where THIS package is hosted (#79)


@dataclass(frozen=True)
class WorkspaceManifest:
    """A workspace-root manifest. Pure container — declares member
    package paths and (optionally) workspace-level overrides that
    apply to every member's resolution (W5 #77 wires the application).

    Virtual-workspace-only: a workspace manifest may NOT carry deps
    or kind. To make the workspace root also be a package, put the
    package at a subdirectory and list it as a member.

    See #25 and W1 (#73) for the design.
    """
    members: tuple[str, ...]
    overrides: tuple["Override", ...] = ()


class ManifestError(Exception):
    """Raised when milpa.kdl is malformed or violates the schema.

    `code` is the stable error-catalog identifier (#14). New raise
    sites should always pass it; legacy single-arg raises remain
    valid (code is None) during the gradual instrumentation."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


# What the parser accepts. These are the source of truth for validation;
# the schema doc at milpa/schema/milpa.schema.kdl documents the same shape
# for humans. Drift between the two is checked indirectly via tests against
# example manifests.
_PACKAGE_TOP_LEVEL = frozenset({"deps", "kind", "overrides", "name", "src_dir", "flags", "mirrors"})
_PREDICATE_PROPS = frozenset({"platform", "arch", "nim", "milpa", "flag"})
_URL_DEP_PROPS = frozenset({"git", "ref"}) | _PREDICATE_PROPS
_VALID_KINDS: tuple[Kind, ...] = ("library", "application")
_VALID_GIT_SCHEMES = frozenset({"https", "http", "ssh", "git"})


def parse_workspace_or_manifest(
    text: str, *, source: str | None = None,
) -> "WorkspaceManifest | Manifest":
    """Parse a milpa.kdl source string into either a WorkspaceManifest (if it
    declares a `workspace { ... }` block) or a Manifest (package form).

    Virtual-workspace-only: the two roles are disjoint. A document
    with a `workspace` block is a workspace; one with `deps`/`kind`
    is a package. Mixing is rejected (see W1).
    """
    try:
        doc = kdl.parse(text)
    except kdl.errors.ParseError as e:
        raise ManifestError(
            f"KDL syntax error: {e}", code="MAN-KDL-SYNTAX",
        ) from e
    has_workspace = any(node.name == "workspace" for node in doc.nodes)
    if has_workspace:
        return _parse_workspace_doc(doc)
    return _parse_manifest_doc(doc)


_WORKSPACE_TOP_LEVEL = frozenset({"workspace", "name", "overrides"})


def _parse_workspace_doc(doc) -> "WorkspaceManifest":
    members: list[str] = []
    overrides: list[Override] = []
    seen_override_names: set[str] = set()
    for node in doc.nodes:
        if node.name in {"deps", "kind"}:
            raise ManifestError(
                f"a workspace manifest must not declare {node.name!r} — "
                f"workspaces are pure containers, not packages "
                f"(virtual-workspace-only); to make the root also a "
                f"package, declare `member \".\"` and put deps/kind in "
                f"the root member's milpa.kdl",
                code="MAN-WORKSPACE-HAS-DEPS-OR-KIND",
            )
        if node.name == "workspace":
            for child in node.nodes:
                if child.name != "member":
                    raise ManifestError(
                        f"unknown node {child.name!r} in workspace block "
                        f"(allowed: 'member')",
                        code="MAN-WORKSPACE-UNKNOWN-NODE",
                    )
                if len(child.args) != 1 or not isinstance(child.args[0], str):
                    raise ManifestError(
                        "workspace 'member' takes exactly one positional "
                        "string argument (the member directory path)",
                        code="MAN-WORKSPACE-MEMBER-ARITY",
                    )
                path = child.args[0]
                if path in members:
                    raise ManifestError(
                        f"duplicate workspace member {path!r}",
                        code="MAN-WORKSPACE-MEMBER-DUPLICATE",
                    )
                members.append(path)
        elif node.name == "overrides":
            for child in node.nodes:
                ov = _parse_override(child)
                if ov.name in seen_override_names:
                    raise ManifestError(
                        f"duplicate override for {ov.name!r}",
                        code="MAN-OVERRIDE-DUPLICATE",
                    )
                seen_override_names.add(ov.name)
                overrides.append(ov)
        elif node.name not in _WORKSPACE_TOP_LEVEL:
            allowed = ", ".join(sorted(_WORKSPACE_TOP_LEVEL))
            raise ManifestError(
                f"unknown top-level node {node.name!r} in workspace "
                f"manifest (allowed: {allowed})",
                code="MAN-WORKSPACE-UNKNOWN-TOP-LEVEL",
            )
    return WorkspaceManifest(
        members=tuple(members),
        overrides=tuple(overrides),
    )


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
        raise ManifestError(
            f"KDL syntax error: {e}", code="MAN-KDL-SYNTAX",
        ) from e
    return _parse_manifest_doc(doc)


def _parse_manifest_doc(doc) -> Manifest:
    deps: list[Dep] = []
    overrides: list[Override] = []
    flags: list[FlagDecl] = []
    self_mirrors: list[str] = []
    kind: Kind = "library"
    name: str | None = None
    src_dir: str = ""
    seen_names: set[str] = set()
    seen_override_names: set[str] = set()
    seen_flag_names: set[str] = set()
    for node in doc.nodes:
        if node.name == "name":
            if name is not None:
                raise ManifestError(
                    "duplicate top-level 'name' node — only one allowed",
                    code="MAN-NAME-DUPLICATE",
                )
            if len(node.args) != 1 or not isinstance(node.args[0], str):
                raise ManifestError(
                    "'name' takes exactly one positional string argument",
                    code="MAN-NAME-TYPE",
                )
            name = node.args[0]
            continue
        if node.name == "src_dir":
            if len(node.args) != 1 or not isinstance(node.args[0], str):
                raise ManifestError(
                    "'src_dir' takes exactly one positional string argument",
                    code="MAN-SRC-DIR-TYPE",
                )
            src_dir = node.args[0]
            continue
        if node.name == "deps":
            for child in node.nodes:
                for dep in _expand_dep_child(child, inherited_preds=()):
                    if dep.name in seen_names:
                        raise ManifestError(
                            f"duplicate dep {dep.name!r} in manifest",
                            code="MAN-DEP-DUPLICATE",
                        )
                    seen_names.add(dep.name)
                    deps.append(dep)
        elif node.name == "kind":
            kind = _parse_kind(node)
        elif node.name == "overrides":
            for child in node.nodes:
                ov = _parse_override(child)
                if ov.name in seen_override_names:
                    raise ManifestError(
                        f"duplicate override for {ov.name!r}",
                        code="MAN-OVERRIDE-DUPLICATE",
                    )
                seen_override_names.add(ov.name)
                overrides.append(ov)
        elif node.name == "flags":
            for child in node.nodes:
                fd = _parse_flag_decl(child)
                if fd.name in seen_flag_names:
                    raise ManifestError(
                        f"duplicate flag declaration {fd.name!r}",
                        code="MAN-FLAG-DUPLICATE",
                    )
                seen_flag_names.add(fd.name)
                flags.append(fd)
        elif node.name == "mirrors":
            # Top-level mirrors {} block declares URLs where THIS
            # package is hosted (#79). Each child is `mirror (url)"X"`.
            for child in node.nodes:
                if child.name != "mirror":
                    raise ManifestError(
                        f"unknown child node {child.name!r} in mirrors "
                        f"block (allowed: 'mirror')",
                        code="MAN-MIRRORS-UNKNOWN-CHILD",
                    )
                if len(child.args) != 1:
                    raise ManifestError(
                        "top-level 'mirror' takes exactly one positional "
                        "URL argument",
                        code="MAN-MIRRORS-ARITY",
                    )
                self_mirrors.append(
                    _url_arg("top-level mirrors", "mirror", child.args[0]),
                )
        elif node.name == "workspace":
            raise ManifestError(
                "'workspace' block found in a package manifest — "
                "workspace and package roles are disjoint "
                "(virtual-workspace-only). Use parse_workspace_or_manifest "
                "if you want to accept either kind.",
                code="MAN-WORKSPACE-IN-PACKAGE",
            )
        else:
            allowed = ", ".join(sorted(_PACKAGE_TOP_LEVEL))
            raise ManifestError(
                f"unknown top-level node {node.name!r} "
                f"(allowed: {allowed})",
                code="MAN-UNKNOWN-TOP-LEVEL",
            )
    if name is None:
        raise ManifestError(
            "package manifest is missing required top-level 'name' node "
            "(every package must self-identify; add: `name \"<your-name>\"`)",
            code="MAN-NAME-MISSING",
        )
    # Validate flag predicates against declared flags (#23/#90):
    # `when flag="X"` must reference a declared flag, else it's a typo.
    declared_flag_names = {fd.name for fd in flags}
    for dep in deps:
        for pred in getattr(dep, "predicates", ()):
            if pred.name != "flag":
                continue
            for v in pred.values:
                if v not in declared_flag_names:
                    allowed = ", ".join(repr(n) for n in sorted(declared_flag_names)) or "<none declared>"
                    raise ManifestError(
                        f"dep {dep.name!r}: `when flag={v!r}` references "
                        f"an undeclared flag (declared flags: {allowed})",
                        code="MAN-FLAG-UNDECLARED-REFERENCE",
                    )
    return Manifest(
        deps=tuple(deps),
        kind=kind,
        name=name,
        src_dir=src_dir,
        overrides=tuple(overrides),
        flags=tuple(flags),
        self_mirrors=tuple(self_mirrors),
    )


def load_manifest(path: Path) -> Manifest:
    """Read milpa.kdl from `path` and parse it.

    Raises `ManifestError` if the file is missing, unreadable, or
    malformed. The error message includes the path so the user can
    locate the offending file quickly.
    """
    try:
        text = path.read_text()
    except FileNotFoundError as e:
        raise ManifestError(
            f"manifest file not found: {path}", code="MAN-FILE-NOT-FOUND",
        ) from e
    except OSError as e:
        raise ManifestError(
            f"cannot read manifest {path}: {e}", code="MAN-FILE-UNREADABLE",
        ) from e
    return parse_manifest(text, source=str(path))


_MANIFEST_HEADER = "// generated by milpa; edit by hand or via `milpa add` / `milpa remove`"


def format_manifest(m: Manifest) -> str:
    """Render a Manifest to milpa.kdl text.

    Emits a deps {...} block (omitted if no deps) plus the kind line.
    UrlDeps use the recommended `(url)` annotation on the git value;
    NamedDeps emit as `name` alone or `name "<constraint>"`.

    Output is deterministic but does NOT preserve hand-written
    comments — comment-preserving serialization is #15's deliverable.
    """
    lines: list[str] = [_MANIFEST_HEADER, ""]
    if m.name is not None:
        lines.append(f'name "{m.name}"')
        lines.append("")
    if m.src_dir:
        lines.append(f'src_dir "{m.src_dir}"')
        lines.append("")
    if m.deps:
        lines.append("deps {")
        for dep in m.deps:
            lines.append(_format_dep_line(dep))
        lines.append("}")
        lines.append("")
    if m.overrides:
        lines.append("overrides {")
        for ov in m.overrides:
            lines.append(
                f'    pkg {_quote_name(ov.name)} '
                f'git=(url)"{ov.git}" ref="{ov.ref}"'
            )
        lines.append("}")
        lines.append("")
    if m.self_mirrors:
        lines.append("mirrors {")
        for url in m.self_mirrors:
            lines.append(f'    mirror (url)"{url}"')
        lines.append("}")
        lines.append("")
    if m.flags:
        lines.append("flags {")
        for fd in m.flags:
            parts = [f'    {_quote_name(fd.name)}']
            if fd.default:
                parts.append("default=true")
            else:
                parts.append("default=false")
            if fd.description:
                parts.append(f'description="{fd.description}"')
            if fd.defines:
                # Multi-line: head then defines child node
                lines.append(" ".join(parts) + " {")
                args = " ".join(f'"{d}"' for d in fd.defines)
                lines.append(f"        defines {args}")
                lines.append("    }")
            else:
                lines.append(" ".join(parts))
        lines.append("}")
        lines.append("")
    lines.append(f'kind "{m.kind}"')
    return "\n".join(lines) + "\n"


def _format_dep_line(dep: Dep) -> str:
    """One deps-block child as a single KDL line (or multi-line block
    when the dep has children — e.g. mirrors on a UrlDep)."""
    if isinstance(dep, UrlDep):
        head = (
            f'    {_quote_name(dep.name)} '
            f'git=(url)"{dep.git}" ref="{dep.ref}"'
        )
        # Single-value predicates emit inline; multi-value predicates
        # emit as child nodes (#88). Negation: (not) annotation on the
        # value (inline) or on every arg (child).
        inline_preds = [p for p in dep.predicates if len(p.values) == 1]
        child_preds = [p for p in dep.predicates if len(p.values) > 1]
        for pred in inline_preds:
            v = pred.values[0]
            if pred.negated:
                head += f' {pred.name}=(not)"{v}"'
            else:
                head += f' {pred.name}="{v}"'

        if not dep.mirrors and not child_preds and not dep.flag_requests:
            return head

        lines = [head + " {"]
        for pred in child_preds:
            args = " ".join(
                f'(not)"{v}"' if pred.negated else f'"{v}"'
                for v in pred.values
            )
            lines.append(f'        {pred.name} {args}')
        for url in dep.mirrors:
            lines.append(f'        mirror (url)"{url}"')
        for fr in dep.flag_requests:
            if fr.enabled:
                lines.append(f'        flag "{fr.name}"')
            else:
                lines.append(f'        flag "{fr.name}" false')
        lines.append("    }")
        return "\n".join(lines)
    if isinstance(dep, LocalDep):
        return f'    {_quote_name(dep.name)} local="{dep.path}"'
    if isinstance(dep, MemberDep):
        return f'    member "{dep.name}"'
    if isinstance(dep, TarballDep):
        # Only emit non-default properties — keeps minimal-form
        # manifests round-trip-stable without sha256/strip noise.
        parts = [
            f'    {_quote_name(dep.name)}',
            f'tarball=(url)"{dep.url}"',
        ]
        if dep.sha256 is not None:
            parts.append(f'sha256="{dep.sha256}"')
        if dep.strip_components != 0:
            parts.append(f'strip_components={dep.strip_components}')
        return " ".join(parts)
    # NamedDep
    if dep.constraint is None:
        return f'    {_quote_name(dep.name)}'
    return f'    {_quote_name(dep.name)} "{dep.constraint}"'


def format_workspace(w: WorkspaceManifest) -> str:
    """Render a WorkspaceManifest to milpa.kdl text. Counterpart of
    parse_workspace_or_manifest for the workspace branch."""
    lines: list[str] = [_MANIFEST_HEADER, ""]
    lines.append("workspace {")
    for member in w.members:
        lines.append(f'    member "{member}"')
    lines.append("}")
    return "\n".join(lines) + "\n"


def _quote_name(name: str) -> str:
    """Names always emitted as quoted strings — safe for any value
    (alphanumeric stays parseable as a bare identifier OR a quoted
    string, so we pick quoted for uniformity)."""
    return f'"{name}"'


def _parse_dep(node: kdl.Node) -> Dep:
    """Validate and convert one child of the `deps` block.

    Disambiguation: a child with `git=` property is a UrlDep; without
    it, it's a NamedDep (registry-resolved). Named deps may carry zero
    or one positional string argument for the version constraint.

    Examples:
        chronos git=(url)"..." ref="main"   → UrlDep
        results                              → NamedDep(name, constraint=None)
        stew ">= 0.5.0"                      → NamedDep(name, constraint=">= 0.5.0")
    """
    # `member "<name>"` is the workspace-internal dep form (symmetric
    # with `pkg "<name>"` in overrides). KDL doesn't allow bare-
    # identifier args, so a reserved leading keyword is the cleanest
    # way to disambiguate from NamedDep.
    if node.name == "member":
        return _parse_member_dep(node)
    if "git" in node.props:
        return _parse_url_dep(node)
    if "local" in node.props:
        return _parse_local_dep(node)
    if "tarball" in node.props:
        return _parse_tarball_dep(node)
    return _parse_named_dep(node)


def _parse_url_dep(node: kdl.Node) -> UrlDep:
    """Validate and convert a URL-shaped dep child."""
    name = node.name
    extra = set(node.props.keys()) - _URL_DEP_PROPS
    if extra:
        unknown = ", ".join(repr(p) for p in sorted(extra))
        allowed = ", ".join(sorted(_URL_DEP_PROPS))
        raise ManifestError(
            f"dep {name!r}: unknown property/properties {unknown} "
            f"(allowed: {allowed})",
            code="MAN-DEP-UNKNOWN-PROPS",
        )
    if "ref" not in node.props:
        raise ManifestError(
            f"dep {name!r}: missing required property 'ref'",
            code="MAN-DEP-REF-MISSING",
        )
    # `git` may be a plain str or a ParseResult (when written with the
    # `(url)` KDL type annotation, kdl-py auto-converts). Normalize to
    # str so UrlDep is shape-stable regardless of annotation choice.
    git_raw = node.props["git"]
    git = git_raw.geturl() if isinstance(git_raw, ParseResult) else git_raw
    _validate_git_url(name, git)
    mirrors, child_preds, flag_requests = _parse_url_dep_children(name, node)
    inline_preds = _parse_predicates(name, node)
    predicates = _merge_predicates(name, inline_preds, child_preds)
    return UrlDep(
        name=name, git=git, ref=node.props["ref"],
        mirrors=mirrors, predicates=predicates,
        flag_requests=flag_requests,
    )


def _url_arg(context: str, field: str, raw) -> str:
    """Normalize a URL argument: accepts either a bare string (legacy)
    or a urllib ParseResult (from KDL's `(url)` type annotation).
    Always returns the URL as a string."""
    if isinstance(raw, ParseResult):
        return raw.geturl()
    if isinstance(raw, str):
        return raw
    raise ManifestError(
        f"{context}: {field!r} expects a URL string "
        f"(plain or (url)-annotated); got {type(raw).__name__}",
        code="MAN-URL-ARG-TYPE",
    )


def _parse_url_dep_children(
    dep_name: str, node: kdl.Node,
) -> tuple[tuple[str, ...], tuple[Predicate, ...], tuple[FlagRequest, ...]]:
    """Split a UrlDep's child nodes into (mirror URLs, predicate
    child nodes, flag requests). Unknown children raise."""
    mirrors: list[str] = []
    child_preds: list[Predicate] = []
    flag_requests: list[FlagRequest] = []
    for child in node.nodes:
        if child.name == "mirror":
            if len(child.args) != 1:
                raise ManifestError(
                    f"dep {dep_name!r}: 'mirror' takes exactly one "
                    f"positional argument (the URL)",
                    code="MAN-DEP-MIRROR-ARITY",
                )
            mirrors.append(_url_arg(dep_name, "mirror", child.args[0]))
        elif child.name == "flag":
            flag_requests.append(_parse_flag_request(dep_name, child))
        elif child.name in _PREDICATE_PROPS:
            child_preds.append(
                _parse_predicate_child_node(f"dep {dep_name!r}", child),
            )
        else:
            raise ManifestError(
                f"dep {dep_name!r}: unknown child node {child.name!r} "
                f"(allowed: 'mirror', 'flag', or a predicate child node — "
                f"{', '.join(sorted(_PREDICATE_PROPS))})",
                code="MAN-DEP-UNKNOWN-CHILD",
            )
    return tuple(mirrors), tuple(child_preds), tuple(flag_requests)


def _parse_flag_request(dep_name: str, node: kdl.Node) -> FlagRequest:
    """Parse a consumer flag request on a dep.

    Grammar:
      flag "name"           # enable
      flag "name" true      # enable (explicit)
      flag "name" false     # opt out (overrides default-true)
    """
    if len(node.args) < 1 or not isinstance(node.args[0], str):
        raise ManifestError(
            f"dep {dep_name!r}: 'flag' requires a quoted name as the "
            f"first positional argument",
            code="MAN-DEP-FLAG-NAME-MISSING",
        )
    if len(node.args) > 2:
        raise ManifestError(
            f"dep {dep_name!r}: 'flag' takes at most two args "
            f"(name, optional bool)",
            code="MAN-DEP-FLAG-TOO-MANY-ARGS",
        )
    name = node.args[0]
    enabled = True
    if len(node.args) == 2:
        v = node.args[1]
        if not isinstance(v, bool):
            raise ManifestError(
                f"dep {dep_name!r}: 'flag {name!r}' second arg must be "
                f"a boolean",
                code="MAN-DEP-FLAG-BOOL",
            )
        enabled = v
    return FlagRequest(name=name, enabled=enabled)


def _merge_predicates(
    dep_name: str,
    inline: tuple[Predicate, ...],
    child: tuple[Predicate, ...],
) -> tuple[Predicate, ...]:
    """Combine inline-form + child-node-form predicates. Reject if the
    same predicate name appears in BOTH forms — that's ambiguous; the
    user should pick one form per predicate."""
    inline_names = {p.name for p in inline}
    child_names = {p.name for p in child}
    overlap = inline_names & child_names
    if overlap:
        names = ", ".join(sorted(overlap))
        raise ManifestError(
            f"dep {dep_name!r}: predicate(s) {names} declared in both "
            f"inline form (e.g. {next(iter(overlap))}=\"...\") and "
            f"child-node form ({{ {next(iter(overlap))} ... }}) — "
            f"pick one form per predicate",
            code="MAN-PREDICATE-FORM-CONFLICT",
        )
    # Canonical order: sort by predicate name so structural equality
    # holds regardless of which form (inline / child) the user chose
    # for each predicate.
    return tuple(sorted(inline + child, key=lambda p: p.name))


def _expand_dep_child(child: kdl.Node, *, inherited_preds: tuple[Predicate, ...]):
    """Yield one or more Dep values from a child of the `deps {}` block.

    A plain dep node yields itself (with inherited predicates appended).
    A `when` block yields each of its children with the block's
    predicates added to those inherited from any outer context.
    Block + inline predicates compose with AND."""
    if child.name == "when":
        block_preds = _parse_predicates_from_props(
            "<when block>", child.props,
        )
        all_preds = inherited_preds + block_preds
        for grandchild in child.nodes:
            yield from _expand_dep_child(grandchild, inherited_preds=all_preds)
        return
    dep = _parse_dep(child)
    if inherited_preds and isinstance(dep, UrlDep):
        from dataclasses import replace as dc_replace
        dep = dc_replace(dep, predicates=inherited_preds + dep.predicates)
    yield dep


def _parse_predicates_from_props(
    context: str, props,
) -> tuple[Predicate, ...]:
    """Shared predicate parser — works on a kdl.Node's props OR any
    mapping. Used by both inline dep predicates and when blocks.

    Single value per prop (KDL has no array value type). For OR
    semantics use the child-node form (#88) which goes through
    _parse_predicate_child_node."""
    preds: list[Predicate] = []
    for key, val in props.items():
        if key not in _PREDICATE_PROPS:
            raise ManifestError(
                f"{context}: unknown predicate {key!r} "
                f"(allowed: {', '.join(sorted(_PREDICATE_PROPS))})",
                code="MAN-PREDICATE-UNKNOWN",
            )
        tag = getattr(val, "tag", None)
        actual = getattr(val, "value", val)
        if not isinstance(actual, str):
            raise ManifestError(
                f"{context}: predicate {key!r} value must be a string",
                code="MAN-PREDICATE-VALUE-TYPE",
            )
        negated = (tag == "not")
        if tag is not None and not negated:
            raise ManifestError(
                f"{context}: predicate {key!r} unsupported "
                f"type annotation ({tag!r}); only (not) is recognized",
                code="MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
            )
        preds.append(Predicate(name=key, values=(actual,), negated=negated))
    return tuple(preds)


def _parse_predicate_child_node(
    context: str, child: kdl.Node,
) -> Predicate:
    """Parse a predicate expressed as a child node with positional args
    (e.g., `platform \"linux\" \"macosx\"` ≡ OR over those values).

    Per-arg (not) annotations are honored: ALL args must agree on
    negation. Mixing (some bare, some (not)) is rejected as ambiguous."""
    if child.name not in _PREDICATE_PROPS:
        raise ManifestError(
            f"{context}: unknown predicate {child.name!r} as child node "
            f"(allowed: {', '.join(sorted(_PREDICATE_PROPS))})",
            code="MAN-PREDICATE-UNKNOWN",
        )
    if not child.args:
        raise ManifestError(
            f"{context}: predicate child node {child.name!r} requires "
            f"at least one positional argument",
            code="MAN-PREDICATE-CHILD-NO-ARGS",
        )
    values: list[str] = []
    negations: list[bool] = []
    for a in child.args:
        tag = getattr(a, "tag", None)
        actual = getattr(a, "value", a)
        if not isinstance(actual, str):
            raise ManifestError(
                f"{context}: predicate {child.name!r} arg must be a string",
                code="MAN-PREDICATE-CHILD-ARG-TYPE",
            )
        neg = (tag == "not")
        if tag is not None and not neg:
            raise ManifestError(
                f"{context}: predicate {child.name!r} unsupported "
                f"type annotation ({tag!r}); only (not) is recognized",
                code="MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
            )
        values.append(actual)
        negations.append(neg)
    if len(set(negations)) > 1:
        raise ManifestError(
            f"{context}: predicate {child.name!r} mixes (not) and bare "
            f"args — all args must agree on negation",
            code="MAN-PREDICATE-MIXED-NEGATION",
        )
    return Predicate(
        name=child.name, values=tuple(values), negated=negations[0],
    )


def _parse_predicates(dep_name: str, node: kdl.Node) -> tuple[Predicate, ...]:
    """Extract predicate props from a UrlDep node. Predicates are the
    subset of props whose names are in _PREDICATE_PROPS; non-predicate
    props (git, ref) are silently ignored here (they're handled
    separately)."""
    pred_props = {k: v for k, v in node.props.items() if k in _PREDICATE_PROPS}
    return _parse_predicates_from_props(f"dep {dep_name!r}", pred_props)


_LOCAL_DEP_PROPS = frozenset({"local"})


def _parse_local_dep(node: kdl.Node) -> LocalDep:
    """Validate and convert a local-path dep child.

    Grammar: `<name> local="<path>"`. The path string is preserved
    verbatim; relative-to-project resolution happens in the resolver.
    """
    name = node.name
    extra = set(node.props.keys()) - _LOCAL_DEP_PROPS
    if extra:
        unknown = ", ".join(repr(p) for p in sorted(extra))
        raise ManifestError(
            f"dep {name!r}: unknown property/properties {unknown} "
            f"on a local dep (allowed: 'local')",
            code="MAN-DEP-UNKNOWN-PROPS",
        )
    path = node.props["local"]
    if not isinstance(path, str) or not path:
        raise ManifestError(
            f"dep {name!r}: 'local' property must be a non-empty string path",
            code="MAN-DEP-LOCAL-PATH",
        )
    return LocalDep(name=name, path=path)


_TARBALL_DEP_PROPS = frozenset({"tarball", "sha256", "strip_components"})


def _parse_tarball_dep(node: kdl.Node) -> TarballDep:
    """Validate and convert a tarball-form dep child.

    Grammar: `<name> tarball="<URL>" [sha256="<hex>"] [strip_components=<N>]`

    `sha256` is optional (TOFU on first fetch; lockfile pins
    thereafter). `strip_components` defaults to 0; set to 1 for
    GitHub-auto-generated tarballs that wrap content in `<repo>-<sha>/`.
    """
    name = node.name
    extra = set(node.props.keys()) - _TARBALL_DEP_PROPS
    if extra:
        unknown = ", ".join(repr(p) for p in sorted(extra))
        allowed = ", ".join(sorted(_TARBALL_DEP_PROPS))
        raise ManifestError(
            f"dep {name!r}: unknown property/properties {unknown} "
            f"on a tarball dep (allowed: {allowed})",
            code="MAN-DEP-UNKNOWN-PROPS",
        )
    url_raw = node.props["tarball"]
    url = url_raw.geturl() if isinstance(url_raw, ParseResult) else url_raw
    if not isinstance(url, str) or not url:
        raise ManifestError(
            f"dep {name!r}: 'tarball' must be a non-empty URL string",
            code="MAN-DEP-TARBALL-URL",
        )

    sha256 = node.props.get("sha256")
    if sha256 is not None and not isinstance(sha256, str):
        raise ManifestError(
            f"dep {name!r}: 'sha256' must be a string when provided",
            code="MAN-DEP-TARBALL-SHA",
        )

    strip_raw = node.props.get("strip_components", 0)
    # kdl-py parses bare numeric literals as float; accept ints or
    # integer-valued floats.
    if isinstance(strip_raw, float) and strip_raw.is_integer():
        strip_raw = int(strip_raw)
    if not isinstance(strip_raw, int) or isinstance(strip_raw, bool) or strip_raw < 0:
        raise ManifestError(
            f"dep {name!r}: 'strip_components' must be a non-negative integer",
            code="MAN-DEP-TARBALL-STRIP",
        )

    return TarballDep(
        name=name,
        url=url,
        sha256=sha256,
        strip_components=strip_raw,
    )


def _parse_member_dep(node: kdl.Node) -> MemberDep:
    """Validate and convert a workspace-internal member dep.

    Grammar: `member "<name>"`. Exactly one positional string
    argument (the member name); no properties.
    """
    if node.props:
        unknown = ", ".join(repr(p) for p in sorted(node.props.keys()))
        raise ManifestError(
            f"'member' dep takes no properties (got {unknown})",
            code="MAN-DEP-MEMBER-PROPS",
        )
    if len(node.args) != 1 or not isinstance(node.args[0], str):
        raise ManifestError(
            "'member' dep takes exactly one positional string argument "
            "(the workspace-member name)",
            code="MAN-DEP-MEMBER-ARITY",
        )
    return MemberDep(name=node.args[0])


def _parse_named_dep(node: kdl.Node) -> NamedDep:
    """Validate and convert a named (registry-resolved) dep child.

    Grammar: `<name> [<constraint-string>]`. Zero or one positional
    string argument. No properties (any property other than `git=`,
    which would route to URL path, is an error).
    """
    name = node.name
    if node.props:
        unknown = ", ".join(repr(p) for p in sorted(node.props.keys()))
        raise ManifestError(
            f"dep {name!r}: unknown property/properties {unknown} "
            f"on a named dep (a URL dep must declare 'git=...'; "
            f"a named dep takes only a positional version constraint)",
            code="MAN-DEP-NAMED-PROPS",
        )
    if len(node.args) == 0:
        return NamedDep(name=name, constraint=None)
    if len(node.args) == 1:
        constraint = node.args[0]
        if not isinstance(constraint, str):
            raise ManifestError(
                f"dep {name!r}: version constraint must be a quoted string",
                code="MAN-DEP-NAMED-CONSTRAINT",
            )
        return NamedDep(name=name, constraint=constraint)
    raise ManifestError(
        f"dep {name!r}: named deps take at most one positional argument "
        f"(the version constraint); got {len(node.args)}",
        code="MAN-DEP-NAMED-ARITY",
    )


_FLAG_DECL_PROPS = frozenset({"default", "description"})


def _parse_flag_decl(node: kdl.Node) -> FlagDecl:
    """Parse one child of the `flags { ... }` block.

    Grammar:
      <name> [default=<bool>] [description="..."] [{ defines "X" "Y" }]

    The node's identifier is the flag name. `defines` (a child node)
    overrides the convention `-d:<package>_<flag>` emission."""
    name = node.name
    if node.args:
        raise ManifestError(
            f"flag {name!r}: positional args not allowed "
            f"(use props: default=<bool>, description=\"...\")",
            code="MAN-FLAG-POS-ARGS",
        )
    extra = set(node.props.keys()) - _FLAG_DECL_PROPS
    if extra:
        unknown = ", ".join(repr(p) for p in sorted(extra))
        allowed = ", ".join(sorted(_FLAG_DECL_PROPS))
        raise ManifestError(
            f"flag {name!r}: unknown property/properties {unknown} "
            f"(allowed: {allowed})",
            code="MAN-FLAG-UNKNOWN-PROPS",
        )
    default_raw = node.props.get("default", False)
    if not isinstance(default_raw, bool):
        raise ManifestError(
            f"flag {name!r}: 'default' must be a boolean",
            code="MAN-FLAG-DEFAULT-TYPE",
        )
    description_raw = node.props.get("description", "")
    if not isinstance(description_raw, str):
        raise ManifestError(
            f"flag {name!r}: 'description' must be a string",
            code="MAN-FLAG-DESCRIPTION-TYPE",
        )
    defines: list[str] = []
    for child in node.nodes:
        if child.name != "defines":
            raise ManifestError(
                f"flag {name!r}: unknown child node {child.name!r} "
                f"(allowed: 'defines')",
                code="MAN-FLAG-UNKNOWN-CHILD",
            )
        for a in child.args:
            if not isinstance(a, str):
                raise ManifestError(
                    f"flag {name!r}: 'defines' args must be strings",
                    code="MAN-FLAG-DEFINES-ARG-TYPE",
                )
            defines.append(a)
    return FlagDecl(
        name=name,
        default=default_raw,
        description=description_raw,
        defines=tuple(defines),
    )


def _parse_override(node: kdl.Node) -> Override:
    """Validate and convert one child of the `overrides` block.

    Grammar (v0.x — pkg form only):
      pkg "<name>" git=(url)"<URL>" ref="<git-ref>"

    The first positional arg is the match name. The git= and ref=
    properties carry the substitute provenance.
    """
    if node.name != "pkg":
        raise ManifestError(
            f"unknown override kind {node.name!r} "
            f"(supported: 'pkg')",
            code="MAN-OVERRIDE-KIND",
        )
    if len(node.args) != 1 or not isinstance(node.args[0], str):
        raise ManifestError(
            "pkg override takes one positional argument (the dep name)",
            code="MAN-OVERRIDE-ARITY",
        )
    name = node.args[0]
    extra = set(node.props.keys()) - _URL_DEP_PROPS
    if extra:
        unknown = ", ".join(repr(p) for p in sorted(extra))
        allowed = ", ".join(sorted(_URL_DEP_PROPS))
        raise ManifestError(
            f"override for {name!r}: unknown property/properties {unknown} "
            f"(allowed: {allowed})",
            code="MAN-OVERRIDE-UNKNOWN-PROPS",
        )
    if "git" not in node.props:
        raise ManifestError(
            f"override for {name!r}: missing required property 'git'",
            code="MAN-OVERRIDE-GIT-MISSING",
        )
    if "ref" not in node.props:
        raise ManifestError(
            f"override for {name!r}: missing required property 'ref'",
            code="MAN-OVERRIDE-REF-MISSING",
        )
    git_raw = node.props["git"]
    git = git_raw.geturl() if isinstance(git_raw, ParseResult) else git_raw
    _validate_git_url(name, git)
    return Override(name=name, git=git, ref=node.props["ref"])


def _parse_kind(node: kdl.Node) -> Kind:
    if len(node.args) != 1:
        raise ManifestError(
            f"'kind' takes exactly one value (got {len(node.args)})",
            code="MAN-KIND-ARITY",
        )
    value = node.args[0]
    if value not in _VALID_KINDS:
        allowed = ", ".join(repr(k) for k in _VALID_KINDS)
        raise ManifestError(
            f"invalid kind {value!r} (allowed: {allowed})",
            code="MAN-KIND-INVALID",
        )
    return value


def _validate_git_url(dep_name: str, url: str) -> None:
    parsed = urlparse(url)
    if not parsed.scheme:
        raise ManifestError(
            f"dep {dep_name!r}: git URL {url!r} has no scheme "
            f"(expected one of: {', '.join(sorted(_VALID_GIT_SCHEMES))})",
            code="MAN-GIT-URL-NO-SCHEME",
        )
    if parsed.scheme not in _VALID_GIT_SCHEMES:
        raise ManifestError(
            f"dep {dep_name!r}: git URL {url!r} has unsupported scheme "
            f"{parsed.scheme!r} "
            f"(expected one of: {', '.join(sorted(_VALID_GIT_SCHEMES))})",
            code="MAN-GIT-URL-BAD-SCHEME",
        )


# ---------------------------------------------------------------------------
# .nimble compatibility — auto-promote a .nimble file when no milpa.kdl exists
# ---------------------------------------------------------------------------

def manifest_from_nimble(nm, *, name: str) -> "Manifest":  # nm: NimbleManifest
    """Convert a parsed NimbleManifest to a milpa Manifest.

    `name` is the package's intrinsic identity (W1, #73). For a .nimble
    auto-promotion, callers pass the stem of the .nimble filename (Nim
    convention — `myproject.nimble` is the manifest for package
    `myproject`).

    Mapping:
      - UrlRequirement   → UrlDep (name derived from URL last segment)
      - NamedRequirement → NamedDep (constraint preserved)
      - `nim` requirements are dropped — the compiler version is the
        v2 toolchain RFC's territory, not source-dep resolution.

    `kind` defaults to "library" since .nimble has no equivalent
    concept. Consumers who want the library/application distinction
    write milpa.kdl.
    """
    # Imported here to avoid a circular import at module load.
    from .nimble_parse import NamedRequirement, UrlRequirement

    deps: list[Dep] = []
    for req in nm.requires:
        if isinstance(req, UrlRequirement):
            dep_name = _name_from_url(req.url)
            deps.append(UrlDep(name=dep_name, git=req.url, ref=req.ref or "main"))
        elif isinstance(req, NamedRequirement):
            if req.name == "nim":
                continue
            deps.append(NamedDep(name=req.name, constraint=req.constraint))
    return Manifest(deps=tuple(deps), kind="library", name=name)


def _name_from_url(url: str) -> str:
    """Derive a package name from a git URL.

    `https://github.com/x/foo.git` → `foo`
    `https://github.com/x/foo`     → `foo`
    """
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail


def load_or_discover_manifest(project_dir: Path) -> Manifest:
    """Load milpa.kdl if present; otherwise auto-promote a .nimble file.

    Discovery order:
      1. <project_dir>/milpa.kdl — preferred. If present, wins regardless
         of any .nimble files present.
      2. <project_dir>/<project_dir_basename>.nimble — matches Nim
         convention of naming the .nimble after the project.
      3. Any single <project_dir>/*.nimble file — fallback when the
         project dir name doesn't match a .nimble. Ambiguous (multiple
         .nimble files) raises ManifestError.

    Raises ManifestError if no manifest source can be found or if the
    discovered source has parse errors.
    """
    milpa_kdl = project_dir / "milpa.kdl"
    if milpa_kdl.exists():
        return load_manifest(milpa_kdl)

    # Try <project_name>.nimble first
    project_name = project_dir.name
    primary = project_dir / f"{project_name}.nimble"
    if primary.exists():
        return _load_manifest_from_nimble(primary)

    # Fallback: any *.nimble
    candidates = sorted(project_dir.glob("*.nimble"))
    if len(candidates) == 1:
        return _load_manifest_from_nimble(candidates[0])
    if len(candidates) > 1:
        names = ", ".join(c.name for c in candidates)
        raise ManifestError(
            f"multiple .nimble files in {project_dir} ({names}); "
            f"either rename one to match the project directory "
            f"({project_name}.nimble) or add a milpa.kdl",
            code="MAN-NIMBLE-AMBIGUOUS",
        )

    raise ManifestError(
        f"no manifest found in {project_dir} — looked for "
        f"milpa.kdl, {project_name}.nimble, and any *.nimble",
        code="MAN-NO-MANIFEST",
    )


def _load_manifest_from_nimble(path: Path) -> Manifest:
    """Read a .nimble file and convert it to a milpa Manifest."""
    from .nimble_parse import NimbleParseError, parse_nimble
    try:
        text = path.read_text()
    except OSError as e:
        raise ManifestError(
            f"cannot read {path}: {e}", code="MAN-FILE-UNREADABLE",
        ) from e
    try:
        nm = parse_nimble(text)
    except NimbleParseError as e:
        raise ManifestError(
            f"failed to parse {path} as a nimble manifest: {e}",
            code="MAN-NIMBLE-PARSE",
        ) from e
    return manifest_from_nimble(nm, name=path.stem)
