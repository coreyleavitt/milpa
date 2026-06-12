"""milpa.kdl manifest data model and parser.

NO FILESYSTEM I/O.  This module is pure text↔value.  All file-loading
(``load_or_discover_manifest``, ``.nimble`` fallback discovery) lives in
``workspace.py`` / a loader helper.

Entry points:
  ``parse_manifest(text) -> Manifest``
      Parse a KDL 2.0 string into a typed ``Manifest``.
  ``parse_workspace_or_manifest(text) -> Manifest | WorkspaceManifest``
      Auto-detect role and dispatch to the appropriate parser.
  ``format_manifest(manifest) -> str``
      Serialize a ``Manifest`` to a KDL 2.0 string (fresh AST, not a round-trip).
      URL fields are emitted with ``(url)`` annotation (§2).
      ``spec-version`` is present/absent per §4.4.
      If the manifest had comments (``manifest.had_comments``), a warning is
      emitted to stderr (§8).

Data model (slices 3a–3c-4):
  ``Predicate``    — one conditional clause (inline or child-node form)
  ``FlagRequest``  — consumer flag request on a UrlDep child
  ``UrlDep``       — git + ref (+ optional mirrors / predicates / flags)
  ``NamedDep``     — registry-resolved dep; constraint pre-typed at parse
  ``LocalDep``     — local filesystem path dep
  ``TarballDep``   — tarball URL dep with optional sha256 / strip_components
  ``MemberDep``    — workspace-internal member reference
  ``Override``     — pkg-form override (name → git + ref)
  ``FlagDecl``     — named feature flag declared by a package
  ``Manifest``     — top-level package manifest
  ``WorkspaceManifest`` — workspace container

Later slices (3c-5..3d, 3e) slot in via the dispatch seam in
``_parse_dep_block`` / ``_parse_manifest_doc`` without touching this
skeleton.

Boundary criteria (RFC §4.2):
  - Imports ``kdl_io`` (the only kdl-py importer) via its typed façade.
  - Imports ``version.py`` for ``VersionSet.from_constraint``.
  - Imports ``errors.py`` for slug constants + ``MilpaError``.
  - NO ``kdl.*`` types cross the module boundary.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse

from milpa.errors import (
    MAN_CAS_DIR_MISSING,
    MAN_CAS_DIR_TYPE,
    MAN_DEP_DUPLICATE,
    MAN_DEP_FLAG_BOOL,
    MAN_DEP_FLAG_NAME_MISSING,
    MAN_DEP_FLAG_TOO_MANY_ARGS,
    MAN_DEP_LOCAL_PATH,
    MAN_DEP_MEMBER_ARITY,
    MAN_DEP_MEMBER_PROPS,
    MAN_DEP_MIRROR_ARITY,
    MAN_DEP_NAMED_ARITY,
    MAN_DEP_NAMED_CONSTRAINT,
    MAN_DEP_NAMED_PROPS,
    MAN_DEP_REF_MISSING,
    MAN_DEP_TARBALL_SHA,
    MAN_DEP_TARBALL_STRIP,
    MAN_DEP_TARBALL_URL,
    MAN_DEP_UNKNOWN_CHILD,
    MAN_DEP_UNKNOWN_PROPS,
    MAN_FLAG_DEFAULT_TYPE,
    MAN_FLAG_DEFINES_ARG_TYPE,
    MAN_FLAG_DESCRIPTION_TYPE,
    MAN_FLAG_DUPLICATE,
    MAN_FLAG_POS_ARGS,
    MAN_FLAG_UNDECLARED_REFERENCE,
    MAN_FLAG_UNKNOWN_CHILD,
    MAN_FLAG_UNKNOWN_PROPS,
    MAN_GIT_URL_BAD_SCHEME,
    MAN_GIT_URL_NO_SCHEME,
    MAN_KIND_ARITY,
    MAN_KIND_INVALID,
    MAN_MIRRORS_ARITY,
    MAN_MIRRORS_UNKNOWN_CHILD,
    MAN_NAME_DUPLICATE,
    MAN_NAME_MISSING,
    MAN_NAME_TYPE,
    MAN_OVERRIDE_ARITY,
    MAN_OVERRIDE_DUPLICATE,
    MAN_OVERRIDE_GIT_MISSING,
    MAN_OVERRIDE_KIND,
    MAN_OVERRIDE_REF_MISSING,
    MAN_OVERRIDE_UNKNOWN_PROPS,
    MAN_PREDICATE_CHILD_ARG_TYPE,
    MAN_PREDICATE_CHILD_NO_ARGS,
    MAN_PREDICATE_FORM_CONFLICT,
    MAN_PREDICATE_MIXED_NEGATION,
    MAN_PREDICATE_UNKNOWN,
    MAN_PREDICATE_UNSUPPORTED_ANNOTATION,
    MAN_PREDICATE_VALUE_TYPE,
    MAN_SPEC_VERSION_TYPE,
    MAN_SPEC_VERSION_UNSUPPORTED,
    MAN_SRC_DIR_TYPE,
    MAN_UNKNOWN_TOP_LEVEL,
    MAN_URL_ARG_TYPE,
    MAN_WORKSPACE_HAS_DEPS_OR_KIND,
    MAN_WORKSPACE_MEMBER_ARITY,
    MAN_WORKSPACE_MEMBER_DUPLICATE,
    MAN_WORKSPACE_UNKNOWN_NODE,
    MAN_WORKSPACE_UNKNOWN_TOP_LEVEL,
    MilpaError,
)
from milpa.kdl_io import (
    KdlDocument,
    KdlNode,
    has_kdl_comments,
    node_arg_str,
    node_arg_tag,
    node_arg_url,
    node_args,
    node_children,
    node_name,
    node_prop_bool,
    node_prop_int,
    node_prop_str,
    node_prop_tag,
    node_prop_url,
    node_props,
    nodes,
    parse_kdl,
)
from milpa.version import VersionSet

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

Kind = Literal["library", "application"]

MANIFEST_SPEC_VERSION: int = 1
"""Highest manifest spec-version epoch this implementation understands.

Bumped only for breaking semantic changes; additive changes stay within
the current epoch (P3 forward-unknown, §4.1).
"""

_VALID_KINDS: tuple[Kind, ...] = ("library", "application")
_VALID_GIT_SCHEMES: frozenset[str] = frozenset({"https", "http", "ssh", "git"})

# All recognized top-level node names for a package manifest (§3.1).
_PACKAGE_TOP_LEVEL: frozenset[str] = frozenset(
    {
        "name",
        "kind",
        "deps",
        "dev-deps",
        "overrides",
        "src_dir",
        "flags",
        "mirrors",
        "cas",
        "spec-version",
    }
)

# Property names recognized on a UrlDep node (dispatched to UrlDep, not NamedDep).
_URL_DEP_KNOWN_PROPS: frozenset[str] = frozenset(
    {"git", "ref", "platform", "arch", "nim", "milpa", "flag"}
)

# Recognized predicate property names.
_PREDICATE_PROPS: frozenset[str] = frozenset({"platform", "arch", "nim", "milpa", "flag"})

# Top-level nodes permitted in a workspace manifest.
_WORKSPACE_TOP_LEVEL: frozenset[str] = frozenset(
    {"workspace", "name", "overrides", "spec-version"}
)


# ---------------------------------------------------------------------------
# Data model — 3a
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Predicate:
    """One conditional clause on a dep.

    ``name`` is the predicate key (``platform``, ``arch``, ``nim``,
    ``milpa``, ``flag``).  ``values`` is the tuple of match tokens.
    ``negated=False`` → satisfied if ANY value matches (OR); ``negated=True``
    → satisfied if NO value matches.

    Both inline form (single-value property on the dep node) and child-node
    form (multi-value child node, OR semantics) are represented identically
    here — the distinction is erased at parse time.
    """

    name: str
    values: tuple[str, ...]
    negated: bool = False


@dataclass(frozen=True)
class FlagRequest:
    """A consumer's request for a specific flag state on a UrlDep.

    ``enabled=True`` turns the flag on (default); ``enabled=False``
    explicitly opts out (overrides a ``default=true`` declaration).
    """

    name: str
    enabled: bool = True


@dataclass(frozen=True)
class UrlDep:
    """A dep declared by git URL and ref.

    Grammar: ``<name> git=(url)"<URL>" ref="<git-ref>" [predicates] [{ … }]``

    ``mirrors`` are fallback URLs tried in order after ``git`` fails.
    ``predicates`` are evaluated before the dep is passed to the solver.
    ``flag_requests`` are consumer feature-flag requests to the dep.
    """

    name: str
    git: str
    ref: str
    mirrors: tuple[str, ...] = ()
    predicates: tuple[Predicate, ...] = ()
    flag_requests: tuple[FlagRequest, ...] = ()


@dataclass(frozen=True)
class NamedDep:
    """A dep resolved against the tianguis index.

    Grammar: ``<name>`` or ``<name> "<version-constraint>"``

    ``constraint`` is the raw string from the manifest (or ``None``
    when absent).  ``constraint_set`` is a pre-typed ``VersionSet``
    parsed at construction time (the #121 design: parse-to-typed-value
    once at the manifest parse boundary; illegal states unrepresentable).

    A malformed ``constraint`` string raises
    ``MilpaError(MAN_DEP_NAMED_CONSTRAINT)`` at construction time.
    """

    name: str
    constraint: str | None  # e.g. ">= 0.5.0" or None for any version
    constraint_set: VersionSet | None = field(default=None, compare=False, hash=False)

    def __post_init__(self) -> None:
        """Pre-type the constraint at construction time.

        Uses ``object.__setattr__`` because the dataclass is frozen.
        """
        if self.constraint is not None and self.constraint_set is None:
            try:
                parsed = VersionSet.from_constraint(self.constraint)
            except ValueError as exc:
                raise MilpaError(
                    MAN_DEP_NAMED_CONSTRAINT,
                    f"dep {self.name!r}: invalid version constraint "
                    f"{self.constraint!r}: {exc}",
                    dep=self.name,
                    constraint=self.constraint,
                ) from exc
            object.__setattr__(self, "constraint_set", parsed)


@dataclass(frozen=True)
class LocalDep:
    """A dep declared by local filesystem path.

    Grammar: ``<name> local="<path>"``

    ``path`` is the literal user-supplied string; the resolver lifts it
    to an absolute Path against the project root before constructing a
    provenance record.  LocalDep is NOT CAS-admissible.
    """

    name: str
    path: str


@dataclass(frozen=True)
class TarballDep:
    """A dep declared by tarball URL.

    Grammar:
        ``<name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]``

    ``sha256`` is optional (TOFU when absent).  ``strip_components``
    stripping is applied BEFORE ``content_hash`` computation.
    TarballDep IS CAS-admissible.
    """

    name: str
    url: str
    sha256: str | None = None
    strip_components: int = 0


@dataclass(frozen=True)
class MemberDep:
    """A workspace-internal member reference.

    Grammar: ``member "<member-name>"``

    The node name is the literal keyword ``member`` (not the package
    name).  The positional arg is the workspace member's intrinsic name.
    MemberDep is NOT CAS-admissible.
    """

    name: str


# Union of all dep forms.
Dep = UrlDep | NamedDep | LocalDep | TarballDep | MemberDep


@dataclass(frozen=True)
class Override:
    """A pkg-form override: any dep matching ``name`` resolves to this
    git URL + ref instead of the manifest or transitive result.

    Project-wide scope.  Does not propagate to downstream consumers.
    """

    name: str
    git: str
    ref: str


@dataclass(frozen=True)
class FlagDecl:
    """A named feature flag declared by a package.

    ``default`` is the flag's value when no consumer requests otherwise.
    ``description`` is human-facing documentation.
    ``defines`` are explicit ``-d:`` flags for the Nim compiler when
    active; empty tuple uses the convention ``-d:<pkg>_<flag>``.
    """

    name: str
    default: bool = False
    description: str = ""
    defines: tuple[str, ...] = ()


@dataclass(frozen=True)
class Manifest:
    """A parsed package manifest (milpa.kdl in package role).

    ``deps`` and ``dev_deps`` are both tuples of ``Dep`` values.
    ``spec_version_explicit`` is ``True`` iff the source declared a
    ``spec-version`` node (absent-stays-absent serialization rule, §4.4).
    ``had_comments`` is ``True`` iff the source text contained any KDL
    comments (``//``, ``/*``, or ``/-``).  When ``True``, ``format_manifest``
    emits a stderr warning (§8) because comments are dropped by the fresh-AST
    serializer.
    """

    name: str
    deps: tuple[Dep, ...]
    kind: Kind = "library"
    src_dir: str = ""
    overrides: tuple[Override, ...] = ()
    flags: tuple[FlagDecl, ...] = ()
    self_mirrors: tuple[str, ...] = ()
    cas_dir: str = ""
    spec_version: int = 1
    spec_version_explicit: bool = False
    dev_deps: tuple[Dep, ...] = ()
    had_comments: bool = False


@dataclass(frozen=True)
class WorkspaceManifest:
    """A workspace-root manifest.

    Pure container: declares member package paths and optional
    workspace-level overrides.  A workspace manifest MUST NOT declare
    ``deps`` or ``kind`` (``MAN-WORKSPACE-HAS-DEPS-OR-KIND``).
    """

    members: tuple[str, ...]
    overrides: tuple[Override, ...] = ()
    name: str | None = None


# ---------------------------------------------------------------------------
# Public parse entry points
# ---------------------------------------------------------------------------


def parse_manifest(text: str) -> Manifest:
    """Parse a KDL 2.0 string into a typed ``Manifest``.

    Raises ``MilpaError`` with the appropriate ``MAN-*`` slug on any
    structural or semantic error.  No filesystem I/O.

    Sets ``manifest.had_comments = True`` when the source text contains any
    KDL comments, so that ``format_manifest`` can warn on the comment-drop
    (§8).
    """
    comments_present = has_kdl_comments(text)
    doc = parse_kdl(text, context="manifest")
    m = _parse_manifest_doc(doc)
    if comments_present:
        # had_comments is frozen; use object.__setattr__ to set post-construction.
        object.__setattr__(m, "had_comments", True)
    return m


def parse_workspace_or_manifest(text: str) -> Manifest | WorkspaceManifest:
    """Auto-detect document role and parse accordingly.

    Returns ``WorkspaceManifest`` if a top-level ``workspace { }`` node
    is present; otherwise returns ``Manifest`` (package form).
    """
    doc = parse_kdl(text, context="manifest")
    has_workspace = any(node_name(n) == "workspace" for n in nodes(doc))
    if has_workspace:
        return _parse_workspace_doc(doc)
    comments_present = has_kdl_comments(text)
    m = _parse_manifest_doc(doc)
    if comments_present:
        object.__setattr__(m, "had_comments", True)
    return m


# ---------------------------------------------------------------------------
# Internal — manifest doc parser
# ---------------------------------------------------------------------------


def _check_flag_predicate_references(
    deps: list[Dep], declared_flag_names: frozenset[str]
) -> None:
    """Validate that all ``flag=`` predicate values name a declared flag.

    Walks ``UrlDep.predicates``; any ``Predicate(name='flag')`` whose
    values reference an undeclared flag name raises
    ``MAN-FLAG-UNDECLARED-REFERENCE``.
    """
    for dep in deps:
        if not isinstance(dep, UrlDep):
            continue
        for pred in dep.predicates:
            if pred.name != "flag":
                continue
            for value in pred.values:
                if value not in declared_flag_names:
                    raise MilpaError(
                        MAN_FLAG_UNDECLARED_REFERENCE,
                        f"dep {dep.name!r}: predicate references undeclared flag "
                        f"{value!r} — declare it in the 'flags' block first",
                        dep=dep.name,
                        flag=value,
                    )


def _parse_manifest_doc(doc: KdlDocument) -> Manifest:
    deps: list[Dep] = []
    dev_deps: list[Dep] = []
    overrides: list[Override] = []
    flags: list[FlagDecl] = []
    self_mirrors: list[str] = []
    kind: Kind = "library"
    name: str | None = None
    src_dir: str = ""
    cas_dir: str = ""
    spec_version: int = 1
    spec_version_explicit: bool = False
    seen_top_level: set[str] = set()

    for n in nodes(doc):
        nm = node_name(n)

        # --- spec-version ---
        if nm == "spec-version":
            epoch = _parse_spec_version_node(n)
            spec_version = epoch
            spec_version_explicit = True
            continue

        # --- workspace in a package manifest ---
        if nm == "workspace":
            raise MilpaError(
                MAN_WORKSPACE_HAS_DEPS_OR_KIND,
                "a workspace manifest must not declare 'kind' or 'deps' — "
                "and a package manifest must not declare 'workspace'",
            )

        # --- unknown top-level ---
        if nm not in _PACKAGE_TOP_LEVEL:
            raise MilpaError(
                MAN_UNKNOWN_TOP_LEVEL,
                f"unknown top-level node {nm!r} in package manifest "
                f"(allowed: {', '.join(sorted(_PACKAGE_TOP_LEVEL))})",
                node=nm,
            )

        # --- duplicate top-level ---
        if nm in seen_top_level and nm not in ("deps", "dev-deps"):
            pass  # handled per-node below for name/kind/src_dir
        seen_top_level.add(nm)

        if nm == "name":
            if name is not None:
                raise MilpaError(
                    MAN_NAME_DUPLICATE,
                    "duplicate top-level 'name' node — only one allowed",
                )
            v = node_arg_str(n, 0)
            if v is None:
                # Present but wrong type or missing
                raw_args = node_args(n)
                if len(raw_args) == 0:
                    raise MilpaError(
                        MAN_NAME_TYPE,
                        "'name' takes exactly one positional string argument",
                    )
                raise MilpaError(
                    MAN_NAME_TYPE,
                    f"'name' argument must be a string, got {type(raw_args[0]).__name__!r}",
                )
            name = v

        elif nm == "kind":
            raw_args = node_args(n)
            if len(raw_args) != 1:
                raise MilpaError(
                    MAN_KIND_ARITY,
                    "'kind' takes exactly one positional string argument "
                    "('library' or 'application')",
                )
            if not isinstance(raw_args[0], str):
                raise MilpaError(
                    MAN_KIND_ARITY,
                    "'kind' argument must be a string",
                )
            if raw_args[0] not in _VALID_KINDS:
                raise MilpaError(
                    MAN_KIND_INVALID,
                    f"'kind' must be 'library' or 'application', got {raw_args[0]!r}",
                    value=raw_args[0],
                )
            # raw_args[0] is in _VALID_KINDS so it is a Kind literal
            kind = raw_args[0] if raw_args[0] == "application" else "library"

        elif nm == "src_dir":
            v = node_arg_str(n, 0)
            if v is None:
                raise MilpaError(
                    MAN_SRC_DIR_TYPE,
                    "'src_dir' takes exactly one positional string argument",
                )
            src_dir = v

        elif nm == "cas":
            cas_dir = _parse_cas_block(n)

        elif nm == "deps":
            block_deps = _parse_dep_block(n, block_name="deps")
            deps.extend(block_deps)

        elif nm == "dev-deps":
            block_deps = _parse_dep_block(n, block_name="dev-deps")
            dev_deps.extend(block_deps)

        elif nm == "overrides":
            overrides = _parse_overrides_block(n)

        elif nm == "mirrors":
            self_mirrors = _parse_mirrors_block(n)

        elif nm == "flags":
            flags = _parse_flags_block(n)

    if name is None:
        raise MilpaError(
            MAN_NAME_MISSING,
            "manifest is missing required 'name' node",
        )

    # 3c-8 post-parse: check that all 'flag' predicate references name a
    # declared flag (MAN-FLAG-UNDECLARED-REFERENCE).
    declared_flag_names = frozenset(f.name for f in flags)
    _check_flag_predicate_references(
        list(deps) + list(dev_deps), declared_flag_names
    )

    return Manifest(
        name=name,
        deps=tuple(deps),
        kind=kind,
        src_dir=src_dir,
        overrides=tuple(overrides),
        flags=tuple(flags),
        self_mirrors=tuple(self_mirrors),
        cas_dir=cas_dir,
        spec_version=spec_version,
        spec_version_explicit=spec_version_explicit,
        dev_deps=tuple(dev_deps),
    )


def _parse_cas_block(n: KdlNode) -> str:
    """Parse a ``cas { dir "<path>" }`` block and return the dir string."""
    children = node_children(n)
    dir_children = [c for c in children if node_name(c) == "dir"]
    if not dir_children:
        raise MilpaError(
            MAN_CAS_DIR_MISSING,
            "cas block is missing required 'dir' child node",
        )
    dir_node = dir_children[0]
    v = node_arg_str(dir_node, 0)
    if v is None:
        raise MilpaError(
            MAN_CAS_DIR_TYPE,
            "'cas.dir' takes exactly one positional string argument",
        )
    return v


# ---------------------------------------------------------------------------
# Internal — workspace doc parser
# ---------------------------------------------------------------------------


def _parse_workspace_doc(doc: KdlDocument) -> WorkspaceManifest:
    members: list[str] = []
    overrides: list[Override] = []
    ws_name: str | None = None

    for n in nodes(doc):
        nm = node_name(n)

        if nm == "spec-version":
            epoch = _parse_spec_version_node(n)
            if epoch > MANIFEST_SPEC_VERSION:
                raise MilpaError(
                    MAN_SPEC_VERSION_UNSUPPORTED,
                    f"manifest declares spec-version {epoch} but this "
                    f"implementation only supports up to "
                    f"spec-version {MANIFEST_SPEC_VERSION}",
                    declared=epoch,
                    supported=MANIFEST_SPEC_VERSION,
                )
            continue

        if nm in {"deps", "kind"}:
            raise MilpaError(
                MAN_WORKSPACE_HAS_DEPS_OR_KIND,
                f"a workspace manifest must not declare {nm!r} — "
                "workspaces are pure containers, not packages",
                node=nm,
            )

        if nm not in _WORKSPACE_TOP_LEVEL:
            raise MilpaError(
                MAN_WORKSPACE_UNKNOWN_TOP_LEVEL,
                f"unknown top-level node {nm!r} in workspace manifest "
                f"(allowed: {', '.join(sorted(_WORKSPACE_TOP_LEVEL))})",
                node=nm,
            )

        if nm == "name":
            v = node_arg_str(n, 0)
            if v is not None:
                ws_name = v

        elif nm == "workspace":
            for child in node_children(n):
                child_nm = node_name(child)
                if child_nm != "member":
                    raise MilpaError(
                        MAN_WORKSPACE_UNKNOWN_NODE,
                        f"unknown node {child_nm!r} in workspace block "
                        "(allowed: 'member')",
                        node=child_nm,
                    )
                raw_child_args = node_args(child)
                if len(raw_child_args) != 1 or not isinstance(raw_child_args[0], str):
                    raise MilpaError(
                        MAN_WORKSPACE_MEMBER_ARITY,
                        "workspace 'member' takes exactly one positional "
                        "string argument (the member directory path)",
                    )
                path = raw_child_args[0]
                if path in members:
                    raise MilpaError(
                        MAN_WORKSPACE_MEMBER_DUPLICATE,
                        f"duplicate workspace member {path!r}",
                        path=path,
                    )
                members.append(path)

        elif nm == "overrides":
            overrides = _parse_overrides_block(n)

    return WorkspaceManifest(
        members=tuple(members),
        overrides=tuple(overrides),
        name=ws_name,
    )


# ---------------------------------------------------------------------------
# Internal — dep block parser
# ---------------------------------------------------------------------------


def _parse_dep_block(
    block: KdlNode,
    *,
    block_name: str,
    outer_predicates: tuple[Predicate, ...] = (),
) -> list[Dep]:
    """Parse all dep declarations inside a ``deps { }`` or ``dev-deps { }`` block.

    Handles ``when { }`` grouping sub-blocks (§6.3): predicates on the ``when``
    node are inherited by every dep inside it (AND semantics with any
    dep-own predicates).
    """
    deps: list[Dep] = []
    seen_names: set[str] = set()

    for child in node_children(block):
        child_nm = node_name(child)

        if child_nm == "when":
            # Parse inline predicates from the `when` node's properties.
            when_predicates = _parse_inline_predicates_from_node(
                child, dep_name="when"
            )
            # Recurse: every dep inside the when-block inherits the combined set.
            sub_deps = _parse_dep_block(
                child,
                block_name=block_name,
                outer_predicates=outer_predicates + tuple(when_predicates),
            )
            for dep in sub_deps:
                if dep.name in seen_names:
                    raise MilpaError(
                        MAN_DEP_DUPLICATE,
                        f"duplicate dep {dep.name!r} in {block_name!r} block",
                        dep=dep.name,
                        block=block_name,
                    )
                seen_names.add(dep.name)
                deps.append(dep)
            continue

        dep = _parse_dep_node(
            child, block_name=block_name, outer_predicates=outer_predicates
        )
        dep_name = dep.name

        if dep_name in seen_names:
            raise MilpaError(
                MAN_DEP_DUPLICATE,
                f"duplicate dep {dep_name!r} in {block_name!r} block",
                dep=dep_name,
                block=block_name,
            )
        seen_names.add(dep_name)
        deps.append(dep)

    return deps


def _parse_dep_node(
    n: KdlNode,
    *,
    block_name: str,
    outer_predicates: tuple[Predicate, ...] = (),
) -> Dep:
    """Disambiguate and parse a single dep node.

    Disambiguation order (§3.2):
      1. node name is ``member``   → MemberDep
      2. has ``git=`` property     → UrlDep
      3. has ``local=`` property   → LocalDep
      4. has ``tarball=`` property → TarballDep
      5. otherwise                 → NamedDep
    """
    nm = node_name(n)
    props = node_props(n)

    if nm == "member":
        return _parse_member_dep(n)
    if "git" in props:
        return _parse_url_dep(n, dep_name=nm, outer_predicates=outer_predicates)
    if "local" in props:
        return _parse_local_dep(n, dep_name=nm)
    if "tarball" in props:
        return _parse_tarball_dep(n, dep_name=nm)
    return _parse_named_dep(n, dep_name=nm)


# ---------------------------------------------------------------------------
# Internal — individual dep form parsers
# ---------------------------------------------------------------------------


def _parse_url_dep(
    n: KdlNode,
    *,
    dep_name: str,
    outer_predicates: tuple[Predicate, ...] = (),
) -> UrlDep:
    """Parse a UrlDep node.

    Requires ``git=`` (URL) and ``ref=`` properties.  Permitted additional
    properties: ``platform``, ``arch``, ``nim``, ``milpa``, ``flag``
    (inline predicate form).  Children: ``mirror``, ``flag``, predicate
    child nodes.

    ``outer_predicates`` are inherited predicates from an enclosing ``when``
    block (§6.3); they are prepended to the dep's own predicates (AND semantics).
    """
    # --- git= URL ---
    git_url_v = node_prop_url(n, "git")
    if git_url_v is None:
        raise MilpaError(
            MAN_URL_ARG_TYPE,
            f"dep {dep_name!r}: 'git=' value must be a URL string",
            dep=dep_name,
        )
    git_url = str(git_url_v)
    _validate_git_url(git_url, dep_name)

    # --- ref= ---
    ref = node_prop_str(n, "ref")
    if ref is None:
        raise MilpaError(
            MAN_DEP_REF_MISSING,
            f"dep {dep_name!r}: UrlDep requires a 'ref=' property",
            dep=dep_name,
        )

    # --- validate no unknown properties ---
    for prop_key in node_props(n):
        if prop_key not in _URL_DEP_KNOWN_PROPS:
            raise MilpaError(
                MAN_DEP_UNKNOWN_PROPS,
                f"dep {dep_name!r}: unknown property {prop_key!r}",
                dep=dep_name,
                prop=prop_key,
            )

    # --- inline predicate properties (single-value form) ---
    # Collect first so form-conflict check can compare with child-node predicates.
    inline_pred_keys: set[str] = set()
    inline_predicates: list[Predicate] = []
    for prop_key in node_props(n):
        if prop_key in _PREDICATE_PROPS:
            inline_predicates.append(
                _parse_inline_predicate(n, prop_key, dep_name=dep_name)
            )
            inline_pred_keys.add(prop_key)

    # --- children: mirror, flag, predicate child nodes ---
    mirrors: list[str] = []
    flag_requests: list[FlagRequest] = []
    child_predicates: list[Predicate] = []

    for child in node_children(n):
        child_nm = node_name(child)
        if child_nm == "mirror":
            mirrors.append(_parse_mirror_child(child, dep_name=dep_name))
        elif child_nm == "flag":
            flag_requests.append(_parse_flag_request_child(child, dep_name=dep_name))
        elif child_nm in _PREDICATE_PROPS:
            # Check form-conflict: same key already present as inline prop.
            if child_nm in inline_pred_keys:
                raise MilpaError(
                    MAN_PREDICATE_FORM_CONFLICT,
                    f"dep {dep_name!r}: predicate {child_nm!r} appears both as "
                    "an inline property and as a child node — use one form only",
                    dep=dep_name,
                    predicate=child_nm,
                )
            child_predicates.append(
                _parse_predicate_child(child, dep_name=dep_name)
            )
        else:
            raise MilpaError(
                MAN_DEP_UNKNOWN_CHILD,
                f"dep {dep_name!r}: unknown child node {child_nm!r} "
                "(allowed: 'mirror', 'flag', predicate names)",
                dep=dep_name,
                child=child_nm,
            )

    all_predicates = (
        list(outer_predicates) + inline_predicates + child_predicates
    )

    return UrlDep(
        name=dep_name,
        git=git_url,
        ref=ref,
        mirrors=tuple(mirrors),
        predicates=tuple(all_predicates),
        flag_requests=tuple(flag_requests),
    )


def _validate_git_url(url: str, dep_name: str) -> None:
    """Validate that ``url`` has a recognized git scheme."""
    parsed = urlparse(url)
    if not parsed.scheme:
        raise MilpaError(
            MAN_GIT_URL_NO_SCHEME,
            f"dep {dep_name!r}: git URL {url!r} has no scheme "
            "(expected https://, http://, ssh://, or git://)",
            dep=dep_name,
            url=url,
        )
    if parsed.scheme not in _VALID_GIT_SCHEMES:
        raise MilpaError(
            MAN_GIT_URL_BAD_SCHEME,
            f"dep {dep_name!r}: git URL scheme {parsed.scheme!r} is not supported "
            f"(allowed: {', '.join(sorted(_VALID_GIT_SCHEMES))})",
            dep=dep_name,
            scheme=parsed.scheme,
        )


def _parse_mirror_child(n: KdlNode, *, dep_name: str) -> str:
    """Parse a ``mirror (url)"<URL>"`` child node.  Returns the URL string.

    - No argument → ``MAN-DEP-MIRROR-ARITY``
    - Argument present but not a string → ``MAN-URL-ARG-TYPE``
    """
    raw_args = node_args(n)
    if not raw_args:
        raise MilpaError(
            MAN_DEP_MIRROR_ARITY,
            f"dep {dep_name!r}: 'mirror' requires exactly one URL argument",
            dep=dep_name,
        )
    url_v = node_arg_url(n, 0)
    if url_v is None:
        raise MilpaError(
            MAN_URL_ARG_TYPE,
            f"dep {dep_name!r}: 'mirror' URL argument must be a string, "
            f"got {type(raw_args[0]).__name__!r}",
            dep=dep_name,
        )
    return str(url_v)


def _parse_flag_request_child(n: KdlNode, *, dep_name: str) -> FlagRequest:
    """Parse a ``flag "<name>" [<bool>]`` child node on a UrlDep."""
    raw_args = node_args(n)

    if len(raw_args) == 0:
        raise MilpaError(
            MAN_DEP_FLAG_NAME_MISSING,
            f"dep {dep_name!r}: 'flag' child requires a name argument",
            dep=dep_name,
        )

    if len(raw_args) > 2:
        raise MilpaError(
            MAN_DEP_FLAG_TOO_MANY_ARGS,
            f"dep {dep_name!r}: 'flag' takes at most two arguments "
            "(name and optional bool)",
            dep=dep_name,
        )

    flag_name = raw_args[0]
    if not isinstance(flag_name, str):
        raise MilpaError(
            MAN_DEP_FLAG_NAME_MISSING,
            f"dep {dep_name!r}: 'flag' first argument must be a string name",
            dep=dep_name,
        )

    if len(raw_args) == 1:
        return FlagRequest(name=flag_name, enabled=True)

    # Second arg must be bool
    second = raw_args[1]
    if not isinstance(second, bool):
        raise MilpaError(
            MAN_DEP_FLAG_BOOL,
            f"dep {dep_name!r}: 'flag' second argument must be a boolean "
            f"(#true or #false), got {second!r}",
            dep=dep_name,
            flag=flag_name,
        )
    return FlagRequest(name=flag_name, enabled=second)


def _parse_predicate_child(n: KdlNode, *, dep_name: str) -> Predicate:
    """Parse a predicate child-node (multi-value OR form, §6.2).

    All positional args MUST be strings; each MAY carry the ``(not)``
    annotation (negation).  All args MUST agree on negation — mixing bare
    and ``(not)``-annotated values raises ``MAN-PREDICATE-MIXED-NEGATION``.
    A child node with NO args raises ``MAN-PREDICATE-CHILD-NO-ARGS``.
    A non-string arg raises ``MAN-PREDICATE-CHILD-ARG-TYPE``.
    """
    pred_name = node_name(n)
    raw_args = node_args(n)

    if not raw_args:
        raise MilpaError(
            MAN_PREDICATE_CHILD_NO_ARGS,
            f"dep {dep_name!r}: predicate child node {pred_name!r} "
            "requires at least one value argument",
            dep=dep_name,
            predicate=pred_name,
        )

    values: list[str] = []
    negation_flags: list[bool] = []

    for i, v in enumerate(raw_args):
        if not isinstance(v, str):
            raise MilpaError(
                MAN_PREDICATE_CHILD_ARG_TYPE,
                f"dep {dep_name!r}: predicate {pred_name!r} arg {i} "
                f"must be a string, got {type(v).__name__!r}",
                dep=dep_name,
                predicate=pred_name,
            )
        tag = node_arg_tag(n, i)
        if tag is not None and tag != "not":
            raise MilpaError(
                MAN_PREDICATE_UNSUPPORTED_ANNOTATION,
                f"dep {dep_name!r}: predicate {pred_name!r} arg {i} "
                f"has unsupported type annotation {tag!r} (only '(not)' is allowed)",
                dep=dep_name,
                predicate=pred_name,
            )
        negation_flags.append(tag == "not")
        values.append(v)

    # Mixed-negation check: all must agree.
    if len(set(negation_flags)) > 1:
        raise MilpaError(
            MAN_PREDICATE_MIXED_NEGATION,
            f"dep {dep_name!r}: predicate {pred_name!r} mixes bare and "
            "'(not)'-annotated values — all must be bare or all negated",
            dep=dep_name,
            predicate=pred_name,
        )

    return Predicate(
        name=pred_name,
        values=tuple(values),
        negated=negation_flags[0],
    )


def _parse_inline_predicate(
    n: KdlNode, prop_key: str, *, dep_name: str
) -> Predicate:
    """Parse an inline predicate property (single-value form, §6.1).

    The value MUST be a string (bare or ``(not)``-annotated).  A non-string
    value raises ``MAN-PREDICATE-VALUE-TYPE``.  An unsupported annotation
    (anything other than ``(not)``) raises
    ``MAN-PREDICATE-UNSUPPORTED-ANNOTATION``.
    """
    raw = node_props(n).get(prop_key)

    # Check type annotation before checking value type.
    tag = node_prop_tag(n, prop_key)
    if tag is not None and tag != "not":
        raise MilpaError(
            MAN_PREDICATE_UNSUPPORTED_ANNOTATION,
            f"dep {dep_name!r}: predicate property {prop_key!r} has "
            f"unsupported type annotation {tag!r} (only '(not)' is allowed)",
            dep=dep_name,
            predicate=prop_key,
        )

    if not isinstance(raw, str):
        raise MilpaError(
            MAN_PREDICATE_VALUE_TYPE,
            f"dep {dep_name!r}: predicate {prop_key!r} value must be a string, "
            f"got {type(raw).__name__!r}",
            dep=dep_name,
            predicate=prop_key,
        )

    negated = tag == "not"
    return Predicate(name=prop_key, values=(raw,), negated=negated)


def _parse_inline_predicates_from_node(
    n: KdlNode, *, dep_name: str
) -> list[Predicate]:
    """Parse all predicate properties from a node (e.g., a ``when`` node).

    Validates predicate keys — unknown keys raise ``MAN-PREDICATE-UNKNOWN``.
    Returns the list of parsed ``Predicate`` objects.
    """
    predicates: list[Predicate] = []
    for prop_key in node_props(n):
        if prop_key not in _PREDICATE_PROPS:
            raise MilpaError(
                MAN_PREDICATE_UNKNOWN,
                f"dep {dep_name!r}: unknown predicate key {prop_key!r} "
                f"(allowed: {', '.join(sorted(_PREDICATE_PROPS))})",
                predicate=prop_key,
            )
        predicates.append(_parse_inline_predicate(n, prop_key, dep_name=dep_name))
    return predicates


def _parse_named_dep(n: KdlNode, *, dep_name: str) -> NamedDep:
    """Parse a NamedDep (registry-resolved).

    Grammar: ``<name>`` or ``<name> "<version-constraint>"``

    The constraint string is pre-typed to ``VersionSet`` at this boundary.
    """
    raw_args = node_args(n)
    props = node_props(n)

    # Any property (other than git= which routes to UrlDep) is an error.
    if props:
        for prop_key in props:
            raise MilpaError(
                MAN_DEP_NAMED_PROPS,
                f"dep {dep_name!r}: NamedDep does not accept properties "
                f"(got {prop_key!r}); use 'git=' for a UrlDep",
                dep=dep_name,
                prop=prop_key,
            )

    if len(raw_args) > 1:
        raise MilpaError(
            MAN_DEP_NAMED_ARITY,
            f"dep {dep_name!r}: NamedDep takes at most one positional argument "
            "(the version constraint string)",
            dep=dep_name,
        )

    if len(raw_args) == 0:
        # No constraint — any version
        return NamedDep(name=dep_name, constraint=None, constraint_set=None)

    # Exactly one arg — must be a string constraint.
    # A non-string arg (int, bool, etc.) → MAN-DEP-NAMED-CONSTRAINT.
    arg = raw_args[0]
    if not isinstance(arg, str):
        raise MilpaError(
            MAN_DEP_NAMED_CONSTRAINT,
            f"dep {dep_name!r}: version constraint must be a string, "
            f"got {type(arg).__name__!r}",
            dep=dep_name,
        )

    # Pre-type: MilpaError(MAN_DEP_NAMED_CONSTRAINT) raised by __post_init__
    # if the string is malformed.
    return NamedDep(name=dep_name, constraint=arg)


def _parse_local_dep(n: KdlNode, *, dep_name: str) -> LocalDep:
    """Parse a LocalDep node.

    Grammar: ``<name> local="<path>"``

    The ``local=`` value must be a non-empty string.
    No other properties are permitted.
    """
    props = node_props(n)

    # Check for unknown properties (anything except "local")
    for prop_key in props:
        if prop_key != "local":
            raise MilpaError(
                MAN_DEP_UNKNOWN_PROPS,
                f"dep {dep_name!r}: LocalDep does not accept property {prop_key!r}",
                dep=dep_name,
                prop=prop_key,
            )

    path = node_prop_str(n, "local")
    if not path:
        # Either absent (shouldn't happen — we checked), wrong type, or empty string.
        raw = props.get("local")
        if not isinstance(raw, str):
            raise MilpaError(
                MAN_DEP_LOCAL_PATH,
                f"dep {dep_name!r}: 'local=' must be a non-empty string path",
                dep=dep_name,
            )
        raise MilpaError(
            MAN_DEP_LOCAL_PATH,
            f"dep {dep_name!r}: 'local=' path must not be empty",
            dep=dep_name,
        )

    return LocalDep(name=dep_name, path=path)


def _parse_tarball_dep(n: KdlNode, *, dep_name: str) -> TarballDep:
    """Parse a TarballDep node.

    Grammar:
        ``<name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]``

    ``tarball=`` must be a non-empty URL string (plain or ``(url)``-annotated).
    ``sha256`` optional string; non-string raises MAN-DEP-TARBALL-SHA.
    ``strip_components`` optional non-negative int; negative/non-int/bool
    raises MAN-DEP-TARBALL-STRIP.
    """
    props = node_props(n)

    # --- tarball= URL ---
    tarball_url_v = node_prop_url(n, "tarball")
    if tarball_url_v is None:
        # Present but wrong type
        raw = props.get("tarball")
        if raw is not None:
            raise MilpaError(
                MAN_DEP_TARBALL_URL,
                f"dep {dep_name!r}: 'tarball=' must be a URL string",
                dep=dep_name,
            )
        raise MilpaError(
            MAN_DEP_TARBALL_URL,
            f"dep {dep_name!r}: 'tarball=' URL is missing",
            dep=dep_name,
        )
    url = str(tarball_url_v)
    if not url:
        raise MilpaError(
            MAN_DEP_TARBALL_URL,
            f"dep {dep_name!r}: 'tarball=' URL must not be empty",
            dep=dep_name,
        )

    # --- sha256 (optional) ---
    sha256: str | None = None
    if "sha256" in props:
        sha256 = node_prop_str(n, "sha256")
        if sha256 is None:
            raise MilpaError(
                MAN_DEP_TARBALL_SHA,
                f"dep {dep_name!r}: 'sha256=' must be a string",
                dep=dep_name,
            )

    # --- strip_components (optional, non-negative int) ---
    strip_components: int = 0
    if "strip_components" in props:
        raw_strip = props.get("strip_components")
        # Must NOT be a bool (bool is a subclass of int in Python).
        if isinstance(raw_strip, bool):
            raise MilpaError(
                MAN_DEP_TARBALL_STRIP,
                f"dep {dep_name!r}: 'strip_components=' must be a non-negative integer",
                dep=dep_name,
            )
        strip_v = node_prop_int(n, "strip_components")
        if strip_v is None:
            raise MilpaError(
                MAN_DEP_TARBALL_STRIP,
                f"dep {dep_name!r}: 'strip_components=' must be a non-negative integer",
                dep=dep_name,
            )
        if strip_v < 0:
            raise MilpaError(
                MAN_DEP_TARBALL_STRIP,
                f"dep {dep_name!r}: 'strip_components=' must be non-negative, "
                f"got {strip_v}",
                dep=dep_name,
                value=strip_v,
            )
        strip_components = strip_v

    return TarballDep(
        name=dep_name,
        url=url,
        sha256=sha256,
        strip_components=strip_components,
    )


def _parse_overrides_block(block: KdlNode) -> list[Override]:
    """Parse an ``overrides { }`` block.

    Each child MUST be named ``pkg``.  Grammar:
        ``pkg "<name>" git=(url)"<URL>" ref="<ref>"``

    Error codes:
    - Unknown child name → ``MAN-OVERRIDE-KIND``
    - ``pkg`` with no positional arg (arity 0) or non-string arg → ``MAN-OVERRIDE-ARITY``
    - Missing ``git=`` → ``MAN-OVERRIDE-GIT-MISSING``
    - Missing ``ref=`` → ``MAN-OVERRIDE-REF-MISSING``
    - Unknown property → ``MAN-OVERRIDE-UNKNOWN-PROPS``
    - Duplicate name → ``MAN-OVERRIDE-DUPLICATE``
    """
    overrides: list[Override] = []
    seen_names: set[str] = set()

    for child in node_children(block):
        child_nm = node_name(child)
        if child_nm != "pkg":
            raise MilpaError(
                MAN_OVERRIDE_KIND,
                f"unknown override kind {child_nm!r} — only 'pkg' is supported",
                kind=child_nm,
            )

        raw_args = node_args(child)
        if len(raw_args) != 1 or not isinstance(raw_args[0], str):
            raise MilpaError(
                MAN_OVERRIDE_ARITY,
                "'pkg' override requires exactly one positional string argument "
                "(the package name to match)",
            )
        pkg_name: str = raw_args[0]

        # Check for unknown properties (only git= and ref= are allowed).
        _OVERRIDE_KNOWN_PROPS = frozenset({"git", "ref"})
        for prop_key in node_props(child):
            if prop_key not in _OVERRIDE_KNOWN_PROPS:
                raise MilpaError(
                    MAN_OVERRIDE_UNKNOWN_PROPS,
                    f"override for {pkg_name!r}: unknown property {prop_key!r} "
                    "(allowed: 'git', 'ref')",
                    name=pkg_name,
                    prop=prop_key,
                )

        git_url_v = node_prop_url(child, "git")
        if git_url_v is None:
            raise MilpaError(
                MAN_OVERRIDE_GIT_MISSING,
                f"override for {pkg_name!r}: missing required 'git=' property",
                name=pkg_name,
            )
        git_url = str(git_url_v)
        _validate_git_url(git_url, pkg_name)

        ref = node_prop_str(child, "ref")
        if ref is None:
            raise MilpaError(
                MAN_OVERRIDE_REF_MISSING,
                f"override for {pkg_name!r}: missing required 'ref=' property",
                name=pkg_name,
            )

        if pkg_name in seen_names:
            raise MilpaError(
                MAN_OVERRIDE_DUPLICATE,
                f"duplicate override for {pkg_name!r}",
                name=pkg_name,
            )
        seen_names.add(pkg_name)
        overrides.append(Override(name=pkg_name, git=git_url, ref=ref))

    return overrides


def _parse_mirrors_block(block: KdlNode) -> list[str]:
    """Parse a top-level ``mirrors { }`` block.

    Each child MUST be named ``mirror`` and carry exactly one URL argument.

    Error codes:
    - Unknown child name → ``MAN-MIRRORS-UNKNOWN-CHILD``
    - Wrong arity or non-URL arg → ``MAN-MIRRORS-ARITY`` / ``MAN-URL-ARG-TYPE``
    """
    mirrors: list[str] = []

    for child in node_children(block):
        child_nm = node_name(child)
        if child_nm != "mirror":
            raise MilpaError(
                MAN_MIRRORS_UNKNOWN_CHILD,
                f"unknown child {child_nm!r} in 'mirrors' block "
                "(only 'mirror' is allowed)",
                child=child_nm,
            )
        raw_args = node_args(child)
        if not raw_args:
            raise MilpaError(
                MAN_MIRRORS_ARITY,
                "'mirrors.mirror' requires exactly one URL argument",
            )
        url_v = node_arg_url(child, 0)
        if url_v is None:
            raise MilpaError(
                MAN_URL_ARG_TYPE,
                f"'mirrors.mirror' URL argument must be a string, "
                f"got {type(raw_args[0]).__name__!r}",
            )
        mirrors.append(str(url_v))

    return mirrors


def _parse_flags_block(block: KdlNode) -> list[FlagDecl]:
    """Parse a ``flags { }`` block.

    Each child is a flag declaration; the KDL identifier is the flag name.
    Permitted properties: ``default`` (bool), ``description`` (string).
    Optional child node: ``defines`` with one or more string args.

    Error codes:
    - Positional args on flag node → ``MAN-FLAG-POS-ARGS``
    - ``default=`` non-bool → ``MAN-FLAG-DEFAULT-TYPE``
    - ``description=`` non-string → ``MAN-FLAG-DESCRIPTION-TYPE``
    - Unknown property → ``MAN-FLAG-UNKNOWN-PROPS``
    - Unknown child node → ``MAN-FLAG-UNKNOWN-CHILD``
    - Non-string ``defines`` arg → ``MAN-FLAG-DEFINES-ARG-TYPE``
    - Duplicate flag name → ``MAN-FLAG-DUPLICATE``
    """
    flags: list[FlagDecl] = []
    seen_names: set[str] = set()

    for child in node_children(block):
        flag_name = node_name(child)

        # No positional args allowed on a flag node.
        raw_args = node_args(child)
        if raw_args:
            raise MilpaError(
                MAN_FLAG_POS_ARGS,
                f"flag {flag_name!r}: flag declarations do not accept "
                "positional arguments",
                flag=flag_name,
            )

        # Validate properties.
        _FLAG_KNOWN_PROPS = frozenset({"default", "description"})
        for prop_key in node_props(child):
            if prop_key not in _FLAG_KNOWN_PROPS:
                raise MilpaError(
                    MAN_FLAG_UNKNOWN_PROPS,
                    f"flag {flag_name!r}: unknown property {prop_key!r} "
                    "(allowed: 'default', 'description')",
                    flag=flag_name,
                    prop=prop_key,
                )

        # default= (optional bool, default False).
        default: bool = False
        if "default" in node_props(child):
            default_v = node_prop_bool(child, "default")
            if default_v is None:
                raise MilpaError(
                    MAN_FLAG_DEFAULT_TYPE,
                    f"flag {flag_name!r}: 'default=' must be a boolean "
                    "value (#true or #false)",
                    flag=flag_name,
                )
            default = default_v

        # description= (optional string).
        description: str = ""
        if "description" in node_props(child):
            desc_v = node_prop_str(child, "description")
            if desc_v is None:
                raise MilpaError(
                    MAN_FLAG_DESCRIPTION_TYPE,
                    f"flag {flag_name!r}: 'description=' must be a string",
                    flag=flag_name,
                )
            description = desc_v

        # Child nodes: only ``defines`` is allowed.
        defines: list[str] = []
        for sub_child in node_children(child):
            sub_nm = node_name(sub_child)
            if sub_nm != "defines":
                raise MilpaError(
                    MAN_FLAG_UNKNOWN_CHILD,
                    f"flag {flag_name!r}: unknown child node {sub_nm!r} "
                    "(only 'defines' is allowed)",
                    flag=flag_name,
                    child=sub_nm,
                )
            for i, define_arg in enumerate(node_args(sub_child)):
                if not isinstance(define_arg, str):
                    raise MilpaError(
                        MAN_FLAG_DEFINES_ARG_TYPE,
                        f"flag {flag_name!r}: 'defines' argument {i} must be "
                        f"a string, got {type(define_arg).__name__!r}",
                        flag=flag_name,
                    )
                defines.append(define_arg)

        # Duplicate check.
        if flag_name in seen_names:
            raise MilpaError(
                MAN_FLAG_DUPLICATE,
                f"duplicate flag declaration {flag_name!r}",
                flag=flag_name,
            )
        seen_names.add(flag_name)
        flags.append(
            FlagDecl(
                name=flag_name,
                default=default,
                description=description,
                defines=tuple(defines),
            )
        )

    return flags


def _parse_member_dep(n: KdlNode) -> MemberDep:
    """Parse a ``member "<name>"`` node.

    The node name is the literal keyword ``member``.  Requires exactly
    one positional string argument (the member's intrinsic name).
    Properties are not allowed.
    """
    props = node_props(n)
    if props:
        first_prop = next(iter(props))
        raise MilpaError(
            MAN_DEP_MEMBER_PROPS,
            f"'member' node does not accept properties (got {first_prop!r})",
            prop=first_prop,
        )

    raw_args = node_args(n)
    if len(raw_args) != 1 or not isinstance(raw_args[0], str):
        raise MilpaError(
            MAN_DEP_MEMBER_ARITY,
            "'member' takes exactly one positional string argument "
            "(the workspace member's intrinsic name)",
        )

    return MemberDep(name=raw_args[0])


# ---------------------------------------------------------------------------
# Internal — spec-version node parser (shared by package + workspace)
# ---------------------------------------------------------------------------


def _parse_spec_version_node(n: KdlNode) -> int:
    """Parse a ``spec-version <int>`` node and return the epoch integer.

    Validates arity and type per §4.4.  Does NOT enforce the
    MANIFEST_SPEC_VERSION ceiling — callers do that after receiving the
    epoch.
    """
    raw_args = node_args(n)
    if len(raw_args) != 1:
        raise MilpaError(
            MAN_SPEC_VERSION_TYPE,
            "'spec-version' takes exactly one positive integer argument",
        )
    epoch = raw_args[0]
    # Must be an integer (not bool, not float that's non-integer)
    if isinstance(epoch, bool):
        raise MilpaError(
            MAN_SPEC_VERSION_TYPE,
            f"'spec-version' argument must be a positive integer, got bool {epoch!r}",
        )
    if isinstance(epoch, float) and epoch == int(epoch):
        epoch = int(epoch)
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        raise MilpaError(
            MAN_SPEC_VERSION_TYPE,
            f"'spec-version' argument must be a positive integer, "
            f"got {type(epoch).__name__!r}",
        )
    if epoch < 1:
        raise MilpaError(
            MAN_SPEC_VERSION_TYPE,
            f"'spec-version' must be >= 1, got {epoch}",
            value=epoch,
        )
    if epoch > MANIFEST_SPEC_VERSION:
        raise MilpaError(
            MAN_SPEC_VERSION_UNSUPPORTED,
            f"manifest declares spec-version {epoch} but this "
            f"implementation only supports up to "
            f"spec-version {MANIFEST_SPEC_VERSION}",
            declared=epoch,
            supported=MANIFEST_SPEC_VERSION,
        )
    return epoch


# ---------------------------------------------------------------------------
# Serializer — format_manifest (hand-rolled canonical KDL 2.0)
# ---------------------------------------------------------------------------

_COMMENT_WARNING = (
    "warning: milpa.kdl comments are not preserved when the manifest is rewritten\n"
)

_MANIFEST_HEADER = (
    "// generated by milpa; edit by hand or via `milpa add` / `milpa remove`"
)


def _kdl_str(s: str) -> str:
    """Escape a string for KDL 2.0 double-quoted form.

    Handles the characters that KDL requires escaping inside double-quoted
    strings: backslash, double-quote, and the C0 control characters that
    appear in practice.
    """
    return (
        s
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def format_manifest(manifest: Manifest) -> str:
    """Serialize a ``Manifest`` to a KDL 2.0 string.

    Hand-rolled canonical format — byte-identical to the Rust
    ``milpa-manifest::format_manifest``.

    Spec requirements (§8 + §2 + §4.4):
    - Starts with ``// generated by milpa; edit by hand or via ...`` header.
    - All URL-valued fields carry the ``(url)`` type annotation (§2).
    - ``spec-version`` is emitted iff ``manifest.spec_version_explicit``
      (§4.4 present-stays-present / absent-stays-absent).
    - Dep-entry order is insertion-stable (§8).
    - ``kind`` is always last (Rust canonical ordering).
    - If ``manifest.had_comments`` is ``True``, a warning is emitted to
      stderr before returning (§8).

    Returns the serialized KDL 2.0 string (always ends with a newline).
    """
    if manifest.had_comments:
        sys.stderr.write(_COMMENT_WARNING)

    lines: list[str] = [_MANIFEST_HEADER, ""]

    # spec-version — present/absent round-trip (§4.4).
    if manifest.spec_version_explicit:
        lines.append(f"spec-version {manifest.spec_version}")
        lines.append("")

    # name (required)
    lines.append(f'name "{_kdl_str(manifest.name)}"')
    lines.append("")

    # src_dir (only when non-empty)
    if manifest.src_dir:
        lines.append(f'src_dir "{_kdl_str(manifest.src_dir)}"')
        lines.append("")

    # cas { dir "..." }
    if manifest.cas_dir:
        lines.append("cas {")
        lines.append(f'    dir "{_kdl_str(manifest.cas_dir)}"')
        lines.append("}")
        lines.append("")

    # deps { ... }
    if manifest.deps:
        lines.append("deps {")
        for dep in manifest.deps:
            lines.append(_format_dep_line(dep))
        lines.append("}")
        lines.append("")

    # dev-deps { ... }
    if manifest.dev_deps:
        lines.append("dev-deps {")
        for dep in manifest.dev_deps:
            lines.append(_format_dep_line(dep))
        lines.append("}")
        lines.append("")

    # overrides { pkg "name" git=(url)"..." ref="..." }
    if manifest.overrides:
        lines.append("overrides {")
        for ov in manifest.overrides:
            lines.append(
                f'    pkg "{_kdl_str(ov.name)}"'
                f' git=(url)"{_kdl_str(ov.git)}"'
                f' ref="{_kdl_str(ov.ref)}"'
            )
        lines.append("}")
        lines.append("")

    # mirrors { mirror (url)"..." ... }
    if manifest.self_mirrors:
        lines.append("mirrors {")
        for url in manifest.self_mirrors:
            lines.append(f'    mirror (url)"{_kdl_str(url)}"')
        lines.append("}")
        lines.append("")

    # flags { "<name>" default=#true/#false ... }
    if manifest.flags:
        lines.append("flags {")
        for fd in manifest.flags:
            default_kw = "#true" if fd.default else "#false"
            head = f'    "{_kdl_str(fd.name)}" default={default_kw}'
            if fd.description:
                head += f' description="{_kdl_str(fd.description)}"'
            if not fd.defines:
                lines.append(head)
            else:
                defines_args = " ".join(f'"{_kdl_str(d)}"' for d in fd.defines)
                lines.append(f"{head} {{")
                lines.append(f"        defines {defines_args}")
                lines.append("    }")
        lines.append("}")
        lines.append("")

    # kind — always last (Rust canonical ordering)
    lines.append(f'kind "{_kdl_str(manifest.kind)}"')

    return "\n".join(lines) + "\n"


def _format_dep_line(dep: Dep) -> str:
    """Render one dep as a KDL line (or multi-line block) inside a deps { } block.

    Matches the Rust ``format_dep_line`` byte-for-byte.

    Indentation: 4 spaces for dep-level, 8 spaces for child nodes inside a
    URL dep block.
    """
    if isinstance(dep, MemberDep):
        return f'    member "{_kdl_str(dep.name)}"'

    if isinstance(dep, NamedDep):
        if dep.constraint is None:
            return f'    "{_kdl_str(dep.name)}"'
        return f'    "{_kdl_str(dep.name)}" "{_kdl_str(dep.constraint)}"'

    if isinstance(dep, LocalDep):
        return f'    "{_kdl_str(dep.name)}" local="{_kdl_str(dep.path)}"'

    if isinstance(dep, TarballDep):
        parts = [
            f'    "{_kdl_str(dep.name)}"',
            f'tarball=(url)"{_kdl_str(dep.url)}"',
        ]
        if dep.sha256 is not None:
            parts.append(f'sha256="{_kdl_str(dep.sha256)}"')
        if dep.strip_components != 0:
            parts.append(f"strip_components={dep.strip_components}")
        return " ".join(parts)

    # UrlDep
    assert isinstance(dep, UrlDep)

    # Split predicates: inline (single value) vs child-node (multi-value).
    inline_preds = [p for p in dep.predicates if len(p.values) == 1]
    child_preds = [p for p in dep.predicates if len(p.values) > 1]

    head = (
        f'    "{_kdl_str(dep.name)}"'
        f' git=(url)"{_kdl_str(dep.git)}"'
        f' ref="{_kdl_str(dep.ref)}"'
    )
    for pred in inline_preds:
        val = pred.values[0]
        if pred.negated:
            head += f' {pred.name}=(not)"{_kdl_str(val)}"'
        else:
            head += f' {pred.name}="{_kdl_str(val)}"'

    # If no children, emit as single line.
    if not dep.mirrors and not child_preds and not dep.flag_requests:
        return head

    # Multi-line block form.
    block: list[str] = [f"{head} {{"]
    for pred in child_preds:
        if pred.negated:
            args_str = " ".join(f'(not)"{_kdl_str(v)}"' for v in pred.values)
        else:
            args_str = " ".join(f'"{_kdl_str(v)}"' for v in pred.values)
        block.append(f"        {pred.name} {args_str}")
    for mirror_url in dep.mirrors:
        block.append(f'        mirror (url)"{_kdl_str(mirror_url)}"')
    for fr in dep.flag_requests:
        if fr.enabled:
            block.append(f'        flag "{_kdl_str(fr.name)}"')
        else:
            block.append(f'        flag "{_kdl_str(fr.name)}" #false')
    block.append("    }")
    return "\n".join(block)
