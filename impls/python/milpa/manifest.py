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
  ``GitTarget``    — override target: git URL + ref
  ``LocalTarget``  — override target: local filesystem path
  ``MemberTarget`` — override target: workspace member name
  ``Override``     — pkg-form override (name + discriminated-union target)
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
    MAN_DEP_OPTIONAL_FLAG_CLASH,
    MAN_DEP_FLAG_NAME_MISSING,
    MAN_DEP_FLAG_TOO_MANY_ARGS,
    MAN_DEP_LOCAL_PATH,
    MAN_DEP_MEMBER_ARITY,
    MAN_DEP_MEMBER_PROPS,
    MAN_DEP_MIRROR_ARITY,
    MAN_DEP_NAME_INVALID,
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
    MAN_FLAG_DEFINES_UNSAFE,
    MAN_FLAG_DESCRIPTION_TYPE,
    MAN_FLAG_DUPLICATE,
    MAN_FLAG_ENABLES_UNDECLARED,
    MAN_FLAG_NAME_INVALID,
    MAN_FLAG_POS_ARGS,
    MAN_FLAG_UNDECLARED_REFERENCE,
    MAN_FLAG_UNKNOWN_CHILD,
    MAN_FLAG_UNKNOWN_PROPS,
    MAN_GIT_URL_BAD_SCHEME,
    MAN_GIT_URL_NO_SCHEME,
    MAN_KIND_ARITY,
    MAN_KIND_INVALID,
    MAN_MEMBER_WHEN_GATED,
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
    MAN_OVERRIDE_TARGET_AMBIGUOUS,
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
    MAN_SRC_DIR_UNSAFE,
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
    value_as_strict_int,
)
from milpa.predicate import Predicate  # SSOT for Predicate; re-exported below
from milpa.trust import TrustPolicy, _parse_trust_policy
from milpa.version import VersionSet

# Re-export so ``milpa.manifest.Predicate`` still resolves for all existing
# importers (back-compat; the new SSOT is ``milpa.predicate``).
__all__ = ["Predicate"]

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
        "attestation-policy",
        # S5 (RFC registry-trust-federation §6.4): whole-index attestation gate.
        "index-trust",
        "index-trust-signer",
        "index-trust-bundle",
    }
)

# Property names recognized on a UrlDep node (dispatched to UrlDep, not NamedDep).
_URL_DEP_KNOWN_PROPS: frozenset[str] = frozenset(
    {"git", "ref", "platform", "arch", "nim", "milpa", "flag", "optional"}
)

# Implementation detail of valid_dep_name — do NOT call .match() on this
# directly outside that function.  Use valid_dep_name(s) at every call site.
# (Valid charset for dep/flag names: [A-Za-z0-9_-]+.)
import re as _re
_FLAG_NAME_CHARSET_RE = _re.compile(r"^[A-Za-z0-9_\-]+$")

# Unsafe strings: ASCII control chars (0x00-0x1F, 0x7F) AND Unicode line
# separators U+2028/U+2029, which act as line breaks in some contexts.
# (R2-Unicode fix — broadens H1 ASCII-only check.)
# Implementation detail of contains_unsafe_char — call that function; do not
# call _UNSAFE_STRING_RE.search() directly.
_UNSAFE_STRING_RE = _re.compile("[\x00-\x1f\x7f  ]")

def contains_unsafe_char(s: str) -> bool:
    """Return True if ``s`` contains any unsafe character.

    Unsafe characters are ASCII control chars (0x00-0x1F, 0x7F) and Unicode
    line separators U+2028/U+2029.  These can break nim.cfg --path: lines if
    they appear in a src_dir value.

    This is the SINGLE SOURCE OF TRUTH for the unsafe-char predicate -- both
    the milpa.kdl parse path and the .nimble fallback path import this function.
    Mirrors ``contains_unsafe_char`` in milpa-manifest/src/lib.rs (Rust SSOT).
    """
    return bool(_UNSAFE_STRING_RE.search(s))

def valid_dep_name(s: str) -> bool:
    """Return True if ``s`` is a valid dep/flag name: non-empty [A-Za-z0-9_-]+.

    This is the SINGLE SOURCE OF TRUTH for the dep-name charset predicate.
    Used at the manifest parse boundary (``_parse_dep_node``) and re-exported
    for the lockfile parse boundary (``lockfile.py``) so both callers reuse
    this predicate without duplication.
    Mirrors ``valid_flag_name`` in milpa-manifest/src/lib.rs (Rust SSOT).
    """
    return bool(_FLAG_NAME_CHARSET_RE.fullmatch(s))

# Recognized predicate property names.
_PREDICATE_PROPS: frozenset[str] = frozenset({"platform", "arch", "nim", "milpa", "flag"})

# Top-level nodes permitted in a workspace manifest.
# S5 redesign (RFC registry-trust-federation §6.4a root-authority model):
# index-trust / index-trust-signer / index-trust-bundle are legal on a
# workspace ROOT manifest — the registry index is a process-global,
# workspace-shared resource, so index-trust is a property of the resolution
# root, not of each member.  These three nodes are neither 'deps' nor 'kind',
# so permitting them does not loosen the deps/kind rejection.
_WORKSPACE_TOP_LEVEL: frozenset[str] = frozenset(
    {
        "workspace",
        "name",
        "overrides",
        "spec-version",
        "flags",
        "index-trust",
        "index-trust-signer",
        "index-trust-bundle",
    }
)


# ---------------------------------------------------------------------------
# Data model — 3a
# ---------------------------------------------------------------------------


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
    ``optional`` is retained for round-trip serialization; the parse-time
    desugar pass (S7 RFC #23 §3.2) injects the auto-flag + ``flag=`` predicate
    into the manifest, so resolution never sees this field directly.
    """

    name: str
    git: str
    ref: str
    mirrors: tuple[str, ...] = ()
    predicates: tuple[Predicate, ...] = ()
    flag_requests: tuple[FlagRequest, ...] = ()
    optional: bool = False


@dataclass(frozen=True)
class NamedDep:
    """A dep resolved against the tianguis index.

    Grammar: ``<name>`` or ``<name> "<version-constraint>"``
    Optionally with a ``{ flag "x" }`` child block (§3.1.5, S3).

    ``constraint`` is the raw string from the manifest (or ``None``
    when absent).  ``constraint_set`` is a pre-typed ``VersionSet``
    parsed at construction time (the #121 design: parse-to-typed-value
    once at the manifest parse boundary; illegal states unrepresentable).
    ``flag_requests`` are consumer feature-flag requests to this dep
    (structurally identical to ``UrlDep.flag_requests`` — SSOT).
    ``optional`` is retained for round-trip serialization; the parse-time
    desugar pass (S7 RFC #23 §3.2) injects the auto-flag + ``flag=`` predicate
    into the manifest, so resolution never sees this field directly.

    A malformed ``constraint`` string raises
    ``MilpaError(MAN_DEP_NAMED_CONSTRAINT)`` at construction time.
    """

    name: str
    constraint: str | None  # e.g. ">= 0.5.0" or None for any version
    constraint_set: VersionSet | None = field(default=None, compare=False, hash=False)
    flag_requests: tuple[FlagRequest, ...] = ()
    optional: bool = False
    predicates: tuple[Predicate, ...] = ()  # S7: auto-injected gate for optional
    # S5b: namespace from ``namespace=`` attribute or slash-shorthand desugar.
    # None = default (bare-name lookup, existing behavior).  Non-None = qualified
    # lookup that bypasses TNG-AMBIGUOUS-NAME (registry-protocol §5.1).
    namespace: str | None = None

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

    ``predicates`` are evaluated before the dep is passed to the solver
    (§6.3 NORMATIVE: all five dep forms support ``when``-conditional syntax).
    Populated from enclosing ``when`` block predicates by ``_parse_local_dep``.
    """

    name: str
    path: str
    predicates: tuple[Predicate, ...] = ()


@dataclass(frozen=True)
class TarballDep:
    """A dep declared by tarball URL.

    Grammar:
        ``<name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]``

    ``sha256`` is optional (TOFU when absent).  ``strip_components``
    stripping is applied BEFORE ``content_hash`` computation.
    TarballDep IS CAS-admissible.

    ``predicates`` are evaluated before the dep is passed to the solver
    (§6.3 NORMATIVE: all five dep forms support ``when``-conditional syntax).
    Populated from enclosing ``when`` block predicates by ``_parse_tarball_dep``.
    """

    name: str
    url: str
    sha256: str | None = None
    strip_components: int = 0
    predicates: tuple[Predicate, ...] = ()


@dataclass(frozen=True)
class MemberDep:
    """A workspace-internal member reference.

    Grammar: ``member "<member-name>"``

    The node name is the literal keyword ``member`` (not the package
    name).  The positional arg is the workspace member's intrinsic name.
    MemberDep is NOT CAS-admissible.

    ``predicates`` are evaluated before the dep is passed to the solver
    (§6.3 NORMATIVE: all five dep forms support ``when``-conditional syntax).
    Populated from enclosing ``when`` block predicates by ``_parse_member_dep``.
    Note: MAN-DEP-MEMBER-PROPS still forbids properties directly ON the member
    node — predicates come exclusively from enclosing ``when`` blocks.
    """

    name: str
    predicates: tuple[Predicate, ...] = ()


# Union of all dep forms.
Dep = UrlDep | NamedDep | LocalDep | TarballDep | MemberDep


@dataclass(frozen=True)
class GitTarget:
    """Override target: replace a dep with a git fork URL + ref.

    Corresponds to ``pkg "name" git=(url)"..." ref="..."`` (the original
    git form, unchanged behavior).  Identity-bearing; CAS-admissible.
    """

    git: str
    ref: str


@dataclass(frozen=True)
class LocalTarget:
    """Override target: replace a dep with a local filesystem path.

    Corresponds to ``pkg "name" local="<relative-path>"``.
    Liveness-only; NOT CAS-admissible; non-reproducible for external
    consumers (§3.3 carve-out).  Resolution wired in S8a.
    """

    path: str


@dataclass(frozen=True)
class MemberTarget:
    """Override target: replace a dep with a workspace member.

    Corresponds to ``pkg "name" { member "<member-name>" }``.
    Identity-bearing; NOT CAS-admissible.  Resolution wired in S8b.
    """

    member_name: str


# Discriminated union of all override target kinds (S8, RFC #23 §3.3).
OverrideTarget = GitTarget | LocalTarget | MemberTarget


@dataclass(frozen=True)
class Override:
    """A pkg-form override (S8 discriminated union, RFC #23 §3.3).

    ``name`` is the dep name to intercept.  ``target`` is exactly one of
    ``GitTarget``, ``LocalTarget``, or ``MemberTarget`` — never a mix.
    Zero or multiple targets in the same ``pkg`` rule raise
    ``MAN-OVERRIDE-TARGET-AMBIGUOUS``.

    Project-wide scope.  Does not propagate to downstream consumers.
    """

    name: str
    target: OverrideTarget


@dataclass(frozen=True)
class CrossPkgEnable:
    """A cross-package enable entry inside an ``enables`` node.

    Reuses ``FlagRequest`` for the per-flag requests (SSOT).

    ``dep`` is the dep node-name (validated as a KDL identifier at parse
    time).  ``flag_requests`` are the ``flag`` children of that dep node,
    structurally identical to ``UrlDep.flag_requests``.
    """

    dep: str
    flag_requests: tuple[FlagRequest, ...]


@dataclass(frozen=True)
class FlagDecl:
    """A named feature flag declared by a package.

    ``default`` is the flag's value when no consumer requests otherwise.
    ``description`` is human-facing documentation.
    ``defines`` are explicit ``-d:`` flags for the Nim compiler when
    active; empty tuple uses the convention ``-d:<pkg>_<flag>``.

    S1 (RFC #23 §3.1.1 / §3.1.4):
    ``enables_same_pkg`` — same-package flag names this flag enables when active.
    ``enables_cross_pkg`` — cross-package dep→flag activation entries.
    Multiple ``enables`` nodes union together (§3.1.1).
    ``conflicts`` — same-package flag names that cannot be co-active (§3.1.4).
    """

    name: str
    default: bool = False
    description: str = ""
    defines: tuple[str, ...] = ()
    enables_same_pkg: tuple[str, ...] = ()
    enables_cross_pkg: tuple[CrossPkgEnable, ...] = ()
    conflicts: tuple[str, ...] = ()


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
    ``optional_auto_flags`` is the set of flag names that were auto-injected
    by the parse-time optional desugaring (S7 RFC #23 §3.2).  These are
    implied by ``optional=#true`` on the dep and must NOT be serialized in
    the ``flags {}`` block (they'd cause a clash on re-parse).
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
    attestation_policy: TrustPolicy = "warn"
    optional_auto_flags: frozenset[str] = frozenset()  # S7: not serialized
    # S5 (RFC registry-trust-federation §6.4): whole-index attestation gate policy.
    index_trust_policy: TrustPolicy = "warn"
    """Effective index-trust policy parsed from ``index-trust`` node; defaults to ``'warn'``."""
    index_trust_signer: str | None = None
    """Expected SubjectAltName override from ``index-trust-signer`` node (RFC §3.2)."""
    index_trust_bundle: str | None = None
    """Trust-root override (``file://`` path) from ``index-trust-bundle`` node (RFC §3.2)."""
    index_trust_policy_explicit: bool = False
    """``True`` iff the source declared an ``index-trust`` node (absent-stays-absent
    rule, mirrors ``spec_version_explicit``).  Needed because ``'warn'`` is both the
    default AND a legal explicit value: a workspace MEMBER manifest that explicitly
    declares ``index-trust "warn"`` must still raise ``WS-INDEX-TRUST-ON-MEMBER``
    (RFC registry-trust-federation §6.4a) even though the value matches the default."""


@dataclass(frozen=True)
class WorkspaceManifest:
    """A workspace-root manifest.

    Pure container: declares member package paths and optional
    workspace-level overrides.  A workspace manifest MUST NOT declare
    ``deps`` or ``kind`` (``MAN-WORKSPACE-HAS-DEPS-OR-KIND``).

    S11 (RFC #23 §3.8): workspace root may carry a ``flags {}`` block whose
    default-true activations apply workspace-wide.  Reuses ``FlagDecl`` — no
    parallel flag type.

    S5 redesign (RFC registry-trust-federation §6.4a root-authority model):
    the workspace root is the resolution root for index-trust purposes, so
    it — and ONLY it — may declare ``index-trust`` / ``index-trust-signer`` /
    ``index-trust-bundle``.  A member manifest declaring any of these three
    raises ``WS-INDEX-TRUST-ON-MEMBER`` at workspace-load time
    (``workspace.py``, not this module).
    """

    members: tuple[str, ...]
    overrides: tuple[Override, ...] = ()
    name: str | None = None
    flags: tuple["FlagDecl", ...] = ()  # S11: workspace-root flags (§3.8)
    # S5 (RFC registry-trust-federation §6.4a): whole-index attestation gate,
    # declared ONLY on the resolution root.
    index_trust_policy: TrustPolicy = "warn"
    """Effective index-trust policy for the whole workspace; defaults to ``'warn'``."""
    index_trust_signer: str | None = None
    """Expected SubjectAltName override from ``index-trust-signer`` node."""
    index_trust_bundle: str | None = None
    """Trust-root override (``file://`` path) from ``index-trust-bundle`` node."""
    index_trust_policy_explicit: bool = False
    """``True`` iff the source declared an ``index-trust`` node (absent-stays-absent
    rule, mirrors ``Manifest.index_trust_policy_explicit``). Needed so the
    serializer only emits ``index-trust`` when it was actually declared — never
    a spurious default ``"warn"`` that wasn't in the source."""


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

    Walks ``dep.predicates`` for ALL five dep forms (UrlDep, NamedDep,
    LocalDep, TarballDep, MemberDep); any ``Predicate(name='flag')`` whose
    values reference an undeclared flag name raises
    ``MAN-FLAG-UNDECLARED-REFERENCE``.
    """
    for dep in deps:
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


def _check_flag_conflicts_references(
    flags: list["FlagDecl"],
    declared_flag_names: frozenset[str],
) -> None:
    """Post-parse validation for ``conflicts`` bare same-package names.

    Walks every ``FlagDecl.conflicts``; any name not present in
    ``declared_flag_names`` raises ``MAN-FLAG-CONFLICTS-UNDECLARED``.

    Scope: same-package only (cross-package conflicts deferred, RFC #23 §3.1.4).
    Forward references are legal — this runs after the full flags table is built.
    """
    from milpa.errors import MAN_FLAG_CONFLICTS_UNDECLARED, MAN_FLAG_CONFLICTS_SELF

    for fd in flags:
        for flag_name_ref in fd.conflicts:
            if flag_name_ref == fd.name:
                raise MilpaError(
                    MAN_FLAG_CONFLICTS_SELF,
                    f"flag {fd.name!r}: conflicts with itself — a flag cannot "
                    f"list its own name in conflicts",
                    flag=fd.name,
                )
            if flag_name_ref not in declared_flag_names:
                raise MilpaError(
                    MAN_FLAG_CONFLICTS_UNDECLARED,
                    f"flag {fd.name!r}: conflicts references undeclared flag "
                    f"{flag_name_ref!r}",
                    flag=fd.name,
                    conflicts=flag_name_ref,
                )


def _check_flag_enables_references(
    flags: list["FlagDecl"],
    declared_flag_names: frozenset[str],
    dep_names: frozenset[str],
) -> None:
    """Post-parse validation for ``enables`` bare same-package names.

    Walks every ``FlagDecl.enables_same_pkg``; any name not present in
    ``declared_flag_names`` raises ``MAN-FLAG-ENABLES-UNDECLARED``.

    When the undeclared name is also a dep name, the diagnostic adds:
    ``"<name>" is a dependency, not a flag — add optional=#true …``

    Cross-package ``enables_cross_pkg`` entries are NOT validated here.
    """
    for fd in flags:
        for flag_name_ref in fd.enables_same_pkg:
            if flag_name_ref not in declared_flag_names:
                base_msg = (
                    f"flag {fd.name!r}: enables references undeclared flag "
                    f"{flag_name_ref!r}"
                )
                if flag_name_ref in dep_names:
                    base_msg += (
                        f" ({flag_name_ref!r} is a dependency, not a flag"
                        " — add optional=#true to make it a feature)"
                    )
                raise MilpaError(
                    MAN_FLAG_ENABLES_UNDECLARED,
                    base_msg,
                    flag=fd.name,
                    enables=flag_name_ref,
                )


def flag_enables_closure(
    flags: "tuple[FlagDecl, ...] | list[FlagDecl]",
    seed: "frozenset[str]",
) -> "frozenset[str]":
    """Monotone least-fixpoint of same-package ``enables`` over one manifest's flag table.

    S2 (RFC #23 §7 + §3.1.2).

    Input:
      ``flags``  — the ``FlagDecl`` tuples from a single manifest.
      ``seed``   — the starting active-flag-name set (e.g. default-true flags,
                   CLI-requested flags, or a cross-package request set).

    Output:
      The closure: ``seed`` ∪ every same-package flag reachable by following
      ``enables_same_pkg`` edges from any active flag, to a fixed point.

    Properties guaranteed (§3.1.2):
      - **Seed inclusion**: result ⊇ seed.
      - **Transitive**: follows multi-hop enables chains.
      - **Idempotence**: ``closure(closure(S)) == closure(S)``.
      - **Cycle termination**: ``a enables b, b enables a`` → ``{a, b}`` in O(n).
      - **Order-independence**: result is independent of flag declaration order
        (union is commutative).
      - **Cross-package ignored**: ``enables_cross_pkg`` entries are NOT followed
        here — they are activated at resolve time in S3/S4a.
      - **Unknown targets skipped**: any enables target not in the flag table is
        silently ignored (post-parse validation ensures this is unreachable in
        practice, but the function is safe if called on partially-built tables).

    Design note: the caller is responsible for seeding from ``default=#true``
    flags (``frozenset(f.name for f in flags if f.default)``).  This keeps the
    pure closure function a single-responsibility SSOT.
    """
    # Build a name→enables_same_pkg lookup for O(1) access.
    enables_by_name: dict[str, tuple[str, ...]] = {
        fd.name: fd.enables_same_pkg for fd in flags
    }
    active = set(seed)
    worklist = list(seed)
    while worklist:
        flag_name = worklist.pop()
        for target in enables_by_name.get(flag_name, ()):
            if target not in active and target in enables_by_name:
                active.add(target)
                worklist.append(target)
    return frozenset(active)


def _desugar_one_dep(
    dep: "Dep",
    declared_flag_names: "frozenset[str]",
    new_flags: "list[FlagDecl]",
    injected_flag_names: "set[str]",
) -> "Dep":
    """Desugar one dep that carries ``optional=True``.

    Returns the transformed dep (or the original if not optional).
    Mutates ``new_flags`` and ``injected_flag_names`` in-place.

    Extracted from the former nested ``_desugar_dep`` closure inside
    ``_desugar_optional_deps`` to eliminate hidden effectful coupling.
    """
    if not isinstance(dep, (UrlDep, NamedDep)):
        return dep
    if not dep.optional:
        return dep

    dep_nm = dep.name

    # 1. Clash with already-declared flags (pre-desugar) or already-injected
    #    auto-flags from earlier optional deps in this same parse.
    if dep_nm in declared_flag_names or dep_nm in injected_flag_names:
        raise MilpaError(
            MAN_DEP_OPTIONAL_FLAG_CLASH,
            f"dep {dep_nm!r}: optional dep name {dep_nm!r} collides with an "
            "already-declared flag of the same name — rename the flag or "
            "the dep (RFC #23 §3.2)",
            dep=dep_nm,
            flag=dep_nm,
        )

    # 2. Inject auto-flag FlagDecl(name=dep_nm, default=False).
    injected_flag_names.add(dep_nm)
    new_flags.append(FlagDecl(name=dep_nm, default=False))

    # 3. Inject flag=<depname> predicate, deduplicating if already explicit.
    gate_pred = Predicate(name="flag", values=(dep_nm,), negated=False)
    if isinstance(dep, UrlDep):
        existing_preds = dep.predicates
        # Idempotent: collapse a duplicate explicit gate, compose any others.
        if gate_pred not in existing_preds:
            new_preds = existing_preds + (gate_pred,)
        else:
            new_preds = existing_preds
        # Return a new UrlDep with the injected predicate (frozen dataclass).
        return UrlDep(
            name=dep.name,
            git=dep.git,
            ref=dep.ref,
            mirrors=dep.mirrors,
            predicates=new_preds,
            flag_requests=dep.flag_requests,
            optional=True,  # preserve for round-trip
        )
    else:
        # NamedDep: inject the gate predicate into the predicates field
        # (same approach as UrlDep — all five dep forms carry predicates; SSOT).
        existing_preds = dep.predicates
        if gate_pred not in existing_preds:
            new_preds = existing_preds + (gate_pred,)
        else:
            new_preds = existing_preds
        return NamedDep(
            name=dep.name,
            constraint=dep.constraint,
            constraint_set=dep.constraint_set,
            flag_requests=dep.flag_requests,
            optional=True,
            predicates=new_preds,
            namespace=dep.namespace,  # S5b: preserve namespace through desugar
        )


def _desugar_optional_deps(
    deps: list[Dep],
    dev_deps: list[Dep],
    flags: list[FlagDecl],
    declared_flag_names: frozenset[str],
) -> tuple[list[Dep], list[Dep], list[FlagDecl], frozenset[str]]:
    """Parse-time desugaring of ``optional=#true`` deps (S7, RFC #23 §3.2).

    For each dep with ``optional=True`` in ``deps`` or ``dev_deps``:
    1. Check no flag of that name is already declared — else
       ``MAN-DEP-OPTIONAL-FLAG-CLASH``.
    2. Auto-declare a ``FlagDecl(name=dep_name, default=False)`` and append
       it to ``flags``.
    3. Inject a ``flag=<depname>`` predicate into the dep's predicates
       (deduplicating if an explicit identical predicate already exists).

    Note: charset validation (``[A-Za-z0-9_-]+``) is performed earlier by the
    dep-name parser (``MAN-DEP-NAME-INVALID``), which runs for ALL dep names
    before optional desugaring.  ``MAN-DEP-OPTIONAL-INVALID-NAME`` is only
    raised by ``milpa add --optional`` when the user supplies a name on the
    command line that violates the flag-name charset.

    Namespace hygiene (§3.2 normative): also checks that **non-optional** deps
    do not share a name with any **explicitly declared** flag (pre-desugar).
    This catches latent confusion where a dep name and a flag name fuse
    unexpectedly.  Error: ``MAN-DEP-OPTIONAL-FLAG-CLASH``.

    Returns the updated ``(deps, dev_deps, flags, injected_names)`` 4-tuple.
    ``injected_names`` is the ``frozenset`` of flag names that were auto-
    injected (needed by ``format_manifest`` to skip them in the flags block).
    All inputs are consumed and must not be used after this call.
    """
    # Namespace hygiene: non-optional deps must not collide with declared flags.
    # NORMATIVE (spec/errors.md §MAN-DEP-OPTIONAL-FLAG-CLASH): all five dep
    # forms are checked — only UrlDep/NamedDep can carry optional=True, so
    # LocalDep/TarballDep/MemberDep are always non-optional.
    # Mirrors Rust desugar_optional_deps (milpa-manifest/src/lib.rs).
    for dep in list(deps) + list(dev_deps):
        is_optional = isinstance(dep, (UrlDep, NamedDep)) and dep.optional
        if not is_optional and dep.name in declared_flag_names:
            # R8-D2: only UrlDep/NamedDep support optional=#true; LocalDep,
            # TarballDep, and MemberDep cannot be made optional, so the hint
            # must be suppressed for those types.
            if isinstance(dep, (UrlDep, NamedDep)):
                hint = "rename one or mark the dep optional=#true"
            else:
                hint = "rename the dep or the flag"
            raise MilpaError(
                    MAN_DEP_OPTIONAL_FLAG_CLASH,
                    f"dep {dep.name!r}: dep name collides with a declared flag "
                    f"{dep.name!r} — dep and flag namespaces are fused by "
                    f"optional deps (RFC #23 §3.2); {hint}",
                    dep=dep.name,
                    flag=dep.name,
                )

    # Track newly injected flags so we can detect clash among optional deps too.
    injected_flag_names: set[str] = set()
    new_flags: list[FlagDecl] = list(flags)

    new_deps = [
        _desugar_one_dep(d, declared_flag_names, new_flags, injected_flag_names)
        for d in deps
    ]
    new_dev_deps = [
        _desugar_one_dep(d, declared_flag_names, new_flags, injected_flag_names)
        for d in dev_deps
    ]
    return new_deps, new_dev_deps, new_flags, frozenset(injected_flag_names)


# ---------------------------------------------------------------------------
# Shared index-trust node parsers (SSOT — used by both the package-manifest
# parser and the workspace-root parser; RFC registry-trust-federation §6.4a)
# ---------------------------------------------------------------------------


def _parse_index_trust_node(n: "KdlNode") -> TrustPolicy:
    """Parse an ``index-trust "<policy>"`` node into a ``TrustPolicy``."""
    raw_args = node_args(n)
    if len(raw_args) != 1 or not isinstance(raw_args[0], str):
        raise MilpaError(
            MAN_UNKNOWN_TOP_LEVEL,
            "'index-trust' takes exactly one string argument "
            "('warn', 'strict', or 'off')",
            node="index-trust",
        )
    return _parse_trust_policy(raw_args[0], node="index-trust")


def _parse_index_trust_signer_node(n: "KdlNode") -> str:
    """Parse an ``index-trust-signer "<identity>"`` node into its raw string."""
    raw_args = node_args(n)
    if len(raw_args) != 1 or not isinstance(raw_args[0], str):
        raise MilpaError(
            MAN_UNKNOWN_TOP_LEVEL,
            "'index-trust-signer' takes exactly one string argument "
            "(expected SubjectAltName / OIDC workflow URL)",
            node="index-trust-signer",
        )
    return raw_args[0]


def _parse_index_trust_bundle_node(n: "KdlNode") -> str:
    """Parse an ``index-trust-bundle "<file://path>"`` node into its raw string."""
    raw_args = node_args(n)
    if len(raw_args) != 1 or not isinstance(raw_args[0], str):
        raise MilpaError(
            MAN_UNKNOWN_TOP_LEVEL,
            "'index-trust-bundle' takes exactly one string argument "
            "(a file:// path to an alternate trust root bundle)",
            node="index-trust-bundle",
        )
    return raw_args[0]


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
    attestation_policy: TrustPolicy = "warn"
    # S5: index-trust nodes (RFC registry-trust-federation §6.4)
    index_trust_policy: TrustPolicy = "warn"
    index_trust_signer: str | None = None
    index_trust_bundle: str | None = None
    index_trust_policy_explicit: bool = False
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
            # R2-C2 + R2-Unicode fix: reject control chars and Unicode line
            # separators — src_dir flows verbatim to nim.cfg --path: lines.
            if contains_unsafe_char(v):
                raise MilpaError(
                    MAN_SRC_DIR_UNSAFE,
                    f"'src_dir' value {v!r} contains a control character or "
                    "Unicode line separator (U+2028/U+2029) — this would allow "
                    "nim.cfg injection; rejected at parse boundary",
                    value=repr(v),
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

        elif nm == "attestation-policy":
            raw_args = node_args(n)
            if len(raw_args) != 1 or not isinstance(raw_args[0], str):
                raise MilpaError(
                    MAN_UNKNOWN_TOP_LEVEL,
                    "'attestation-policy' takes exactly one string argument "
                    "('warn', 'strict', or 'off')",
                    node="attestation-policy",
                )
            attestation_policy = _parse_trust_policy(
                raw_args[0], node="attestation-policy"
            )

        elif nm == "index-trust":
            # S5: whole-index attestation gate policy (RFC §6.4).
            index_trust_policy = _parse_index_trust_node(n)
            index_trust_policy_explicit = True

        elif nm == "index-trust-signer":
            # S5: expected SubjectAltName override (RFC §3.2, §6.4).
            index_trust_signer = _parse_index_trust_signer_node(n)

        elif nm == "index-trust-bundle":
            # S5: trust-root override — a file:// path to a custom Fulcio CA +
            # Rekor key bundle (RFC §3.2, §6.4).
            index_trust_bundle = _parse_index_trust_bundle_node(n)

        elif nm == "flags":
            flags = _parse_flags_block(n)

    if name is None:
        raise MilpaError(
            MAN_NAME_MISSING,
            "manifest is missing required 'name' node",
        )

    # Collect dep_names (used both by desugar and enables-reference check).
    dep_names = frozenset(
        d.name for d in list(deps) + list(dev_deps)
        if not isinstance(d, MemberDep)
    )

    # S7 (RFC #23 §3.2) parse-time optional desugaring runs FIRST among the
    # post-parse passes so the auto-injected flag names are visible to all
    # downstream reference checks (enables, conflicts, flag predicates).
    # Checks namespace hygiene (non-optional dep sharing a flag name);
    # raises MAN-DEP-OPTIONAL-FLAG-CLASH on error.  Charset validation
    # (MAN-DEP-NAME-INVALID) runs earlier at dep-parse time.
    declared_flag_names = frozenset(f.name for f in flags)
    deps, dev_deps, flags, optional_auto_flags = _desugar_optional_deps(
        deps=deps,
        dev_deps=dev_deps,
        flags=flags,
        declared_flag_names=declared_flag_names,
    )
    # Recompute after desugar so auto-injected flag names are included.
    declared_flag_names = frozenset(f.name for f in flags)

    # 3c-8 post-parse: check that all 'flag' predicate references name a
    # declared flag (MAN-FLAG-UNDECLARED-REFERENCE).
    # Runs AFTER desugar so the auto-injected gate predicates don't falsely
    # trigger this check (they reference auto-injected flags that are now declared).
    _check_flag_predicate_references(
        list(deps) + list(dev_deps), declared_flag_names
    )

    # S1 (RFC #23 §3.1.1) post-parse: check that all enables bare same-pkg names
    # reference a declared flag (MAN-FLAG-ENABLES-UNDECLARED).  Forward references
    # are legal because we do this AFTER the full flags table is built.
    # Runs AFTER desugar so enables referencing auto-injected optional-flag names
    # (e.g. `enables "optlib"` for an `optlib optional=#true` dep) are valid.
    # Cross-package enables children are NOT validated here (resolve-time concern).
    _check_flag_enables_references(flags, declared_flag_names, dep_names)

    # S4c (RFC #23 §3.1.4) post-parse: check that all conflicts bare same-pkg
    # names reference a declared flag (MAN-FLAG-CONFLICTS-UNDECLARED).  Same
    # structure as the enables check above — post-parse, forward references legal,
    # same-package only.
    _check_flag_conflicts_references(flags, declared_flag_names)

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
        attestation_policy=attestation_policy,
        optional_auto_flags=optional_auto_flags,
        index_trust_policy=index_trust_policy,
        index_trust_signer=index_trust_signer,
        index_trust_bundle=index_trust_bundle,
        index_trust_policy_explicit=index_trust_policy_explicit,
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
    ws_flags: list[FlagDecl] = []
    # S5 (RFC registry-trust-federation §6.4a): index-trust is a root-authority
    # field — legal ONLY on the workspace root (this function).  Members that
    # declare it raise WS-INDEX-TRUST-ON-MEMBER in workspace.py at load time.
    ws_index_trust_policy: TrustPolicy = "warn"
    ws_index_trust_signer: str | None = None
    ws_index_trust_bundle: str | None = None
    ws_index_trust_policy_explicit: bool = False

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

        elif nm == "flags":
            # S11 (RFC #23 §3.8): workspace-root flags {}.
            # Reuses _parse_flags_block (SSOT).
            ws_flags = _parse_flags_block(n)

        elif nm == "index-trust":
            # S5 (RFC registry-trust-federation §6.4a): root-authority policy.
            ws_index_trust_policy = _parse_index_trust_node(n)
            ws_index_trust_policy_explicit = True

        elif nm == "index-trust-signer":
            ws_index_trust_signer = _parse_index_trust_signer_node(n)

        elif nm == "index-trust-bundle":
            ws_index_trust_bundle = _parse_index_trust_bundle_node(n)

    return WorkspaceManifest(
        members=tuple(members),
        overrides=tuple(overrides),
        name=ws_name,
        flags=tuple(ws_flags),  # S11
        index_trust_policy=ws_index_trust_policy,
        index_trust_signer=ws_index_trust_signer,
        index_trust_bundle=ws_index_trust_bundle,
        index_trust_policy_explicit=ws_index_trust_policy_explicit,
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
    # S5b: uniqueness key is the qualified identity.  For NamedDep it is
    # ``(namespace, name)`` — two NamedDeps with the same bare name but
    # different namespaces are DISTINCT and both allowed in one block.
    # For all other dep types (UrlDep, LocalDep, TarballDep, MemberDep) the
    # name is the bare node name and no namespace exists, so the key is
    # ``(None, name)`` (same as before this change).
    seen_names: set[tuple[str | None, str]] = set()

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
                ns = dep.namespace if isinstance(dep, NamedDep) else None
                _key = (ns, dep.name)
                if _key in seen_names:
                    display = f"{ns}/{dep.name}" if ns else dep.name
                    raise MilpaError(
                        MAN_DEP_DUPLICATE,
                        f"duplicate dep {display!r} in {block_name!r} block",
                        dep=dep.name,
                        block=block_name,
                    )
                seen_names.add(_key)
                deps.append(dep)
            continue

        dep = _parse_dep_node(
            child, block_name=block_name, outer_predicates=outer_predicates
        )
        dep_name = dep.name
        ns = dep.namespace if isinstance(dep, NamedDep) else None
        _dep_key = (ns, dep_name)
        display_name = f"{ns}/{dep_name}" if ns else dep_name

        if _dep_key in seen_names:
            raise MilpaError(
                MAN_DEP_DUPLICATE,
                f"duplicate dep {display_name!r} in {block_name!r} block",
                dep=dep_name,
                block=block_name,
            )
        seen_names.add(_dep_key)
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
        return _parse_member_dep(n, outer_predicates=outer_predicates)

    # S5b: slash-shorthand desugar (manifest-grammar.md §3.2 NamedDep).
    # ``"core/pkg"`` desugars to namespace="core", name="pkg" at parse time.
    # The desugar happens before the charset check so downstream only sees the
    # attribute form.  A name with more than one `/` or empty parts is malformed.
    slash_namespace: str | None = None
    if "/" in nm:
        parts = nm.split("/")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise MilpaError(
                MAN_DEP_NAME_INVALID,
                f"dep {nm!r}: qualified dep names must have exactly one '/' separator "
                "with non-empty namespace and package name parts (e.g. \"core/pkg\")",
                dep=nm,
            )
        ns_part, name_part = parts
        if not valid_dep_name(ns_part):
            raise MilpaError(
                MAN_DEP_NAME_INVALID,
                f"dep {nm!r}: namespace part {ns_part!r} must match [A-Za-z0-9_-]+",
                dep=nm,
            )
        if not valid_dep_name(name_part):
            raise MilpaError(
                MAN_DEP_NAME_INVALID,
                f"dep {nm!r}: name part {name_part!r} must match [A-Za-z0-9_-]+",
                dep=nm,
            )
        slash_namespace = ns_part
        nm = name_part
    else:
        # R2-C1 security fix: validate dep name charset at parse boundary.
        # KDL 2.0 quoted node names can contain chars outside [A-Za-z0-9_-].
        # A dep name with \n (or other nim.cfg-significant char) would inject content
        # via --path:"_deps/<name>" and -d:<pkg>_<flag> emit lines in nimcfg.py.
        if not valid_dep_name(nm):
            raise MilpaError(
                MAN_DEP_NAME_INVALID,
                f"dep {nm!r}: dep names must match [A-Za-z0-9_-]+ "
                "(no spaces, control characters, or nim.cfg-significant chars)",
                dep=nm,
            )

    if "git" in props:
        return _parse_url_dep(n, dep_name=nm, outer_predicates=outer_predicates)
    if "local" in props:
        return _parse_local_dep(n, dep_name=nm, outer_predicates=outer_predicates)
    if "tarball" in props:
        return _parse_tarball_dep(n, dep_name=nm, outer_predicates=outer_predicates)
    return _parse_named_dep(
        n,
        dep_name=nm,
        outer_predicates=outer_predicates,
        slash_namespace=slash_namespace,
    )


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

    # --- optional= (bool; default False) ---
    # Parsed here but NOT desugared here — the desugar pass in
    # ``_parse_manifest_doc`` runs after all deps + flags are collected so it
    # can check for name clashes.  ``optional`` is retained on the dep for
    # round-trip serialization (``format_manifest`` emits ``optional=#true``).
    optional: bool = False
    if "optional" in node_props(n):
        optional_raw = node_props(n).get("optional")
        from milpa.kdl_io import node_prop_bool
        optional_v = node_prop_bool(n, "optional")
        if optional_v is None:
            raise MilpaError(
                MAN_DEP_UNKNOWN_PROPS,
                f"dep {dep_name!r}: 'optional=' must be a boolean (#true or #false)",
                dep=dep_name,
                prop="optional",
            )
        optional = optional_v

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
        optional=optional,
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


def _parse_named_dep(
    n: KdlNode,
    *,
    dep_name: str,
    outer_predicates: tuple[Predicate, ...] = (),
    slash_namespace: str | None = None,
) -> NamedDep:
    """Parse a NamedDep (registry-resolved).

    Grammar: ``<name>`` or ``<name> "<version-constraint>"``
    S5b extension: ``<name> namespace="<ns>" ["<constraint>"]`` or
    slash-shorthand ``"<ns>/<name>" ["<constraint>"]`` (desugared before this call).

    Optionally with a ``{ flag "x" }`` child block (§3.1.5, S3 RFC #23).
    ``optional=#true`` is permitted (S7 RFC #23 §3.2).

    The constraint string is pre-typed to ``VersionSet`` at this boundary.
    Children: only ``flag`` child nodes are accepted (same parser as UrlDep).

    ``outer_predicates`` are inherited predicates from an enclosing ``when``
    block (§6.3); they are stored as the initial predicates tuple.  The
    optional-desugar pass (S7) may extend this tuple with a flag gate.

    ``slash_namespace`` carries the namespace extracted by the slash-desugar
    pass in ``_parse_dep_node``; the ``namespace=`` attribute overrides it
    (both cannot be set simultaneously — redundant but harmless).
    """
    raw_args = node_args(n)
    props = node_props(n)

    # --- namespace= (str; default None) S5b ---
    # Accept ``namespace="..."`` as a property on NamedDep; mutually compatible
    # with slash-shorthand (the two paths converge here).
    namespace: str | None = slash_namespace
    if "namespace" in props:
        ns_val = node_prop_str(n, "namespace")
        if ns_val is None:
            raise MilpaError(
                MAN_DEP_NAMED_PROPS,
                f"dep {dep_name!r}: 'namespace=' must be a string",
                dep=dep_name,
                prop="namespace",
            )
        if not valid_dep_name(ns_val):
            raise MilpaError(
                MAN_DEP_NAME_INVALID,
                f"dep {dep_name!r}: namespace {ns_val!r} must match [A-Za-z0-9_-]+ "
                "(same charset as dep names)",
                dep=dep_name,
            )
        # M2 (rfc-resolver-correctness.md): if BOTH slash-shorthand AND namespace=
        # attribute are present AND they DISAGREE, raise MAN-DEP-NAME-INVALID.
        # If they agree, accept (idempotent; author just over-specified).
        if slash_namespace is not None and slash_namespace != ns_val:
            raise MilpaError(
                MAN_DEP_NAME_INVALID,
                f"dep {dep_name!r}: slash namespace {slash_namespace!r} disagrees "
                f"with namespace= attribute {ns_val!r}; use one or the other",
                dep=dep_name,
            )
        namespace = ns_val

    # --- optional= (bool; default False) ---
    # Allowed on NamedDep (RFC #23 §3.2 covers both URL and named deps).
    optional: bool = False
    if "optional" in props:
        from milpa.kdl_io import node_prop_bool
        optional_v = node_prop_bool(n, "optional")
        if optional_v is None:
            raise MilpaError(
                MAN_DEP_NAMED_PROPS,
                f"dep {dep_name!r}: 'optional=' must be a boolean (#true or #false)",
                dep=dep_name,
                prop="optional",
            )
        optional = optional_v

    # Any property other than 'optional' and 'namespace' is an error.
    # (git= routes to UrlDep before we reach here.)
    for prop_key in props:
        if prop_key not in ("optional", "namespace"):
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

    # Parse children: only ``flag`` child nodes accepted (§3.1.5).
    flag_requests: list[FlagRequest] = []
    for child in node_children(n):
        child_nm = node_name(child)
        if child_nm == "flag":
            flag_requests.append(_parse_flag_request_child(child, dep_name=dep_name))
        else:
            raise MilpaError(
                MAN_DEP_UNKNOWN_CHILD,
                f"dep {dep_name!r}: unknown child node {child_nm!r} "
                "(NamedDep accepts only 'flag' children)",
                dep=dep_name,
                child=child_nm,
            )

    if len(raw_args) == 0:
        # No constraint — any version
        return NamedDep(
            name=dep_name,
            constraint=None,
            constraint_set=None,
            flag_requests=tuple(flag_requests),
            optional=optional,
            predicates=outer_predicates,
            namespace=namespace,
        )

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
    return NamedDep(
        name=dep_name,
        constraint=arg,
        flag_requests=tuple(flag_requests),
        optional=optional,
        predicates=outer_predicates,
        namespace=namespace,
    )


def _parse_local_dep(
    n: KdlNode,
    *,
    dep_name: str,
    outer_predicates: tuple[Predicate, ...] = (),
) -> LocalDep:
    """Parse a LocalDep node.

    Grammar: ``<name> local="<path>"``

    The ``local=`` value must be a non-empty string.
    No other properties are permitted.

    ``outer_predicates`` are inherited predicates from an enclosing ``when``
    block (§6.3); they are stored on the LocalDep for filter-before-solve.
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

    return LocalDep(name=dep_name, path=path, predicates=outer_predicates)


def _parse_tarball_dep(
    n: KdlNode,
    *,
    dep_name: str,
    outer_predicates: tuple[Predicate, ...] = (),
) -> TarballDep:
    """Parse a TarballDep node.

    Grammar:
        ``<name> tarball=(url)"<URL>" [sha256="<hex>"] [strip_components=<N>]``

    ``tarball=`` must be a non-empty URL string (plain or ``(url)``-annotated).
    ``sha256`` optional string; non-string raises MAN-DEP-TARBALL-SHA.
    ``strip_components`` optional non-negative int; negative/non-int/bool
    raises MAN-DEP-TARBALL-STRIP.

    ``outer_predicates`` are inherited predicates from an enclosing ``when``
    block (§6.3); they are stored on the TarballDep for filter-before-solve.
    """
    props = node_props(n)

    # --- tarball= URL ---
    tarball_url_v = node_prop_url(n, "tarball")
    if tarball_url_v is None:
        if "tarball" in props:
            # Present but not a (url)-annotated string (plain string, wrong type, etc.)
            raise MilpaError(
                MAN_URL_ARG_TYPE,
                f"dep {dep_name!r}: 'tarball=' must be a (url)-annotated URL string",
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
        # Must NOT be a float literal (including whole floats like 1.0).
        # KDL 2.0 distinguishes integer literals from float literals at the type
        # level; 1.0 is a float literal and is rejected here to match Rust
        # (kdl-rs typed API rejects Float at integer-typed fields).
        if isinstance(raw_strip, float):
            raise MilpaError(
                MAN_DEP_TARBALL_STRIP,
                f"dep {dep_name!r}: 'strip_components=' must be an integer literal, "
                f"got float {raw_strip!r}",
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
        predicates=outer_predicates,
    )


def _parse_overrides_block(block: KdlNode) -> list[Override]:
    """Parse an ``overrides { }`` block.

    Each child MUST be named ``pkg``.  S8 grammar (RFC #23 §3.3):
        git form:    ``pkg "<name>" git=(url)"<URL>" ref="<ref>"``
        local form:  ``pkg "<name>" local="<relative-path>"``
        member form: ``pkg "<name>" { member "<member-name>" }``

    Exactly one provenance target per ``pkg`` rule; zero or multiple targets
    raises ``MAN-OVERRIDE-TARGET-AMBIGUOUS``.

    Error codes:
    - Unknown child name → ``MAN-OVERRIDE-KIND``
    - ``pkg`` with no positional arg (arity 0) or non-string arg → ``MAN-OVERRIDE-ARITY``
    - Zero or multiple target forms → ``MAN-OVERRIDE-TARGET-AMBIGUOUS``
    - Missing ``ref=`` on git form → ``MAN-OVERRIDE-REF-MISSING``
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

        # --- Detect which target forms are present ---
        props = node_props(child)
        children = node_children(child)

        # Known properties across all forms; validate unknowns first.
        _OVERRIDE_KNOWN_PROPS = frozenset({"git", "ref", "local"})
        for prop_key in props:
            if prop_key not in _OVERRIDE_KNOWN_PROPS:
                raise MilpaError(
                    MAN_OVERRIDE_UNKNOWN_PROPS,
                    f"override for {pkg_name!r}: unknown property {prop_key!r} "
                    "(allowed: 'git', 'ref', 'local')",
                    name=pkg_name,
                    prop=prop_key,
                )

        has_git = "git" in props
        has_local = "local" in props
        # member form: a single child node named "member"
        member_children = [c for c in children if node_name(c) == "member"]
        has_member = len(member_children) > 0

        # Count target forms (exactly one required).
        target_count = sum([has_git, has_local, has_member])
        if target_count != 1:
            raise MilpaError(
                MAN_OVERRIDE_TARGET_AMBIGUOUS,
                f"override for {pkg_name!r}: exactly one provenance form is required "
                f"(git, local, or member); got {target_count} "
                f"({'none' if target_count == 0 else 'multiple forms mixed'})",
                name=pkg_name,
            )

        # --- Parse the selected target form ---
        target: OverrideTarget
        if has_git:
            git_url_v = node_prop_url(child, "git")
            if git_url_v is None:
                # git= present but not a URL value — url_arg already rejected it above;
                # treat as missing for error consistency.
                raise MilpaError(
                    MAN_OVERRIDE_GIT_MISSING,
                    f"override for {pkg_name!r}: 'git=' must be a URL string",
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
            target = GitTarget(git=git_url, ref=ref)

        elif has_local:
            local_path = node_prop_str(child, "local")
            if not local_path:
                raise MilpaError(
                    MAN_DEP_LOCAL_PATH,
                    f"override for {pkg_name!r}: 'local=' must be a non-empty string path",
                    name=pkg_name,
                )
            target = LocalTarget(path=local_path)

        else:  # has_member
            mc = member_children[0]
            member_args = node_args(mc)
            if len(member_args) != 1 or not isinstance(member_args[0], str):
                raise MilpaError(
                    MAN_DEP_MEMBER_ARITY,
                    f"override for {pkg_name!r}: 'member' child takes exactly one "
                    "positional string argument (the workspace member name)",
                    name=pkg_name,
                )
            target = MemberTarget(member_name=member_args[0])

        if pkg_name in seen_names:
            raise MilpaError(
                MAN_OVERRIDE_DUPLICATE,
                f"duplicate override for {pkg_name!r}",
                name=pkg_name,
            )
        seen_names.add(pkg_name)
        overrides.append(Override(name=pkg_name, target=target))

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


def _parse_enables_node(
    node: KdlNode,
    *,
    flag_name: str,
    enables_same_pkg: list[str],
    enables_cross_pkg: list[CrossPkgEnable],
) -> None:
    """Parse one ``enables`` node into same-pkg names and cross-pkg entries.

    A single ``enables`` node may carry BOTH bare string args (same-package
    flag names) AND child nodes (cross-package dep→flag requests).  Multiple
    ``enables`` nodes union into the same lists (callers pass shared lists).

    Cross-package child form: ``<dep-name> { flag "<flag>" [#false] }``
    Reuses ``_parse_flag_request_child`` for the flag children (SSOT).
    """
    # Bare string args = same-package flag names.
    for i, arg in enumerate(node_args(node)):
        if not isinstance(arg, str):
            raise MilpaError(
                MAN_FLAG_UNKNOWN_CHILD,
                f"flag {flag_name!r}: 'enables' argument {i} must be a "
                f"string flag name, got {type(arg).__name__!r}",
                flag=flag_name,
                child="enables",
            )
        enables_same_pkg.append(arg)

    # Children = cross-package dep→flag entries.
    for dep_node in node_children(node):
        dep_nm = node_name(dep_node)
        # The dep node may have flag children.
        flag_reqs: list[FlagRequest] = []
        for flag_child in node_children(dep_node):
            child_nm = node_name(flag_child)
            if child_nm != "flag":
                raise MilpaError(
                    MAN_FLAG_UNKNOWN_CHILD,
                    f"flag {flag_name!r}: enables cross-pkg dep {dep_nm!r} "
                    f"has unknown child {child_nm!r} (only 'flag' is allowed)",
                    flag=flag_name,
                    child=child_nm,
                )
            flag_reqs.append(
                _parse_flag_request_child(flag_child, dep_name=f"{flag_name}→{dep_nm}")
            )
        enables_cross_pkg.append(CrossPkgEnable(dep=dep_nm, flag_requests=tuple(flag_reqs)))


def _parse_flags_block(block: KdlNode) -> list[FlagDecl]:
    """Parse a ``flags { }`` block.

    Each child is a flag declaration; the KDL identifier is the flag name.
    Permitted properties: ``default`` (bool), ``description`` (string).
    Optional child nodes: ``defines``, ``enables``, ``conflicts``.

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

        # H1 security fix: validate flag name charset at parse boundary.
        # KDL 2.0 quoted node names can contain chars outside [A-Za-z0-9_-].
        # A malicious dep could declare a flag named "x\n--passC:..." to inject
        # nim.cfg lines via the childless-convention emit: -d:<pkg>_<flagname>.
        if not valid_dep_name(flag_name):
            raise MilpaError(
                MAN_FLAG_NAME_INVALID,
                f"flag name {flag_name!r} is not valid — flag names must match "
                "[A-Za-z0-9_-]+ (no spaces, special characters, or control characters)",
                flag=flag_name,
            )

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

        # Child nodes: ``defines``, ``enables``, ``conflicts`` are allowed.
        # (S1 RFC #23 §3.1.1 / §3.1.4 adds ``enables`` and ``conflicts``.)
        defines: list[str] = []
        enables_same_pkg: list[str] = []
        enables_cross_pkg: list[CrossPkgEnable] = []
        conflicts_names: list[str] = []

        for sub_child in node_children(child):
            sub_nm = node_name(sub_child)
            if sub_nm == "defines":
                for i, define_arg in enumerate(node_args(sub_child)):
                    if not isinstance(define_arg, str):
                        raise MilpaError(
                            MAN_FLAG_DEFINES_ARG_TYPE,
                            f"flag {flag_name!r}: 'defines' argument {i} must be "
                            f"a string, got {type(define_arg).__name__!r}",
                            flag=flag_name,
                        )
                    # H1 + R2-Unicode fix: reject control chars and Unicode line
                    # separators at parse boundary. An embedded \n (or any control
                    # char, or U+2028/U+2029) in a defines value would be emitted
                    # verbatim to nim.cfg, injecting arbitrary compiler flags → code exec.
                    if contains_unsafe_char(define_arg):
                        raise MilpaError(
                            MAN_FLAG_DEFINES_UNSAFE,
                            f"flag {flag_name!r}: 'defines' argument {i} contains "
                            f"a control character or Unicode line separator "
                            f"(0x00–0x1F, 0x7F, U+2028, U+2029) — this would allow "
                            f"nim.cfg injection; rejected at parse boundary",
                            flag=flag_name,
                            arg_index=i,
                            value=repr(define_arg),
                        )
                    defines.append(define_arg)
            elif sub_nm == "enables":
                # Bare string args = same-package flag names.
                # Children = cross-package dep→flag entries.
                # Multiple enables nodes union together.
                _parse_enables_node(
                    sub_child,
                    flag_name=flag_name,
                    enables_same_pkg=enables_same_pkg,
                    enables_cross_pkg=enables_cross_pkg,
                )
            elif sub_nm == "conflicts":
                # Bare string args = same-package flag names this flag conflicts with.
                for i, arg in enumerate(node_args(sub_child)):
                    if not isinstance(arg, str):
                        raise MilpaError(
                            MAN_FLAG_UNKNOWN_CHILD,
                            f"flag {flag_name!r}: 'conflicts' argument {i} must be "
                            f"a string flag name",
                            flag=flag_name,
                            child=sub_nm,
                        )
                    conflicts_names.append(arg)
            else:
                raise MilpaError(
                    MAN_FLAG_UNKNOWN_CHILD,
                    f"flag {flag_name!r}: unknown child node {sub_nm!r} "
                    "(allowed: 'defines', 'enables', 'conflicts')",
                    flag=flag_name,
                    child=sub_nm,
                )

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
                enables_same_pkg=tuple(enables_same_pkg),
                enables_cross_pkg=tuple(enables_cross_pkg),
                conflicts=tuple(conflicts_names),
            )
        )

    return flags


def _parse_member_dep(
    n: KdlNode,
    *,
    outer_predicates: tuple[Predicate, ...] = (),
) -> MemberDep:
    """Parse a ``member "<name>"`` node.

    The node name is the literal keyword ``member``.  Requires exactly
    one positional string argument (the member's intrinsic name).
    Properties are not allowed (MAN-DEP-MEMBER-PROPS still forbids them —
    predicates come exclusively from enclosing ``when`` blocks, not as
    direct properties on the member node).

    ``outer_predicates`` are inherited predicates from an enclosing ``when``
    block (§6.3); they are stored on the MemberDep for filter-before-solve.
    """
    # S1b: members are unconditional workspace topology — a `member` inside a
    # `when` block is a category error.  Reject at parse time rather than
    # silently dropping or silently honoring the enclosing predicates.
    if outer_predicates:
        raise MilpaError(
            MAN_MEMBER_WHEN_GATED,
            "'member' dep cannot be placed inside a 'when' block — workspace "
            "members are unconditional topology present in every resolution; "
            "move the 'member' declaration outside the 'when' block",
        )

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

    # R6-F3 security fix: validate member name charset at parse boundary.
    # The name flows to ResolvedDep.name → nimcfg --path: lines, same
    # injection class as the R2-C1 dep-name fix.  Reuse SSOT charset predicate.
    nm = raw_args[0]
    if not valid_dep_name(nm):
        raise MilpaError(
            MAN_DEP_NAME_INVALID,
            f"member {nm!r}: dep names must match [A-Za-z0-9_-]+ "
            "(no spaces, control characters, or nim.cfg-significant chars)",
            dep=nm,
        )

    return MemberDep(name=nm, predicates=outer_predicates)


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
    # Must be an integer literal (not bool, not float — including whole floats
    # like 1.0).  KDL 2.0 distinguishes integer literals from float literals at
    # the type level; accepting 1.0 as "1" would be a type coercion that Rust
    # (kdl-rs typed API) rejects.  We match the stricter behavior here.
    if isinstance(epoch, bool):
        raise MilpaError(
            MAN_SPEC_VERSION_TYPE,
            f"'spec-version' argument must be a positive integer, got bool {epoch!r}",
        )
    if isinstance(epoch, float):
        raise MilpaError(
            MAN_SPEC_VERSION_TYPE,
            f"'spec-version' argument must be an integer literal, got float {epoch!r}",
        )
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
    #              pkg "name" local="<path>"
    #              pkg "name" { member "<name>" }
    if manifest.overrides:
        lines.append("overrides {")
        for ov in manifest.overrides:
            t = ov.target
            if isinstance(t, GitTarget):
                lines.append(
                    f'    pkg "{_kdl_str(ov.name)}"'
                    f' git=(url)"{_kdl_str(t.git)}"'
                    f' ref="{_kdl_str(t.ref)}"'
                )
            elif isinstance(t, LocalTarget):
                lines.append(
                    f'    pkg "{_kdl_str(ov.name)}"'
                    f' local="{_kdl_str(t.path)}"'
                )
            elif isinstance(t, MemberTarget):
                lines.append(
                    f'    pkg "{_kdl_str(ov.name)}" {{'
                )
                lines.append(
                    f'        member "{_kdl_str(t.member_name)}"'
                )
                lines.append("    }")
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
    # Skip auto-injected flags (from optional=#true desugaring — they're implied
    # by the dep's optional=#true and must not be serialized, else re-parse clashes).
    explicit_flags = [
        fd for fd in manifest.flags
        if fd.name not in manifest.optional_auto_flags
    ]
    if explicit_flags:
        lines.append("flags {")
        for fd in explicit_flags:
            default_kw = "#true" if fd.default else "#false"
            head = f'    "{_kdl_str(fd.name)}" default={default_kw}'
            if fd.description:
                head += f' description="{_kdl_str(fd.description)}"'
            # Gather child nodes: defines, enables (canonical single-node form), conflicts.
            # A block is needed iff at least one child is non-empty.
            has_block = bool(fd.defines or fd.enables_same_pkg or fd.enables_cross_pkg or fd.conflicts)
            if not has_block:
                lines.append(head)
            else:
                lines.append(f"{head} {{")
                if fd.defines:
                    defines_args = " ".join(f'"{_kdl_str(d)}"' for d in fd.defines)
                    lines.append(f"        defines {defines_args}")
                # enables — canonical single-node form (RFC §3.1.1).
                if fd.enables_same_pkg or fd.enables_cross_pkg:
                    same_pkg_args = " ".join(f'"{_kdl_str(n)}"' for n in fd.enables_same_pkg)
                    if not fd.enables_cross_pkg:
                        # No cross-pkg: single-line form.
                        lines.append(f"        enables {same_pkg_args}")
                    else:
                        # Cross-pkg children present: block form.
                        enables_head = f"        enables"
                        if same_pkg_args:
                            enables_head += f" {same_pkg_args}"
                        lines.append(f"{enables_head} {{")
                        for cpe in fd.enables_cross_pkg:
                            # Each cross-pkg dep: <dep-name> { flag "<f>" [#false] }
                            if cpe.flag_requests:
                                lines.append(f"            {_kdl_str(cpe.dep)} {{")
                                for fr in cpe.flag_requests:
                                    if fr.enabled:
                                        lines.append(f'                flag "{_kdl_str(fr.name)}"')
                                    else:
                                        lines.append(f'                flag "{_kdl_str(fr.name)}" #false')
                                lines.append("            }")
                            else:
                                lines.append(f"            {_kdl_str(cpe.dep)}")
                        lines.append("        }")
                if fd.conflicts:
                    conflicts_args = " ".join(f'"{_kdl_str(n)}"' for n in fd.conflicts)
                    lines.append(f"        conflicts {conflicts_args}")
                lines.append("    }")
        lines.append("}")
        lines.append("")

    # index-trust / index-trust-signer / index-trust-bundle (S5, RFC
    # registry-trust-federation §6.4a). Only emit "index-trust" when the
    # source explicitly declared it (absent-stays-absent — "warn" is both the
    # default AND a legal explicit value, so the explicit bit is load-bearing:
    # a spurious emitted default would turn a workspace MEMBER manifest
    # illegal on re-parse, WS-INDEX-TRUST-ON-MEMBER). signer/bundle are
    # emitted whenever present, independent of the policy explicit bit.
    if manifest.index_trust_policy_explicit:
        lines.append(f'index-trust "{_kdl_str(manifest.index_trust_policy)}"')
    if manifest.index_trust_signer is not None:
        lines.append(f'index-trust-signer "{_kdl_str(manifest.index_trust_signer)}"')
    if manifest.index_trust_bundle is not None:
        lines.append(f'index-trust-bundle "{_kdl_str(manifest.index_trust_bundle)}"')
    if (
        manifest.index_trust_policy_explicit
        or manifest.index_trust_signer is not None
        or manifest.index_trust_bundle is not None
    ):
        lines.append("")

    # kind — always last (Rust canonical ordering)
    lines.append(f'kind "{_kdl_str(manifest.kind)}"')

    return "\n".join(lines) + "\n"


_WORKSPACE_HEADER = (
    "// generated by milpa; edit by hand or via `milpa workspace add-member` / `milpa workspace remove-member`"
)


def format_workspace_manifest(ws: "WorkspaceManifest") -> str:
    """Serialize a ``WorkspaceManifest`` to a KDL 2.0 string.

    Hand-rolled canonical format — byte-identical to the Rust
    ``milpa-manifest::format_workspace_manifest``.

    Spec requirements (manifest-grammar §8 + §3.F):
    - Starts with the workspace-specific ``// generated by milpa ...`` header.
    - ``name`` emitted iff present (workspace root name is optional).
    - ``workspace { member "..." }`` block emitted with all members in
      declaration order.
    - ``overrides {}`` block emitted iff non-empty (same format as package).
    - ``flags {}`` block emitted iff non-empty (S11 workspace-root flags).
    - Comments are dropped (byte-stable canonical re-serialization — §3.F).
      A warning is emitted to stderr if the workspace had comments (not
      tracked on ``WorkspaceManifest`` — the warning is a no-op for now,
      consistent with package serializer behavior pre-#15).

    Returns the serialized KDL 2.0 string (always ends with a newline).
    """
    lines: list[str] = [_WORKSPACE_HEADER, ""]

    # name (optional on workspace root)
    if ws.name is not None:
        lines.append(f'name "{_kdl_str(ws.name)}"')
        lines.append("")

    # workspace { member "..." }
    lines.append("workspace {")
    for member_path in ws.members:
        lines.append(f'    member "{_kdl_str(member_path)}"')
    lines.append("}")
    lines.append("")

    # overrides { pkg "name" ... }
    if ws.overrides:
        lines.append("overrides {")
        for ov in ws.overrides:
            t = ov.target
            if isinstance(t, GitTarget):
                lines.append(
                    f'    pkg "{_kdl_str(ov.name)}"'
                    f' git=(url)"{_kdl_str(t.git)}"'
                    f' ref="{_kdl_str(t.ref)}"'
                )
            elif isinstance(t, LocalTarget):
                lines.append(
                    f'    pkg "{_kdl_str(ov.name)}"'
                    f' local="{_kdl_str(t.path)}"'
                )
            elif isinstance(t, MemberTarget):
                lines.append(
                    f'    pkg "{_kdl_str(ov.name)}" {{'
                )
                lines.append(
                    f'        member "{_kdl_str(t.member_name)}"'
                )
                lines.append("    }")
        lines.append("}")
        lines.append("")

    # flags { "<name>" default=#true/#false ... }
    # Workspace flags: no optional-auto-flags to skip (workspace has no deps).
    if ws.flags:
        lines.append("flags {")
        for fd in ws.flags:
            default_kw = "#true" if fd.default else "#false"
            head = f'    "{_kdl_str(fd.name)}" default={default_kw}'
            if fd.description:
                head += f' description="{_kdl_str(fd.description)}"'
            has_block = bool(fd.defines or fd.enables_same_pkg or fd.enables_cross_pkg or fd.conflicts)
            if not has_block:
                lines.append(head)
            else:
                lines.append(f"{head} {{")
                if fd.defines:
                    defines_args = " ".join(f'"{_kdl_str(d)}"' for d in fd.defines)
                    lines.append(f"        defines {defines_args}")
                if fd.enables_same_pkg or fd.enables_cross_pkg:
                    same_pkg_args = " ".join(f'"{_kdl_str(n)}"' for n in fd.enables_same_pkg)
                    if not fd.enables_cross_pkg:
                        lines.append(f"        enables {same_pkg_args}")
                    else:
                        enables_head = "        enables"
                        if same_pkg_args:
                            enables_head += f" {same_pkg_args}"
                        lines.append(f"{enables_head} {{")
                        for cpe in fd.enables_cross_pkg:
                            if cpe.flag_requests:
                                lines.append(f"            {_kdl_str(cpe.dep)} {{")
                                for fr in cpe.flag_requests:
                                    if fr.enabled:
                                        lines.append(f'                flag "{_kdl_str(fr.name)}"')
                                    else:
                                        lines.append(f'                flag "{_kdl_str(fr.name)}" #false')
                                lines.append("            }")
                            else:
                                lines.append(f"            {_kdl_str(cpe.dep)}")
                        lines.append("        }")
                if fd.conflicts:
                    conflicts_args = " ".join(f'"{_kdl_str(n)}"' for n in fd.conflicts)
                    lines.append(f"        conflicts {conflicts_args}")
                lines.append("    }")
        lines.append("}")
        lines.append("")

    # index-trust / index-trust-signer / index-trust-bundle (S5, RFC
    # registry-trust-federation §6.4a — root-authority policy). Only emit
    # "index-trust" when the source explicitly declared it (absent-stays-
    # absent — see format_manifest for why the explicit bit is load-bearing).
    if ws.index_trust_policy_explicit:
        lines.append(f'index-trust "{_kdl_str(ws.index_trust_policy)}"')
    if ws.index_trust_signer is not None:
        lines.append(f'index-trust-signer "{_kdl_str(ws.index_trust_signer)}"')
    if ws.index_trust_bundle is not None:
        lines.append(f'index-trust-bundle "{_kdl_str(ws.index_trust_bundle)}"')
    if (
        ws.index_trust_policy_explicit
        or ws.index_trust_signer is not None
        or ws.index_trust_bundle is not None
    ):
        lines.append("")

    # Strip any trailing blank line so the file ends after the last block.
    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines) + "\n"


def _format_predicate_props(preds: "tuple[Predicate, ...] | list[Predicate]") -> str:
    """Render a sequence of single-value predicates as inline KDL properties.

    Used to build the property string for a ``when`` node header.
    All predicates MUST have exactly one value (multi-value predicates can only
    appear on UrlDep child nodes, never on ``when`` node headers).

    Returns a space-prefixed string like `` platform="linux" flag="extras"``
    or an empty string when ``preds`` is empty.
    """
    parts: list[str] = []
    for pred in preds:
        assert len(pred.values) == 1, (
            f"_format_predicate_props: predicate {pred.name!r} has "
            f"{len(pred.values)} values — only single-value predicates are "
            "valid on `when` node headers"
        )
        val = pred.values[0]
        if pred.negated:
            parts.append(f'{pred.name}=(not)"{_kdl_str(val)}"')
        else:
            parts.append(f'{pred.name}="{_kdl_str(val)}"')
    if not parts:
        return ""
    return " " + " ".join(parts)


def _format_dep_line(dep: Dep) -> str:
    """Render one dep as a KDL line (or multi-line block) inside a deps { } block.

    Matches the Rust ``format_dep_line`` byte-for-byte.

    Indentation: 4 spaces for dep-level, 8 spaces for child nodes inside a
    URL dep block.

    §8 round-trip: deps with explicit when-predicates are wrapped in a
    ``when <preds> { <dep-node> }`` grouping block so their predicates survive
    a format → parse cycle.  UrlDep predicates are emitted inline/as child-nodes
    on the dep node itself (existing behaviour preserved).  For NamedDep,
    LocalDep, TarballDep, and MemberDep the wrapping form is the only valid
    form because those node types do not accept predicate properties directly.
    """
    if isinstance(dep, MemberDep):
        # MemberDep predicates come exclusively from enclosing when blocks
        # (MAN-DEP-MEMBER-PROPS forbids inline properties).  Wrap if non-empty.
        if dep.predicates:
            inner = f'        member "{_kdl_str(dep.name)}"'
            when_props = _format_predicate_props(dep.predicates)
            return f"    when{when_props} {{\n{inner}\n    }}"
        return f'    member "{_kdl_str(dep.name)}"'

    if isinstance(dep, NamedDep):
        # S7: strip the auto-injected gate predicate (flag=<depname>) — it's
        # implied by optional=#true and must not be double-emitted as a when-block
        # predicate.  All other predicates (from outer when blocks) ARE serialized.
        if dep.optional:
            auto_gate = Predicate(name="flag", values=(dep.name,), negated=False)
            when_preds = tuple(p for p in dep.predicates if p != auto_gate)
        else:
            when_preds = dep.predicates

        # Build the dep node body (without leading indentation — added below).
        # S5b: emit ``namespace="..."`` attribute (canonical form) when present.
        # The slash shorthand is NEVER emitted — canonical output always uses the
        # attribute form so downstream parsers only see one form.
        ns_attr = f' namespace="{_kdl_str(dep.namespace)}"' if dep.namespace is not None else ""
        if dep.constraint is None:
            head = f'"{_kdl_str(dep.name)}"{ns_attr}'
        else:
            head = f'"{_kdl_str(dep.name)}"{ns_attr} "{_kdl_str(dep.constraint)}"'
        # optional=#true — round-trip preservation (S7 RFC #23 §3.2).
        if dep.optional:
            head += " optional=#true"

        if dep.flag_requests:
            # Multi-line block form for flag_requests (§3.1.5 S3 RFC #23).
            if when_preds:
                inner_lines = [f"        {head} {{"]
                for fr in dep.flag_requests:
                    if fr.enabled:
                        inner_lines.append(f'            flag "{_kdl_str(fr.name)}"')
                    else:
                        inner_lines.append(f'            flag "{_kdl_str(fr.name)}" #false')
                inner_lines.append("        }")
                inner = "\n".join(inner_lines)
                when_props = _format_predicate_props(when_preds)
                return f"    when{when_props} {{\n{inner}\n    }}"
            else:
                block: list[str] = [f"    {head} {{"]
                for fr in dep.flag_requests:
                    if fr.enabled:
                        block.append(f'        flag "{_kdl_str(fr.name)}"')
                    else:
                        block.append(f'        flag "{_kdl_str(fr.name)}" #false')
                block.append("    }")
                return "\n".join(block)
        else:
            if when_preds:
                inner = f"        {head}"
                when_props = _format_predicate_props(when_preds)
                return f"    when{when_props} {{\n{inner}\n    }}"
            return f"    {head}"

    if isinstance(dep, LocalDep):
        node_body = f'"{_kdl_str(dep.name)}" local="{_kdl_str(dep.path)}"'
        if dep.predicates:
            inner = f"        {node_body}"
            when_props = _format_predicate_props(dep.predicates)
            return f"    when{when_props} {{\n{inner}\n    }}"
        return f"    {node_body}"

    if isinstance(dep, TarballDep):
        parts = [
            f'"{_kdl_str(dep.name)}"',
            f'tarball=(url)"{_kdl_str(dep.url)}"',
        ]
        if dep.sha256 is not None:
            parts.append(f'sha256="{_kdl_str(dep.sha256)}"')
        if dep.strip_components != 0:
            parts.append(f"strip_components={dep.strip_components}")
        node_body = " ".join(parts)
        if dep.predicates:
            inner = f"        {node_body}"
            when_props = _format_predicate_props(dep.predicates)
            return f"    when{when_props} {{\n{inner}\n    }}"
        return f"    {node_body}"

    # UrlDep — predicates emitted inline / as child-nodes on the dep node itself
    # (existing behaviour unchanged).
    assert isinstance(dep, UrlDep)

    # Split predicates: inline (single value) vs child-node (multi-value).
    # For serialization, exclude the auto-injected flag=<depname> predicate when
    # optional=True — it's implied by optional=#true and must not be double-emitted.
    # Any OTHER flag predicates or non-flag predicates are serialized normally.
    if dep.optional:
        auto_gate = Predicate(name="flag", values=(dep.name,), negated=False)
        serializable_preds = tuple(p for p in dep.predicates if p != auto_gate)
    else:
        serializable_preds = dep.predicates
    inline_preds = [p for p in serializable_preds if len(p.values) == 1]
    child_preds = [p for p in serializable_preds if len(p.values) > 1]

    head = (
        f'    "{_kdl_str(dep.name)}"'
        f' git=(url)"{_kdl_str(dep.git)}"'
        f' ref="{_kdl_str(dep.ref)}"'
    )
    # optional=#true — round-trip preservation (S7 RFC #23 §3.2).
    if dep.optional:
        head += " optional=#true"
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
    block = [f"{head} {{"]
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
