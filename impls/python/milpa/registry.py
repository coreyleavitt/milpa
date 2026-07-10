"""tianguis ``index.kdl`` reader — S8a.

``parse_index(text) -> Index`` parses a KDL 2.0 ``index.kdl`` document into a
queryable ``Index``.  All security-critical fields (commit SHA shape, OCI digest
shape, no-leading-dash, unsafe name) are validated at parse time before any
index-supplied string can reach subprocess argv or the filesystem.

Spec authority: ``spec/registry-protocol.md`` (registry-protocol §2–§5).
Cross-reference: ``spec/errors.md`` for ``TNG-*`` error codes.

Two resolution entry points:
  - ``resolve_named_all(index, name, constraint)`` — Phase-A enumerate step.
  - ``resolve_named(index, name, constraint)`` — single highest-version result.

``is_safe_name`` is the single source of truth for the safe-name rule (§3.1
NORMATIVE); the resolver's URL-derived-name check shares this predicate.
"""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from milpa.errors import (
    TNG_AMBIGUOUS_NAME,
    TNG_BAD_COMMIT_SHA,
    TNG_BAD_DEP_DECL,
    TNG_BAD_OCI_DIGEST,
    TNG_NO_PROVENANCE,
    TNG_NO_SATISFYING_VERSION,
    TNG_NOT_FOUND,
    TNG_SCHEMA_UNKNOWN,
    TNG_UNSAFE_NAME,
    TNG_UNSAFE_OCI_FIELD,
    TNG_UNSAFE_REF,
    TNG_UNSAFE_URL,
    MilpaError,
)
from milpa.kdl_io import (
    KdlDocument,
    KdlNode,
    node_arg_str,
    node_children,
    node_name,
    node_prop_str,
    nodes,
    parse_kdl,
    value_as_int,
)
from milpa.version import Version, VersionSet, parse_version

# ---------------------------------------------------------------------------
# Schema version
# ---------------------------------------------------------------------------

#: The only index schema version this milpa understands.  A document declaring a
#: higher integer is refused (``TNG-SCHEMA-UNKNOWN``); lower-or-equal reads
#: forward-compatibly (registry-protocol §2 NORMATIVE).
TIANGUIS_INDEX_SCHEMA_VERSION: int = 1

# ---------------------------------------------------------------------------
# Security validators (single source of truth — called from parse_index)
# ---------------------------------------------------------------------------

_RE_40HEX = re.compile(r"^[0-9a-f]{40}$")
#: Single source of truth for the ``sha256:<64 lowercase hex>`` pointer format.
#: Used by both ``_validate_oci_digest`` (TNG-BAD-OCI-DIGEST) and
#: ``_validate_dep_decl_pointer`` (TNG-BAD-DEP-DECL) — the two differ ONLY in
#: which error code they raise.  Also reused by ``fetchers/oci.py`` so that a
#: future algorithm change (e.g. sha512) has exactly ONE update site.
_RE_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RE_UNSAFE_NAME = re.compile(r"[/\\]|\.\.")
#: Bare (no ``sha256:`` prefix) 64-lowercase-hex form — the ``bundle sha256=``
#: property's value shape (registry-protocol §3.2 NORMATIVE).  Distinct from
#: ``_RE_SHA256_DIGEST`` (which requires the prefix) because the property key
#: already names the algorithm.
_RE_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def is_safe_name(name: str) -> bool:
    """Return ``True`` iff *name* is safe as a ``_deps/<name>/`` path component.

    Names containing ``..``, ``/``, ``\\``, or that are absolute paths would
    escape the sandbox.  Single source of truth (registry-protocol §3.1
    NORMATIVE); shared by the resolver's URL-derived-name check.
    """
    return not (_RE_UNSAFE_NAME.search(name) or Path(name).is_absolute())


def _validate_safe_name(name: str) -> None:
    if not is_safe_name(name):
        raise MilpaError(
            TNG_UNSAFE_NAME,
            f"package name {name!r} contains path-traversal characters "
            f"(`..`, `/`, `\\`, or absolute path) — unsafe under _deps/",
            name=name,
        )


def _validate_no_leading_dash(value: str, field_label: str, slug: str) -> None:
    """Reject *value* beginning with ``-`` — would be interpreted as a flag."""
    if value.startswith("-"):
        raise MilpaError(
            slug,
            f"{field_label} {value!r} begins with `-` (flag injection)",
            value=value,
        )


def _validate_commit_sha(sha: str) -> None:
    """Reject ``commit_sha`` values that are not exactly 40 lowercase hex chars."""
    if not _RE_40HEX.fullmatch(sha):
        raise MilpaError(
            TNG_BAD_COMMIT_SHA,
            f"commit_sha {sha!r} is not exactly 40 lowercase hexadecimal characters",
            sha=sha,
        )


def _validate_oci_digest(digest: str) -> None:
    """Reject OCI digests not in ``sha256:<64-hex>`` form."""
    if not _RE_SHA256_DIGEST.fullmatch(digest):
        raise MilpaError(
            TNG_BAD_OCI_DIGEST,
            f"OCI digest {digest!r} is not in `sha256:<64 hex>` format",
            digest=digest,
        )


def _validate_dep_decl_pointer(pointer: str) -> None:
    """Reject ``dep_decl`` pointers not in ``sha256:<64 lowercase hex>`` form.

    Validated at index-parse time (registry-protocol §3.2 NORMATIVE).  The
    pointer is later used as a filesystem path component (``FileDepDeclStore``)
    and as a URL path segment (``HttpDepDeclStore``); a malformed value
    containing path-traversal chars (e.g. ``sha256:../../etc/passwd``) would
    reach those sites before the hash check — the boundary validation makes
    that structurally impossible.  Raises ``MilpaError(TNG-BAD-DEP-DECL)``
    for any value not matching ``^sha256:[0-9a-f]{64}$``.
    """
    if not _RE_SHA256_DIGEST.fullmatch(pointer):
        raise MilpaError(
            TNG_BAD_DEP_DECL,
            f"dep_decl pointer {pointer!r} is not in `sha256:<64 lowercase hex>` format "
            f"— path-traversal or malformed pointer rejected at parse boundary",
            pointer=pointer,
        )


# ---------------------------------------------------------------------------
# Provenance types (index-local; mirror the manifest grammar, not re-imported)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitIndexProvenance:
    """Git provenance record as stored in the index.

    Fields mirror ``manifest-grammar.md`` §4.2 (registry-protocol §3.3
    NORMATIVE: index provenance is a strict subset of the manifest grammar).
    """

    url: str
    ref: str
    commit_sha: str | None = None


@dataclass(frozen=True)
class OciIndexProvenance:
    """OCI provenance record as stored in the index."""

    registry: str
    repository: str
    digest: str


#: Union type for index-level provenance records.
IndexProvenance = GitIndexProvenance | OciIndexProvenance

# ---------------------------------------------------------------------------
# Per-entry attestation record (RFC: per-entry-attestation, P1/P2; §3.2)
#
# One optional tagged record on IndexVersion — not independently-nullable
# fields — so the kind/signer correlation is structural, not conventional.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RekorRef:
    """Durable Rekor transparency-log reference (registry-protocol §3.2)."""

    uuid: str
    log_index: str
    integrated_time: str


@dataclass(frozen=True)
class AuthorSigned:
    """``attestation "author-signed"`` — ``signer`` is REQUIRED for this kind."""

    signer: str


@dataclass(frozen=True)
class MilpaVendored:
    """``attestation "milpa-vendored"`` — no per-entry signer field by design.

    The effective signer for this kind is derived at *verification* time
    (not parse time) from Layer 1's resolved vendor-bot identity — see
    ``rfc-per-entry-attestation.md`` §5.  This parser never reads or stores
    a signer for the vendored kind.
    """


#: Closed set (registry-protocol §3.2 NORMATIVE) — the only two recognized
#: ``attestation`` kinds.  Any other value collapses to unattested.
AttestationKind = AuthorSigned | MilpaVendored


@dataclass(frozen=True)
class EntryAttestation:
    """Per-entry Layer 2 author-attribution CLAIM (attribution, not integrity).

    Parsed from the ``attestation`` / ``signed_by`` / ``rekor`` / ``bundle``
    sibling child nodes on one ``version`` node (registry-protocol §3.2).
    Records the CLAIM only — whether it is cryptographically true is a later
    (P3) question; this type carries zero verification state.

    ``bundle_pin`` — sha256 hex of the attestation bundle BYTES (the ``bundle
    sha256=`` delivery-integrity pin).  ``None`` is the normal, expected state
    before per-entry bundle delivery ships (P4).
    """

    kind: AttestationKind
    rekor: RekorRef | None = None
    bundle_pin: str | None = None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexVersion:
    """One published version of a package as recorded in ``index.kdl``.

    ``content_hash`` — ``sha256:<64-hex>`` identity; empty string on legacy
    entries predating the identity mandate (caught as ``TNG-NO-IDENTITY``
    when selected, never silently).

    ``provenances`` — **preference-ordered** (index document order): element 0
    is canonical, the rest mirrors.  Callers MUST NOT reorder — the identity
    gate makes any mirror yielding different bytes a hard error, so ordered
    fall-through is safe (registry-protocol §3.3).

    ``dep_decl`` — optional ``sha256:``-prefixed hash pointer to the DepDecl
    artifact for this version (registry-protocol §3.2.3).  ``None`` when
    absent (forward-compat: old index entries omit it).

    ``dep_decl_schema_version`` — the DepDecl schema version integer that
    produced ``dep_decl`` (registry-protocol §3.2.1).  ``None`` when absent.

    ``attestation`` — the per-entry Layer 2 attribution CLAIM (registry-protocol
    §3.2), or ``None`` when the entry carries no attestation record, OR when a
    present record failed the closed-set / structural-validity check and
    conservatively collapsed to unattested (RFC per-entry-attestation §2).
    """

    version: str
    content_hash: str = ""
    provenances: tuple[IndexProvenance, ...] = ()
    dep_decl: str | None = None
    dep_decl_schema_version: int | None = None
    attestation: EntryAttestation | None = None


@dataclass(frozen=True)
class Package:
    """A package: ``(namespace, name)`` identity plus sorted versions.

    Two packages MAY share a bare ``name`` under different namespaces; the
    identity key is always the ``(namespace, name)`` pair.
    """

    name: str
    namespace: str
    versions: tuple[IndexVersion, ...]


@dataclass(frozen=True)
class AmbiguousName:
    """Returned by ``Index.lookup_bare`` when a bare name matches multiple namespaces.

    A typed value, **not** an exception: the primitive stays raise-free so a
    future multi-version provider can enumerate all candidates while
    backtracking (registry-protocol §3.2 NOTE).
    """

    name: str
    namespaces: list[str] = field(default_factory=list)


@dataclass
class Index:
    """The parsed registry index.

    Packages are stored in document order for deterministic iteration.
    Internal lookup is by ``(namespace, name)`` for qualified access or by
    bare name for ``lookup_bare``.
    """

    packages: list[Package] = field(default_factory=list)

    def lookup_bare(self, name: str) -> Package | AmbiguousName | None:
        """Bare-name (namespace-unqualified) lookup.

        Returns:
          - the ``Package`` on a unique match,
          - ``AmbiguousName`` when multiple namespaces share the bare name,
          - ``None`` when not found.

        Registry-protocol §5.1 NORMATIVE: policy (which ``TNG-*`` error to
        raise) lives in the callers ``resolve_named`` / ``resolve_named_all``.
        """
        matches = [p for p in self.packages if p.name == name]
        if not matches:
            return None
        if len(matches) == 1:
            return matches[0]
        return AmbiguousName(name=name, namespaces=[p.namespace for p in matches])

    def resolve_named_all(
        self,
        name: str,
        constraint: str | None = None,
    ) -> list[IndexVersion]:
        """Return ALL ``IndexVersion`` records satisfying *constraint*, newest-first.

        This is the Phase-A enumerate step for the two-phase solver provider
        (registry-protocol §5.5 NORMATIVE).

        Error precedence (registry-protocol §5.5): ``TNG-NOT-FOUND`` →
        ``TNG-AMBIGUOUS-NAME`` → ``TNG-NO-PROVENANCE`` → ``TNG-NO-SATISFYING-VERSION``.

        ``TNG-NO-IDENTITY`` is NOT raised here — it fires when a version is
        actually selected for fetch (``resolve_named`` / ``resolve_named_all`` gate
        is the enumeration step; identity check is the selection step).
        """
        result = self.lookup_bare(name)
        if result is None:
            raise MilpaError(
                TNG_NOT_FOUND,
                f"package {name!r} is not in the tianguis index",
                name=name,
            )
        if isinstance(result, AmbiguousName):
            nss = sorted(result.namespaces)
            raise MilpaError(
                TNG_AMBIGUOUS_NAME,
                f"package {name!r} matches multiple namespaces: {', '.join(nss)} "
                f"— use a namespace-qualified reference",
                name=name,
                namespaces=nss,
            )

        pkg = result
        vs = VersionSet.from_constraint(constraint)

        satisfying: list[IndexVersion] = []
        provenance_less: list[str] = []

        for iv in pkg.versions:
            parsed = parse_version(iv.version)
            if parsed is None:
                continue  # unparseable version strings skipped (§5.2 NORMATIVE)
            if vs.contains(parsed):
                if not iv.provenances:
                    provenance_less.append(iv.version)
                    warnings.warn(
                        f"version {iv.version!r} of {name!r} has no provenance — skipped",
                        stacklevel=2,
                    )
                    continue
                satisfying.append(iv)

        if satisfying:
            return satisfying

        if provenance_less:
            raise MilpaError(
                TNG_NO_PROVENANCE,
                f"{name!r} has no fetchable version satisfying constraint "
                f"{constraint!r} — all satisfying versions lack provenance: "
                f"{', '.join(provenance_less)}",
                name=name,
                constraint=constraint,
                excluded=provenance_less,
            )

        raise MilpaError(
            TNG_NO_SATISFYING_VERSION,
            f"no version of {name!r} satisfies constraint {constraint!r} "
            f"(available: {', '.join(iv.version for iv in pkg.versions)})",
            name=name,
            constraint=constraint,
            available=[iv.version for iv in pkg.versions],
        )

    def resolve_named(
        self,
        name: str,
        constraint: str | None = None,
    ) -> IndexVersion:
        """Return the single highest-semver ``IndexVersion`` satisfying *constraint*.

        Equivalent to ``resolve_named_all(…)[0]``.  Raises the same
        ``TNG-*`` errors as ``resolve_named_all`` (registry-protocol §5.5).

        When the caller selects a version for fetch, it MUST check
        ``content_hash`` before attempting the fetch:

        .. code-block:: python

            iv = index.resolve_named(name, constraint)
            if not iv.content_hash:
                raise MilpaError(TNG_NO_IDENTITY, ...)
        """
        return self.resolve_named_all(name, constraint)[0]

    # ------------------------------------------------------------------
    # S5b — qualified lookup (namespace-aware)
    # ------------------------------------------------------------------

    def lookup_qualified(self, namespace: str, name: str) -> Package | None:
        """Qualified (namespace, name) lookup — always returns at most one Package.

        Returns the ``Package`` when the ``(namespace, name)`` pair is found,
        ``None`` when not found.  Never returns ``AmbiguousName`` — the caller
        supplies a namespace, so ambiguity cannot occur.

        Registry-protocol §5.1 S5b: this path bypasses ``TNG-AMBIGUOUS-NAME``
        because the manifest grammar provided an explicit namespace qualifier.
        """
        for p in self.packages:
            if p.namespace == namespace and p.name == name:
                return p
        return None

    def resolve_named_all_qualified(
        self,
        namespace: str,
        name: str,
        constraint: str | None = None,
    ) -> list[IndexVersion]:
        """Qualified-namespace resolve — bypasses ``TNG-AMBIGUOUS-NAME``.

        Same behaviour as ``resolve_named_all`` for error precedence, but uses
        ``lookup_qualified`` instead of ``lookup_bare``:
          ``TNG-NOT-FOUND`` → ``TNG-NO-PROVENANCE`` → ``TNG-NO-SATISFYING-VERSION``.
        ``TNG-AMBIGUOUS-NAME`` is never raised (namespace was specified).

        Called by the resolver when ``dep_key.namespace`` is not None (S5b).
        """
        pkg = self.lookup_qualified(namespace, name)
        if pkg is None:
            raise MilpaError(
                TNG_NOT_FOUND,
                f"package {namespace!r}/{name!r} is not in the tianguis index",
                name=name,
                namespace=namespace,
            )

        vs = VersionSet.from_constraint(constraint)

        satisfying: list[IndexVersion] = []
        provenance_less: list[str] = []

        for iv in pkg.versions:
            parsed = parse_version(iv.version)
            if parsed is None:
                continue
            if vs.contains(parsed):
                if not iv.provenances:
                    provenance_less.append(iv.version)
                    warnings.warn(
                        f"version {iv.version!r} of {namespace!r}/{name!r} has no provenance — skipped",
                        stacklevel=2,
                    )
                    continue
                satisfying.append(iv)

        if satisfying:
            return satisfying

        qualified = f"{namespace}/{name}"
        if provenance_less:
            raise MilpaError(
                TNG_NO_PROVENANCE,
                f"{qualified!r} has no fetchable version satisfying constraint "
                f"{constraint!r} — all satisfying versions lack provenance: "
                f"{', '.join(provenance_less)}",
                name=name,
                constraint=constraint,
                excluded=provenance_less,
            )

        raise MilpaError(
            TNG_NO_SATISFYING_VERSION,
            f"no version of {qualified!r} satisfies constraint {constraint!r} "
            f"(available: {', '.join(iv.version for iv in pkg.versions)})",
            name=name,
            constraint=constraint,
            available=[iv.version for iv in pkg.versions],
        )


# ---------------------------------------------------------------------------
# parse_index — the public entry point
# ---------------------------------------------------------------------------


def parse_index(text: str) -> Index:
    """Parse an ``index.kdl`` KDL 2.0 document into a queryable ``Index``.

    Validates schema version, then every package: name safety-checked, each
    version's provenances sanitized (``TNG-UNSAFE-NAME`` / ``TNG-BAD-COMMIT-SHA``
    / ``TNG-BAD-OCI-DIGEST`` / ``TNG-UNSAFE-URL`` / ``TNG-UNSAFE-REF`` /
    ``TNG-UNSAFE-OCI-FIELD``), and the ``dep_decl`` pointer validated
    (``TNG-BAD-DEP-DECL``).

    Forward-compat rules (registry-protocol §1, §3 NORMATIVE):
      - Unknown top-level nodes are silently skipped.
      - A package node with a non-string name emits a ``UserWarning`` and is
        skipped (MUST NOT hard-error).
      - Duplicate version strings: first occurrence kept, subsequent ones skip
        with a ``UserWarning`` (MUST NOT hard-error).
      - Unknown provenance ``kind`` values are silently skipped.

    Versions are ordered newest-first: parseable semver versions descending,
    then unparseable versions in document order (registry-protocol §5.2
    NORMATIVE).

    Spec authority: ``spec/registry-protocol.md`` §2–§4.
    """
    doc: KdlDocument = parse_kdl(text, context="registry")
    _check_schema_version(doc)

    packages: list[Package] = []
    for top_node in nodes(doc):
        if node_name(top_node) != "package":
            continue
        name = node_arg_str(top_node, 0)
        if name is None:
            warnings.warn(
                "package node with non-string name skipped (malformed index entry)",
                stacklevel=2,
            )
            continue
        _validate_safe_name(name)
        namespace = _child_scalar(top_node, "namespace") or ""
        versions, diagnostics = _parse_versions(name, namespace, top_node)
        for diag in diagnostics:
            warnings.warn(diag, stacklevel=2)
        packages.append(Package(name=name, namespace=namespace, versions=tuple(versions)))

    return Index(packages=packages)


# ---------------------------------------------------------------------------
# Internal parse helpers
# ---------------------------------------------------------------------------


def _check_schema_version(doc: KdlDocument) -> None:
    """Refuse an index whose declared ``schema_version`` exceeds the supported epoch."""
    for n in nodes(doc):
        if node_name(n) != "schema_version":
            continue
        args = _node_int_arg(n)
        if args is not None and args > TIANGUIS_INDEX_SCHEMA_VERSION:
            raise MilpaError(
                TNG_SCHEMA_UNKNOWN,
                f"index declares schema_version {args}, but this milpa understands "
                f"at most {TIANGUIS_INDEX_SCHEMA_VERSION} — upgrade milpa",
                declared=args,
                max_understood=TIANGUIS_INDEX_SCHEMA_VERSION,
            )
        return  # found the node; done (absent node = tolerated)


def _node_int_arg(n: KdlNode) -> int | None:
    """Return the first positional arg of *n* as an ``int``, or ``None``.

    ``kdl-py`` may return integer literals as ``float``; a whole-number float
    is coerced.  A ``bool`` is explicitly rejected (``bool`` is an ``int``
    subclass in Python).
    """
    from milpa.kdl_io import node_args

    args = node_args(n)
    if not args:
        return None
    v = args[0]
    return value_as_int(v)


def _child_scalar(parent: KdlNode, child_node_name: str) -> str | None:
    """Return the first positional string arg of *parent*'s child named *child_node_name*."""
    for child in node_children(parent):
        if node_name(child) == child_node_name:
            return node_arg_str(child, 0)
    return None


def _child_scalar_url(parent: KdlNode, child_node_name: str) -> str | None:
    """Return the first positional arg of *parent*'s child named *child_node_name*.

    Accepts both plain strings and ``(url)``-annotated values (the milpa KDL
    url convention — registry-protocol §3.3 NORMATIVE).
    """
    from milpa.kdl_io import node_arg_url

    for child in node_children(parent):
        if node_name(child) == child_node_name:
            uv = node_arg_url(child, 0)
            if uv is not None:
                return str(uv)
            return node_arg_str(child, 0)
    return None


def _parse_versions(
    pkg_name: str, namespace: str, pkg_node: KdlNode
) -> tuple[list[IndexVersion], list[str]]:
    """Parse all ``version`` children of *pkg_node* into ``IndexVersion`` objects.

    Duplicate version strings are tolerated: first wins, subsequent ones emit
    a ``UserWarning`` (registry-protocol §3.2 NORMATIVE).

    Output is sorted: parseable semver versions descending by semver, then
    unparseable versions in document order (registry-protocol §5.2 NORMATIVE).

    Returns ``(versions, diagnostics)`` — *diagnostics* aggregates the
    per-entry attestation collapse diagnostics from every version node
    (registry-protocol §3.2 NORMATIVE "parse boundary shape"); the caller
    threads them to the warning channel.
    """
    seen: list[str] = []
    raw: list[IndexVersion] = []
    diagnostics: list[str] = []

    for child in node_children(pkg_node):
        if node_name(child) != "version":
            continue
        ver_str = node_arg_str(child, 0)
        if ver_str is None:
            continue  # non-string version arg: silently skipped (§3.2)
        if ver_str in seen:
            warnings.warn(
                f"duplicate version {ver_str!r} in package {pkg_name!r} — "
                f"keeping first occurrence",
                stacklevel=4,
            )
            continue
        seen.append(ver_str)
        iv, iv_diagnostics = _parse_version_node(namespace, pkg_name, ver_str, child)
        raw.append(iv)
        diagnostics.extend(iv_diagnostics)

    # Sort: parseable semver versions descending, unparseable in document order.
    # Build explicit list of (IndexVersion, Version) pairs — the filter guarantees
    # the second element is non-None so the sort key is well-typed.
    parseable_pairs: list[tuple[IndexVersion, Version]] = []
    unparseable: list[IndexVersion] = []
    for iv in raw:
        pv = parse_version(iv.version)
        if pv is not None:
            parseable_pairs.append((iv, pv))
        else:
            unparseable.append(iv)
    parseable_pairs.sort(key=lambda t: t[1], reverse=True)
    return [t[0] for t in parseable_pairs] + unparseable, diagnostics


def _parse_version_node(
    namespace: str, pkg_name: str, ver_str: str, node: KdlNode
) -> tuple[IndexVersion, list[str]]:
    """Parse one ``version "<ver>" { … }`` node into an ``IndexVersion``.

    Returns ``(IndexVersion, collapse diagnostics)`` — registry-protocol §3.2
    NORMATIVE "parse boundary shape".  The diagnostics list is non-empty only
    when the entry's attestation record collapsed (closed-set violation,
    structurally-invalid ``author-signed``, or a malformed ``bundle`` pin).
    """
    content_hash = _child_scalar(node, "content_hash") or ""
    provenances: list[IndexProvenance] = []
    dep_decl: str | None = None
    dep_decl_schema_version: int | None = None

    for child in node_children(node):
        name = node_name(child)
        if name == "provenance":
            prov = _parse_provenance_node(child)
            if prov is not None:
                provenances.append(prov)
        elif name == "dep_decl":
            raw_ptr = node_arg_str(child, 0) or None
            if raw_ptr is not None:
                _validate_dep_decl_pointer(raw_ptr)
            dep_decl = raw_ptr
        elif name == "dep_decl_schema_version":
            dep_decl_schema_version = _node_int_arg(child)

    attestation, diagnostics = _parse_entry_attestation(namespace, pkg_name, ver_str, node)

    return (
        IndexVersion(
            version=ver_str,
            content_hash=content_hash,
            provenances=tuple(provenances),
            dep_decl=dep_decl,
            dep_decl_schema_version=dep_decl_schema_version,
            attestation=attestation,
        ),
        diagnostics,
    )


def _parse_entry_attestation(
    namespace: str, pkg_name: str, ver_str: str, node: KdlNode
) -> tuple[EntryAttestation | None, list[str]]:
    """Parse the ``attestation``/``signed_by``/``rekor``/``bundle`` sibling
    child nodes of one ``version`` node into an ``EntryAttestation`` or
    ``None`` (registry-protocol §3.2 NORMATIVE).

    Conservative collapse: an unrecognized ``attestation`` kind, or
    ``"author-signed"`` with no ``signed_by``, collapses the WHOLE record to
    ``None`` (unattested) with an observable diagnostic.  A malformed
    ``bundle`` pin is narrower — it collapses only the bundle pin to ``None``,
    never the enclosing kind/signer pairing (registry-protocol §3.2 NORMATIVE).
    """
    coordinate = f"pkg:tianguis/{namespace}/{pkg_name}@{ver_str}"
    diagnostics: list[str] = []

    attestation_label = _child_scalar(node, "attestation")
    rekor = _parse_rekor_block(node)
    bundle_pin, bundle_diag = _parse_bundle_pin(node, coordinate)
    diagnostics.extend(bundle_diag)

    if attestation_label is None:
        # No attestation kind: a lone `rekor` block (if any) does not construct
        # an EntryAttestation — there is no kind to tag it with (§3.2 NORMATIVE).
        return None, diagnostics

    kind: AttestationKind
    if attestation_label == "author-signed":
        signed_by = _child_scalar(node, "signed_by")
        if not signed_by:
            diagnostics.append(
                f"attestation claim for {coordinate} collapsed to unattested: "
                f"\"author-signed\" with no signed_by (registry-protocol §3.2)"
            )
            return None, diagnostics
        kind = AuthorSigned(signer=signed_by)
    elif attestation_label == "milpa-vendored":
        kind = MilpaVendored()
    else:
        diagnostics.append(
            f"attestation claim for {coordinate} collapsed to unattested: "
            f"unrecognized kind {attestation_label!r} (registry-protocol §3.2)"
        )
        return None, diagnostics

    return EntryAttestation(kind=kind, rekor=rekor, bundle_pin=bundle_pin), diagnostics


def _parse_rekor_block(node: KdlNode) -> RekorRef | None:
    """Parse the optional ``rekor { uuid; log_index; integrated_time }`` block."""
    for child in node_children(node):
        if node_name(child) == "rekor":
            return RekorRef(
                uuid=_child_scalar(child, "uuid") or "",
                log_index=_child_scalar(child, "log_index") or "",
                integrated_time=_child_scalar(child, "integrated_time") or "",
            )
    return None


def _parse_bundle_pin(node: KdlNode, coordinate: str) -> tuple[str | None, list[str]]:
    """Parse the optional ``bundle sha256="<64-hex>"`` delivery-integrity pin.

    A malformed value normalizes to ``None`` with a diagnostic, WITHOUT
    collapsing the enclosing kind/signer pairing (registry-protocol §3.2
    NORMATIVE — an absent bundle pin is the ordinary, expected pre-delivery
    state, not evidence of a malformed claim).
    """
    for child in node_children(node):
        if node_name(child) != "bundle":
            continue
        raw = node_prop_str(child, "sha256")
        if raw is None:
            return None, []
        if _RE_HEX64.fullmatch(raw):
            return raw, []
        return None, [
            f"bundle pin for {coordinate} dropped: malformed sha256 value "
            f"{raw!r} (registry-protocol §3.2)"
        ]
    return None, []


def _parse_provenance_node(node: KdlNode) -> IndexProvenance | None:
    """Parse one ``provenance { … }`` child node.

    Returns ``None`` for unknown ``kind`` values (forward-compat skip —
    registry-protocol §3.3 NORMATIVE).  Raises ``MilpaError(TNG-*)`` for
    known-kind validation failures.

    ``kind`` is a child node with a positional string arg (not a property).
    """
    kind = _child_scalar(node, "kind")

    if kind == "git":
        url = _child_scalar_url(node, "url") or ""
        ref = _child_scalar(node, "ref") or ""
        commit_sha_raw = _child_scalar(node, "commit_sha") or None
        _validate_no_leading_dash(url, "git url", TNG_UNSAFE_URL)
        _validate_no_leading_dash(ref, "git ref", TNG_UNSAFE_REF)
        if commit_sha_raw is not None:
            _validate_commit_sha(commit_sha_raw)
        return GitIndexProvenance(url=url, ref=ref, commit_sha=commit_sha_raw)

    if kind == "oci":
        registry = _child_scalar(node, "registry") or ""
        repository = _child_scalar(node, "repository") or ""
        digest = _child_scalar(node, "digest") or ""
        _validate_no_leading_dash(registry, "oci registry", TNG_UNSAFE_OCI_FIELD)
        _validate_no_leading_dash(repository, "oci repository", TNG_UNSAFE_OCI_FIELD)
        _validate_oci_digest(digest)
        return OciIndexProvenance(registry=registry, repository=repository, digest=digest)

    # Unknown kind: silently skipped (forward-compat).
    return None
