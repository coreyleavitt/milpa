"""Edge-sourcing seam — S4-i + S3b (RFC: Content-Addressed Attested Dependency Metadata).

This module implements the resolver-level ``EdgeSource`` protocol and the
``resolve_edges`` coordinator specified in ``spec/resolver-semantics.md §4.2.1``
(the normative §4.2.1 amendment introduced by S4-i).

Design
------
Edge sourcing is the decision "given a package at a fetched path, which source
supplies its declared requires (EdgeSet)?" Three source kinds exist:

1. ``DepDeclEdgeSource`` (S3b): index-attested DepDecl artifact.  Fetches bytes
   via a ``DepDeclStore`` (hash-verified), then calls ``parse_dep_decl``.
   Validates ``dep_decl_schema_version`` consistency (§3.2.1 / spec §5).
2. ``MilpaKdlEdgeSource``: parses the package's ``milpa.kdl`` → transitive projection
   → EdgeSet.  Enforces §9 (dev-deps excluded) and §10.2 (overrides dropped).
3. ``NimbleEdgeSource``: heuristic line-scan of ``.nimble`` → EdgeSet (fallback).

The coordinator ``resolve_edges`` selects the source **once per (package, version)**
via a resolver-scoped ``edge_cache`` memo (clause a), then dispatches to the
appropriate source (clauses b, c, d).

``EdgeSourceCtx`` carries the heterogeneous inputs the sources need.  The fields are
genuinely asymmetric — ``DepDeclEdgeSource`` uses ``dep_decl`` + ``dep_decl_schema_version``
but no ``dep_path``; ``NimbleEdgeSource`` uses ``dep_path`` but ignores ``dep_decl``
— which is WHY the sources are separate deep units rather than one signature pretending
to be uniform.

Spec authority: spec/resolver-semantics.md §4.2.1, §9, §10.2.
Spec authority: spec/dep-decl.md §1 (EdgeSet single shared type), §5 (schema checks).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from milpa.dep_decl import EdgeSet, EdgeSource, NamedRequire, UrlRequire
from milpa.errors import (
    MAN_NIMBLE_CONSTRAINT,
    MAN_SRC_DIR_UNSAFE,
    TNG_DEPDECL_SCHEMA_MISMATCH,
    TNG_DEPDECL_SCHEMA_UNSUPPORTED,
    MilpaError,
)
from milpa.manifest import contains_unsafe_char, parse_manifest
from milpa.nimble import parse_nimble
from milpa.predicate import dep_passes_flag_predicates
from milpa.version import VersionSource, parse_version

if TYPE_CHECKING:
    from milpa.manifest import Override
    from milpa.solver import Term
    from milpa.version import Version, VersionSet


# ---------------------------------------------------------------------------
# EdgeSourceCtx — heterogeneous per-package context carrier
# ---------------------------------------------------------------------------


@dataclass
class EdgeSourceCtx:
    """Context carrier for a single (package, version) edge-sourcing decision.

    Fields
    ------
    dep_path:
        Absolute path to the fetched dep tree (``_deps/<name>/``).
        ``None`` for DepDeclEdgeSource (which needs no local tree for edges).
    dep_name:
        The package name (used by NimbleEdgeSource to find ``<name>.nimble``).
    dep_decl:
        Hash pointer from the index entry (``sha256:…``), or ``None`` if the
        index has no DepDecl for this version.  Populated from
        ``IndexVersion.dep_decl`` (S2 field) by the resolver's stub materialisation
        path.  ``None`` for URL/local/tarball deps (not in the index).
    dep_decl_schema_version:
        The ``dep_decl_schema_version`` integer from the index entry, or ``None``
        when absent.  Used by ``DepDeclEdgeSource`` for the schema-consistency
        check (§3.2.1): the index pointer's schema version MUST match the artifact's
        embedded ``dep_decl_schema_version`` (``TNG-DEPDECL-SCHEMA-MISMATCH``).
    is_overridden:
        True when this package's provenance was redirected by a root-manifest
        ``overrides {}`` block (§10.1).  Overridden packages MUST fall through to
        MilpaKdl/Nimble; the attested DepDecl describes the *original* tree and is
        invalid for the redirected source.
    has_milpa_kdl:
        True when the fetched dep tree contains a ``milpa.kdl`` file.
        Populated by the resolver after fetch (``(dep_path / "milpa.kdl").exists()``).
    overrides_by_name:
        Root-manifest overrides dict (name → Override); passed to MilpaKdlEdgeSource
        and NimbleEdgeSource so they can convert an overridden NamedDep into a
        URL-sentinel term correctly.
    ref:
        The dep declaration's git ``ref`` (branch/tag/SHA), or ``None``.  Only
        ever populated by the git/url worker (§3 Axis A (b) step 3 — A3); local/
        tarball/named/member deps have no ref and always leave this ``None``.
        Consumed solely by ``declared_version_for``'s step-3 tag fallback.
    version:
        The dep declaration's own ``version=`` annotation (§3 Axis A (b) step 4
        — A3b), or ``None``.  Populated by the git/url/local/tarball workers
        from ``UrlDep.version``/``LocalDep.version``/``TarballDep.version`` —
        for an override-redirected dep this is the OVERRIDE RULE's
        ``version=`` (D-A3: the redirect discards the original declaration
        entirely and builds a fresh dep from the override target, so a stale
        annotation on the now-redirected original is never read). Named/member
        deps never populate this (out of A3b's grammar scope). Consumed
        solely by ``declared_version_for``'s step-4 fallback.
    """

    dep_path: Path | None
    dep_name: str
    dep_decl: str | None
    is_overridden: bool
    has_milpa_kdl: bool
    dep_decl_schema_version: int | None = None
    overrides_by_name: dict[str, "Override"] = field(default_factory=dict)
    # S3 (RFC #23 §7 + §3.1.2): per-dep active flags seeded by cross-package
    # requests from the consumer.  Used by MilpaKdlEdgeSource to filter
    # flag-predicated transitive deps against the consumer's requested-flag set
    # (in addition to the dep's own default-true flags from S2.5).
    # Single-hop scope: set by the resolver for DIRECT deps only in S3;
    # the full fixpoint arrives in S4a.
    active_flags: frozenset[str] = field(default_factory=frozenset)
    ref: str | None = None
    version: "Version | None" = None


# ---------------------------------------------------------------------------
# EdgeSource protocol (one deep unit per source kind)
# ---------------------------------------------------------------------------


class EdgeSourceProtocol(Protocol):
    """Protocol for a single edge source kind.

    ``edges_for`` is the only entry point; it returns an ``EdgeSet`` ready to
    be consumed by the resolver's term-builder (``_edgeset_to_terms``).
    """

    def edges_for(
        self,
        name: str,
        version: "Version",
        ctx: EdgeSourceCtx,
    ) -> EdgeSet: ...


# ---------------------------------------------------------------------------
# NimbleEdgeSource
# ---------------------------------------------------------------------------


class NimbleEdgeSource:
    """Heuristic ``.nimble`` line-scan → EdgeSet.

    Transitional fallback for packages not yet indexed (raw git-URL deps, etc.).
    Returns an EdgeSet with ``source = EdgeSource.NIMBLE_FALLBACK``.
    """

    def edges_for(
        self,
        name: str,
        version: "Version",
        ctx: EdgeSourceCtx,
    ) -> EdgeSet:
        """Scan ``<ctx.dep_path>/<name>.nimble`` → EdgeSet.

        Falls back gracefully: if no ``.nimble`` is found, returns an empty EdgeSet.
        """
        assert ctx.dep_path is not None, "NimbleEdgeSource requires dep_path"
        requires, src_dir = _nimble_edges(ctx.dep_path, name)
        return EdgeSet(requires=requires, src_dir=src_dir, source=EdgeSource.NIMBLE_FALLBACK)


def _nimble_edges(dep_path: Path, dep_name: str) -> tuple[list[NamedRequire | UrlRequire], str]:
    """Extract requires + src_dir from the ``.nimble`` file at ``dep_path``.

    Raises:
        MilpaError(MAN-NIMBLE-CONSTRAINT): a named requires line has a
            malformed version constraint (``NamedDep.constraint`` is set but
            ``NamedDep.constraint_set`` is ``None``).  Mirrors the Rust
            reference (``resolver.rs`` ~line 1326-1348): the scanner stores
            the raw string; the NimbleFallback layer validates and raises.
    """
    from milpa.nimble import parse_nimble
    from milpa.manifest import UrlDep, NamedDep

    nimble_path = _find_nimble_file(dep_path, dep_name)
    if nimble_path is None:
        return [], ""

    try:
        text = nimble_path.read_text(encoding="utf-8")
    except OSError:
        return [], ""

    nm = parse_nimble(text)
    src_dir = nm.src_dir or ""
    # Security: validate src_dir at the earliest boundary where nimble-sourced
    # values are materialized.  Mirrors the milpa.kdl parse path (manifest.py
    # line ~903) which rejects unsafe src_dir at parse time.  The same
    # contains_unsafe_char predicate (SSOT in manifest.py) is used here so
    # both paths are byte-identical in what they reject.
    if src_dir and contains_unsafe_char(src_dir):
        raise MilpaError(
            MAN_SRC_DIR_UNSAFE,
            f"dep {dep_name!r}: 'srcDir' value {src_dir!r} from .nimble "
            f"contains a control character or Unicode line separator "
            f"(U+2028/U+2029) — possible nim.cfg injection attack",
            name=dep_name,
            src_dir=src_dir,
        )
    requires: list[NamedRequire | UrlRequire] = []
    for i, dep in enumerate(nm.deps):
        # Aligned predicates: dep_predicates is a tuple aligned with nm.deps.
        # Guard against index out of range for back-compat with callers that
        # produce NimbleManifest without dep_predicates (e.g. old tests).
        preds = nm.dep_predicates[i] if i < len(nm.dep_predicates) else ()
        if isinstance(dep, UrlDep):
            requires.append(UrlRequire(url=dep.git, ref=dep.ref, predicates=preds, name=dep.name))
        elif isinstance(dep, NamedDep):
            if dep.name == "nim":
                continue
            # Malformed constraint detection (§121 / Rust parity):
            # _build_dep preserves constraint_set=None when parsing failed.
            # Here (NimbleFallback path) we raise instead of widening.
            if dep.constraint is not None and dep.constraint_set is None:
                raise MilpaError(
                    MAN_NIMBLE_CONSTRAINT,
                    f"dep {dep.name!r}: malformed version constraint "
                    f"{dep.constraint!r} in .nimble requires",
                    name=dep.name,
                    constraint=dep.constraint,
                )
            requires.append(NamedRequire(
                name=dep.name,
                constraint_str=dep.constraint or "",
                predicates=preds,
            ))
    return requires, src_dir


def _find_nimble_file(dep_path: Path, dep_name: str) -> Path | None:
    """Locate the ``.nimble`` file for ``dep_name`` under ``dep_path``.

    Returns ``None`` if no ``.nimble`` is found (unlike the resolver's internal
    ``_find_nimble_file`` which raises FileNotFoundError — we need graceful fallback).
    """
    candidate = dep_path / f"{dep_name}.nimble"
    if candidate.is_file():
        return candidate
    matches = list(dep_path.glob("*.nimble"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        named = [m for m in matches if m.stem == dep_name]
        if named:
            return named[0]
        return matches[0]
    return None


# ---------------------------------------------------------------------------
# declared_version_for — Axis A (b) precedence steps 1-2 (resolution-semantics
# RFC §3 Axis A). A candidate-labeling concern, orthogonal to EdgeSource: this
# answers "what version does this package call itself", not "what does this
# package require" — so it is a standalone function, not an EdgeSet field
# (EdgeSet is the spec-owned edge type, spec/dep-decl.md §1; cramming a
# package's own version into it would conflate two distinct concerns).
# ---------------------------------------------------------------------------


def declared_version_for(ctx: EdgeSourceCtx) -> "tuple[Version, VersionSource] | None":
    """The fetched package's own declared version, source-agnostic (§3 Axis A (b)).

    Precedence (steps 1-4):

    1. the fetched package's ``milpa.kdl`` ``version`` field (A1's manifest parse) —
       ``VersionSource.MANIFEST``;
    2. else its ``.nimble`` ``version`` (A1's nimble scanner) — ``VersionSource.NIMBLE``;
    3. else, **git deps only** (``ctx.ref`` populated), a version-shaped git
       ``ref`` tag (``v?X.Y.Z``) — parsed via the same ``parse_version`` used
       everywhere else (A3) — ``VersionSource.TAG``;
    4. else, the dep declaration's own ``version=`` annotation (``ctx.version``,
       A3b) — the user-supplied escape hatch for when the fetched artifact
       (steps 1-2) and its ref (step 3) yield no version.  Note steps 1-3 WIN
       over the annotation when present: the annotation only fills the gap —
       ``VersionSource.ANNOTATION``.

    Reads the SAME on-disk files ``MilpaKdlEdgeSource``/``NimbleEdgeSource`` already
    parse for requires, but for a different question — hence a peer function, not
    a shared field. Non-fatal on any read/parse failure or absence: falls through
    to the next step, ultimately ``None`` (version-unknown; A2 keeps the sentinel
    label for that case — the constrained/unconstrained partition + hard error is
    A4, out of scope here).

    Returns ``(version, source)`` as one pair — never merged into a sum type at
    the STORAGE boundary (A5, §3 Axis A: value and source stay two sibling
    fields on the candidate/lockfile record); paired here only so a single
    ``declared_version_for`` call yields both facts without a second,
    potentially file-re-reading, lookup (mirrors ``_candidate_label``'s
    existing ``(label, version_unknown)`` pairing).

    Only meaningful for git/url/local/tarball/member deps. Named/index deps get
    their real version from the index directly (``IndexVersion.version``) and
    never call this.
    """
    if ctx.dep_path is not None:
        if ctx.has_milpa_kdl:
            kdl_path = ctx.dep_path / "milpa.kdl"
            try:
                text = kdl_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                text = None
            if text is not None:
                try:
                    manifest = parse_manifest(text)
                except MilpaError:
                    manifest = None
                if manifest is not None and manifest.version is not None:
                    return manifest.version, VersionSource.MANIFEST

        nimble_path = _find_nimble_file(ctx.dep_path, ctx.dep_name)
        if nimble_path is not None:
            try:
                text = nimble_path.read_text(encoding="utf-8")
            except OSError:
                text = None
            if text is not None:
                nm = parse_nimble(text)
                if nm.version is not None:
                    return nm.version, VersionSource.NIMBLE

    # Step 3 (A3): git tag-derived fallback.  ``ctx.ref`` is populated only by
    # the git/url worker — local/tarball/named/member contexts leave it None,
    # so this step is a no-op for them.  A branch name, bare SHA, or ``main``
    # simply fails ``parse_version``'s strict semver grammar and falls through
    # to version-unknown (A4, out of scope) — no separate "is this a tag"
    # check is needed beyond the version shape itself.
    if ctx.ref is not None:
        tag_version = parse_version(ctx.ref)
        if tag_version is not None:
            return tag_version, VersionSource.TAG

    # Step 4 (A3b): the dep declaration's ``version=`` annotation.  Only
    # reached when steps 1-3 all missed — steps 1-3 WIN over the annotation
    # when present (this is a gap-filler, not an override).
    if ctx.version is not None:
        return ctx.version, VersionSource.ANNOTATION

    return None


# ---------------------------------------------------------------------------
# MilpaKdlEdgeSource
# ---------------------------------------------------------------------------


class MilpaKdlEdgeSource:
    """``milpa.kdl`` → transitive projection → EdgeSet.

    Parses a full Manifest from ``milpa.kdl``, then projects to an EdgeSet via
    the normative transitive-projection rules (§9 + §10.2):

    - Read ONLY ``manifest.deps``; NEVER ``manifest.dev_deps``.
    - DROP ``manifest.overrides`` entirely (a transitive dep's overrides are ignored).
    - Map ``manifest.src_dir → EdgeSet.src_dir``.

    Returns an EdgeSet with ``source = EdgeSource.MILPA_KDL``.
    """

    def edges_for(
        self,
        name: str,
        version: "Version",
        ctx: EdgeSourceCtx,
    ) -> EdgeSet:
        """Parse ``ctx.dep_path / "milpa.kdl"`` and project → EdgeSet.

        Falls back to an empty EdgeSet if parsing fails (mirrors the existing
        ``_parse_transitive_deps`` malformed-KDL fallback — a transitive dep's
        parse failure is non-fatal for the root resolve).
        """
        assert ctx.dep_path is not None, "MilpaKdlEdgeSource requires dep_path"
        kdl_path = ctx.dep_path / "milpa.kdl"

        try:
            text = kdl_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return EdgeSet(requires=[], src_dir="", source=EdgeSource.MILPA_KDL)

        from milpa.manifest import parse_manifest
        from milpa.errors import MilpaError

        try:
            manifest = parse_manifest(text)
        except MilpaError:
            # Malformed transitive milpa.kdl — return empty EdgeSet (non-fatal).
            return EdgeSet(requires=[], src_dir="", source=EdgeSource.MILPA_KDL)

        # S3: pass ctx.active_flags so consumer-requested flags extend the
        # default-true filter (single-hop; full fixpoint arrives in S4a).
        return _manifest_to_edgeset(manifest, active_flags=ctx.active_flags)


def _manifest_to_edgeset(
    manifest: "Manifest",  # type: ignore[name-defined]
    *,
    active_flags: frozenset[str] = frozenset(),
) -> EdgeSet:
    """Normative transitive projection: Manifest → EdgeSet.

    NORMATIVE (§9 + §10.2 + S2.5 + S3 RFC #23 §2.6 + §3.1.2):
    - Reads ONLY ``manifest.deps`` (never ``dev_deps``).
    - Drops ``manifest.overrides`` entirely.
    - Maps ``manifest.src_dir → EdgeSet.src_dir``.
    - Filters flag-predicated deps by the UNION of:
        (a) the manifest's own default-true flags (S2.5),
        (b) ``active_flags`` — flags seeded by cross-package consumer requests
            (S3: single-hop, set by resolver for direct deps).
      Non-flag predicates (platform/arch/nim/milpa) are passed through — they
      are evaluated at root-resolve time by ``filter_manifest``,
      not here (same as Rust).

    This is the single structural guard for the transitive-exclusion rule.
    Both the edge_cache memo and this projection ensure §9/§10.2 correctness.

    ``active_flags`` is the caller-supplied set of externally-activated flags;
    defaults to frozenset() (no external activation, same as S2.5 baseline).
    """
    from milpa.manifest import UrlDep, NamedDep

    # S2.5 + S3: seed active flags from the dep-manifest's own default-true flags
    # (S2.5, matching Rust ``build_edgeset_from_manifest``) UNION the consumer's
    # requested flags threaded in via ctx.active_flags (S3).
    effective_flags: frozenset[str] = frozenset(
        fd.name for fd in manifest.flags if fd.default
    ) | active_flags

    requires: list[NamedRequire | UrlRequire] = []
    for dep in manifest.deps:  # NORMATIVE §9: ONLY manifest.deps
        # S2.5 + S3: filter by the dep's flag predicates against the effective set.
        # Non-flag predicates are skipped (Rust parity).
        predicates = dep.predicates
        if not dep_passes_flag_predicates(predicates, effective_flags):
            continue
        if isinstance(dep, UrlDep):
            requires.append(UrlRequire(
                url=dep.git,
                ref=dep.ref,
                name=dep.name,
                # S3 + S4b: carry flag_requests so edgeset_to_bfs_deps can pass
                # them through to UrlDep without a second manifest parse.
                # Matches Rust UrlRequire.flag_requests (milpa-types).
                flag_requests=dep.flag_requests,
            ))
        elif isinstance(dep, NamedDep):
            if dep.name == "nim":
                continue
            requires.append(NamedRequire(
                name=dep.name,
                constraint_str=dep.constraint or "",
                # H2 (rfc-resolver-correctness.md): carry namespace so transitive
                # qualified deps survive the EdgeSet boundary.
                namespace=dep.namespace,
            ))
        # Tarball/Local/Member from transitive milpa.kdl: out of scope (mirrors
        # existing _parse_transitive_deps deferral; only URL + named enter the graph).

    src_dir = manifest.src_dir or ""
    # manifest.overrides dropped entirely (§10.2 NORMATIVE).
    return EdgeSet(requires=requires, src_dir=src_dir, source=EdgeSource.MILPA_KDL)


# ---------------------------------------------------------------------------
# DepDeclEdgeSource (S3b)
# ---------------------------------------------------------------------------


class DepDeclEdgeSource:
    """Index-attested DepDecl artifact → EdgeSet (S3b).

    The SINGLE site that calls ``store.get(dep_decl_hash)`` (hash already
    verified inside ``store.get``), then calls ``parse_dep_decl(bytes)``
    and applies the two schema-consistency checks from spec §5:

    1. ``dep_decl_schema_version`` in the **artifact** MUST match the
       ``dep_decl_schema_version`` from the **index pointer** carried in
       ``ctx.dep_decl_schema_version`` → ``TNG-DEPDECL-SCHEMA-MISMATCH``.

    2. The artifact's ``dep_decl_schema_version`` MUST NOT exceed
       ``MAX_DEP_DECL_SCHEMA_VERSION`` (this impl's cap) →
       ``TNG-DEPDECL-SCHEMA-UNSUPPORTED``.

    Uses NO ``dep_path`` — only ``ctx.dep_decl`` (the hash pointer) and
    ``ctx.dep_decl_schema_version`` (the index's pointer schema version).

    SECURITY: integrity failures (HASH-MISMATCH, PARSE-ERROR, SCHEMA-*)
    are always hard errors — no fallback (NORMATIVE).  Only FETCH-FAILED
    (unreachable artifact) is subject to strict/non-strict policy (S5).
    """

    def __init__(self, store: object) -> None:
        """Create a DepDeclEdgeSource backed by the given DepDeclStore.

        ``store`` must satisfy the ``DepDeclStore`` protocol (``get`` + ``is_cached``).
        """
        self._store = store

    def edges_for(
        self,
        name: str,
        version: "Version",
        ctx: EdgeSourceCtx,
    ) -> EdgeSet:
        """Fetch artifact bytes, verify, parse, check schemas, return EdgeSet.

        Raises:
            MilpaError(TNG-DEPDECL-FETCH-FAILED):   Artifact unreachable (from store.get).
            MilpaError(TNG-DEPDECL-HASH-MISMATCH):  Hash mismatch (from store.get — SECURITY).
            MilpaError(TNG-DEPDECL-PARSE-ERROR):    Malformed KDL artifact.
            MilpaError(TNG-DEPDECL-SCHEMA-MISMATCH):    Index schema version ≠ artifact schema version.
            MilpaError(TNG-DEPDECL-SCHEMA-UNSUPPORTED): Artifact schema version > impl cap.
        """
        assert ctx.dep_decl is not None, "DepDeclEdgeSource requires ctx.dep_decl"

        # Fetch + verify (SECURITY: hash-verify is inside store.get, not here).
        artifact_bytes = self._store.get(ctx.dep_decl)  # type: ignore[attr-defined]

        # Parse → (EdgeSet, schema_version) — DOM-sourced, no secondary text-scan.
        # parse_dep_decl returns the schema_version from the KDL DOM node so there
        # is a SINGLE read of the version integer (SSOT, R3 fix).
        from milpa.dep_decl import MAX_DEP_DECL_SCHEMA_VERSION, parse_dep_decl
        es, artifact_schema_version = parse_dep_decl(artifact_bytes)

        # Check (i): artifact schema version MUST NOT exceed impl cap.
        if artifact_schema_version > MAX_DEP_DECL_SCHEMA_VERSION:
            raise MilpaError(
                TNG_DEPDECL_SCHEMA_UNSUPPORTED,
                f"DepDecl artifact for {name!r} declares "
                f"dep_decl_schema_version {artifact_schema_version}, but this "
                f"milpa only understands up to {MAX_DEP_DECL_SCHEMA_VERSION} "
                f"— upgrade milpa to read this artifact",
                name=name,
                artifact_version=artifact_schema_version,
                max_supported=MAX_DEP_DECL_SCHEMA_VERSION,
            )

        # Check (ii): artifact schema version MUST match index pointer version.
        if ctx.dep_decl_schema_version is not None:
            if artifact_schema_version != ctx.dep_decl_schema_version:
                raise MilpaError(
                    TNG_DEPDECL_SCHEMA_MISMATCH,
                    f"DepDecl artifact for {name!r} embeds "
                    f"dep_decl_schema_version {artifact_schema_version}, but the "
                    f"index pointer says {ctx.dep_decl_schema_version} — "
                    f"the artifact and index are out of sync",
                    name=name,
                    artifact_version=artifact_schema_version,
                    index_version=ctx.dep_decl_schema_version,
                )

        return es


# ---------------------------------------------------------------------------
# resolve_edges coordinator + edge_cache
# ---------------------------------------------------------------------------


def _resolve_edges_pure(
    name: str,
    version: "Version",
    ctx: EdgeSourceCtx,
    *,
    nimble_source: NimbleEdgeSource | None = None,
    milpakdl_source: MilpaKdlEdgeSource | None = None,
    dep_decl_source: "DepDeclEdgeSource | None" = None,
    strict_attestation: bool = False,
) -> EdgeSet:
    """Implement clauses (b)(c)(d) of §4.2.1 ``resolve_edges`` — no cache.

    This is the **pure** dispatch used by:
    - The URL/tarball/local **workers** (S2b): they call this directly because
      they run on worker threads before the edge_cache is available for writing.
      Workers now honor clause (b) override-suppression and clause (c) DepDecl
      instead of falling through to clause (d) only (the old ``_pick_edges`` bug).
    - ``resolve_edges`` (the thin cached wrapper below): delegates to this after
      the clause-(a) cache check.

    Clause (b) — Override suppresses DepDecl:
        When ``ctx.is_overridden``, the attested DepDecl describes the *original*
        tree and is invalid for the redirected source.  Fall through to
        MilpaKdl/Nimble.

    Clause (c) — DepDecl mainline (S3b):
        When ``ctx.dep_decl`` is set AND ``dep_decl_source`` is not None, use the
        attested source.

    Clause (d) — MilpaKdl / Nimble fallback:
        ``has_milpa_kdl → MilpaKdlEdgeSource``; else ``NimbleEdgeSource``.
    """
    # Resolve source singletons.
    _nimble = nimble_source if nimble_source is not None else NimbleEdgeSource()
    _milpakdl = milpakdl_source if milpakdl_source is not None else MilpaKdlEdgeSource()

    if ctx.is_overridden:
        # Clause (b): override suppresses DepDecl — DepDecl describes original tree.
        # Fall through to MilpaKdl or Nimble on the overridden source.
        if ctx.has_milpa_kdl:
            es = _milpakdl.edges_for(name, version, ctx)
        else:
            es = _nimble.edges_for(name, version, ctx)

    elif ctx.dep_decl is not None and dep_decl_source is not None:
        # Clause (c): index-attested DepDecl mainline (S3b).
        # dep_decl_source is injected from MilpaEnv.dep_decl_store (wired at S3b).
        # S5: FETCH-FAILED is policy-gated.
        #   Non-strict: fall through to Nimble on unreachable artifact.
        #   Strict: re-raise as hard error (clause b).
        #   Integrity failures (HASH-MISMATCH, PARSE-ERROR, SCHEMA-*): ALWAYS hard.
        from milpa.errors import TNG_DEPDECL_FETCH_FAILED
        try:
            es = dep_decl_source.edges_for(name, version, ctx)
        except MilpaError as exc:
            if exc.slug == TNG_DEPDECL_FETCH_FAILED and not strict_attestation:
                # Non-strict: artifact unreachable → fall back to Nimble.
                # The summary warning will fire at resolve-end via enforce_attestation_policy.
                _nimble2 = nimble_source if nimble_source is not None else NimbleEdgeSource()
                es = _nimble2.edges_for(name, version, ctx)
            else:
                # Strict FETCH-FAILED OR integrity failure → always hard error.
                raise

    elif ctx.has_milpa_kdl:
        # Clause (d): package ships milpa.kdl → MilpaKdlEdgeSource.
        es = _milpakdl.edges_for(name, version, ctx)

    else:
        # Clause (d): raw git-URL dep with no milpa.kdl → NimbleEdgeSource.
        es = _nimble.edges_for(name, version, ctx)

    return es


def resolve_edges(
    name: str,
    version: "Version",
    ctx: EdgeSourceCtx,
    edge_cache: dict[tuple[str, "Version"], EdgeSet],
    *,
    nimble_source: NimbleEdgeSource | None = None,
    milpakdl_source: MilpaKdlEdgeSource | None = None,
    dep_decl_source: "DepDeclEdgeSource | None" = None,
    strict_attestation: bool = False,
) -> EdgeSet:
    """Thin cached wrapper: clause (a) + delegates to ``_resolve_edges_pure``.

    Implements spec/resolver-semantics.md §4.2.1 ``resolve_edges`` (S4-i amendment):

    Clause (a) — Sealed once:
        If ``(name, version)`` is in ``edge_cache``, return the sealed EdgeSet
        immediately.  A diamond where two BFS parents reach ``D@v`` cannot yield
        two different EdgeSets.

    Clauses (b)(c)(d) — delegated to ``_resolve_edges_pure``.

    Parameters
    ----------
    name, version:
        The package being resolved.
    ctx:
        Per-package context (dep_path, dep_decl, is_overridden, has_milpa_kdl, …).
    edge_cache:
        Resolver-scoped memo; mutated in place (caller owns).
    nimble_source:
        Injectable NimbleEdgeSource (default: a fresh NimbleEdgeSource()).
    milpakdl_source:
        Injectable MilpaKdlEdgeSource (default: a fresh MilpaKdlEdgeSource()).
    dep_decl_source:
        ``DepDeclEdgeSource`` instance (S3b).  ``None`` falls through to
        MilpaKdl/Nimble (S4-i compatibility behavior).  After S3b, the
        resolver injects a real instance from ``MilpaEnv.dep_decl_store``.
    strict_attestation:
        When ``True`` (strict policy from manifest OR ``--require-attested-metadata``
        flag), ``TNG-DEPDECL-FETCH-FAILED`` from the DepDecl store is re-raised
        as a hard error (S5 strict clause b).  When ``False`` (non-strict,
        default), an unreachable DepDecl artifact falls through to Nimble
        fallback so resolution can continue (S5 non-strict deferred behaviour).
        Integrity failures (HASH-MISMATCH, PARSE-ERROR, SCHEMA-*) are ALWAYS
        hard errors regardless of this flag.

    Returns
    -------
    EdgeSet
        Sealed in ``edge_cache`` on first call; returned from cache on repeat calls.
    """
    # Clause (a): sealed once — parent-independent.
    cache_key = (name, version)
    if cache_key in edge_cache:
        return edge_cache[cache_key]

    es = _resolve_edges_pure(
        name, version, ctx,
        nimble_source=nimble_source,
        milpakdl_source=milpakdl_source,
        dep_decl_source=dep_decl_source,
        strict_attestation=strict_attestation,
    )

    # Seal in cache.
    edge_cache[cache_key] = es
    return es


# ---------------------------------------------------------------------------
# EdgeSet → (dep_terms, requires_names) converter
# ---------------------------------------------------------------------------


def edgeset_to_terms(
    es: EdgeSet,
    overrides_by_name: dict[str, "Override"],
) -> tuple[list["Term"], list[str], dict[str, "list[tuple[object, ...]]"]]:
    """Convert an ``EdgeSet`` to the solver's ``(dep_terms, requires_names, requires_predicates)`` tuple.

    This is the single source of truth for ``EdgeSet → Term`` mapping,
    replacing the inline logic scattered across ``_parse_transitive_deps``
    and ``_parse_from_nimble`` in the existing resolver.

    NORMATIVE: applies the same override-coercion as the main BFS loop —
    a named dep whose name is in ``overrides_by_name`` is treated as a URL
    dep.

    Axis A (a) (resolution-semantics RFC §3, D-A2): a URL/local/tarball
    require's own term — and an overridden named require's term — is always
    ``VersionSet.full()``, never ``eq(sentinel)``.  Such a dep has exactly one
    real candidate (materialised elsewhere), so ``full()`` is harmless and
    fixes the causality hole of a pre-fetch term racing the post-fetch
    candidate label (which now carries the real declared version when one is
    parseable — ``declared_version_for``).  There is therefore no longer a
    "sentinel version" parameter here; the self-term does not need one.

    Parameters
    ----------
    es:
        The EdgeSet from any EdgeSource.
    overrides_by_name:
        Root-manifest overrides dict (name → Override).

    Returns
    -------
    (dep_terms, requires_names, requires_predicates):
        ``dep_terms`` and ``requires_names`` are ready for
        ``_Candidate(dep_terms=…, requires_names=…)``.
        ``requires_predicates`` maps dep-name → LIST of predicate-tuples,
        one entry per occurrence of that dep name with non-empty predicates.
        A dep appearing in ≥2 recognized ``when`` branches yields ≥2 list
        entries; each entry becomes one ``CondRequire`` in the lockfile (§3.5).
        Advisory metadata only — never consulted for selection/solving
        (S4, RFC §3.4.3 option a).
    """
    from milpa.predicate import Predicate as _Predicate
    from milpa.solver import Term
    from milpa.version import VersionSet, parse_version

    dep_terms: list[Term] = []
    requires_names: list[str] = []
    # S4: maps dep-name → ALL predicate-tuples collected across ALL occurrences.
    # A dep appearing in ≥2 ``when`` branches yields ≥2 entries in this list,
    # each carrying the branch's own predicate set.  One CondRequire is emitted
    # per entry (§3.5, lockfile-schema.md).  The dict is keyed by name to keep
    # ordering stable; we accumulate into a list rather than overwriting.
    # Spec §7.1: no dedup at the scanner level; the dep name may appear more
    # than once in ``es.requires`` with different predicate sets.
    requires_predicates: dict[str, list[tuple[_Predicate, ...]]] = {}
    # Track names already added to dep_terms/requires_names to avoid solver
    # duplicates (the solver needs each dep name exactly once as a Term).
    # Dedup is correct HERE (resolved dep set, not the raw scanner output).
    seen_dep_names: set[str] = set()

    for entry in es.requires:
        if isinstance(entry, UrlRequire):
            # URL requires → full() self-term (Axis A (a), D-A2).
            # ONE-NAME-PER-DECLARATION: prefer the DECLARED node name
            # (milpa.kdl/.nimble source, e.g. `"z3" git=(url)"…/nim-z3.git"`)
            # so the solver term this parent candidate carries agrees with
            # the name `edgeset_to_bfs_deps` enqueues the child under (it
            # already prefers `entry.name`) and the name root-authority /
            # `overrides {}` / the provenance gate key on. Falls back to the
            # URL-tail derivation only when no declared name exists (DepDecl-
            # sourced entries, where `entry.name` is always None).
            dep_name = entry.name if entry.name is not None else _name_from_url(entry.url)
            if dep_name is None:
                continue
            if dep_name not in seen_dep_names:
                dep_terms.append(Term.require(dep_name, VersionSet.full()))
                requires_names.append(dep_name)
                seen_dep_names.add(dep_name)
            if entry.predicates:
                requires_predicates.setdefault(dep_name, []).append(entry.predicates)

        elif isinstance(entry, NamedRequire):
            if entry.name == "nim":
                continue
            # H2 (rfc-resolver-correctness.md): use the solver_var (``ns::name``
            # for qualified deps) as the PubGrub term key so that
            # ``ns1::bar`` and ``ns2::bar`` are distinct solver variables even
            # when both have bare name ``"bar"``.
            from milpa.version import DepKey as _DK
            _entry_dk = _DK(name=entry.name, namespace=entry.namespace)
            _svar = _entry_dk.solver_var()  # "bar" or "ns1::bar"
            if _svar not in seen_dep_names:
                if entry.name in overrides_by_name:
                    # Named dep with override → URL-like full() self-term (D-A2).
                    dep_terms.append(
                        Term.require(_svar, VersionSet.full())
                    )
                else:
                    # Parse constraint_str → VersionSet.
                    if entry.constraint_str:
                        from milpa.version import VersionSet as VS
                        try:
                            vs = VS.from_constraint(entry.constraint_str)
                        except Exception:
                            vs = VS.full()
                    else:
                        from milpa.version import VersionSet as VS
                        vs = VS.full()
                    dep_terms.append(Term.require(_svar, vs))
                requires_names.append(_svar)
                seen_dep_names.add(_svar)
            if entry.predicates:
                requires_predicates.setdefault(_svar, []).append(entry.predicates)

    return dep_terms, requires_names, requires_predicates


def edgeset_to_bfs_deps(
    es: EdgeSet,
    overrides_by_name: dict[str, object],
) -> list[object]:
    """Convert an ``EdgeSet`` to raw dep objects for BFS enqueuing.

    This is the S2b replacement for ``_collect_transitive_deps``.  Instead of
    re-parsing the fetched tree (the old bug: ``list(m.deps)`` without flag
    filtering), workers now call this on the EdgeSet they already computed via
    ``_resolve_edges_pure`` — which already applied flag filtering via
    ``_manifest_to_edgeset``.

    Returns a list of ``UrlDep | NamedDep`` objects.  Tarball/Local/Member
    entries are absent from the EdgeSet by construction (``_manifest_to_edgeset``
    drops them at line 349), so no explicit filtering is needed here.

    Parameters
    ----------
    es:
        The EdgeSet produced by ``_resolve_edges_pure`` for this dep.
        Already flag-filtered — every entry in ``es.requires`` is "active".
    overrides_by_name:
        Root-manifest overrides dict (passed through for callers; BFS enqueuing
        applies override routing after this function returns).

    Returns
    -------
    list[UrlDep | NamedDep]
        Raw dep objects ready for ``_enqueue_dep``.
    """
    from milpa.manifest import NamedDep as _NamedDep, UrlDep as _UrlDep
    from milpa.nimble import url_to_name as _url_to_name

    result: list[object] = []
    for entry in es.requires:
        if isinstance(entry, UrlRequire):
            # Use the declared name if set (milpa.kdl/nimble source);
            # fall back to url_to_name for DepDecl-sourced entries (name=None).
            if entry.name is not None:
                name = entry.name
            else:
                name = _url_to_name(entry.url)
            # Pass flag_requests through directly — they're already FlagRequest
            # objects on UrlRequire (M5: no raw-tuple round-trip).
            result.append(_UrlDep(name=name, git=entry.url, ref=entry.ref, flag_requests=entry.flag_requests))
        elif isinstance(entry, NamedRequire):
            # H2 (rfc-resolver-correctness.md): carry namespace so transitive
            # qualified deps reconstruct the correct DepKey in the BFS loop.
            result.append(_NamedDep(
                name=entry.name,
                constraint=entry.constraint_str or "",
                namespace=entry.namespace,
            ))
    return result


def _name_from_url(url: str) -> str | None:
    """Derive a dep name from a git URL — wraps ``nimble.url_to_name`` (M3 SSOT).

    Uses ``nimble.url_to_name`` as the single derivation logic, then applies the
    None-drop guard for degenerate inputs where no meaningful path component
    exists (e.g. bare scheme-only URLs).  The None return causes the dep to be
    silently dropped from the EdgeSet, which is the correct EdgeSet-level behavior.

    Callers in ``edgeset_to_terms`` use ``continue`` on None (dep dropped).
    Callers in the ``nimble`` module use ``url_to_name`` directly (returns a
    non-empty string even for degenerate inputs, which is correct for UrlDep.name).
    """
    from milpa.nimble import url_to_name as _url_to_name
    name = _url_to_name(url)
    # None-drop guard: if the "name" equals the full URL (no path component found
    # by url_to_name's fallback), or contains path separators / bad chars, drop it.
    # url_to_name returns the full URL as fallback; detect this by checking that the
    # result is not the same as the stripped URL and has no path separators.
    stripped = url.rstrip("/")
    if stripped.endswith(".git"):
        stripped = stripped[:-4]
    # A meaningful name must differ from the full stripped URL and contain no "/"
    if name == stripped or "/" in name or ".." in name or name.startswith("/"):
        return None
    return name
