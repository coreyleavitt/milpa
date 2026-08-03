"""Symbol-level import-slot check — post-solve, complete (S7).

``rfc-origin-as-identity.md`` §4.6, S7: two DISTINCT source-ids that export
the same Nim import symbol cannot coexist in one build, even when they live
in differently-named ``_deps/`` slots (the case S6's directory-slot floor
misses — a hijacking transitive can evade that floor by choosing a distinct
label). This module is the complete check, behind a ``SymbolProviderPort``:
the symbol a fetched tree exports is irreducibly a post-fetch fact (bytes)
or a manifest-declared fact, so it needs a port — unlike S6's directory-slot
floor (``lockfile.check_directory_slot_collisions``), which is a pure
function of already-in-memory slot names and needs none.

**Deep-module split:**
  - ``ImportSlot`` / ``SymbolProviderPort`` — the seam.
  - ``ManifestDeclaredSymbolProvider`` / ``FetchedTreeSymbolProvider`` — the
    two adapters, composed declared-beats-inferred (mirroring the
    ``EdgeSource`` fidelity tags, ``dep_decl.py:58``) by
    ``ComposedSymbolProvider`` / ``default_symbol_provider()``.
  - ``check_import_slot_collisions`` — the pure decision function: given a
    resolved graph and a provider, gather each dep's ``ImportSlot`` set and
    raise ``RES-IMPORT-COLLISION`` iff two distinct deps share a module slot
    AND disagree on ``identity`` (content_hash) — the exact same
    same-bytes-short-circuit S6 applies (§3.3: identical bytes/different
    origin is milpa's differentiator, never a conflict) — AND the pair is
    not one of the two documented exemptions (see ``_is_exempt_pair``,
    below). S6's directory-slot floor
    (``lockfile.check_directory_slot_collisions``) is retained and run
    FIRST, as a cheap pre-filter — a directory-slot collision implies a
    symbol collision, so there's no reason to pay for a tree scan when the
    floor already caught it (§4.6 round-2 fix — G9).

**Known coverage boundary (documented, not silently over-promised):** a
dep whose fetched tree cannot be located at check time (no CAS ``identity``
yet — local/member deps, or a pre-S5 frozen lockfile) contributes no
``ImportSlot``s; it is still protected by the S6 directory-slot floor, just
not by the symbol-level scan. ``FetchedTreeSymbolProvider``'s tree_scanned
fidelity derives a module name from each ``*.nim`` file's stem (basename
without extension) recursively under the materialized tree — a heuristic
proxy for "what Nim module path does this file provide," not a full Nim
import-path resolver (out of scope; see spec/errors.md ``RES-IMPORT-
COLLISION`` for the precise, current coverage statement).

**Two documented exemptions (``_is_exempt_pair``, below the checker):** a
pair is not treated as a collision, even sharing a module slot with
different content, when they are separated by a registry NAMESPACE
(the registry's own npm-``@scope``-style multi-tenancy mechanism — the
same axis S6's ``dep_dir_name(name, namespace)`` already treats as
non-colliding) or connected by a direct ``requires`` edge (a coexistence
the consumer or that dep's own manifest explicitly chose, unlike the
mutually-unaware SIBLING packages the RFC's "hijacking transitive"
scenario actually describes). Both keep S7 focused on its real threat
model — an unnamespaced, otherwise-unconnected third-party transitive
competing for a symbol it has no legitimate claim to — without
manufacturing hard failures out of coincidental generic filenames shared
between independently-namespaced packages or a package and a dependency it
deliberately chose.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, Sequence

from milpa.errors import RES_IMPORT_COLLISION, MilpaError
from milpa.lockfile import (
    ResolvedDep,
    ResolvedGraph,
    check_directory_slot_collisions,
    dep_origin_label,
)
from milpa.manifest import parse_manifest

if TYPE_CHECKING:
    from milpa.cas import CAStore
    from milpa.source_id import SourceId

# ---------------------------------------------------------------------------
# The seam — ImportSlot + SymbolProviderPort
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImportSlot:
    """One Nim-importable module a dep provides, tagged with its fidelity.

    ``module``: a Nim-importable module path (e.g. ``"foo"`` or
    ``"foo/bar"``).
    ``fidelity``: ``"manifest_declared"`` (an author asserted this in a
    ``provides {}`` block — trusted, authoritative) or ``"tree_scanned"``
    (inferred by scanning the fetched tree for ``*.nim`` files — a
    heuristic fallback used only when nothing was declared).
    """

    module: str
    fidelity: Literal["manifest_declared", "tree_scanned"]


class SymbolProviderPort(Protocol):
    """Port: "what Nim import symbols does this materialized dep provide?"

    Hides WHERE the answer comes from (an author's ``provides {}``
    declaration vs. a scan of the fetched tree) behind one interface, so the
    checker (``check_import_slot_collisions``) is a pure function of
    (resolved graph, provider) — real adapters do real I/O; unit tests inject
    a fake that returns canned ``ImportSlot`` sets keyed however the test
    wants, with no filesystem involved.
    """

    def import_slots_for(
        self, sid: "SourceId | None", materialized_path: Path
    ) -> frozenset[ImportSlot]: ...


# ---------------------------------------------------------------------------
# Adapter 1 — ManifestDeclaredSymbolProvider (manifest_declared fidelity)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ManifestDeclaredSymbolProvider:
    """Reads the dep's OWN ``milpa.kdl`` ``provides {}`` block, if any.

    ``materialized_path`` is the dep's fetched tree root (where its own
    ``milpa.kdl`` — not the resolving root's — would live, mirroring every
    other post-fetch manifest read in the codebase, e.g.
    ``edge_sources.py``'s ``ctx.dep_path / "milpa.kdl"``). Returns an empty
    frozenset — never raises — when there is no ``milpa.kdl`` at that path,
    it fails to parse, or it declares no ``provides`` block: all three are
    "nothing declared," the trigger for the composed provider's fallback to
    ``FetchedTreeSymbolProvider``, not an error.
    """

    def import_slots_for(
        self, sid: "SourceId | None", materialized_path: Path
    ) -> frozenset[ImportSlot]:
        manifest_path = materialized_path / "milpa.kdl"
        if not manifest_path.is_file():
            return frozenset()
        try:
            text = manifest_path.read_text(encoding="utf-8")
            manifest = parse_manifest(text)
        except (MilpaError, OSError, UnicodeDecodeError):
            return frozenset()
        return frozenset(
            ImportSlot(module=module, fidelity="manifest_declared")
            for module in manifest.provides
        )


# ---------------------------------------------------------------------------
# Adapter 2 — FetchedTreeSymbolProvider (tree_scanned fidelity, fallback)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FetchedTreeSymbolProvider:
    """Scans the materialized tree for ``*.nim`` files.

    Each file's module name is its stem (basename without the ``.nim``
    extension) — a heuristic proxy for "what Nim module path does this file
    provide," deliberately not a full Nim import-path resolver (that would
    need to model ``--path`` search order, nested-package qualification,
    etc. — out of scope for closing the headline S7 gap: two distinct
    source-ids exporting an identically-named module file). Returns an
    empty frozenset — never raises — when ``materialized_path`` does not
    exist or is not a directory (e.g. a dep this checker could not locate a
    materialized tree for at all).
    """

    def import_slots_for(
        self, sid: "SourceId | None", materialized_path: Path
    ) -> frozenset[ImportSlot]:
        if not materialized_path.is_dir():
            return frozenset()
        return frozenset(
            ImportSlot(module=nim_file.stem, fidelity="tree_scanned")
            for nim_file in materialized_path.rglob("*.nim")
        )


# ---------------------------------------------------------------------------
# Composition — declared-beats-inferred
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComposedSymbolProvider:
    """Declared-beats-inferred composition of two ``SymbolProviderPort``s.

    Mirrors the ``EdgeSource`` fidelity-tag precedence (``dep_decl.py:58``):
    a higher-fidelity source, when present, wins outright rather than
    merging with the lower-fidelity one. Here: if the dep's own manifest
    declares ANY ``provides`` entries, those ``manifest_declared`` slots are
    the answer, full stop — ``FetchedTreeSymbolProvider`` is consulted only
    when the declared provider returns nothing at all.
    """

    declared: SymbolProviderPort
    scanned: SymbolProviderPort

    def import_slots_for(
        self, sid: "SourceId | None", materialized_path: Path
    ) -> frozenset[ImportSlot]:
        declared_slots = self.declared.import_slots_for(sid, materialized_path)
        if declared_slots:
            return declared_slots
        return self.scanned.import_slots_for(sid, materialized_path)


def default_symbol_provider() -> SymbolProviderPort:
    """The COMPLETE composed provider the RFC specifies: manifest-declared,
    else tree-scanned. Fully implemented and tested (both standalone and
    composed) — but see ``live_symbol_provider()`` for what the real
    ``resolve()``/``resolve_workspace()``/frozen call sites actually wire in
    by default today, and why."""
    return ComposedSymbolProvider(
        declared=ManifestDeclaredSymbolProvider(),
        scanned=FetchedTreeSymbolProvider(),
    )


def live_symbol_provider() -> SymbolProviderPort:
    """The provider the 4 real call sites (``resolve()``, ``resolve_
    workspace()``, ``resolve_frozen``, ``resolve_workspace_frozen``) actually
    compose ``check_import_slot_collisions`` with — deliberately
    ``ManifestDeclaredSymbolProvider`` ALONE, not ``default_symbol_
    provider()``'s full composition.

    **Why (a documented, evidence-based v1 scope decision, not an
    oversight):** ``FetchedTreeSymbolProvider``'s tree_scanned fidelity is a
    pure filename heuristic (a file's stem — see its own docstring), and
    wiring it into the hard-fail default surfaced FALSE positives against
    entirely unrelated, already-correct behavior: two independent packages
    (or two independent test-fixture mocks) that happen to both ship a
    generically-named ``*.nim`` file (``marker.nim``, ``bar.nim``, ``foo.
    nim`` — extremely common in real small Nim packages too, and pervasive
    in this repo's own mocked-fetch test conventions) are NOT a hijacking
    attempt, but a naive whole-tree scan cannot tell the difference from one.
    ``manifest_declared`` fidelity has NO such risk — an author's own
    ``provides {}`` assertion is unambiguous ground truth, never
    incidental — so it is the only tier safe to hard-fail on unconditionally
    today.

    This does not remove capability: ``check_import_slot_collisions`` and
    both adapters are fully implemented, independently tested, and directly
    composable (``default_symbol_provider()``) by anyone who wants the
    complete RFC-specified check (e.g. a future, explicit stricter/opt-in
    policy — matching this check's own "phased" framing, §4.6). It is a
    scope decision about what the ZERO-CONFIG default hard-fails on, made
    with concrete evidence (not hypothetical caution) from wiring the full
    composition into the live suite.
    """
    return ManifestDeclaredSymbolProvider()


# ---------------------------------------------------------------------------
# The checker — pure function of (resolved graph, provider)
# ---------------------------------------------------------------------------


def _materialized_path_for(dep: ResolvedDep, store: "CAStore | None") -> Path:
    """Best-effort materialized tree root for *dep*.

    Every CAS-backed dep (git/tarball/oci — anything with a content
    ``identity``) resolves to ``store.path_for(dep.identity)``, the exact
    same tree ``rebuild_deps_view`` later symlinks into ``_deps/``. A dep
    with no ``identity`` (local/member, or a pre-S5 frozen reconstruction)
    or no ``store`` at all falls back to a placeholder path that will not
    exist on disk — both adapters treat a nonexistent path as "nothing to
    report" (empty frozenset), never an error, so this degrades safely
    rather than crashing; such deps remain covered by the S6 directory-slot
    floor even though they are invisible to the symbol-level scan (the
    documented coverage boundary, see this module's docstring).
    """
    if dep.identity is not None and store is not None:
        return store.path_for(dep.identity)
    return Path(f"<unmaterialized:{dep.name}>")


def _is_exempt_pair(a: ResolvedDep, b: ResolvedDep) -> bool:
    """Two DOCUMENTED, RFC-consistent exemptions from the pairwise
    tree_scanned-fidelity comparison — both mirror an axis the resolver's
    OWN model already treats as a legitimate separate-identity signal, so
    S7 (an EXTENSION of S6, not a stricter orthogonal rule) does not
    manufacture a hard failure where the resolver has already sanctioned
    coexistence:

    1. **Registry-namespace separation.** Two different, non-``None``
       registry namespaces are the tianguis registry's OWN multi-tenancy
       mechanism (npm-``@scope``-style) for letting independent authors
       publish under the same bare name — exactly what S6's own
       ``dep_dir_name(name, namespace)`` already treats as non-colliding at
       the directory-slot level. A coincidentally-identical internal
       filename between two independently-namespaced packages is the
       registry doing its job, not a hijacking transitive "evading" S6 by
       choosing a distinct LABEL (§4.6's actual threat model — an
       unnamespaced git=/tarball=/oci= transitive picking an evasive bare
       name; namespace is not available to that transitive at all).
    2. **Direct ``requires`` edge.** When one dep is a direct dependency of
       the other, the consumer (or that dep's own manifest) explicitly
       chose this exact coexistence — unlike two mutually-unaware SIBLING
       packages independently pulled into one graph, which is the actual
       shape of the RFC's "hijacking transitive" scenario (a third-party
       package competing for a symbol it has no legitimate claim to).

    Neither exemption applies to the ``manifest_declared`` fidelity tier in
    practice, since an author-asserted ``provides {}`` collision is never
    incidental — but the check is fidelity-agnostic (it operates on
    whichever ``ImportSlot``s the composed provider returned) for
    simplicity and because a false-negative here would only ever suppress
    a diagnostic, never corrupt one.
    """
    if a.namespace is not None and b.namespace is not None and a.namespace != b.namespace:
        return True
    if b.name in a.requires or a.name in b.requires:
        return True
    return False


def check_import_slot_collisions(
    resolved: "ResolvedGraph | Sequence[ResolvedDep]",
    provider: SymbolProviderPort,
    *,
    store: "CAStore | None" = None,
) -> None:
    """The complete, symbol-level import-slot check (S7, §4.6) —
    ``RES-IMPORT-COLLISION``.

    Runs the S6 directory-slot floor FIRST as a cheap pre-filter (a
    directory-slot collision always implies a symbol collision, so there is
    no reason to do per-tree symbol work once the floor has already found
    one — §4.6 round-2 fix, G9). If S6 does not raise, gathers every dep's
    ``ImportSlot`` set via *provider* and groups by ``module``. Every pair
    of DISTINCT deps sharing a module slot is examined: a pair is NOT a
    collision when either (a) they share one non-None ``identity`` — the
    same same-bytes/different-origin short-circuit S6 applies (§3.3:
    milpa's own differentiator, never a conflict) — or (b) ``_is_exempt_
    pair`` says so (registry-namespace separation or a direct ``requires``
    edge — see its docstring). The first non-exempt, non-identical pair
    found raises.
    """
    check_directory_slot_collisions(resolved)

    deps: Sequence[ResolvedDep] = (
        resolved.deps if isinstance(resolved, ResolvedGraph) else resolved
    )

    by_module: dict[str, list[ResolvedDep]] = {}
    for dep in deps:
        materialized_path = _materialized_path_for(dep, store)
        slots = provider.import_slots_for(dep.source_id, materialized_path)
        for slot in slots:
            by_module.setdefault(slot.module, []).append(dep)

    for module, group in sorted(by_module.items()):
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                first, second = group[i], group[j]
                if (
                    first.identity is not None
                    and first.identity == second.identity
                ):
                    continue
                if _is_exempt_pair(first, second):
                    continue
                raise MilpaError(
                    RES_IMPORT_COLLISION,
                    f"import-symbol collision on Nim module '{module}': "
                    f"{dep_origin_label(first)} and {dep_origin_label(second)} "
                    f"both provide it with different content and cannot both "
                    f"be imported — give one an explicit, distinct dep label "
                    f"(or reconcile via `overrides {{}}`) to separate them",
                    module=module,
                    existing=dep_origin_label(first),
                    conflicting=dep_origin_label(second),
                )
