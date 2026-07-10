"""Consumer ratchet — pure in-memory dominance-fold engine (registry-protocol
§3.5, `rfc-registry-append-only.md` slice A2b).

This module is a **standalone** engine: no filesystem I/O, no sidecar
lifecycle, no ``index-history`` policy plumbing, no CLI. It answers exactly
one question — "does *candidate* legally dominate *baseline*?" — and reports
the answer as data. Everything downstream (baseline sidecar persistence,
sticky-advance write ordering, TOFU, `milpa index status`/`accept`) is A2d's
job; the ``index-history`` policy axis (``off``/``warn``/``strict``) is
A2c's; raising ``MilpaError`` with a ``TNG-*`` slug from a ``RatchetOutcome``
is A2d's gate seam. This module never raises.

Public surface
---------------
- ``EntryKey`` — the ``(namespace, name, version)`` key (§3.5.1 NORMATIVE).
  ``ROOT_KEY`` is the reserved empty key document-root fields fold under.
- ``RawField`` / ``RatchetEntry`` / ``IndexState`` — the input shape. See
  "Raw-value sourcing" below for why these exist instead of feeding the
  engine ``registry.IndexVersion`` directly.
- ``Baseline`` — wraps a baseline ``IndexState``; ``.check(candidate)``
  returns a ``RatchetOutcome``. Monomorphic: one index shape, no generics.
- ``RatchetOutcome(violations, advanced, transitions)`` — the verdict.
  ``advanced`` is true iff the diff was clean (sticky-advance semantics,
  §3.5.2); *writing* the new baseline on a clean diff is the caller's job.
- ``canonical_digest(violations)`` — sha256 over the composite-sorted
  tab-joined 7-tuple lines (§3.5.3 NORMATIVE (canonical violation digest)).

Raw-value sourcing (candidate_value for the digest)
-----------------------------------------------------
§3.5.3 requires the digest's ``candidate_value`` to be "the raw document
string exactly as served — never re-formatted". This engine has no access
to the served KDL text (that lives at the parse-at-gate seam A2d owns) and
`registry.IndexVersion` — deliberately, per A2a — retains only typed values,
not raw source text. Reopening A2a to retrofit raw-string retention is out
of this slice's scope.

The resolution: ``RawField`` carries the typed ``value`` (used for
dominance comparison) **and** an independent ``raw`` string (used for the
digest) as two separate, caller-supplied pieces of data. The caller that
builds an ``IndexState`` from a real index — A2d's parse-at-gate seam, which
has the literal document text in hand — supplies ``raw`` explicitly.
``RawField.raw_str()`` falls back to ``str(value)`` only when ``raw`` is
omitted, as a convenience for hand-built test fixtures; production callers
MUST pass the literal raw text.

Full enforcement (registry-protocol §3.5.1 NORMATIVE (staged enforcement))
------------------------------------------------------------------------------
The lattice has been complete in this module from day one — every order kind
and every field's transition logic was implemented and directly testable
before its enforcement went live. The last two rows to gain enforcement, the
attestation record (``attestation`` — attestation-monotone) and the
``rekor`` block (frozen/set-once), plus the ``attestation-epoch`` root field
(also set-once), landed at `rfc-registry-append-only.md`'s A6 slice, once
Part 2's P2 parser change made their inputs parse-to-typed. As of A6 every
row in ``LATTICE`` is live in ``Baseline.check()`` unconditionally — there is
no longer a staged/full distinction to select between.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum

# ---------------------------------------------------------------------------
# Order-kind tags (registry-protocol §3.5.1) — five DISJOINT tags. A
# conformant fold MUST NOT share one tag between two English-synonymous but
# structurally distinct orders (e.g. attestation-monotone vs
# ordinal-non-decreasing both read as "monotone" in prose; they are
# deliberately separate tags here).
# ---------------------------------------------------------------------------


class OrderKind(Enum):
    SET_ONCE = "set-once"
    ATTESTATION_MONOTONE = "attestation-monotone"
    APPEND_ONLY_MULTISET = "append-only-multiset"
    ADVISORY_MUTABLE = "advisory-mutable"
    ORDINAL_NON_DECREASING = "ordinal-non-decreasing"


# ---------------------------------------------------------------------------
# Violation classes (§3.5.3) and sub-class "kind" discriminators.
#
# These are plain string constants, not yet declared in ``errors.py``: the
# raise-site-in-same-change norm (RFC A2 slug-staging note) means A2d adds
# them to ``errors.py`` when it adds the raise site, not this slice.
# ---------------------------------------------------------------------------

ROOT_MUTATED = "TNG-INDEX-ROOT-MUTATED"
ROLLBACK = "TNG-INDEX-ROLLBACK"
ENTRY_MUTATED = "TNG-ENTRY-MUTATED"

_CLASS_RANK: dict[str, int] = {ROOT_MUTATED: 0, ROLLBACK: 1, ENTRY_MUTATED: 2}

#: Closed set (§3.5.3 NORMATIVE (structured payload)).
FROZEN_CHANGED = "frozen-changed"
FROZEN_UNSET = "frozen-unset"
MONOTONE_STRIPPED = "monotone-stripped"
MONOTONE_REATTRIBUTED = "monotone-reattributed"
MONOTONE_DOWNGRADED = "monotone-downgraded"
MONOTONE_REPINNED = "monotone-repinned"
PROVENANCE_REMOVED = "provenance-removed"
ROOT_FIELD_CHANGED = "root-field-changed"


# ---------------------------------------------------------------------------
# Entry key (§3.5.1 NORMATIVE (entry key))
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EntryKey:
    """``(namespace, name, raw version string)`` — the entry key.

    Keying on the raw version string (not a parsed/normalized ``Version``)
    means a cosmetic re-spelling is a disappearance-plus-appearance under
    this key, caught as rollback, not silently matched (§3.5.1).
    """

    namespace: str
    name: str
    version: str


#: The reserved empty key document-root fields fold under (§3.5.1
#: NORMATIVE (root-level fields)) — exactly the key §3.5.3's composite
#: ordering already assigns root violations.
ROOT_KEY = EntryKey(namespace="", name="", version="")


# ---------------------------------------------------------------------------
# Input shape: RawField / RatchetEntry / IndexState
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawField:
    """One field's value on one entry snapshot (baseline OR candidate side).

    ``value`` is the typed value used for dominance comparison. ``None`` is
    the canonical absent sentinel for EVERY order kind — callers MUST
    normalize domain-specific empties (e.g. ``IndexVersion.content_hash ==
    ""``) to ``None`` before constructing a ``RatchetEntry``.

    ``raw`` is the "raw document string exactly as served" the canonical
    digest requires (see module docstring, "Raw-value sourcing"). Falls
    back to ``str(value)`` via ``raw_str()`` when omitted.
    """

    value: object = None
    raw: str | None = None

    def raw_str(self) -> str:
        """The digest-ready raw string: ``""`` when absent, else ``raw`` or
        ``str(value)``."""
        if self.value is None:
            return ""
        if self.raw is not None:
            return self.raw
        return str(self.value)


@dataclass(frozen=True)
class RatchetEntry:
    """One entry's (or the reserved root pseudo-entry's) field snapshot.

    ``fields`` maps field name -> ``RawField``. A field absent from the dict
    is equivalent to an explicit ``RawField()`` (value ``None``) — the
    lattice fold is agnostic to which fields "belong" to root vs a normal
    entry; a field that is structurally irrelevant to this entry kind is
    simply always-absent-on-both-sides and never produces a violation.
    """

    fields: dict[str, RawField] = field(default_factory=dict)

    def get(self, name: str) -> RawField:
        return self.fields.get(name, RawField())


#: A parsed index state: every observed entry key (INCLUDING the reserved
#: ``ROOT_KEY`` for document-root fields, if any are set) mapped to its
#: field snapshot.
IndexState = dict[EntryKey, RatchetEntry]


# ---------------------------------------------------------------------------
# Attestation value shape (for the attestation-monotone field; §3.5.1).
# Structural comparison only — no crypto, no verification state.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestationValue:
    """Structural snapshot of an ``EntryAttestation`` for ratchet comparison.

    ``kind`` is ``"author-signed"`` or ``"milpa-vendored"``. ``signer`` is
    ``None`` for vendored (the parser never stores a per-entry signer for
    that kind — registry.py's ``MilpaVendored`` carries none by design).
    """

    kind: str
    signer: str | None = None
    bundle_pin: str | None = None


# ---------------------------------------------------------------------------
# Violations, transitions, outcome
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Violation:
    """``(class, entry_key, field, kind, baseline_value, candidate_value)``
    (§3.5.3 NORMATIVE (structured payload)).

    ``baseline_value`` / ``candidate_value`` are the raw-string forms
    (``RawField.raw_str()``) — ``candidate_value`` is what the canonical
    digest hashes; ``baseline_value`` rides the payload for human display
    only and is deliberately excluded from the digest.
    """

    class_: str
    entry_key: EntryKey
    field: str
    kind: str
    baseline_value: str
    candidate_value: str


@dataclass(frozen=True)
class Transition:
    """A legal advisory-mutable transition surfaced for the caller (A5) to
    report — never a violation, never blocks ``advanced`` (§3.5.3 NORMATIVE
    (yank-transition notices are not errors))."""

    entry_key: EntryKey
    kind: str  # "yank"
    direction: str  # "yanked" | "unyanked"
    reason: str | None = None


@dataclass(frozen=True)
class RatchetOutcome:
    """``Baseline.check(candidate) -> RatchetOutcome`` — the verdict.

    Monomorphic (no ``Baseline[T]`` generics): one index shape, one outcome
    shape. ``violations`` IS the verdict; ``advanced`` is true iff
    ``violations`` is empty (sticky-advance, §3.5.2) — *writing* the
    advanced baseline is the caller's job, this module only reports.
    ``transitions`` carries legal yank-state changes (§3.5.3) for A5.
    """

    violations: list[Violation]
    advanced: bool
    transitions: list[Transition] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations


# ---------------------------------------------------------------------------
# The lattice (registry-protocol §3.5.1's table, transcribed as data).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldSpec:
    kind: OrderKind


#: NOTE: ``dep_decl`` / ``dep_decl_schema_version`` are NOT listed here —
#: they move in lockstep (§3.5.1) and are handled as one composite field via
#: ``LOCKSTEP_GROUPS`` below, reported under the primary name ``"dep_decl"``.
LATTICE: dict[str, FieldSpec] = {
    # --- Frozen / set-once (entry-level) ---
    "content_hash": FieldSpec(OrderKind.SET_ONCE),
    "published_at": FieldSpec(OrderKind.SET_ONCE),
    "rekor": FieldSpec(OrderKind.SET_ONCE),
    # --- Attestation-monotone (entry-level) ---
    "attestation": FieldSpec(OrderKind.ATTESTATION_MONOTONE),
    # --- Append-only-multiset (entry-level) ---
    "provenances": FieldSpec(OrderKind.APPEND_ONLY_MULTISET),
    # --- Advisory-mutable (entry-level) — never violates; yank transitions
    #     are surfaced separately (see _yank_transition), never through this
    #     dispatch table.
    "yanked": FieldSpec(OrderKind.ADVISORY_MUTABLE),
    # --- Root fields (document-level, reserved empty key) ---
    "schema_version": FieldSpec(OrderKind.ORDINAL_NON_DECREASING),
    "attestation-epoch": FieldSpec(OrderKind.SET_ONCE),
}

#: Field groups that move in lockstep (§3.5.1: "``dep_decl`` **together
#: with** ``dep_decl_schema_version``" — mutating one alone is a violation
#: even though neither, read alone, "changed" from a legal prior value).
#: Reported under the group's first member's name.
LOCKSTEP_GROUPS: tuple[tuple[str, ...], ...] = (("dep_decl", "dep_decl_schema_version"),)


# ---------------------------------------------------------------------------
# Per-order-kind dominance functions. Each takes (baseline_value,
# candidate_value) and returns a violation "kind" string, or ``None`` if
# legal. These operate on typed values (``RawField.value``), never raw
# strings — raw strings are purely a digest-rendering concern.
# ---------------------------------------------------------------------------


def _dominates_set_once(baseline: object, candidate: object) -> str | None:
    if baseline is None:
        return None  # absent -> anything: legal, exactly once per baseline
    if candidate is None:
        return FROZEN_UNSET
    if candidate != baseline:
        return FROZEN_CHANGED
    return None


def _dominates_ordinal(baseline: object, candidate: object) -> str | None:
    # absent ≡ spec default 1 (§3.5.1 root-field table, schema_version row)
    b = 1 if baseline is None else baseline
    c = 1 if candidate is None else candidate
    if c < b:  # type: ignore[operator]
        return ROOT_FIELD_CHANGED
    return None


def _dominates_attestation(baseline: object, candidate: object) -> str | None:
    b, c = baseline, candidate
    if b is None:
        return None  # None -> anything: legal (backfill/upgrade)
    if c is None:
        return MONOTONE_STRIPPED
    assert isinstance(b, AttestationValue) and isinstance(c, AttestationValue)
    if b.kind == c.kind:
        if b.kind == "author-signed" and b.signer != c.signer:
            return MONOTONE_REATTRIBUTED
        # same kind (and, for author-signed, same signer): the bundle pin
        # must be structurally equal — a same-kind pin swap is a violation.
        if b.bundle_pin != c.bundle_pin:
            return MONOTONE_REPINNED
        return None
    if b.kind == "author-signed" and c.kind == "milpa-vendored":
        return MONOTONE_DOWNGRADED
    return None  # milpa-vendored -> author-signed: upgrade, legal


def _dominates_multiset(baseline: object, candidate: object) -> str | None:
    b_items: Sequence[object] = baseline or ()  # type: ignore[assignment]
    c_items: Sequence[object] = candidate or ()  # type: ignore[assignment]
    b_counts = Counter(b_items)
    c_counts = Counter(c_items)
    for item, count in b_counts.items():
        if c_counts.get(item, 0) < count:
            return PROVENANCE_REMOVED
    return None


def _dominates_advisory(baseline: object, candidate: object) -> str | None:
    return None  # everything comparable, both directions legal


def _lockstep_raw(entry: RatchetEntry, group: tuple[str, ...]) -> str:
    """The lockstep group's closed-field-set rendering (§3.5.3 NORMATIVE
    (lockstep-group candidate_value is a closed-field-set record, not its
    first member)): the group's raw values, in declared order, joined by
    ``\\x1f`` — the same method §3.5.3 already uses for ``attestation``/
    ``rekor`` (single-element closed-field-set records). Rendering from
    ONLY the first member (``dep_decl``) would leave ``candidate_value``
    blind to a violation whose sole change is a later group member (e.g.
    ``dep_decl_schema_version``), masking a genuinely new mutation as a
    recurring one under §3.5.2's warn-mode digest comparison."""
    return "\x1f".join(entry.get(f).raw_str() for f in group)


_DISPATCH: dict[OrderKind, Callable[[object, object], str | None]] = {
    OrderKind.SET_ONCE: _dominates_set_once,
    OrderKind.ORDINAL_NON_DECREASING: _dominates_ordinal,
    OrderKind.ATTESTATION_MONOTONE: _dominates_attestation,
    OrderKind.APPEND_ONLY_MULTISET: _dominates_multiset,
    OrderKind.ADVISORY_MUTABLE: _dominates_advisory,
}


# ---------------------------------------------------------------------------
# The generic dominance fold (§3.5.1 NORMATIVE (dominance fold)): ONE
# function over field/order-kind tags. Root-vs-entry is a data difference
# (which fields happen to be populated on this entry, and whether the
# entry key is the reserved ``ROOT_KEY``) — not a second code path.
# ---------------------------------------------------------------------------


def _dominates_entry(
    key: EntryKey,
    baseline_entry: RatchetEntry,
    candidate_entry: RatchetEntry,
) -> list[Violation]:
    is_root = key == ROOT_KEY
    cls = ROOT_MUTATED if is_root else ENTRY_MUTATED
    violations: list[Violation] = []

    for group in LOCKSTEP_GROUPS:
        b_vals = tuple(baseline_entry.get(f).value for f in group)
        c_vals = tuple(candidate_entry.get(f).value for f in group)
        b_composite = b_vals if any(v is not None for v in b_vals) else None
        c_composite = c_vals if any(v is not None for v in c_vals) else None
        kind = _dominates_set_once(b_composite, c_composite)
        if kind is not None:
            reported = ROOT_FIELD_CHANGED if is_root else kind
            violations.append(
                Violation(
                    class_=cls,
                    entry_key=key,
                    field=group[0],
                    kind=reported,
                    baseline_value=_lockstep_raw(baseline_entry, group),
                    candidate_value=_lockstep_raw(candidate_entry, group),
                )
            )

    for field_name, spec in LATTICE.items():
        b_field = baseline_entry.get(field_name)
        c_field = candidate_entry.get(field_name)
        kind = _DISPATCH[spec.kind](b_field.value, c_field.value)
        if kind is not None:
            reported = ROOT_FIELD_CHANGED if is_root else kind
            violations.append(
                Violation(
                    class_=cls,
                    entry_key=key,
                    field=field_name,
                    kind=reported,
                    baseline_value=b_field.raw_str(),
                    candidate_value=c_field.raw_str(),
                )
            )

    return violations


def _rollback_violation(key: EntryKey) -> Violation:
    """Presence dominance failure (§3.5.1): a baseline entry key with no
    candidate counterpart. Presence is tagged Frozen alongside the ordinary
    fields, so this reuses ``frozen-unset``'s shape (value existed, now
    gone) rather than inventing a new kind; ``field=""`` denotes the
    entry's own presence dimension, not a named field (mirroring the
    reserved-empty-key convention used at the entry-key level)."""
    return Violation(
        class_=ROLLBACK,
        entry_key=key,
        field="",
        kind=FROZEN_UNSET,
        baseline_value="present",
        candidate_value="",
    )


def _yank_transition(
    key: EntryKey, baseline_entry: RatchetEntry, candidate_entry: RatchetEntry
) -> Transition | None:
    b = bool(baseline_entry.get("yanked").value)
    c = bool(candidate_entry.get("yanked").value)
    if b == c:
        return None
    if c:
        reason = candidate_entry.get("yanked_reason").value
        return Transition(entry_key=key, kind="yank", direction="yanked", reason=reason)  # type: ignore[arg-type]
    reason = baseline_entry.get("yanked_reason").value
    return Transition(entry_key=key, kind="yank", direction="unyanked", reason=reason)  # type: ignore[arg-type]


def _sort_key(v: Violation) -> tuple[int, str, str, str, str]:
    """§3.5.3 NORMATIVE (ordering and precedence): composite key
    ``(class_rank, namespace, name, version, field)``."""
    return (
        _CLASS_RANK[v.class_],
        v.entry_key.namespace,
        v.entry_key.name,
        v.entry_key.version,
        v.field,
    )


# ---------------------------------------------------------------------------
# Baseline — the public engine entry point.
# ---------------------------------------------------------------------------


class Baseline:
    """Wraps a baseline ``IndexState``. ``.check(candidate)`` diffs it
    against a candidate state and returns a ``RatchetOutcome``.

    Pure and side-effect-free: does not mutate ``self.state``, does not
    touch the filesystem. Sticky-advance (§3.5.2) is a *caller* concern —
    the caller decides whether/when to replace its stored baseline with the
    candidate, using ``outcome.advanced``; this engine only reports.
    """

    def __init__(self, state: IndexState):
        self.state = state

    def check(self, candidate: IndexState) -> RatchetOutcome:
        violations: list[Violation] = []
        transitions: list[Transition] = []

        root_baseline = self.state.get(ROOT_KEY, RatchetEntry())
        root_candidate = candidate.get(ROOT_KEY, RatchetEntry())
        violations.extend(_dominates_entry(ROOT_KEY, root_baseline, root_candidate))

        for key, b_entry in self.state.items():
            if key == ROOT_KEY:
                continue
            if key not in candidate:
                violations.append(_rollback_violation(key))
                continue
            c_entry = candidate[key]
            violations.extend(_dominates_entry(key, b_entry, c_entry))
            transition = _yank_transition(key, b_entry, c_entry)
            if transition is not None:
                transitions.append(transition)

        violations.sort(key=_sort_key)
        return RatchetOutcome(violations=violations, advanced=not violations, transitions=transitions)


# ---------------------------------------------------------------------------
# Canonical violation digest (§3.5.3 NORMATIVE (canonical violation digest))
# ---------------------------------------------------------------------------


def canonical_digest(violations: list[Violation]) -> str:
    """sha256 over the UTF-8 concatenation of one ``\\n``-terminated,
    tab-joined line per violation, in composite-key order:
    ``(class, namespace, name, version, field, kind, candidate_value)``.
    ``baseline_value`` is deliberately excluded (the baseline is frozen
    while violations persist, so it adds no discriminating information)."""
    ordered = sorted(violations, key=_sort_key)
    lines = []
    for v in ordered:
        row = (
            v.class_,
            v.entry_key.namespace,
            v.entry_key.name,
            v.entry_key.version,
            v.field,
            v.kind,
            v.candidate_value,
        )
        lines.append("\t".join(row) + "\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()
