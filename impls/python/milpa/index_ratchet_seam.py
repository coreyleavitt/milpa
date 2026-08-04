"""index-history ratchet seam — bridges parsed KDL text to ``milpa.ratchet``'s
``IndexState``, and decides what the index-cache gate should do with the
result (registry-protocol §3.5.2/§3.5.3, ``rfc-registry-append-only.md``
slice A2d).

This module is **pure computation**: it never touches the filesystem.
``milpa.index_cache`` owns every read and write (the sidecar layout, the
unique-temp-name atomic writer, the four-state freshness cache); this module
answers "what does this text parse to" and "what should happen given a
policy, a candidate, and an optional baseline" as data (or a raised
``MilpaError``), and ``index_cache.py`` acts on the answer. This mirrors
``ratchet.py``'s own "no I/O" discipline one layer up.

Two responsibilities:

1. **Raw-as-served extraction** (``build_index_state``) — ``ratchet.py``'s
   docstring explains why the engine can't build its own ``IndexState``:
   ``registry.IndexVersion`` retains only typed values, never the literal
   document text the §3.5.3 canonical digest requires. This module re-walks
   the parsed KDL document (via the SAME validated, typed ``Index`` that
   ``registry.parse_index`` already produces — single source of truth for
   structural validation) to pair each field's typed value with its raw
   served string where the two can diverge: ``published_at`` (per-entry) and
   ``attestation-epoch`` (root) need the re-walk; every other lattice field
   — ``content_hash``, ``dep_decl``(+ schema version), ``schema_version``,
   ``yanked``(+reason) — is already a string/int/bool whose ``str()``
   round-trips losslessly, and ``attestation``/``rekor`` get their own
   canonical (never ``str()``/``repr()``) rendering per §3.5.3 NORMATIVE
   (canonical rendering for non-scalar candidate values) — see
   ``_attestation_canonical_raw`` / ``_rekor_canonical_raw`` below, live as
   of A6 alongside the ``attestation``/``rekor``/``attestation-epoch`` rows'
   enforcement (registry-protocol §3.5.1 NORMATIVE (staged enforcement)).

   ``build_index_state`` IS the parse-at-gate seam: call it (directly, or
   via ``evaluate_gate``) BEFORE any cache mutation. A raised ``MilpaError``
   here means the candidate never touches the cache.

2. **The gate decision** (``evaluate_gate``) — TOFU establishment, the
   sticky-advance clean/dirty branch, warn's new-vs-recurring habituation
   defense, and strict's hard-fail. Returns a ``GateDecision`` the caller
   acts on: which bytes (if any) to write to the baseline sidecar, what to
   write to ``.baseline.meta``, and what (if anything) to print to stderr.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, datetime

from milpa.errors import TNG_INDEX_BASELINE_CORRUPT as _BASELINE_CORRUPT
from milpa.errors import TNG_SCHEMA_UNKNOWN, MilpaError
from milpa.kdl_io import (
    KdlDocument,
    node_arg_str,
    node_args,
    node_children,
    node_name,
    nodes,
    parse_kdl,
    value_as_int,
)
from milpa.ratchet import (
    ROOT_KEY,
    AttestationValue,
    Baseline,
    EntryKey,
    IndexState,
    RatchetEntry,
    RawField,
    Transition,
    Violation,
    canonical_digest,
)
from milpa.registry import (
    AuthorSigned,
    EntryAttestation,
    GitIndexProvenance,
    Index,
    OciIndexProvenance,
    RekorRef,
    _validate_no_control_chars,
    parse_index,
)

# ---------------------------------------------------------------------------
# Candidate/baseline text -> (typed Index, ratchet IndexState)
# ---------------------------------------------------------------------------


def build_index_state(text: str) -> tuple[Index, IndexState]:
    """Parse *text* (already UTF-8-decoded index bytes) into both the typed,
    validated ``Index`` (``registry.parse_index`` — raises the usual
    ``TNG-*`` codes on malformed input) and the ratchet ``IndexState``.

    This IS the parse-at-gate seam (registry-protocol §3.5.2 NORMATIVE (the
    check)): an exception here means the candidate is never written to the
    cache — the caller must not have touched disk yet.
    """
    index = parse_index(text)
    doc = parse_kdl(text, context="registry")
    return index, _index_state_from(doc, index)


def _provenance_canonical_raw(provenances: tuple[object, ...]) -> str:
    """Canonical, cross-impl-identical rendering of a provenance multiset for
    the §3.5.3 canonical violation digest (NORMATIVE (canonical rendering
    for non-scalar candidate values)) — the MUST-RESOLVE item flagged at A3:
    a naive ``str(value)``/``repr(value)`` fallback renders Python
    dataclasses one way and Rust's ``Debug`` derive another way, for
    identical semantic content. Each record is encoded as
    ``<kind>\\x1f<field1>\\x1f<field2>\\x1f<field3>[\\x1f<field4>]`` in the
    record's own declared field order (git: url, ref, commit_sha; oci:
    registry, repository, digest, source; an absent optional field renders
    as the empty string); records are sorted lexicographically by their own
    encoding (never by document position — order is advisory-mutable,
    §3.5.1) and joined with ``\\x1e``. The ``oci`` instantiation's ``source``
    field was added closing the digest-collision gap tracked at
    registry-protocol §3.5.3 (two violations differing only in ``source``
    used to hash identically). Mirrors
    ``index_ratchet_seam.rs::provenance_canonical_raw`` byte-for-byte."""
    encoded: list[str] = []
    for p in provenances:
        if isinstance(p, GitIndexProvenance):
            encoded.append("git\x1f" + p.url + "\x1f" + p.ref + "\x1f" + (p.commit_sha or ""))
        elif isinstance(p, OciIndexProvenance):
            encoded.append(
                "oci\x1f"
                + p.registry
                + "\x1f"
                + p.repository
                + "\x1f"
                + p.digest
                + "\x1f"
                + (p.source_url or "")
            )
        else:  # pragma: no cover — parse_index never constructs other kinds (§3.3)
            encoded.append("unrecognized\x1f" + repr(p))
    encoded.sort()
    return "\x1e".join(encoded)


def _attestation_canonical_raw(attestation: EntryAttestation | None) -> str:
    """Canonical, cross-impl-identical rendering of an ``EntryAttestation``
    for the §3.5.3 canonical violation digest (NORMATIVE (canonical
    rendering for non-scalar candidate values), the ``attestation``
    instantiation, live as of A6): a single closed field set — ``kind``,
    ``signer`` (``author-signed`` only, ``""`` for ``milpa-vendored``),
    ``bundle_pin`` (``""`` when unset) — encoded as
    ``<kind>\\x1f<signer>\\x1f<bundle_pin>``. ``""`` when *attestation* is
    absent, consistent with the scalar-field absent-component convention.
    Mirrors ``index_ratchet_seam.rs::attestation_canonical_raw`` byte-for-byte."""
    if attestation is None:
        return ""
    if isinstance(attestation.kind, AuthorSigned):
        kind, signer = "author-signed", attestation.kind.signer
    else:
        kind, signer = "milpa-vendored", ""
    return kind + "\x1f" + signer + "\x1f" + (attestation.bundle_pin or "")


def _attestation_typed_value(attestation: EntryAttestation | None) -> AttestationValue | None:
    """``EntryAttestation`` -> ``ratchet.AttestationValue`` structural
    snapshot (dominance-comparison shape; ``ratchet.py`` stays
    registry-agnostic, so this conversion lives at the seam)."""
    if attestation is None:
        return None
    if isinstance(attestation.kind, AuthorSigned):
        return AttestationValue(kind="author-signed", signer=attestation.kind.signer, bundle_pin=attestation.bundle_pin)
    return AttestationValue(kind="milpa-vendored", signer=None, bundle_pin=attestation.bundle_pin)


def _rekor_canonical_raw(rekor: RekorRef | None) -> str:
    """Canonical rendering of the ``rekor`` block for the canonical
    violation digest (§3.5.3 NORMATIVE (canonical rendering for non-scalar
    candidate values) — the ``rekor`` instantiation, live as of A6): the
    same closed-field-set method, field order ``uuid``, ``log_index``,
    ``integrated_time``, joined by ``\\x1f``. ``""`` when *rekor* is absent.
    Mirrors ``index_ratchet_seam.rs::rekor_canonical_raw`` byte-for-byte."""
    if rekor is None:
        return ""
    return rekor.uuid + "\x1f" + rekor.log_index + "\x1f" + rekor.integrated_time


def _index_state_from(doc: KdlDocument, index: Index) -> IndexState:
    state: IndexState = {
        ROOT_KEY: RatchetEntry(
            fields={
                "schema_version": RawField(value=_raw_schema_version(doc)),
                "attestation-epoch": RawField(value=_raw_attestation_epoch(doc)),
                "attestation-epoch-commitment": RawField(
                    value=_raw_attestation_epoch_commitment(doc)
                ),
            }
        ),
    }

    raw_published_at = _collect_raw_published_at(doc)
    for pkg in index.packages:
        for iv in pkg.versions:
            key = EntryKey(namespace=iv.namespace, name=pkg.name, version=iv.version)
            rekor = iv.attestation.rekor if iv.attestation is not None else None
            state[key] = RatchetEntry(
                fields={
                    "content_hash": RawField(value=iv.content_hash or None),
                    "published_at": RawField(
                        value=iv.published_at,
                        raw=raw_published_at.get((iv.namespace, pkg.name, iv.version)),
                    ),
                    "dep_decl": RawField(value=iv.dep_decl),
                    "dep_decl_schema_version": RawField(value=iv.dep_decl_schema_version),
                    "provenances": RawField(
                        value=iv.provenances, raw=_provenance_canonical_raw(iv.provenances)
                    ),
                    "yanked": RawField(value=iv.yanked),
                    "yanked_reason": RawField(value=iv.yanked_reason),
                    "attestation": RawField(
                        value=_attestation_typed_value(iv.attestation),
                        raw=_attestation_canonical_raw(iv.attestation),
                    ),
                    "rekor": RawField(value=rekor, raw=_rekor_canonical_raw(rekor)),
                }
            )
    return state


def _raw_schema_version(doc: KdlDocument) -> int | None:
    """The document-root ``schema_version`` integer, or ``None`` if absent
    (the ordinal-non-decreasing dominance function treats ``None`` as the
    spec default ``1`` — registry-protocol §3.5.1 root-field table)."""
    for n in nodes(doc):
        if node_name(n) != "schema_version":
            continue
        args = node_args(n)
        return value_as_int(args[0]) if args else None
    return None


def _raw_attestation_epoch(doc: KdlDocument) -> str | None:
    """The document-root ``attestation-epoch`` string, or ``None`` if absent
    (`rfc-per-entry-attestation.md` open question 2; registry-protocol
    §3.5.1 root-field table — set-once, live as of A6). An opaque epoch
    identifier: no reformatting margin, so the typed value doubles as its
    own raw digest rendering (the scalar-field convention above).

    This is a document-root field ``registry.parse_index`` never surfaces
    (it isn't part of any ``package`` node, so ``parse_index``'s own charset
    pass never sees it) — this re-walk is the ONLY site that extracts it, so
    it is ALSO the only site that can charset-check it. Same
    ``TNG-UNSAFE-CONTROL-CHAR`` guard ``parse_index`` applies to every other
    free-text field (registry-protocol §3.3 NORMATIVE): unchecked, a control
    character here would inject straight into the root pseudo-entry's
    canonical violation digest row (§3.5.3) and the ``accept``/``status``
    diff text, exactly like an unguarded ``content_hash`` or ``name``.
    """
    for n in nodes(doc):
        if node_name(n) != "attestation-epoch":
            continue
        args = node_args(n)
        if not args:
            return None
        epoch = node_arg_str(n, 0)
        if epoch is not None:
            _validate_no_control_chars(epoch, "attestation-epoch")
        return epoch
    return None


def _raw_attestation_epoch_commitment(doc: KdlDocument) -> str | None:
    """The document-root ``attestation-epoch-commitment`` string, or ``None``
    if absent (registry-protocol §3.4.8's typed pointer / §3.5.1's
    ``Append-once`` root-field row, R12 — S-EpochCommitment,
    ``rfc-attestation-v1-normative.md`` §6, D16). A *new*, separate root
    field from the legacy ``attestation-epoch`` timestamp — see
    ``_raw_attestation_epoch``'s docstring and D16: re-typing that existing
    field's shape would trip ``TNG-INDEX-ROOT-MUTATED`` for every consumer
    with an established baseline the moment a registry re-arms, so this is
    a sibling field with its own ``OrderKind.APPEND_ONCE`` row instead.

    Like ``attestation-epoch``, this field is not part of any ``package``
    node, so ``registry.parse_index``'s own charset pass never sees it —
    this re-walk is the only site that extracts it, so it is also the only
    site that can charset-check it (registry-protocol §3.3 NORMATIVE).
    """
    for n in nodes(doc):
        if node_name(n) != "attestation-epoch-commitment":
            continue
        args = node_args(n)
        if not args:
            return None
        pointer = node_arg_str(n, 0)
        if pointer is not None:
            _validate_no_control_chars(pointer, "attestation-epoch-commitment")
        return pointer
    return None


def _collect_raw_published_at(doc: KdlDocument) -> dict[tuple[str, str, str], str]:
    """``(namespace, name, version) -> raw served text`` of each version's
    ``published_at`` child. Mirrors ``registry._parse_versions``'s
    first-occurrence-wins duplicate handling so keys line up with the
    validated ``Index`` this is paired against — a deliberate, narrow
    re-walk (raw-string capture is a different concern from typed parsing;
    see the module docstring)."""
    out: dict[tuple[str, str, str], str] = {}
    for top in nodes(doc):
        if node_name(top) != "package":
            continue
        name = node_arg_str(top, 0)
        if name is None:
            continue
        namespace = ""
        for child in node_children(top):
            if node_name(child) == "namespace":
                namespace = node_arg_str(child, 0) or ""
                break
        seen: set[str] = set()
        for child in node_children(top):
            if node_name(child) != "version":
                continue
            ver = node_arg_str(child, 0)
            if ver is None or ver in seen:
                continue
            seen.add(ver)
            for vchild in node_children(child):
                if node_name(vchild) == "published_at":
                    raw = node_arg_str(vchild, 0)
                    if raw is not None:
                        out[(namespace, name, ver)] = raw
                    break
    return out


# ---------------------------------------------------------------------------
# Baseline parse — corruption maps to TNG-INDEX-BASELINE-CORRUPT, never a
# raw parse slug (registry-protocol §3.5.2 NORMATIVE (baseline corruption
# is not TOFU)).
# ---------------------------------------------------------------------------


def parse_baseline(text: str) -> IndexState:
    try:
        _, state = build_index_state(text)
    except MilpaError as exc:
        hint = ""
        if exc.slug == TNG_SCHEMA_UNKNOWN:
            hint = " (possible version skew — baseline was written by a newer milpa)"
        raise MilpaError(
            _BASELINE_CORRUPT,
            f"baseline sidecar is unparseable or truncated{hint}; "
            "re-establish the trust anchor via `milpa index accept`",
        ) from exc
    return state


# ---------------------------------------------------------------------------
# .baseline.meta — advisory (registry-protocol §3.5.2 NORMATIVE: missing or
# stale relative to .baseline self-heals to "unset", never an error).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BaselineMeta:
    established_at: str | None = None
    reported_digest: str | None = None
    reported_at: str | None = None

    def render(self) -> str:
        lines = []
        if self.established_at is not None:
            lines.append(f'established_at "{self.established_at}"')
        if self.reported_digest is not None:
            lines.append(f'reported_digest "{self.reported_digest}"')
        if self.reported_at is not None:
            lines.append(f'reported_at "{self.reported_at}"')
        return ("\n".join(lines) + "\n") if lines else ""


def parse_baseline_meta(text: str) -> BaselineMeta:
    """Best-effort parse of ``.baseline.meta``. NEVER raises — any
    corruption self-heals to an unset reported-set."""
    try:
        doc = parse_kdl(text, context="registry")
    except MilpaError:
        return BaselineMeta()

    def _top(name: str) -> str | None:
        for n in nodes(doc):
            if node_name(n) == name:
                return node_arg_str(n, 0)
        return None

    return BaselineMeta(
        established_at=_top("established_at"),
        reported_digest=_top("reported_digest"),
        reported_at=_top("reported_at"),
    )


def iso_timestamp(now_unix: int) -> str:
    return datetime.fromtimestamp(now_unix, tz=UTC).isoformat()


# ---------------------------------------------------------------------------
# The gate decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GateDecision:
    """What ``index_cache.py`` should do after a successful gate evaluation.

    ``index`` is always populated (parse-at-gate's typed result) so the
    caller never re-parses. ``advance`` says whether to write a NEW
    baseline (only on a clean diff or TOFU establishment — sticky-advance,
    §3.5.2). ``new_meta`` is what to (over)write to ``.baseline.meta``;
    ``None`` means leave the existing file untouched (the *recurring*-warn
    case, and the ``off``-policy no-op case). ``warn_message`` is
    pre-formatted stderr text for the caller to print AFTER the ordinary
    warn-path writes complete (bundle/index/stamp — matching the existing
    warn-serves-the-new-index convention elsewhere in this module); ``None``
    means nothing to print.
    """

    index: Index
    advance: bool
    new_meta: BaselineMeta | None
    warn_message: str | None = None


def evaluate_gate(
    *,
    policy: str,
    candidate_text: str,
    baseline_text: str | None,
    existing_meta: BaselineMeta,
    now_unix: int,
    url: str,
) -> GateDecision:
    """The full §3.5.2 decision, given already-read baseline/meta text
    (``baseline_text`` is ``None`` exactly when the baseline sidecar is
    absent, i.e. TOFU). Touches no filesystem I/O.

    This function is NOT entirely stdout/stderr-free: it prints
    yank-transition notices (``_print_yank_notice``) directly and
    immediately, because registry-protocol §3.5.3 requires those to fire
    "under ``warn`` and ``strict`` alike" — including the ``strict`` path
    below, which raises before ever returning a ``GateDecision``, so there
    is no later "caller prints it" point to defer to for that one
    diagnostic. Every OTHER diagnostic is pure data, not a direct print:
    the warn-path violation message is returned via
    ``GateDecision.warn_message`` for the caller to print AFTER the
    ordinary warn-path writes complete (see ``GateDecision``'s docstring);
    the strict-path message rides the raised ``MilpaError`` itself, for
    whatever prints that error.

    Raises ``MilpaError``:
      - the ordinary ``TNG-*`` parse/validation slug if *candidate_text*
        doesn't parse (parse-at-gate — happens regardless of *policy*);
      - ``TNG-INDEX-BASELINE-CORRUPT`` if *baseline_text* is present but
        unparseable (regardless of *policy*, except ``off`` never reaches
        this branch since it never reads the baseline);
      - the primary violation's slug (``TNG-INDEX-ROOT-MUTATED`` /
        ``TNG-INDEX-ROLLBACK`` / ``TNG-ENTRY-MUTATED``) under ``strict``.

    In every raising case the caller MUST NOT have written anything to the
    cache yet (registry-protocol §3.5.2 NORMATIVE (the check) / per-policy
    ``strict`` row: "no cache mutation at all").
    """
    index, candidate_state = build_index_state(candidate_text)  # parse-at-gate

    if policy == "off":
        return GateDecision(index=index, advance=False, new_meta=None)

    if baseline_text is None:
        # TOFU: first contact ever for this URL — nothing to diff, nothing
        # to alarm on. Establishes the trust anchor.
        meta = BaselineMeta(established_at=iso_timestamp(now_unix))
        return GateDecision(index=index, advance=True, new_meta=meta)

    baseline_state = parse_baseline(baseline_text)  # may raise BASELINE-CORRUPT
    outcome = Baseline(baseline_state).check(candidate_state)

    for transition in outcome.transitions:
        _print_yank_notice(transition)

    if outcome.clean:
        # `or` (not `is None`) is deliberate: an empty-string
        # ``established_at`` (hand-corrupted meta, or a pre-this-fix write)
        # self-heals the same as an absent one, rather than freezing the
        # corruption in place forever. Rust mirrors this via `.filter(|s|
        # !s.is_empty())` (`index_ratchet_seam.rs`).
        meta = BaselineMeta(
            established_at=existing_meta.established_at or iso_timestamp(now_unix),
            reported_digest=None,
            reported_at=None,
        )
        return GateDecision(index=index, advance=True, new_meta=meta)

    digest = canonical_digest(outcome.violations)
    recurring = digest == existing_meta.reported_digest
    message = _format_violation_message(
        outcome.violations, digest, recurring=recurring, reported_at=existing_meta.reported_at
    )

    if policy == "strict":
        raise MilpaError(
            outcome.violations[0].class_,
            message,
            violations=[_violation_payload(v) for v in outcome.violations],
            digest=digest,
            url=url,
        )

    # warn: serve the new index (bundle/index/stamp advance as usual); the
    # baseline itself stays sticky (advance=False); .meta only rewrites on
    # a NEW digest (habituation defense — §3.5.2 NORMATIVE (per-policy
    # behavior), the "warn" row). The diagnostic itself is NOT printed here
    # — it rides back as `warn_message` for the caller (`index_cache.py`'s
    # `_apply_ratchet_writes`) to print AFTER the writes below complete.
    new_meta = (
        None
        if recurring
        else BaselineMeta(
            established_at=existing_meta.established_at,
            reported_digest=digest,
            reported_at=iso_timestamp(now_unix),
        )
    )
    return GateDecision(index=index, advance=False, new_meta=new_meta, warn_message=message)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def _print_yank_notice(t: Transition) -> None:
    """§3.5.3 NORMATIVE (yank-transition notices are not errors): fires
    under ``warn`` and ``strict`` alike, never affects the exit code, never
    blocks the baseline from advancing."""
    coord = f"{t.entry_key.namespace}/{t.entry_key.name}@{t.entry_key.version}"
    reason = f" ({t.reason})" if t.reason else ""
    print(
        f"[milpa] warning: yank-state changed: {coord} — {t.direction}{reason}",
        file=sys.stderr,
    )


def _violation_payload(v: Violation) -> dict[str, str]:
    return {
        "class": v.class_,
        "namespace": v.entry_key.namespace,
        "name": v.entry_key.name,
        "version": v.entry_key.version,
        "field": v.field,
        "kind": v.kind,
        "baseline_value": v.baseline_value,
        "candidate_value": v.candidate_value,
    }


def _format_violation_message(
    violations: list[Violation], digest: str, *, recurring: bool, reported_at: str | None
) -> str:
    """Human-readable diagnostic. Message wording is NOT byte-normative
    (only the slug + structured payload are); both the required remediation
    hints (§3.5.3 NORMATIVE (remediation hints required)) are always
    present."""
    primary = violations[0]
    coord = (
        "<document root>"
        if primary.entry_key == ROOT_KEY
        else f"{primary.entry_key.namespace}/{primary.entry_key.name}@{primary.entry_key.version}"
    )
    field_part = f" field={primary.field!r}" if primary.field else ""
    lines = [
        f"[milpa] warning: index-history violation ({primary.class_}) "
        f"at {coord}{field_part}: {primary.kind}"
    ]
    if len(violations) > 1:
        lines.append(f"  ...and {len(violations) - 1} more violation(s) in this diff")
    if recurring:
        lines.append(
            f"  recurring (first reported {reported_at or 'unknown'}); digest unchanged: {digest}"
        )
    else:
        lines.append(f"  digest={digest}")
    lines.append(
        "  remedy: revert the mutation upstream, or run `milpa index accept` "
        "after out-of-band confirmation that this history rewrite is legitimate"
    )
    return "\n".join(lines)
