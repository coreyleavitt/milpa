"""Tests for milpa.ratchet — A2b (rfc-registry-append-only.md).

Pure in-memory: no filesystem, no fetchers, no tmpdirs. Hand-builds
``IndexState`` values and exercises ``Baseline.check()`` directly against
the registry-protocol §3.5.1/§3.5.3 lattice and digest rules.

Covers:
  - Clean append advances the baseline.
  - Presence dominance (rollback: version disappearance).
  - Set-once (Frozen) fields: mutation, unset, and the one-legal-backfill
    transition, including the ``dep_decl``/``dep_decl_schema_version``
    lockstep group.
  - Ordinal-non-decreasing root field (``schema_version``), incl.
    absent ≡ spec default 1.
  - Attestation-monotone lattice + ``rekor`` frozen row (A6: live by
    default, no staging flag).
  - Append-only-multiset provenance (append legal; in-place mutation caught
    as removal).
  - Advisory-mutable yank triple: transitions, never violations.
  - Root-field fold under the reserved empty key, incl. the
    ``attestation-epoch`` vs ``schema_version`` tie-break.
  - Composite ordering (the spec's worked example).
  - Canonical violation digest: hand-computed vector, remutation changes
    it, baseline_value changes do not.
"""

from __future__ import annotations

import hashlib

from milpa.ratchet import (
    ENTRY_MUTATED,
    FROZEN_CHANGED,
    FROZEN_UNSET,
    MONOTONE_DOWNGRADED,
    MONOTONE_REATTRIBUTED,
    MONOTONE_REPINNED,
    MONOTONE_STRIPPED,
    PROVENANCE_REMOVED,
    ROLLBACK,
    ROOT_FIELD_CHANGED,
    ROOT_KEY,
    ROOT_MUTATED,
    AttestationValue,
    Baseline,
    EntryKey,
    RatchetEntry,
    RawField,
    Violation,
    canonical_digest,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def entry(**fields: object) -> RatchetEntry:
    """Build a ``RatchetEntry`` from plain values — wraps each in a
    ``RawField`` for ergonomic test construction."""
    return RatchetEntry(fields={k: RawField(v) for k, v in fields.items()})


def raw_entry(fields: dict[str, RawField]) -> RatchetEntry:
    return RatchetEntry(fields=dict(fields))


V1 = EntryKey(namespace="acme", name="foo", version="1.0.0")
V2 = EntryKey(namespace="acme", name="foo", version="2.0.0")


# ---------------------------------------------------------------------------
# Clean append advances
# ---------------------------------------------------------------------------


def test_clean_append_advances() -> None:
    baseline_state = {V1: entry(content_hash="sha256:" + "a" * 64)}
    candidate_state = {
        V1: entry(content_hash="sha256:" + "a" * 64),
        V2: entry(content_hash="sha256:" + "b" * 64),
    }
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []
    assert outcome.advanced is True


def test_frozen_backfill_is_legal() -> None:
    """absent -> value is the sanctioned one-time Frozen transition."""
    baseline_state = {V1: entry(content_hash=None)}
    candidate_state = {V1: entry(content_hash="sha256:" + "a" * 64)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []
    assert outcome.advanced is True


# ---------------------------------------------------------------------------
# Presence dominance — rollback
# ---------------------------------------------------------------------------


def test_removed_version_is_rollback_violation() -> None:
    baseline_state = {
        V1: entry(content_hash="sha256:" + "a" * 64),
        V2: entry(content_hash="sha256:" + "b" * 64),
    }
    candidate_state = {V1: entry(content_hash="sha256:" + "a" * 64)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.advanced is False
    assert len(outcome.violations) == 1
    v = outcome.violations[0]
    assert v.class_ == ROLLBACK
    assert v.entry_key == V2
    assert v.field == ""
    assert v.kind == FROZEN_UNSET
    assert v.candidate_value == ""


# ---------------------------------------------------------------------------
# Set-once (Frozen) fields
# ---------------------------------------------------------------------------


def test_set_once_field_mutated_is_violation() -> None:
    baseline_state = {V1: entry(content_hash="sha256:" + "a" * 64)}
    candidate_state = {V1: entry(content_hash="sha256:" + "c" * 64)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.advanced is False
    assert len(outcome.violations) == 1
    v = outcome.violations[0]
    assert v.class_ == ENTRY_MUTATED
    assert v.field == "content_hash"
    assert v.kind == FROZEN_CHANGED
    assert v.baseline_value == "sha256:" + "a" * 64
    assert v.candidate_value == "sha256:" + "c" * 64


def test_set_once_field_unset_is_violation() -> None:
    baseline_state = {V1: entry(content_hash="sha256:" + "a" * 64)}
    candidate_state = {V1: entry(content_hash=None)}
    outcome = Baseline(baseline_state).check(candidate_state)
    v = outcome.violations[0]
    assert v.kind == FROZEN_UNSET
    assert v.candidate_value == ""


def test_dep_decl_lockstep_group_backfill_legal() -> None:
    baseline_state = {V1: entry(dep_decl=None, dep_decl_schema_version=None)}
    candidate_state = {V1: entry(dep_decl="sha256:" + "d" * 64, dep_decl_schema_version=1)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


def test_dep_decl_schema_version_alone_changing_is_violation() -> None:
    """§3.5.1: mutating the schema version alone re-interprets the pin —
    a violation even though ``dep_decl`` itself did not change."""
    baseline_state = {V1: entry(dep_decl="sha256:" + "d" * 64, dep_decl_schema_version=1)}
    candidate_state = {V1: entry(dep_decl="sha256:" + "d" * 64, dep_decl_schema_version=2)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    v = outcome.violations[0]
    assert v.field == "dep_decl"
    assert v.kind == FROZEN_CHANGED
    assert v.class_ == ENTRY_MUTATED


# ---------------------------------------------------------------------------
# Ordinal-non-decreasing root field (schema_version)
# ---------------------------------------------------------------------------


def test_schema_version_regression_is_violation() -> None:
    baseline_state = {ROOT_KEY: entry(schema_version=2)}
    candidate_state = {ROOT_KEY: entry(schema_version=1)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.advanced is False
    v = outcome.violations[0]
    assert v.class_ == ROOT_MUTATED
    assert v.entry_key == ROOT_KEY
    assert v.field == "schema_version"
    assert v.kind == ROOT_FIELD_CHANGED


def test_schema_version_equal_is_clean() -> None:
    baseline_state = {ROOT_KEY: entry(schema_version=2)}
    candidate_state = {ROOT_KEY: entry(schema_version=2)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


def test_schema_version_absent_is_default_one() -> None:
    # absent (None) on both sides ≡ 1 == 1: clean.
    outcome = Baseline({ROOT_KEY: entry()}).check({ROOT_KEY: entry()})
    assert outcome.violations == []

    # baseline explicit 1, candidate absent (≡1): clean (no decrease).
    outcome = Baseline({ROOT_KEY: entry(schema_version=1)}).check({ROOT_KEY: entry()})
    assert outcome.violations == []

    # baseline explicit 2, candidate absent (≡1): decrease, violation.
    outcome = Baseline({ROOT_KEY: entry(schema_version=2)}).check({ROOT_KEY: entry()})
    assert len(outcome.violations) == 1
    assert outcome.violations[0].kind == ROOT_FIELD_CHANGED

    # baseline absent (≡1), candidate explicit 2: increase, legal.
    outcome = Baseline({ROOT_KEY: entry()}).check({ROOT_KEY: entry(schema_version=2)})
    assert outcome.violations == []


# ---------------------------------------------------------------------------
# Attestation-monotone + rekor frozen row — live as of A6 (registry-protocol
# §3.5.1 NORMATIVE (staged enforcement); rfc-registry-append-only.md A6).
# Pre-A6 these rows were tagged staged=True and excluded from
# Baseline.check() by default, checkable only via a since-removed
# include_staged=True escape hatch. A6 removed the staging flag entirely
# (clean cutover, no dead parameter) — the assertions below, un-gated, ARE
# the inversion of that pre-A6 posture.
# ---------------------------------------------------------------------------


def test_attestation_strip_is_violation() -> None:
    """A6 inversion: pre-A6 this stayed silently unenforced (staged=True);
    live as of A6, a stripped attestation IS a violation."""
    baseline_state = {V1: entry(attestation=AttestationValue(kind="milpa-vendored"))}
    candidate_state = {V1: entry(attestation=None)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    assert outcome.violations[0].kind == MONOTONE_STRIPPED


def test_attestation_upgrades_are_legal() -> None:
    for baseline_val, candidate_val in [
        (None, AttestationValue(kind="milpa-vendored")),
        (None, AttestationValue(kind="author-signed", signer="alice")),
        (
            AttestationValue(kind="milpa-vendored"),
            AttestationValue(kind="author-signed", signer="alice"),
        ),
    ]:
        baseline_state = {V1: entry(attestation=baseline_val)}
        candidate_state = {V1: entry(attestation=candidate_val)}
        outcome = Baseline(baseline_state).check(candidate_state)
        assert outcome.violations == [], (baseline_val, candidate_val)


def test_attestation_reattribution_is_violation() -> None:
    baseline_state = {V1: entry(attestation=AttestationValue(kind="author-signed", signer="alice"))}
    candidate_state = {V1: entry(attestation=AttestationValue(kind="author-signed", signer="bob"))}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    assert outcome.violations[0].kind == MONOTONE_REATTRIBUTED


def test_attestation_downgrade_is_violation() -> None:
    baseline_state = {V1: entry(attestation=AttestationValue(kind="author-signed", signer="alice"))}
    candidate_state = {V1: entry(attestation=AttestationValue(kind="milpa-vendored"))}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    assert outcome.violations[0].kind == MONOTONE_DOWNGRADED


def test_attestation_repin_is_violation() -> None:
    baseline_state = {
        V1: entry(attestation=AttestationValue(kind="author-signed", signer="alice", bundle_pin="p1"))
    }
    candidate_state = {
        V1: entry(attestation=AttestationValue(kind="author-signed", signer="alice", bundle_pin="p2"))
    }
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    assert outcome.violations[0].kind == MONOTONE_REPINNED


def test_attestation_vendored_signer_rotation_unconstrained() -> None:
    """MilpaVendored -> MilpaVendored is unconstrained (bug ratchet, not a
    security boundary) — no signer is tracked for vendored at all."""
    baseline_state = {V1: entry(attestation=AttestationValue(kind="milpa-vendored"))}
    candidate_state = {V1: entry(attestation=AttestationValue(kind="milpa-vendored"))}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


def test_rekor_backfill_is_legal() -> None:
    baseline_state = {V1: entry(rekor=None)}
    candidate_state = {V1: entry(rekor=("uuid-1", "1", "1000"))}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


def test_rekor_mutated_is_violation() -> None:
    """A6: the rekor block is Frozen/set-once — a later mutation of a
    previously-set rekor reference (not merely backfilling an absent one)
    is caught, just like content_hash."""
    baseline_state = {V1: entry(rekor=("uuid-1", "1", "1000"))}
    candidate_state = {V1: entry(rekor=("uuid-2", "2", "2000"))}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    v = outcome.violations[0]
    assert v.field == "rekor"
    assert v.kind == FROZEN_CHANGED


def test_rekor_unset_is_violation() -> None:
    baseline_state = {V1: entry(rekor=("uuid-1", "1", "1000"))}
    candidate_state = {V1: entry(rekor=None)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations[0].kind == FROZEN_UNSET


# ---------------------------------------------------------------------------
# Append-only-multiset provenance
# ---------------------------------------------------------------------------


def test_provenance_append_is_legal() -> None:
    baseline_state = {V1: entry(provenances=(("git", "url1", "ref1", "sha1"),))}
    candidate_state = {
        V1: entry(provenances=(("git", "url1", "ref1", "sha1"), ("git", "url2", "ref1", "sha1")))
    }
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


def test_provenance_in_place_mutation_is_removal_violation() -> None:
    baseline_state = {V1: entry(provenances=(("git", "url1", "ref1", "sha1"),))}
    candidate_state = {V1: entry(provenances=(("git", "url1", "ref1", "sha-mutated"),))}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    v = outcome.violations[0]
    assert v.field == "provenances"
    assert v.kind == PROVENANCE_REMOVED


def test_provenance_reorder_is_legal() -> None:
    baseline_state = {
        V1: entry(provenances=(("git", "url1", "ref1", "sha1"), ("git", "url2", "ref1", "sha1")))
    }
    candidate_state = {
        V1: entry(provenances=(("git", "url2", "ref1", "sha1"), ("git", "url1", "ref1", "sha1")))
    }
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


# ---------------------------------------------------------------------------
# Advisory-mutable yank triple — transitions, never violations
# ---------------------------------------------------------------------------


def test_yank_transition_is_surfaced_not_a_violation() -> None:
    baseline_state = {V1: entry(yanked=False)}
    candidate_state = {V1: entry(yanked=True, yanked_reason="CVE-2026-0001")}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []
    assert outcome.advanced is True
    assert len(outcome.transitions) == 1
    t = outcome.transitions[0]
    assert t.entry_key == V1
    assert t.direction == "yanked"
    assert t.reason == "CVE-2026-0001"


def test_unyank_transition_carries_baseline_reason() -> None:
    baseline_state = {V1: entry(yanked=True, yanked_reason="CVE-2026-0001")}
    candidate_state = {V1: entry(yanked=False, yanked_reason=None)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []
    t = outcome.transitions[0]
    assert t.direction == "unyanked"
    assert t.reason == "CVE-2026-0001"


def test_no_yank_change_is_no_transition() -> None:
    baseline_state = {V1: entry(yanked=False)}
    candidate_state = {V1: entry(yanked=False)}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.transitions == []


# ---------------------------------------------------------------------------
# Root-field fold under the reserved empty key
# ---------------------------------------------------------------------------


def test_root_fields_fold_under_reserved_empty_key_with_tiebreak() -> None:
    """The RFC's own worked example (root-vs-root tie): both
    ``attestation-epoch`` and ``schema_version`` violate in the same
    candidate — composite ordering breaks the rank/entry-key tie (both rank
    0, both the reserved empty key) on the trailing ``field`` component.
    Live unconditionally as of A6 — no ``include_staged`` escape hatch."""
    baseline_state = {ROOT_KEY: entry(schema_version=2, **{"attestation-epoch": "E1"})}
    candidate_state = {ROOT_KEY: entry(schema_version=1, **{"attestation-epoch": "E2"})}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.advanced is False
    assert len(outcome.violations) == 2
    # both rank 0 (ROOT_MUTATED), both empty entry key -> tie broken by
    # field name: "attestation-epoch" < "schema_version".
    assert [v.field for v in outcome.violations] == ["attestation-epoch", "schema_version"]
    assert all(v.class_ == ROOT_MUTATED for v in outcome.violations)
    assert all(v.entry_key == ROOT_KEY for v in outcome.violations)
    assert all(v.kind == ROOT_FIELD_CHANGED for v in outcome.violations)


def test_attestation_epoch_set_once() -> None:
    """A6 inversion: pre-A6 this row was silently unenforced by default;
    live as of A6, a changed attestation-epoch IS a violation."""
    baseline_state = {ROOT_KEY: raw_entry({"attestation-epoch": RawField("E1")})}
    candidate_state = {ROOT_KEY: raw_entry({"attestation-epoch": RawField("E2")})}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 1
    assert outcome.violations[0].field == "attestation-epoch"
    assert outcome.violations[0].kind == ROOT_FIELD_CHANGED


def test_attestation_epoch_backfill_is_legal() -> None:
    baseline_state = {ROOT_KEY: raw_entry({"attestation-epoch": RawField(None)})}
    candidate_state = {ROOT_KEY: raw_entry({"attestation-epoch": RawField("E1")})}
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.violations == []


# ---------------------------------------------------------------------------
# Composite ordering — the spec's worked example
# ---------------------------------------------------------------------------


def test_composite_ordering_worked_example() -> None:
    """package `aaa` has a frozen-field mutation, package `zzz` has a
    version disappearance in the same diff -> reported slug/primary is
    TNG-INDEX-ROLLBACK (rank wins over alphabetical position); `aaa`'s
    mutation still appears in the payload (registry-protocol §3.5.3)."""
    aaa = EntryKey(namespace="ns", name="aaa", version="1.0.0")
    zzz = EntryKey(namespace="ns", name="zzz", version="1.0.0")
    baseline_state = {
        aaa: entry(content_hash="sha256:" + "a" * 64),
        zzz: entry(content_hash="sha256:" + "b" * 64),
    }
    candidate_state = {
        aaa: entry(content_hash="sha256:" + "c" * 64),
        # zzz is absent from the candidate: rollback
    }
    outcome = Baseline(baseline_state).check(candidate_state)
    assert len(outcome.violations) == 2
    first, second = outcome.violations
    assert first.class_ == ROLLBACK
    assert first.entry_key == zzz
    assert second.class_ == ENTRY_MUTATED
    assert second.entry_key == aaa


# ---------------------------------------------------------------------------
# Canonical violation digest
# ---------------------------------------------------------------------------


def test_canonical_digest_hand_computed_vector() -> None:
    v = Violation(
        class_=ENTRY_MUTATED,
        entry_key=EntryKey(namespace="acme", name="foo", version="1.0.0"),
        field="content_hash",
        kind=FROZEN_CHANGED,
        baseline_value="sha256:" + "a" * 64,
        candidate_value="sha256:" + "c" * 64,
    )
    expected_line = (
        "TNG-ENTRY-MUTATED\tacme\tfoo\t1.0.0\tcontent_hash\tfrozen-changed\t"
        "sha256:" + "c" * 64 + "\n"
    )
    expected = hashlib.sha256(expected_line.encode("utf-8")).hexdigest()
    assert canonical_digest([v]) == expected


def test_canonical_digest_multi_violation_vector_matches_composite_order() -> None:
    aaa = EntryKey(namespace="ns", name="aaa", version="1.0.0")
    zzz = EntryKey(namespace="ns", name="zzz", version="1.0.0")
    entry_violation = Violation(
        class_=ENTRY_MUTATED,
        entry_key=aaa,
        field="content_hash",
        kind=FROZEN_CHANGED,
        baseline_value="sha256:" + "a" * 64,
        candidate_value="sha256:" + "c" * 64,
    )
    rollback_violation = Violation(
        class_=ROLLBACK,
        entry_key=zzz,
        field="",
        kind=FROZEN_UNSET,
        baseline_value="present",
        candidate_value="",
    )
    expected = hashlib.sha256(
        (
            "TNG-INDEX-ROLLBACK\tns\tzzz\t1.0.0\t\tfrozen-unset\t\n"
            "TNG-ENTRY-MUTATED\tns\taaa\t1.0.0\tcontent_hash\tfrozen-changed\t"
            + "sha256:" + "c" * 64 + "\n"
        ).encode("utf-8")
    ).hexdigest()
    # order given to canonical_digest need not be pre-sorted — it sorts.
    assert canonical_digest([entry_violation, rollback_violation]) == expected


def test_digest_changes_on_remutation_of_same_field() -> None:
    key = EntryKey(namespace="acme", name="foo", version="1.0.0")
    v2 = Violation(
        class_=ENTRY_MUTATED,
        entry_key=key,
        field="content_hash",
        kind=FROZEN_CHANGED,
        baseline_value="sha256:" + "a" * 64,
        candidate_value="sha256:" + "b" * 64,  # V2
    )
    v3 = Violation(
        class_=ENTRY_MUTATED,
        entry_key=key,
        field="content_hash",
        kind=FROZEN_CHANGED,
        baseline_value="sha256:" + "a" * 64,
        candidate_value="sha256:" + "c" * 64,  # V3 — a second mutation
    )
    assert canonical_digest([v2]) != canonical_digest([v3])


def test_digest_unaffected_by_baseline_value_change() -> None:
    key = EntryKey(namespace="acme", name="foo", version="1.0.0")
    v_a = Violation(
        class_=ENTRY_MUTATED,
        entry_key=key,
        field="content_hash",
        kind=FROZEN_CHANGED,
        baseline_value="sha256:" + "a" * 64,
        candidate_value="sha256:" + "c" * 64,
    )
    v_b = Violation(
        class_=ENTRY_MUTATED,
        entry_key=key,
        field="content_hash",
        kind=FROZEN_CHANGED,
        baseline_value="sha256:" + "z" * 64,  # different baseline_value
        candidate_value="sha256:" + "c" * 64,  # same candidate_value
    )
    assert canonical_digest([v_a]) == canonical_digest([v_b])
