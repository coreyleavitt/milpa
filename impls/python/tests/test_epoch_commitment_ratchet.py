"""Tests for the `attestation-epoch-commitment` root field's ratchet wiring
(S-EpochCommitment sub-slice 2: registry-protocol §3.5.1 R12, D16).

Verifies: the new field parses via `index_ratchet_seam.build_index_state`,
carries its own `OrderKind.APPEND_ONCE` row (distinct from the legacy
`attestation-epoch`'s `SET_ONCE`), and arming it alongside an UNCHANGED
`attestation-epoch` does NOT trip `TNG-INDEX-ROOT-MUTATED` (the D16 concern).
"""

from __future__ import annotations

from milpa.index_ratchet_seam import build_index_state
from milpa.ratchet import ROOT_KEY, Baseline, OrderKind, LATTICE

SCHEMA_HEADER = "schema_version 1\n"


def test_lattice_has_append_once_row_for_commitment_field() -> None:
    assert LATTICE["attestation-epoch-commitment"].kind is OrderKind.APPEND_ONCE
    assert LATTICE["attestation-epoch"].kind is OrderKind.SET_ONCE
    assert OrderKind.APPEND_ONCE is not OrderKind.SET_ONCE


def test_commitment_pointer_surfaces_on_root_state() -> None:
    text = SCHEMA_HEADER + 'attestation-epoch-commitment "' + "a" * 64 + '"\n'
    _index, state = build_index_state(text)
    root = state[ROOT_KEY]
    assert root.get("attestation-epoch-commitment").value == "a" * 64


def test_absent_commitment_pointer_is_none() -> None:
    _index, state = build_index_state(SCHEMA_HEADER)
    root = state[ROOT_KEY]
    assert root.get("attestation-epoch-commitment").value is None


def test_arming_from_absent_is_clean() -> None:
    baseline_text = SCHEMA_HEADER
    candidate_text = SCHEMA_HEADER + 'attestation-epoch-commitment "' + "b" * 64 + '"\n'
    _idx, baseline_state = build_index_state(baseline_text)
    _idx2, candidate_state = build_index_state(candidate_text)
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.clean, outcome.violations


def test_changing_an_already_armed_commitment_is_a_violation() -> None:
    baseline_text = SCHEMA_HEADER + 'attestation-epoch-commitment "' + "a" * 64 + '"\n'
    candidate_text = SCHEMA_HEADER + 'attestation-epoch-commitment "' + "b" * 64 + '"\n'
    _idx, baseline_state = build_index_state(baseline_text)
    _idx2, candidate_state = build_index_state(candidate_text)
    outcome = Baseline(baseline_state).check(candidate_state)
    assert not outcome.clean
    assert outcome.violations[0].class_ == "TNG-INDEX-ROOT-MUTATED"
    assert outcome.violations[0].field == "attestation-epoch-commitment"


def test_arming_commitment_alongside_unchanged_epoch_is_clean() -> None:
    """D16: arming the NEW field must not disturb the legacy, unchanged
    `attestation-epoch` field's set-once state — the two fields are
    independent root rows."""
    baseline_text = SCHEMA_HEADER + 'attestation-epoch "E1"\n'
    candidate_text = (
        SCHEMA_HEADER + 'attestation-epoch "E1"\n' + 'attestation-epoch-commitment "' + "c" * 64 + '"\n'
    )
    _idx, baseline_state = build_index_state(baseline_text)
    _idx2, candidate_state = build_index_state(candidate_text)
    outcome = Baseline(baseline_state).check(candidate_state)
    assert outcome.clean, outcome.violations


def test_changing_attestation_epoch_alone_still_trips_root_mutated() -> None:
    """Sanity: the legacy field's own set-once enforcement is untouched by
    this change."""
    baseline_text = SCHEMA_HEADER + 'attestation-epoch "E1"\n'
    candidate_text = SCHEMA_HEADER + 'attestation-epoch "E2"\n'
    _idx, baseline_state = build_index_state(baseline_text)
    _idx2, candidate_state = build_index_state(candidate_text)
    outcome = Baseline(baseline_state).check(candidate_state)
    assert not outcome.clean
    assert outcome.violations[0].field == "attestation-epoch"
