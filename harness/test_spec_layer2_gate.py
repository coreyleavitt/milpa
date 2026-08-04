"""Tests for the S2 spec-prose slice (RFC `docs/rfc-attestation-v1-normative.md`,
slice S2 — R3.5/R4/R12/R13 in its §5 reconciliation-deltas table; D9/D10/D14-D18).

S2 is spec-only. It authors, in `spec/registry-protocol.md`:

  (A) R3.5/D10 — a new generic "verification-gate model" section (§3.3a) that
      factors, once, the axis-generic invariants both the whole-index gate
      (§3.4) and the new per-entry gate (§3.6) share: parse-before-crypto
      ordering, the TOCTOU single-read invariant, delegate-not-hand-roll,
      first-failing-stage-wins precedence, subject-binding-precedes-crypto.
  (B) R3.5 — §3.4 reduced to instantiate §3.3a rather than restating it.
  (C) R4 — a new §3.6 "Per-entry attestation gate (Layer 2)": when it fires,
      the 8-stage pipeline / TNG-ENTRY-* outcome mapping, subject-binding
      cardinality exactly 1 (D3), the `EntryGateOutcome` diagnostic type (D9)
      carrying `EpochMembership` (D14).
  (D) R4/D14-D18 — an index-scoped epoch-commitment phase (§3.4.8/§3.4.9, NOT
      inside §3.6): `EpochCommitmentStatus` (Unarmed/Armed(S,E)/ArmingInvalid),
      the enumerated committed set `S` (D17), `identity ∈ S` membership, the
      `milpa-preepoch-v1:` domain-separated commitment hash (D16), the sidecar
      delivery (D15/R13), the new set-once `attestation-epoch-commitment`
      field with its own Append-once `OrderKind` row (R12), and the D18
      co-requirement (arming under `entry-trust=strict` requires
      `index-history=strict`, else a config error).
  (E) R4 — the NORMATIVE cross-axis precedence sentence: index-trust
      (including the epoch-commitment phase) strictly precedes entry-trust;
      `TNG-INDEX-*` and `TNG-ENTRY-*` never co-occur.
  (F) Wire-ups: §3.4's cross-reference to §3.6; the §3.4.0 SSOT table's
      `entry-trust` Normative-home column now points at this document's §3.6
      (not `rfc-per-entry-attestation.md §4`); the default-value column is
      UNCHANGED (still `warn` — S4 flips it).

This module does not test gate *behavior* (nothing is built in this slice) —
only that the normative surface exists, is coherent, and is internally
cross-referenced (§3.4 and §3.6 both point at §3.3a; §3.6 reads
`EpochCommitmentStatus` from §3.4.8).

Run with:
    python3 -m pytest harness/test_spec_layer2_gate.py
    python3 -m unittest harness.test_spec_layer2_gate   # alternative
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_REGISTRY_PROTOCOL = _REPO_ROOT / "spec" / "registry-protocol.md"


def _flow_join(text: str) -> str:
    """Collapse markdown blockquote line-wrapping (`"...\\n> ..."`) into a
    single flowing string, mirroring `test_spec_attestation_reconcile.py`."""
    return re.sub(r"\n>\s?", " ", text)


def _section(text: str, heading_pattern: str) -> str:
    """Return the body of the first section whose heading line matches
    `heading_pattern` (a regex applied per-line, unanchored), up to (but not
    including) the next heading of the SAME OR SHALLOWER level. `text` must
    be the raw (non-flow-joined) markdown so heading lines are still
    identifiable by their leading `#`s."""
    lines = text.splitlines()
    start = None
    level = None
    for i, line in enumerate(lines):
        m = re.match(r"^(#{2,6})\s+(.*)$", line)
        if m and re.search(heading_pattern, line):
            start = i
            level = len(m.group(1))
            break
    if start is None:
        raise AssertionError(f"no heading matched {heading_pattern!r}")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        m = re.match(r"^(#{2,6})\s+", lines[j])
        if m and len(m.group(1)) <= level:
            end = j
            break
    return "\n".join(lines[start:end])


class TestLayer2GateNormativeSurface(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _REGISTRY_PROTOCOL.read_text(encoding="utf-8")
        cls.text = _flow_join(cls.raw)

    # -- (A)/(B): generic gate-model section, referenced by both axes -------

    def test_generic_gate_model_heading_exists(self) -> None:
        self.assertRegex(
            self.raw,
            re.compile(r"^###\s+3\.3a\s+.*[Vv]erification-gate model", re.MULTILINE),
            "expected a §3.3a generic verification-gate model heading",
        )

    def test_generic_model_states_shared_invariants(self) -> None:
        body = _section(self.raw, r"3\.3a")
        for phrase in (
            "parse-before-crypto",
            "TOCTOU",
            "delegate-not-hand-roll",
            "first-failing-stage-wins",
            "subject-binding-precedes-crypto",
        ):
            self.assertIn(
                phrase,
                body,
                msg=f"§3.3a is missing the shared invariant phrase {phrase!r}",
            )

    def test_section_3_4_references_generic_model(self) -> None:
        body = _section(self.raw, r"###\s+3\.4\s")
        self.assertIn(
            "§3.3a",
            _flow_join(body),
            msg="§3.4 (index gate) must instantiate/reference §3.3a, not restate it",
        )

    def test_section_3_6_references_generic_model(self) -> None:
        body = _section(self.raw, r"###\s+3\.6\s")
        self.assertIn(
            "§3.3a",
            _flow_join(body),
            msg="§3.6 (entry gate) must instantiate/reference §3.3a",
        )

    # -- (C): §3.6 per-entry gate --------------------------------------------

    def test_section_3_6_heading_exists(self) -> None:
        self.assertRegex(
            self.raw,
            re.compile(r"^###\s+3\.6\s+.*[Pp]er-entry attestation gate", re.MULTILINE),
            "expected a §3.6 'Per-entry attestation gate (Layer 2)' heading",
        )

    def test_section_3_6_states_subject_cardinality_exactly_one(self) -> None:
        body = _flow_join(_section(self.raw, r"###\s+3\.6\s"))
        self.assertIn(
            "exactly 1",
            body,
            msg="§3.6 must state subject cardinality is exactly 1 (D3)",
        )
        self.assertIn("cardinality", body)

    def test_section_3_6_registry_source_only(self) -> None:
        body = _flow_join(_section(self.raw, r"###\s+3\.6\s"))
        self.assertIn("RES-REGISTRY-SHADOW", body)

    def test_entry_gate_outcome_type_defined(self) -> None:
        self.assertIn("EntryGateOutcome", self.text)

    def test_epoch_membership_type_defined(self) -> None:
        self.assertIn("EpochMembership", self.text)
        self.assertIn("PreEpoch", self.text)
        self.assertIn("PostEpoch", self.text)

    # -- (D): index-scoped epoch-commitment phase ----------------------------

    def test_epoch_commitment_status_type_defined(self) -> None:
        self.assertIn("EpochCommitmentStatus", self.text)
        for variant in ("Unarmed", "Armed", "ArmingInvalid"):
            self.assertIn(variant, self.text)

    def test_epoch_commitment_phase_not_inside_section_3_6(self) -> None:
        """§3.6 may REFERENCE EpochCommitmentStatus (it reads the phase's
        output) but must not itself DEFINE the type (D14: that prose is
        index-scoped, §3.4.8) — check for the defining `= ... Unarmed` type
        block, not the bare name."""
        body_36 = _section(self.raw, r"###\s+3\.6\s")
        self.assertNotIn(
            "EpochCommitmentStatus =",
            body_36,
            msg=(
                "EpochCommitmentStatus's type DEFINITION is index-scoped "
                "(D14) — it belongs under §3.4, not inside §3.6"
            ),
        )

    def test_enumerated_set_membership_language_present(self) -> None:
        self.assertIn(
            "identity ∈ S",
            self.text,
            msg="expected the D17 enumerated-set membership notation 'identity ∈ S'",
        )

    def test_domain_separation_prefix_present(self) -> None:
        self.assertIn("milpa-preepoch-v1:", self.text)

    def test_identity_tuple_present(self) -> None:
        self.assertIn("namespace, name, version, content_hash", self.text)

    def test_new_slug_epoch_commitment_invalid_present(self) -> None:
        self.assertIn("TNG-INDEX-EPOCH-COMMITMENT-INVALID", self.text)

    def test_sidecar_delivery_section_exists(self) -> None:
        self.assertRegex(
            self.raw,
            re.compile(r"^####\s+3\.4\.\d+\s+.*[Ss]idecar", re.MULTILINE),
            "expected a §3.4.x subsection specifying the commitment sidecar acquisition (R13)",
        )

    def test_order_kind_row_for_new_field(self) -> None:
        self.assertIn("attestation-epoch-commitment", self.text)
        self.assertIn("Append-once", self.text)

    def test_d18_co_requirement_present(self) -> None:
        body = self.text
        self.assertIn("co-requirement", body)
        self.assertIn("index-history", body)
        self.assertIn(
            "MUST also be `strict`",
            body,
            msg="expected the D18 co-requirement wording (arming under "
            "entry-trust=strict requires index-history=strict)",
        )
        self.assertIn("configuration error", body)

    def test_d18_does_not_change_index_history_default(self) -> None:
        self.assertIn(
            "does NOT change",
            self.text,
            msg="D18 must state explicitly this is a coupling invariant, not a default flip",
        )

    # -- (E): cross-axis precedence ------------------------------------------

    def test_cross_axis_precedence_sentence_present(self) -> None:
        self.assertIn("strictly precedes entry-trust", self.text)
        self.assertIn("never co-occur", self.text)

    # -- (F): wire-ups --------------------------------------------------------

    def test_ssot_table_entry_trust_normative_home_updated(self) -> None:
        # The SSOT table row is identified by its member-error slug, which is
        # unique and stable across this edit.
        line = next(
            (
                l
                for l in self.raw.splitlines()
                if "WS-ENTRY-TRUST-ON-MEMBER" in l and "|" in l
            ),
            None,
        )
        self.assertIsNotNone(line, "expected the entry-trust SSOT table row")
        assert line is not None
        self.assertIn("§3.6", line)
        self.assertNotIn(
            "rfc-per-entry-attestation.md",
            line,
            msg="entry-trust's normative home must now be this document's §3.6",
        )
        # The default-value column reads `strict` as of S4 (the flip). Strip a
        # leading blockquote marker (`> | ... |`) before splitting into cells.
        row = line.strip()
        if row.startswith(">"):
            row = row[1:].strip()
        cells = [c.strip() for c in row.strip("|").split("|")]
        # cells: axis, manifest node(s), env var, default, member-error slug, normative home
        self.assertEqual(
            cells[3],
            "`strict`",
            msg="S4 flipped the entry-trust default column to `strict`",
        )


class TestLayer2VerificationAlgorithm(unittest.TestCase):
    """S3 (RFC `docs/rfc-attestation-v1-normative.md` §6 slice S3, R4 cont.,
    D3): the per-step verification-algorithm detail extending §3.6.2's stage
    table — placed at a new §3.6.2a, mirroring §3.4.4's role for the
    whole-index axis. Does not re-test §3.6.2's stage table/slug mapping
    (already pinned above) or §3.3a's shared invariants — only the NEW
    per-step crypto prose and the reconciled stage-5-7 ordering text."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = _REGISTRY_PROTOCOL.read_text(encoding="utf-8")
        cls.text = _flow_join(cls.raw)

    def _algorithm_body(self) -> str:
        return _flow_join(_section(self.raw, r"3\.6\.2a"))

    def test_algorithm_subsection_heading_exists(self) -> None:
        self.assertRegex(
            self.raw,
            re.compile(
                r"^####\s+3\.6\.2a\s+.*[Vv]erification algorithm", re.MULTILINE
            ),
            "expected a §3.6.2a per-bundle verification algorithm heading",
        )

    def test_algorithm_nested_under_section_3_6(self) -> None:
        body_36 = _flow_join(_section(self.raw, r"###\s+3\.6\s"))
        self.assertIn(
            "3.6.2a",
            body_36,
            msg="§3.6.2a must be nested inside §3.6, not a sibling top-level section",
        )

    # -- element 2: leaf-cert caveat (D3), carried forward from §3.4.4 -------

    def test_leaf_cert_caveat_wording(self) -> None:
        body = self._algorithm_body()
        self.assertIn("not_before", body)
        self.assertIn("integratedTime", body)
        self.assertIn("leaf", body.lower())
        self.assertIn(
            "bounds-checked",
            body,
            msg="expected the leaf-window bounds-checked-against-integratedTime caveat",
        )

    def test_leaf_cert_caveat_states_guarantee_not_stronger_claim(self) -> None:
        body = self._algorithm_body()
        self.assertIn(
            "stronger claim",
            body,
            msg="expected the D3 caveat to explicitly disclaim the stronger "
            "whole-chain-at-integratedTime reading",
        )

    # -- element 3: DSSE envelope signature -----------------------------------

    def test_dsse_envelope_signature_step_present(self) -> None:
        body = self._algorithm_body()
        self.assertIn("DSSE envelope signature", body)

    # -- element 4: Rekor inclusion, offline + non-normative impl note -------

    def test_rekor_inclusion_offline_present(self) -> None:
        body = self._algorithm_body()
        self.assertIn("Rekor inclusion proof", body)
        self.assertIn("offline", body)

    def test_rekor_adapter_is_non_normative_impl_note(self) -> None:
        body = self._algorithm_body()
        self.assertIn("rekor_adapter", body)
        self.assertIn("IMPL NOTE", body)
        self.assertIn("non-normative", body)

    # -- element 1: subject-binding before crypto, referenced not restated --

    def test_algorithm_orders_subject_binding_before_stage_5(self) -> None:
        body = self._algorithm_body()
        self.assertIn("BEFORE stage 5", body)

    # -- stage 5-7 ordering reconciliation ------------------------------------

    def test_signer_mismatch_precedence_over_rekor_and_dsse_stated(self) -> None:
        body = self._algorithm_body()
        self.assertIn(
            "signer-identity policy before it evaluates Rekor inclusion",
            body,
            msg="expected the reconciled ordering guarantee: signer-identity "
            "policy is evaluated (and can fail) before Rekor inclusion or "
            "the DSSE envelope signature",
        )

    def test_signer_mismatch_precedence_does_not_extend_to_cert_chain(self) -> None:
        body = self._algorithm_body()
        self.assertIn(
            "does NOT extend to the certificate-chain-validity portion",
            body,
            msg="expected the honest carve-out: a cert-chain failure is "
            "evaluated, and reported, before the signer-identity policy "
            "is ever reached",
        )

    def test_call_site_recording_mechanism_referenced(self) -> None:
        body = self._algorithm_body()
        self.assertIn("_RecordingPolicy", body)
        self.assertIn("call-site", body)

    def test_algorithm_does_not_reintroduce_epoch_as_pipeline_step(self) -> None:
        body = self._algorithm_body()
        self.assertIn(
            "not a numbered step of this per-bundle",
            body,
            msg="expected the D14 reaffirmation: epoch classification is not "
            "a post-crypto step of the per-bundle pipeline",
        )

    # -- element 5: no-revocation residual, NORMATIVE NOTE --------------------

    def test_no_revocation_normative_note_present(self) -> None:
        body = self._algorithm_body()
        self.assertIn("NORMATIVE NOTE", body)
        self.assertIn("no revocation", body.lower())
        self.assertIn("verifies", body)
        self.assertIn("forever", body)
        self.assertIn("intrinsic to the keyless model", body)


if __name__ == "__main__":
    unittest.main()
