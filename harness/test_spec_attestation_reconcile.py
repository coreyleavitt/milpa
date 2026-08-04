"""Tests for the S1 spec-prose reconciliation (RFC `docs/rfc-attestation-v1-normative.md`,
slice S1 — R1/R2 in its §5 reconciliation-deltas table).

S1 is spec-only: it retires every dangling forward-reference in
`spec/registry-protocol.md` that described the per-entry attestation gate
(`entry-trust`) as living in a separate not-yet-landed RFC slice, or the
epoch boundary as an open question. The gate's normative home is now this
document's own §3.6 (authored by slice S2); the epoch boundary is a
Rekor-anchored pre-epoch set commitment (per D-Watermark, §8c of the RFC),
not `published_at >= E`.

This module does not test the gate's *behavior* (nothing is built yet in
this slice) — only that the stale hedging language naming the gate as
forthcoming/undecided has been retired from the spec prose.

Run with:
    python3 -m pytest harness/test_spec_attestation_reconcile.py
    python3 -m unittest harness.test_spec_attestation_reconcile   # alternative
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path setup — repo root on sys.path, matching sibling harness/test_*.py
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_REGISTRY_PROTOCOL = _REPO_ROOT / "spec" / "registry-protocol.md"


def _flow_join(text: str) -> str:
    """Collapse markdown blockquote line-wrapping (`"...\\n> ..."`) into a
    single flowing string so a phrase spanning two wrapped `> ` lines is
    still matchable as one substring — the same way a rendered markdown
    reader would join the paragraph. Ordinary blank-line paragraph breaks
    are left alone (they still separate unrelated phrases)."""
    return re.sub(r"\n>\s?", " ", text)


class TestAttestationGateHedgesRetired(unittest.TestCase):
    """Every dangling forward-reference describing the entry-trust gate (or its
    epoch boundary) as unresolved / forthcoming / living in a separate document
    is gone from `spec/registry-protocol.md`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = _flow_join(_REGISTRY_PROTOCOL.read_text(encoding="utf-8"))

    def assert_phrase_absent(self, phrase: str, behavior: str) -> None:
        self.assertNotIn(
            phrase,
            self.text,
            msg=f"{behavior}: stale phrase still present: {phrase!r}",
        )

    def test_open_question_2_label_retired(self) -> None:
        """Open question 2 (epoch classification / published_at mandate) is
        resolved by the RFC; the spec no longer cites it as unresolved."""
        self.assert_phrase_absent(
            "open question 2",
            "the epoch-boundary open question is resolved, not still open",
        )

    def test_gate_lands_separately_framing_retired(self) -> None:
        """The entry-trust gate is no longer described as a separate normative
        surface that lands elsewhere — it lives in this document at §3.6."""
        self.assert_phrase_absent(
            "gate lands separately",
            "the entry-trust gate's normative home is this document, not a future slice",
        )

    def test_no_gate_exists_framing_retired(self) -> None:
        """The parse-boundary NORMATIVE clause no longer claims no policy gate
        exists at this spec layer."""
        self.assert_phrase_absent(
            "no gate exists at this spec layer",
            "the policy gate is specified in this document (§3.6), not absent",
        )

    def test_gate_exists_yet_hedge_retired(self) -> None:
        """The subject-binding NORMATIVE clause no longer disclaims that nothing
        implies the gate exists yet."""
        self.assert_phrase_absent(
            "nothing in this section implies that gate exists yet",
            "the verifier and policy gate are specified in this document (§3.6)",
        )

    def test_not_yet_part_of_spec_surface_retired(self) -> None:
        """The verifier design is no longer described as outside any spec
        surface — it is specified in this document at §3.6."""
        self.assert_phrase_absent(
            "not yet part of any spec surface",
            "the verifier design is a spec surface now (§3.6)",
        )

    def test_claim_only_window_hedge_retired(self) -> None:
        """The `bundle` pin's absence is no longer framed as a transient
        claim-only window preceding an unbuilt bundle-delivery slice."""
        self.assert_phrase_absent(
            "claim-only window",
            "bundle delivery is not framed as a future, not-yet-landed slice",
        )

    def test_separate_document_framing_retired(self) -> None:
        """§3.4's whole-index gate section no longer frames Layer 2 (entry-trust)
        as specified and enforced in a SEPARATE document."""
        self.assert_phrase_absent(
            "SEPARATE document",
            "Layer 2 is specified in this document (§3.6), not a separate RFC",
        )

    def test_amendment_preceding_implementation_hedge_retired(self) -> None:
        """The parse-to-typed NOTE no longer frames itself as a spec amendment
        preceding an unbuilt implementation slice."""
        self.assert_phrase_absent(
            "amendment preceding the implementation",
            "parse-to-typed behavior is implemented, not merely anticipated",
        )

    def test_backdate_lands_with_p3_slice_hedge_retired(self) -> None:
        """The publication-watermark section no longer says the backdating
        check 'lands with Part 2's P3 slice' — that slice-naming scheme is
        superseded by the attestation-v1-normative RFC's own slicing, and the
        check's disposition (build vs retire) is not pre-decided by S1."""
        self.assert_phrase_absent(
            "it lands with Part 2",
            "the backdate check's disposition is not framed as landing on a fixed forthcoming slice",
        )

    def test_published_at_required_on_post_epoch_hedge_retired(self) -> None:
        """`published_at` is no longer described as becoming a REQUIRED field on
        post-epoch entries — under D-Watermark it is informational metadata
        only and is never the epoch boundary."""
        self.assert_phrase_absent(
            "REQUIRED on post-epoch entries",
            "published_at is informational only, not a mandatory post-epoch field",
        )

    def test_entry_trust_gate_points_at_section_3_6(self) -> None:
        """The reconciled prose names §3.6 as the entry-trust gate's normative
        home inside this document (S2 authors §3.6's body in the next slice;
        S1 only needs the forward-pointing cross-reference to exist)."""
        self.assertIn(
            "§3.6",
            self.text,
            msg="expected at least one cross-reference to the new §3.6 entry-trust gate section",
        )

    def test_backdate_check_retired_not_deferred(self) -> None:
        """S-Backdate (RFC D8, round 3): the epoch-boundary backdate purpose is
        subsumed by the epoch-commitment's ArmingInvalid, and published_at is
        informational-only, so v1 retires the TNG-ENTRY-BACKDATED-class check
        rather than building a weaker, already-subsumed audit. §3.5.4 must
        state this definitively — no longer deferring the disposition."""
        self.assert_phrase_absent(
            "disposition settled in `docs/rfc-attestation-v1-normative.md`",
            "§3.5.4 no longer defers the backdate-check disposition to the RFC",
        )
        # The definitive retirement statement is present.
        self.assertIn(
            "`TNG-ENTRY-BACKDATED`-class check and no such slug",
            self.text,
            msg="§3.5.4 must definitively state v1 defines no TNG-ENTRY-BACKDATED check",
        )
        self.assertIn(
            "retired rather than built",
            self.text,
            msg="§3.5.4 must state the check is retired (subsumed), not built",
        )

    def test_backdate_slug_stays_undefined_in_errors_catalog(self) -> None:
        """The retired check has no slug: TNG-ENTRY-BACKDATED must NOT appear in
        the spec-owned error catalog (bijection stays green without it)."""
        errors_md = (_REPO_ROOT / "spec" / "errors.md").read_text(encoding="utf-8")
        self.assertNotIn(
            "TNG-ENTRY-BACKDATED",
            errors_md,
            msg="TNG-ENTRY-BACKDATED is retired, not defined — it must not enter errors.md",
        )


if __name__ == "__main__":
    unittest.main()
