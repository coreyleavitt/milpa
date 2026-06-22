"""Tests for S-A2: certificate.json canonical JSON comparison.

Verifies that ``compare_certificate_json`` and ``_canonical_certificate``
implement the RFC 8785 JCS parse-then-compare primitive plus the domain-
specific rules from ``spec/conformance-fixtures.md §2.7.3``:

  - Structural equality: key order and whitespace in emitted JSON are NOT
    significant.
  - ``message`` is excluded from comparison (non-normative).
  - ``resolved`` and ``witness`` are compared order-sensitively.
  - ``refutation`` is compared as a set (order-independent).
  - A normative-field difference IS flagged.

Also verifies that the Python impl's ``certificate_to_json`` emits
consistent (deterministic) key ordering per the §2.7.3 SHOULD, and that the
emitted JSON parses back to the same value under ``json.loads``.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.assertions import _canonical_certificate, compare_certificate_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _success(**kwargs) -> dict:
    """Build a minimal success certificate dict."""
    base: dict = {
        "kind": "success",
        "resolved": [{"package": "foo", "version": "1.0.0"}],
        "witness": [
            {"package": "foo", "version": "1.0.0",
             "constraint": ">=1.0.0", "satisfied_by": "__root__"},
        ],
    }
    base.update(kwargs)
    return base


def _failure(**kwargs) -> dict:
    """Build a minimal failure certificate dict."""
    base: dict = {
        "kind": "failure",
        "message": "no satisfying version",
        "refutation": [{"package": "foo", "constraint": ">=2.0.0"}],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Key-order insensitivity (the RFC 8785 JCS primitive layer)
# ---------------------------------------------------------------------------

class TestKeyOrderInsensitivity(unittest.TestCase):
    """compare_certificate_json must treat key-permuted objects as equal."""

    def test_success_root_key_order_permuted(self) -> None:
        """Root-level key order of a success cert is not significant."""
        # Standard order
        a = {"kind": "success",
             "resolved": [{"package": "alpha", "version": "1.0.0"}],
             "witness": [{"package": "alpha", "version": "1.0.0",
                          "constraint": ">=1.0.0", "satisfied_by": "__root__"}]}
        # Permuted root keys (witness before resolved, kind last)
        b = {"witness": [{"package": "alpha", "version": "1.0.0",
                          "constraint": ">=1.0.0", "satisfied_by": "__root__"}],
             "resolved": [{"package": "alpha", "version": "1.0.0"}],
             "kind": "success"}
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Root-level key permutation must not cause a mismatch",
        )

    def test_success_resolved_entry_key_order_permuted(self) -> None:
        """Key order inside a resolved-array entry is not significant."""
        a = _success(resolved=[{"package": "alpha", "version": "1.0.0"}])
        # version before package
        b = _success(resolved=[{"version": "1.0.0", "package": "alpha"}])
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Key permutation inside a resolved entry must not cause a mismatch",
        )

    def test_success_witness_entry_key_order_permuted(self) -> None:
        """Key order inside a witness-array entry is not significant."""
        entry_normal = {"package": "foo", "version": "1.0.0",
                        "constraint": ">=1.0.0", "satisfied_by": "__root__"}
        entry_permuted = {"satisfied_by": "__root__", "constraint": ">=1.0.0",
                          "version": "1.0.0", "package": "foo"}
        a = _success(witness=[entry_normal])
        b = _success(witness=[entry_permuted])
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Key permutation inside a witness entry must not cause a mismatch",
        )

    def test_failure_root_key_order_permuted(self) -> None:
        """Root-level key order of a failure cert is not significant."""
        a = {"kind": "failure", "message": None,
             "refutation": [{"package": "x", "constraint": ">=1.0.0"}]}
        # message and refutation before kind
        b = {"refutation": [{"package": "x", "constraint": ">=1.0.0"}],
             "message": None, "kind": "failure"}
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Root-level key permutation in failure cert must not cause a mismatch",
        )

    def test_failure_refutation_entry_key_order_permuted(self) -> None:
        """Key order inside a refutation entry is not significant."""
        a = _failure(refutation=[{"package": "x", "constraint": ">=1.0.0"}])
        b = _failure(refutation=[{"constraint": ">=1.0.0", "package": "x"}])
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Key permutation inside a refutation entry must not cause a mismatch",
        )


# ---------------------------------------------------------------------------
# message exclusion
# ---------------------------------------------------------------------------

class TestMessageExclusion(unittest.TestCase):
    """message is non-normative and must not affect comparison."""

    def test_different_message_strings_equal(self) -> None:
        """Two failure certs differing only in message are equal."""
        a = _failure(message="package X has no satisfying version")
        b = _failure(message="cannot resolve: X >= 2.0.0 is unsatisfiable")
        self.assertIsNone(
            compare_certificate_json(a, b),
            "message difference must not cause a mismatch",
        )

    def test_null_vs_non_null_message_equal(self) -> None:
        """message=null vs message=string is still equal (message excluded)."""
        a = _failure(message=None)
        b = _failure(message="some diagnostic")
        self.assertIsNone(
            compare_certificate_json(a, b),
            "message=null vs non-null must not cause a mismatch",
        )

    def test_message_absent_vs_present_equal(self) -> None:
        """A failure cert without a message key vs one with message is equal."""
        a = {"kind": "failure",
             "refutation": [{"package": "foo", "constraint": ">=2.0.0"}]}
        b = _failure(message="something")
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Absent message vs present message must not cause a mismatch",
        )

    def test_canonical_excludes_message_key(self) -> None:
        """_canonical_certificate does not include the message key."""
        cert = _failure(message="non-normative prose")
        canon = _canonical_certificate(cert)
        self.assertNotIn("message", canon)


# ---------------------------------------------------------------------------
# refutation set equality (order-independent)
# ---------------------------------------------------------------------------

class TestRefutationSetEquality(unittest.TestCase):
    """refutation is a set: order in emitted JSON is non-normative."""

    def test_two_entry_order_reversed(self) -> None:
        """Reversing a two-entry refutation array produces an equal cert."""
        entries = [
            {"package": "x", "constraint": ">=1.0.0"},
            {"package": "y", "constraint": "<2.0.0"},
        ]
        a = _failure(refutation=entries)
        b = _failure(refutation=list(reversed(entries)))
        self.assertIsNone(
            compare_certificate_json(a, b),
            "Reversed refutation order must not cause a mismatch",
        )

    def test_multi_entry_random_order(self) -> None:
        """Any permutation of a three-entry refutation array is equal."""
        entries = [
            {"package": "alpha", "constraint": ">=1.0.0"},
            {"package": "beta",  "constraint": "<3.0.0"},
            {"package": "alpha", "constraint": "<=2.0.0"},
        ]
        perm1 = [entries[2], entries[0], entries[1]]
        perm2 = [entries[1], entries[2], entries[0]]
        a = _failure(refutation=entries)
        b = _failure(refutation=perm1)
        c = _failure(refutation=perm2)
        self.assertIsNone(compare_certificate_json(a, b))
        self.assertIsNone(compare_certificate_json(a, c))

    def test_empty_refutation_both_sides(self) -> None:
        """Two empty refutation arrays are equal."""
        a = _failure(refutation=[])
        b = _failure(refutation=[])
        self.assertIsNone(compare_certificate_json(a, b))

    def test_canonical_sorts_refutation(self) -> None:
        """_canonical_certificate sorts refutation by (package, constraint)."""
        entries = [
            {"package": "z", "constraint": ">=1.0.0"},
            {"package": "a", "constraint": ">=2.0.0"},
            {"package": "a", "constraint": ">=1.0.0"},
        ]
        canon = _canonical_certificate({"kind": "failure", "refutation": entries})
        self.assertEqual(canon["refutation"], [
            {"package": "a", "constraint": ">=1.0.0"},
            {"package": "a", "constraint": ">=2.0.0"},
            {"package": "z", "constraint": ">=1.0.0"},
        ])


# ---------------------------------------------------------------------------
# resolved/witness order sensitivity
# ---------------------------------------------------------------------------

class TestArrayOrderSensitivity(unittest.TestCase):
    """resolved and witness are order-sensitive."""

    def test_resolved_order_matters(self) -> None:
        """Swapping resolved entries is a normative mismatch."""
        entries = [
            {"package": "alpha", "version": "1.0.0"},
            {"package": "beta",  "version": "2.0.0"},
        ]
        # Build witnesses matching each resolved entry
        witnesses = [
            {"package": "alpha", "version": "1.0.0",
             "constraint": ">=1.0.0", "satisfied_by": "__root__"},
            {"package": "beta", "version": "2.0.0",
             "constraint": ">=2.0.0", "satisfied_by": "__root__"},
        ]
        a = {"kind": "success", "resolved": entries, "witness": witnesses}
        b = {"kind": "success", "resolved": list(reversed(entries)),
             "witness": witnesses}
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(
            result,
            "Swapped resolved order must be flagged as a mismatch",
        )

    def test_witness_order_matters(self) -> None:
        """Swapping witness entries is a normative mismatch."""
        resolved = [{"package": "alpha", "version": "1.0.0"}]
        witnesses = [
            {"package": "alpha", "version": "1.0.0",
             "constraint": ">=1.0.0", "satisfied_by": "__root__"},
            {"package": "alpha", "version": "1.0.0",
             "constraint": ">=0.5.0", "satisfied_by": "beta"},
        ]
        a = {"kind": "success", "resolved": resolved, "witness": witnesses}
        b = {"kind": "success", "resolved": resolved,
             "witness": list(reversed(witnesses))}
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(
            result,
            "Swapped witness order must be flagged as a mismatch",
        )


# ---------------------------------------------------------------------------
# Normative-field differences flagged
# ---------------------------------------------------------------------------

class TestNormativeDifferenceFlagged(unittest.TestCase):
    """A difference in a normative field must be flagged."""

    def test_success_kind_vs_failure_kind(self) -> None:
        """kind:success vs kind:failure is always a mismatch."""
        a = _success()
        b = _failure()
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(result, "kind mismatch must be flagged")
        self.assertIn("kind", result)

    def test_success_resolved_version_differs(self) -> None:
        """Different version in resolved entry is a normative mismatch."""
        a = _success(resolved=[{"package": "foo", "version": "1.0.0"}])
        b = _success(resolved=[{"package": "foo", "version": "2.0.0"}])
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(result, "Different resolved version must be flagged")

    def test_success_resolved_package_differs(self) -> None:
        """Different package name in resolved entry is a normative mismatch."""
        a = _success(resolved=[{"package": "alpha", "version": "1.0.0"}])
        b = _success(resolved=[{"package": "beta",  "version": "1.0.0"}])
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(result, "Different resolved package must be flagged")

    def test_failure_refutation_set_differs(self) -> None:
        """Different refutation entries are a normative mismatch."""
        a = _failure(refutation=[{"package": "x", "constraint": ">=1.0.0"}])
        b = _failure(refutation=[{"package": "y", "constraint": ">=1.0.0"}])
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(result, "Different refutation set must be flagged")

    def test_failure_extra_refutation_entry_flagged(self) -> None:
        """A superset refutation is a normative mismatch."""
        base = [{"package": "x", "constraint": ">=1.0.0"}]
        extra = base + [{"package": "y", "constraint": "<2.0.0"}]
        a = _failure(refutation=base)
        b = _failure(refutation=extra)
        result = compare_certificate_json(a, b)
        self.assertIsNotNone(result, "Extra refutation entry must be flagged")


# ---------------------------------------------------------------------------
# Python impl emission determinism (§2.7.3 SHOULD)
# ---------------------------------------------------------------------------

class TestPythonEmissionDeterminism(unittest.TestCase):
    """Python impl's certificate_to_json emits parseable, consistent-key-order JSON.

    §2.7.3 SHOULD: implementations SHOULD emit certificate.json with sorted
    object keys.  We verify Python's SSOT serialiser produces valid JSON and
    that the same input always yields the same output (determinism).  We do
    NOT require alphabetic key order (the SHOULD recommends it but the MUST is
    structural comparison); we require stable key order (same call → same bytes).
    """

    @classmethod
    def setUpClass(cls) -> None:
        try:
            sys.path.insert(0, str(_REPO_ROOT / "impls" / "python"))
            from milpa.solver import (
                SolveSuccess,
                WitnessEntry,
                certificate_to_json,
            )
            cls._certificate_to_json = staticmethod(certificate_to_json)
            cls._SolveSuccess = SolveSuccess
            cls._WitnessEntry = WitnessEntry
            cls._skip_reason = None
        except ImportError as e:
            cls._skip_reason = f"milpa.solver not importable: {e}"

    def _skip_if_unavailable(self) -> None:
        if self.__class__._skip_reason:
            self.skipTest(self.__class__._skip_reason)

    def _make_success(self):
        return self._SolveSuccess(
            resolved=[("__root__", "0.0.0"), ("alpha", "1.0.0")],
            witness=[
                self._WitnessEntry(
                    package="alpha", version="1.0.0",
                    constraint=">=1.0.0", satisfied_by="__root__",
                ),
            ],
        )

    def test_success_cert_is_valid_json(self) -> None:
        """certificate_to_json(success) must produce parseable JSON."""
        self._skip_if_unavailable()
        raw = self._certificate_to_json(self._make_success())
        parsed = json.loads(raw)
        self.assertEqual(parsed["kind"], "success")
        self.assertIn("resolved", parsed)
        self.assertIn("witness", parsed)

    def test_success_cert_is_deterministic(self) -> None:
        """certificate_to_json produces identical bytes on repeated calls."""
        self._skip_if_unavailable()
        s = self._make_success()
        self.assertEqual(
            self._certificate_to_json(s),
            self._certificate_to_json(s),
        )

    def test_failure_cert_is_valid_json(self) -> None:
        """certificate_to_json(None sentinel) must produce parseable failure JSON."""
        self._skip_if_unavailable()
        # None is the sentinel for a non-solver failure; produces
        # kind:failure, message:null, refutation:[].
        raw = self._certificate_to_json(None)
        parsed = json.loads(raw)
        self.assertEqual(parsed["kind"], "failure")
        self.assertIn("refutation", parsed)

    def test_failure_cert_is_deterministic(self) -> None:
        """certificate_to_json(None) produces identical bytes on repeated calls."""
        self._skip_if_unavailable()
        raw1 = self._certificate_to_json(None)
        raw2 = self._certificate_to_json(None)
        self.assertEqual(raw1, raw2)

    def test_none_result_is_valid_json(self) -> None:
        """certificate_to_json(None) produces a valid failure cert with null message."""
        self._skip_if_unavailable()
        raw = self._certificate_to_json(None)
        parsed = json.loads(raw)
        self.assertEqual(parsed["kind"], "failure")
        self.assertIsNone(parsed.get("message"))
        self.assertEqual(parsed.get("refutation"), [])

    def test_success_cert_roundtrips_through_compare(self) -> None:
        """An emitted success cert parses back and passes compare_certificate_json."""
        self._skip_if_unavailable()
        raw = self._certificate_to_json(self._make_success())
        parsed = json.loads(raw)
        result = compare_certificate_json(parsed, parsed)
        self.assertIsNone(result, f"Round-trip comparison failed: {result}")

    def test_failure_cert_roundtrips_through_compare(self) -> None:
        """An emitted failure cert (None sentinel) round-trips through compare."""
        self._skip_if_unavailable()
        raw = self._certificate_to_json(None)
        parsed = json.loads(raw)
        result = compare_certificate_json(parsed, parsed)
        self.assertIsNone(result, f"Round-trip comparison failed: {result}")


if __name__ == "__main__":
    unittest.main()
