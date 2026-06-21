"""Slice A (rfc-conformance-parity §4): the divergence detector must flag
pass/fail asymmetry across impls, not only diffs among impls that BOTH passed.

Regression for Finding 1 in docs/rfc-conformance-parity.baseline.md: under the
old detector an asymmetric fixture (one impl matches expected/, another does
not) produced zero divergences, because only co-passing impls were compared and
two co-passers both equal expected/ by construction. The textbook cross-impl
divergence was therefore invisible and "Cross-impl divergences: NONE" was
structurally vacuous for the static corpus.
"""

from __future__ import annotations

from harness.assertions import AssertionFailure, ConformanceResult
from harness.corpus import _detect_divergences


def _result(
    passed: bool, outputs: dict[str, str] | None = None, detail: str = "boom"
) -> ConformanceResult:
    failures = (
        [] if passed else [AssertionFailure("fx", "impl", "error-fixture", detail)]
    )
    return ConformanceResult(
        run=None,  # type: ignore[arg-type]  # detector never touches .run
        passed=passed,
        failures=failures,
        normalized_outputs=outputs or {},
    )


def test_pass_fail_asymmetry_is_a_divergence() -> None:
    results = {
        "python": _result(True, {"expected/error": "RES-PROVENANCE-CONFLICT"}),
        "rust": _result(False, detail="wrong slug: expected ... got FETCH-ALL-FAILED"),
    }
    divs = _detect_divergences("fixture-099-res-provenance-conflict", "lock", results)
    assert len(divs) >= 1
    assert set(divs[0].impls) == {"python", "rust"}


def test_symmetric_failure_is_not_a_divergence() -> None:
    # Both impls fail identically (a runner-input gap, not a parity violation).
    results = {
        "python": _result(False, detail="same gap"),
        "rust": _result(False, detail="same gap"),
    }
    assert _detect_divergences("fixture-209-s9-features-flag", "lock", results) == []


def test_both_pass_identical_is_not_a_divergence() -> None:
    out = {"expected/milpa.lock": "v=1"}
    results = {"python": _result(True, dict(out)), "rust": _result(True, dict(out))}
    assert _detect_divergences("fx", "lock", results) == []


def test_co_passer_output_diff_still_caught() -> None:
    results = {
        "python": _result(True, {"expected/milpa.lock": "A"}),
        "rust": _result(True, {"expected/milpa.lock": "B"}),
    }
    divs = _detect_divergences("fx", "lock", results)
    assert len(divs) == 1
    assert divs[0].output_file == "expected/milpa.lock"


def test_single_impl_is_never_a_divergence() -> None:
    assert _detect_divergences("fx", "lock", {"rust": _result(False)}) == []
