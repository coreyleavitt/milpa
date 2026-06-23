"""Pin-candidate emission and promotion flow for the differential conformance harness.

## Current low-level API (slice 3d — unchanged)

``pin_candidate(spec, divergence_record, dest_dir)`` — serializes a (shrunk)
``FixtureSpec`` to a candidate directory containing:

  - The serialized fixture inputs (via ``harness.spec.serialize``)
  - ``divergence.json`` — the §2e divergence record

It does **NOT** write ``expected/`` — per RFC §2c, computing ``expected/``
requires human verification: a reviewer reads the spec, inspects the winning
impl's output, and blesses the bytes.  The candidate dir is a ready-to-review
artifact awaiting human-blessed ``expected/`` before promotion to
``conformance/spec-v1/``.

## New ``pin`` subcommand (S-A4)

``python3 -m harness pin <input-dir>`` runs the full promotion workflow:

1. Run both impls against ``<input-dir>`` (treated as a fixture directory).
2. If both impls agree → report "no divergence" and exit (nothing to pin).
3. If impls diverge (or one fails) → emit a *candidate* fixture directory
   alongside ``<input-dir>`` (named ``<input-dir>-candidate/``) containing:
   - All fixture inputs (copied from ``<input-dir>``)
   - ``divergence.json`` — the divergence record
4. Ask the operator which impl is spec-correct via the **injected chooser**
   (default: interactive stdin prompt). The prompt surfaces the
   field-level anti-circularity reminder (RFC §5): the operator must confirm
   the chosen impl's output is derivable from a normative spec clause.
5. Write ``expected/`` from the winning impl's outputs into the candidate dir.
6. Re-run the harness on the candidate fixture against the winning impl only
   and confirm it passes.
7. Report the candidate path and next steps (promote to ``conformance/spec-v1/``).

### Design — decision logic separable from I/O

The core flow lives in ``pin_flow()`` with the interactive gate injected as a
``choose_winner`` callback:

    def choose_winner(impls: list[str], run_results: dict[str, RunResult]) -> str:
        \"\"\"Return the name of the winning impl. May raise SystemExit to abort.\"\"\"

The default ``_stdin_chooser`` reads from stdin.  Tests pass a fake chooser
(e.g. ``lambda impls, runs: "python"``) so the entire flow is exercised
without stdin.

Stdlib only; no 3rd-party dependencies, no import milpa.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Callable, Optional

from harness.spec import FixtureSpec, serialize
from harness.runner import RunResult, run_fixture
from harness.assertions import assert_conformance, ConformanceResult
from harness.corpus import _detect_divergences, DivergenceRecord
from harness.descriptors import ImplDescriptor
from harness import surfaces


# ---------------------------------------------------------------------------
# Existing low-level API (slice 3d) — DO NOT CHANGE
# ---------------------------------------------------------------------------

def pin_candidate(
    spec: FixtureSpec,
    divergence_record: dict,
    dest_dir: Path,
) -> None:
    """Serialize a shrunk FixtureSpec as a pin candidate directory.

    Writes to ``dest_dir`` (created if it does not exist):
      - All fixture inputs via serialize(spec, dest_dir):
          cmd, milpa.kdl, mocked-fetches/<key>/..., index.kdl (if named deps)
      - divergence.json — the §2e divergence record (passed in as a dict)

    Does NOT write expected/ — human verification is required before promotion.

    Parameters
    ----------
    spec              — the (shrunk) FixtureSpec to serialize
    divergence_record — the §2e JSON record dict, typically from Divergence.to_json()
                        parsed back to a dict, or built directly; must be
                        JSON-serializable
    dest_dir          — destination directory (will be created if needed)
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Write all fixture inputs (cmd, milpa.kdl, mocked-fetches/, index.kdl)
    serialize(spec, dest_dir)

    # Write the divergence record as divergence.json
    (dest_dir / "divergence.json").write_text(
        json.dumps(divergence_record, indent=2) + "\n",
        encoding="utf-8",
    )

    # Explicitly assert expected/ was NOT written (invariant documentation)
    expected_dir = dest_dir / "expected"
    assert not expected_dir.exists(), (
        f"pin_candidate must not write expected/; found {expected_dir}"
    )


# ---------------------------------------------------------------------------
# Type alias for the injectable chooser callback
# ---------------------------------------------------------------------------

# Signature: (impl_names, run_results) -> winning_impl_name
# May raise SystemExit to abort the flow (user typed 'q' or 'quit').
ChooserFn = Callable[[list[str], dict[str, RunResult]], str]


# ---------------------------------------------------------------------------
# Core flow — decision logic (testable without stdin)
# ---------------------------------------------------------------------------

class NoDivergence(Exception):
    """Raised by pin_flow when both impls agree (nothing to pin)."""


def _run_both_impls(
    fixture_dir: Path,
    descriptors: list[ImplDescriptor],
    timeout: int = 180,
) -> dict[str, RunResult]:
    """Run each impl against fixture_dir; return {impl_name: RunResult}."""
    results: dict[str, RunResult] = {}
    for desc in descriptors:
        run = run_fixture(fixture_dir, desc, timeout=timeout)
        results[desc.name] = run
    return results


def _build_divergence_dict(
    fixture_name: str,
    run_results: dict[str, RunResult],
    div_records: list[DivergenceRecord],
    conformance_results: dict[str, ConformanceResult],
) -> dict:
    """Build the §2e divergence record dict for divergence.json."""
    if div_records:
        # Use the first divergence record as the canonical shape
        dr = div_records[0]
        return {
            "fixture": fixture_name,
            "cmd": dr.cmd,
            "output_file": dr.output_file,
            "impls": dr.impls,
            "is_verdict_asymmetry": dr.is_verdict_asymmetry,
            "all_divergences": [
                {
                    "output_file": d.output_file,
                    "impls": d.impls,
                    "is_verdict_asymmetry": d.is_verdict_asymmetry,
                }
                for d in div_records
            ],
        }
    # No DivergenceRecord (e.g. one impl crashed) — build from raw runs
    impls_view: dict[str, str] = {}
    for name, run in run_results.items():
        if run.returncode == 0:
            impls_view[name] = "PASS"
        else:
            cr = conformance_results.get(name)
            detail = (
                cr.failures[0].detail if (cr and cr.failures) else f"exit {run.returncode}"
            )
            impls_view[name] = f"FAIL: {detail}"
    return {
        "fixture": fixture_name,
        "cmd": "resolve",
        "output_file": "<conformance-verdict>",
        "impls": impls_view,
        "is_verdict_asymmetry": True,
        "all_divergences": [],
    }


def _copy_fixture_inputs_for_candidate(
    fixture_dir: Path,
    dest_dir: Path,
) -> None:
    """Copy fixture inputs (everything except expected/) into dest_dir."""
    _SKIP = frozenset({"expected"})
    for entry in fixture_dir.iterdir():
        if entry.name in _SKIP:
            continue
        dst = dest_dir / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dst, symlinks=True)
        else:
            shutil.copy2(entry, dst)


def _write_expected_from_run(
    winner_name: str,
    run: RunResult,
    conformance_result: ConformanceResult,
    dest_dir: Path,
) -> None:
    """Write expected/ into dest_dir from the winning impl's run outputs.

    Copies the outputs that the conformance result deemed normative.
    For success fixtures: milpa.lock, nim.cfg, _deps_structure.txt.
    For error fixtures: expected/error (the slug).

    Uses the run's scratch_dir to find actual output files.
    """
    expected_dir = dest_dir / "expected"
    expected_dir.mkdir(parents=True, exist_ok=True)

    scratch = Path(run.scratch_dir)

    # If the run has a slug (error fixture) — write expected/error
    if run.slug is not None and run.returncode == 1:
        (expected_dir / "error").write_text(run.slug + "\n", encoding="utf-8")
        return

    # check-certificate fixtures: copy the certificate to expected/certificate.json.
    # The impl writes the cert to run.cert_path (scratch/_milpa_certificate.json);
    # _write_expected_from_run must mirror it so _confirm_fixture_passes can diff it.
    if run.cert_path is not None:
        cert_src = Path(run.cert_path)
        if cert_src.exists():
            shutil.copy2(cert_src, expected_dir / surfaces.CERTIFICATE_FILE.name)

    # Success fixtures: copy the normative output files that exist in scratch
    for surf in (surfaces.LOCK_FILE, surfaces.ROOT_NIMCFG, surfaces.MANIFEST_FILE):
        src = scratch / surf.name
        if src.exists():
            shutil.copy2(src, expected_dir / surf.name)

    # _deps_structure.txt: generate normalized form
    from harness.assertions import normalize_deps_structure
    deps_text = normalize_deps_structure(run.scratch_dir, run.cas_dir)
    if deps_text is not None:
        (expected_dir / surfaces.DEPS_STRUCTURE_FILE.name).write_text(deps_text, encoding="utf-8")

    # Per-member nim.cfg for workspace fixtures
    # Walk scratch for member dirs (subdirs with milpa.kdl)
    for subdir in sorted(scratch.iterdir()):
        if not subdir.is_dir():
            continue
        if subdir.name.startswith("_") or subdir.name in ("mocked-fetches", "cas-seed"):
            continue
        member_nimcfg = subdir / surfaces.ROOT_NIMCFG.name
        if member_nimcfg.exists():
            member_exp = expected_dir / subdir.name
            member_exp.mkdir(exist_ok=True)
            shutil.copy2(member_nimcfg, member_exp / surfaces.ROOT_NIMCFG.name)


def _confirm_fixture_passes(
    candidate_dir: Path,
    winner_desc: ImplDescriptor,
    timeout: int = 180,
) -> tuple[bool, str]:
    """Re-run the harness on the candidate fixture for the winning impl.

    Returns (passed, message).
    """
    run = run_fixture(candidate_dir, winner_desc, timeout=timeout)
    result = assert_conformance(run, candidate_dir)
    run.cleanup()
    if result.passed:
        return True, f"Confirmed: fixture passes for {winner_desc.name}"
    details = "; ".join(f.detail for f in result.failures[:3])
    return False, f"Fixture does NOT pass for {winner_desc.name}: {details}"


def pin_flow(
    input_dir: Path,
    descriptors: list[ImplDescriptor],
    choose_winner: ChooserFn,
    candidate_dir: Optional[Path] = None,
    timeout: int = 180,
) -> Path:
    """Core pin promotion flow — injectable chooser, no direct stdin/stdout.

    Parameters
    ----------
    input_dir      — the fixture/input directory to run both impls against.
    descriptors    — the impl descriptors to use (must have >= 2 for divergence).
    choose_winner  — callback(impl_names, run_results) -> winner_name.
                     Called only when a divergence is detected.
                     May raise SystemExit to abort.
    candidate_dir  — where to write the candidate fixture (default:
                     ``<input_dir>-candidate/`` as a sibling).
    timeout        — subprocess timeout in seconds (passed to run_fixture).

    Returns
    -------
    Path to the written candidate fixture directory.

    Raises
    ------
    NoDivergence   — when both impls agree on the input (nothing to pin).
    SystemExit     — propagated from choose_winner when the operator aborts.
    """
    input_dir = Path(input_dir).resolve()
    if candidate_dir is None:
        candidate_dir = input_dir.parent / (input_dir.name + "-candidate")

    fixture_name = input_dir.name

    # Step 1: run both impls
    run_results = _run_both_impls(input_dir, descriptors, timeout=timeout)

    # Step 2: assess conformance against expected/ (if present) and detect divergences
    conformance_results: dict[str, ConformanceResult] = {}
    for desc in descriptors:
        if desc.name in run_results:
            conformance_results[desc.name] = assert_conformance(
                run_results[desc.name], input_dir
            )

    div_records = _detect_divergences(
        fixture_name,
        _read_cmd(input_dir),
        conformance_results,
    )

    # If no divergence and all impls passed → nothing to pin
    all_passed = all(r.passed for r in conformance_results.values())
    if all_passed and not div_records:
        # Cleanup scratch dirs
        for run in run_results.values():
            run.cleanup()
        raise NoDivergence(
            f"Both impls agree on {fixture_name!r} — no divergence to pin."
        )

    # Step 3: emit candidate fixture dir (inputs + divergence.json)
    candidate_dir = Path(candidate_dir)
    candidate_dir.mkdir(parents=True, exist_ok=True)
    _copy_fixture_inputs_for_candidate(input_dir, candidate_dir)

    div_dict = _build_divergence_dict(
        fixture_name, run_results, div_records, conformance_results
    )
    (candidate_dir / "divergence.json").write_text(
        json.dumps(div_dict, indent=2) + "\n",
        encoding="utf-8",
    )

    # Step 4: ask the chooser which impl is spec-correct
    impl_names = list(run_results.keys())
    winner_name = choose_winner(impl_names, run_results)

    # Validate the chosen winner is a known impl
    if winner_name not in run_results:
        raise ValueError(
            f"choose_winner returned {winner_name!r} which is not in {impl_names}"
        )

    winner_run = run_results[winner_name]
    winner_cr = conformance_results[winner_name]

    # Step 5: write expected/ from the winning impl's outputs
    _write_expected_from_run(winner_name, winner_run, winner_cr, candidate_dir)

    # Cleanup scratch dirs (winner's scratch was read above; all safe to clean now)
    for run in run_results.values():
        run.cleanup()

    # Step 6: re-run the harness on the candidate fixture for the winner
    winner_desc = next(d for d in descriptors if d.name == winner_name)
    passed, confirm_msg = _confirm_fixture_passes(candidate_dir, winner_desc, timeout)

    if not passed:
        # Confirmation failed — return candidate anyway so the operator can inspect
        raise RuntimeError(
            f"Pin written to {candidate_dir} but confirmation FAILED: {confirm_msg}\n"
            f"Inspect the candidate and check expected/ matches the spec."
        )

    return candidate_dir


def _read_cmd(fixture_dir: Path) -> str:
    """Read the optional cmd file; default 'resolve'."""
    cmd_file = fixture_dir / "cmd"
    if cmd_file.exists():
        return cmd_file.read_text().strip()
    return "resolve"


# ---------------------------------------------------------------------------
# Interactive stdin chooser (default for the CLI)
# ---------------------------------------------------------------------------

_ANTI_CIRCULARITY_REMINDER = """\
REMINDER (RFC §5 field-level anti-circularity rule):
  The chosen impl's output must be derivable from a NORMATIVE SPEC CLAUSE.
  Do NOT bless an output just because one impl happens to produce it.
  Verify: lockfile order → lockfile-schema.md; nim.cfg order → its spec;
  error slug → errors.md.  If the spec is ambiguous, file a spec-sharpening
  issue and type 'q' to abort this pin.
"""


def _stdin_chooser(impl_names: list[str], run_results: dict[str, RunResult]) -> str:
    """Interactive stdin chooser for the CLI ``pin`` subcommand.

    Prints each impl's outcome, the anti-circularity reminder, and prompts
    for a choice. Type 'q' or 'quit' to abort.
    """
    print()
    print("=== DIVERGENCE DETECTED ===")
    print("Impl outcomes:")
    for name in impl_names:
        run = run_results[name]
        if run.returncode == 0:
            outcome = "exit 0 (success)"
        else:
            from harness.runner import extract_slug
            slug, _ = extract_slug(run.stderr)
            outcome = f"exit {run.returncode}" + (f" slug={slug}" if slug else "")
        print(f"  [{name}] {outcome}")
    print()
    print(_ANTI_CIRCULARITY_REMINDER)

    while True:
        prompt = f"Which impl is spec-correct? [{'/'.join(impl_names)}/q] "
        try:
            answer = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            raise SystemExit(1)

        if answer in ("q", "quit"):
            print("Aborted.")
            raise SystemExit(0)
        # Accept any unambiguous prefix
        matches = [n for n in impl_names if n.lower().startswith(answer)]
        if len(matches) == 1:
            return matches[0]
        if answer in impl_names:
            return answer
        print(f"  Please type one of: {', '.join(impl_names)} (or 'q' to quit)")


# ---------------------------------------------------------------------------
# CLI entry point for ``python3 -m harness pin <dir>``
# ---------------------------------------------------------------------------

def cmd_pin(
    args: "argparse.Namespace",  # noqa: F821  (forward ref; argparse imported in caller)
    chooser: Optional[ChooserFn] = None,
) -> int:
    """Implement the ``pin`` subcommand.

    Parameters
    ----------
    args     — parsed argparse namespace with ``.input_dir`` and optional
               ``.candidate_dir``, ``.timeout``.
    chooser  — injectable chooser for testing; defaults to _stdin_chooser.

    Returns
    -------
    Exit code (0 = success, 1 = failure).
    """
    from harness.descriptors import build_descriptors

    repo_root = Path(__file__).resolve().parents[1]
    descriptors = build_descriptors(repo_root)

    input_dir = Path(args.input_dir).resolve()
    if not input_dir.is_dir():
        print(f"error: {input_dir} is not a directory")
        return 1

    candidate_dir = Path(args.candidate_dir).resolve() if getattr(args, "candidate_dir", None) else None
    timeout = getattr(args, "timeout", 180)

    effective_chooser = chooser if chooser is not None else _stdin_chooser

    print(f"Running both impls on: {input_dir}")
    print(f"Impls: {[d.name for d in descriptors]}")
    print()

    try:
        result_dir = pin_flow(
            input_dir=input_dir,
            descriptors=descriptors,
            choose_winner=effective_chooser,
            candidate_dir=candidate_dir,
            timeout=timeout,
        )
        print()
        print(f"Candidate fixture written to: {result_dir}")
        print("Confirmation: PASS")
        print()
        print("Next steps:")
        print(f"  1. Review {result_dir}/expected/ against the normative spec.")
        print(f"  2. Copy to conformance/spec-v1/<fixture-name>/ when satisfied.")
        print(f"  3. Add a descriptive fixture name and remove divergence.json.")
        return 0

    except NoDivergence as e:
        print(f"No divergence: {e}")
        print("Nothing to pin.")
        return 0

    except RuntimeError as e:
        print(f"error: {e}")
        return 1
