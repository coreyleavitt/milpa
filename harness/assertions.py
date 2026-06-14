"""Assertions against expected/ — the conformance gate.

Compares a RunResult against its fixture's expected/ outputs.

Design constraints:
- stdlib only; no import milpa.
- Normalization of _deps_structure.txt per spec §2.6.
- Error fixture check: §3 of spec/conformance-fixtures.md.
- Success fixture check: §2.4/2.5/2.6.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from harness.runner import RunResult


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class AssertionFailure:
    """A single conformance assertion that did not hold."""
    fixture_name: str
    impl_name: str
    kind: str          # "error-fixture", "success-fixture", "harness-error"
    detail: str        # human-readable description of the failure


@dataclass
class ConformanceResult:
    """Outcome of asserting one RunResult against expected/."""
    run: RunResult
    passed: bool
    failures: list[AssertionFailure]
    # Normalized output files for cross-impl comparison (key = relative path
    # within expected/, value = normalized bytes/text). Only populated on pass.
    normalized_outputs: dict[str, str]


# ---------------------------------------------------------------------------
# _deps_structure.txt normalization (spec §2.6)
# ---------------------------------------------------------------------------

def _normalize_deps_structure(scratch_dir: str, cas_dir: str) -> Optional[str]:
    """Read _deps/ symlinks from scratch and produce the normalized text.

    Format per spec §2.6:
      '<name> -> <CAS_ROOT>/sha256/<hex>/\\n'  per dep, sorted lexicographically.

    Normalization rule (spec §2.6 NORMATIVE):
    1. Resolve CAS root to canonical form (no symlinks).
    2. Form prefix as canonical string with NO trailing path separator.
    3. Replace prefix with <CAS_ROOT> in each resolved target.

    Returns None if _deps/ does not exist (no deps were resolved).
    """
    deps_dir = Path(scratch_dir) / "_deps"
    if not deps_dir.is_dir():
        return None

    # Resolve the CAS root canonically (follows symlinks in tmp paths).
    canonical_cas = str(Path(cas_dir).resolve())
    # Ensure no trailing slash in the prefix.
    canonical_cas = canonical_cas.rstrip("/")

    lines = []
    for entry in sorted(deps_dir.iterdir()):
        if entry.is_symlink():
            target = entry.resolve()
            target_str = str(target)
            normalized = target_str.replace(canonical_cas, "<CAS_ROOT>")
            lines.append(f"{entry.name} -> {normalized}/")

    if not lines:
        return ""
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Public assertion entry point
# ---------------------------------------------------------------------------

def _is_check_certificate_cmd(cmd: str) -> bool:
    """True when the fixture cmd is check-certificate."""
    head = cmd.split()[0] if cmd.split() else ""
    return head == "check-certificate"


def _canonical_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    """Comparison-significant canonical form of a certificate.

    The SINGLE definition of "what content is significant in a certificate"
    (conformance-fixtures §2.7.3), shared by BOTH the fixture-vs-impl
    assertion (`_compare_certificate_json`) and the cross-impl divergence
    token (`_assert_check_certificate_fixture`). Keeping these in lockstep is
    the whole point: a kind-only token (#130) was blind to body divergence.

    - ``message`` is EXCLUDED (human-readable, impl-specific).
    - success: ``resolved`` and ``witness`` are order-sensitive (kept as-is).
    - failure: ``refutation`` is set-equality (sorted by package, constraint).
    """
    kind = cert.get("kind")
    if kind == "success":
        return {
            "kind": "success",
            "resolved": cert.get("resolved"),
            "witness": cert.get("witness"),
        }
    if kind == "failure":
        refutation = sorted(
            cert.get("refutation", []),
            key=lambda e: (e.get("package", ""), e.get("constraint", "")),
        )
        return {"kind": "failure", "refutation": refutation}
    return {"kind": kind}


def _compare_certificate_json(
    got: dict[str, Any],
    expected: dict[str, Any],
) -> Optional[str]:
    """Canonical JSON comparison for certificates (conformance-fixtures §2.7.3).

    Equality is decided on the shared `_canonical_certificate` form; on
    mismatch a field-level message is produced for the human reader.

    Returns None on match, or a human-readable mismatch string.
    """
    if got.get("kind") != expected.get("kind"):
        return f"kind mismatch: expected {expected.get('kind')!r}, got {got.get('kind')!r}"
    if got.get("kind") not in ("success", "failure"):
        return f"unknown certificate kind: {got.get('kind')!r}"

    cg = _canonical_certificate(got)
    ce = _canonical_certificate(expected)
    if cg == ce:
        return None

    if cg["kind"] == "success":
        if cg["resolved"] != ce["resolved"]:
            return (
                f"resolved mismatch:\n"
                f"  expected: {json.dumps(ce['resolved'])}\n"
                f"  got:      {json.dumps(cg['resolved'])}"
            )
        return (
            f"witness mismatch:\n"
            f"  expected: {json.dumps(ce['witness'])}\n"
            f"  got:      {json.dumps(cg['witness'])}"
        )
    return (
        f"refutation set mismatch:\n"
        f"  expected (sorted): {json.dumps(ce['refutation'])}\n"
        f"  got (sorted):      {json.dumps(cg['refutation'])}"
    )


def assert_conformance(
    run: RunResult,
    fixture_dir: Path,
) -> ConformanceResult:
    """Assert a RunResult against the fixture's expected/ tree.

    Returns a ConformanceResult; .passed is True iff all assertions held.
    """
    failures: list[AssertionFailure] = []
    normalized_outputs: dict[str, str] = {}

    # Protocol violation check (slug_error) applies to both fixture types.
    if run.slug_error is not None:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="harness-error",
            detail=run.slug_error,
        ))
        return ConformanceResult(run=run, passed=False, failures=failures,
                                 normalized_outputs={})

    expected_dir = fixture_dir / "expected"
    error_file = expected_dir / "error"
    is_error_fixture = error_file.exists()

    cmd_file = fixture_dir / "cmd"
    cmd = cmd_file.read_text().strip() if cmd_file.exists() else "resolve"

    if _is_check_certificate_cmd(cmd):
        _assert_check_certificate_fixture(
            run, fixture_dir, expected_dir, cmd, is_error_fixture,
            failures, normalized_outputs,
        )
    elif is_error_fixture:
        _assert_error_fixture(run, fixture_dir, expected_dir, cmd, failures, normalized_outputs)
    elif _is_liveness_cmd(cmd):
        _assert_liveness_fixture(run, failures, normalized_outputs)
    else:
        _assert_success_fixture(run, expected_dir, cmd, failures, normalized_outputs)

    passed = len(failures) == 0
    return ConformanceResult(
        run=run,
        passed=passed,
        failures=failures,
        normalized_outputs=normalized_outputs,
    )


# ---------------------------------------------------------------------------
# check-certificate fixture assertions (conformance-fixtures §2.7.3)
# ---------------------------------------------------------------------------


def _assert_check_certificate_fixture(
    run: RunResult,
    fixture_dir: Path,
    expected_dir: Path,
    cmd: str,
    is_error_fixture: bool,
    failures: list[AssertionFailure],
    normalized_outputs: dict[str, str],
) -> None:
    """Assert a check-certificate fixture.

    1. Assert certificate.json was emitted (run.cert_path must exist).
    2. Compare emitted JSON to expected/certificate.json (canonical comparison).
    3. Assert the normal exit/slug outcome (same as a resolve or error fixture).
    """
    # Step 1: certificate file must exist (unless the resolver never ran —
    # a non-resolver error like MAN-KDL-SYNTAX won't have a cert).
    cert_file = Path(run.cert_path) if run.cert_path else None
    expected_cert_path = expected_dir / "certificate.json"

    if expected_cert_path.exists():
        # Fixture declares a certificate — impl must have written one.
        if cert_file is None or not cert_file.exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="success-fixture",
                detail=(
                    f"check-certificate: impl did not write certificate to {run.cert_path!r} "
                    f"(expected it to exist after the verb)"
                ),
            ))
        else:
            try:
                got_cert = json.loads(cert_file.read_text(encoding="utf-8"))
                expected_cert = json.loads(expected_cert_path.read_text(encoding="utf-8"))
                mismatch = _compare_certificate_json(got_cert, expected_cert)
                if mismatch:
                    failures.append(AssertionFailure(
                        fixture_name=run.fixture_name,
                        impl_name=run.impl_name,
                        kind="success-fixture",
                        detail=f"check-certificate: {mismatch}",
                    ))
                else:
                    # Cross-impl divergence token: the full canonical cert
                    # body (#130), not just kind — two impls that each match
                    # their fixture can still differ from each other in
                    # witness/resolved/refutation, and that must surface.
                    normalized_outputs["expected/certificate.json"] = json.dumps(
                        _canonical_certificate(got_cert), sort_keys=True
                    )
            except Exception as e:
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="harness-error",
                    detail=f"check-certificate: JSON parse error: {e}",
                ))

    # Step 2: normal exit/slug assertions.
    # For an error fixture: assert exit 1 + correct slug.
    # For a success fixture: assert exit 0 + no slug.
    # We strip the "resolve" cmd from the command to get the verb-level
    # assertion; _assert_error_fixture / _assert_success_fixture already handle
    # the sub-command case, so we can delegate to them but treat cmd as "resolve"
    # for their purposes (they only need to know it's not frozen/parse-lockfile).
    effective_cmd = "resolve"  # check-certificate is a resolve-class fixture
    if is_error_fixture:
        _assert_error_fixture(
            run, fixture_dir, expected_dir, effective_cmd, failures, normalized_outputs,
        )
    else:
        _assert_success_fixture(run, expected_dir, cmd, failures, normalized_outputs)


# ---------------------------------------------------------------------------
# Error fixture assertions
# ---------------------------------------------------------------------------

def _assert_error_fixture(
    run: RunResult,
    fixture_dir: Path,
    expected_dir: Path,
    cmd: str,
    failures: list[AssertionFailure],
    normalized_outputs: dict[str, str],
) -> None:
    """Assert error fixture: exit 1, correct slug, no output files."""
    error_file = expected_dir / "error"
    expected_slug = error_file.read_text().strip()

    if run.returncode != 1:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="error-fixture",
            detail=(
                f"expected exit 1, got {run.returncode}; "
                f"stderr: {run.stderr!r}"
            ),
        ))
    elif run.slug is None:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="error-fixture",
            detail=(
                f"exit 1 but no milpa-error: line found; "
                f"stderr: {run.stderr!r}"
            ),
        ))
    elif run.slug != expected_slug:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="error-fixture",
            detail=(
                f"wrong slug: expected {expected_slug!r}, got {run.slug!r}"
            ),
        ))
    else:
        # Slug matches — record for cross-impl comparison.
        normalized_outputs["expected/error"] = run.slug

    # For resolve and frozen cmds: assert no output files were left in scratch.
    # For resolve: nim.cfg is an OUTPUT — never present on error. milpa.lock is
    #   normally an output too (must be absent), BUT a §8 refetch fixture ships a
    #   prior milpa.lock as INPUT; atomic-write-on-failure then means the input
    #   must survive byte-IDENTICAL (neither removed nor partially rewritten).
    # For frozen: milpa.lock is an INPUT (copied to scratch before the run), so its
    #   presence is expected and must NOT be checked. Only nim.cfg is an output here.
    # For parse-lockfile: no scratch output files to check (we skip entirely).
    if cmd == "resolve":
        scratch = Path(run.scratch_dir)
        if (scratch / "nim.cfg").exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="error-fixture",
                detail=(
                    "error fixture left 'nim.cfg' in scratch "
                    "(expected atomic-write-on-failure to suppress it)"
                ),
            ))
        input_lock = fixture_dir / "milpa.lock"
        scratch_lock = scratch / "milpa.lock"
        if input_lock.exists():
            # §8 refetch fixture: the prior lock must be left untouched on failure.
            if not scratch_lock.exists():
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="error-fixture",
                    detail="error fixture removed the input 'milpa.lock' (expected it left unchanged)",
                ))
            elif scratch_lock.read_text() != input_lock.read_text():
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="error-fixture",
                    detail=(
                        "error fixture modified 'milpa.lock' "
                        "(expected atomic-write-on-failure to leave the prior lock unchanged)"
                    ),
                ))
        elif scratch_lock.exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="error-fixture",
                detail=(
                    "error fixture left 'milpa.lock' in scratch "
                    "(expected atomic-write-on-failure to suppress it)"
                ),
            ))
    elif cmd == "frozen":
        scratch = Path(run.scratch_dir)
        # milpa.lock is the INPUT for frozen — skip it.
        if (scratch / "nim.cfg").exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="error-fixture",
                detail=(
                    "error fixture left 'nim.cfg' in scratch "
                    "(expected atomic-write-on-failure to suppress it)"
                ),
            ))


# ---------------------------------------------------------------------------
# Liveness fixtures (show / --version) — non-frozen stdout (§2.7.2)
# ---------------------------------------------------------------------------

def _is_liveness_cmd(cmd: str) -> bool:
    """True for cmds whose stdout format is non-frozen (show, --version)."""
    head = cmd.split()[0] if cmd.split() else ""
    return head in ("show", "--version")


def _assert_liveness_fixture(
    run: RunResult,
    failures: list[AssertionFailure],
    normalized_outputs: dict[str, str],
) -> None:
    """Assert a liveness fixture: exit 0 + non-empty stdout, NO byte-compare.

    Per conformance-fixtures §2.7.2: show / --version output format is
    non-frozen for spec v1.0, so the harness checks liveness only.
    """
    if run.returncode != 0:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="success-fixture",
            detail=(
                f"liveness fixture: expected exit 0, got {run.returncode}; "
                f"stderr: {run.stderr!r}"
            ),
        ))
        return
    if run.slug is not None:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="success-fixture",
            detail=f"liveness fixture: exit 0 but milpa-error: line found: {run.slug!r}",
        ))
        return
    if not run.stdout.strip():
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="success-fixture",
            detail="liveness fixture: stdout is empty (expected non-empty)",
        ))
        return
    # Liveness passed; record a stable marker (NOT the stdout bytes, which are
    # non-frozen and would create spurious cross-impl divergences).
    normalized_outputs["<liveness>"] = "exit0+nonempty-stdout"


# ---------------------------------------------------------------------------
# Success fixture assertions
# ---------------------------------------------------------------------------

def _assert_success_fixture(
    run: RunResult,
    expected_dir: Path,
    cmd: str,
    failures: list[AssertionFailure],
    normalized_outputs: dict[str, str],
) -> None:
    """Assert success fixture: exit 0, no slug, byte-diff outputs."""
    if run.returncode != 0:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="success-fixture",
            detail=(
                f"expected exit 0, got {run.returncode}; "
                f"stderr: {run.stderr!r}"
            ),
        ))
        return

    if run.slug is not None:
        failures.append(AssertionFailure(
            fixture_name=run.fixture_name,
            impl_name=run.impl_name,
            kind="success-fixture",
            detail=f"exit 0 but milpa-error: line found: {run.slug!r}",
        ))
        return

    scratch = Path(run.scratch_dir)

    # milpa.kdl — mutation fixtures (add/remove) byte-compare the post-mutation
    # manifest (conformance-fixtures §2.4.1). Verbatim byte-diff like milpa.lock.
    expected_manifest = expected_dir / "milpa.kdl"
    if expected_manifest.exists():
        actual_manifest_path = scratch / "milpa.kdl"
        if not actual_manifest_path.exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="success-fixture",
                detail="milpa.kdl not present in scratch after mutation",
            ))
        else:
            actual = actual_manifest_path.read_text()
            expected = expected_manifest.read_text()
            if actual != expected:
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="success-fixture",
                    detail=_diff_summary("milpa.kdl", expected, actual),
                ))
            else:
                normalized_outputs["expected/milpa.kdl"] = actual

    # milpa.lock — required for success fixtures that produce it.
    expected_lock = expected_dir / "milpa.lock"
    if expected_lock.exists():
        actual_lock_path = scratch / "milpa.lock"
        if not actual_lock_path.exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="success-fixture",
                detail="milpa.lock not produced by impl",
            ))
        else:
            actual = actual_lock_path.read_text()
            expected = expected_lock.read_text()
            if actual != expected:
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="success-fixture",
                    detail=_diff_summary("milpa.lock", expected, actual),
                ))
            else:
                normalized_outputs["expected/milpa.lock"] = actual

    # nim.cfg — single-package: expected/nim.cfg; workspace: expected/<member>/nim.cfg
    # Check if there's a root expected/nim.cfg (single-package case).
    expected_nimcfg = expected_dir / "nim.cfg"
    if expected_nimcfg.exists():
        actual_nimcfg_path = scratch / "nim.cfg"
        if not actual_nimcfg_path.exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="success-fixture",
                detail="nim.cfg not produced by impl",
            ))
        else:
            actual = actual_nimcfg_path.read_text()
            expected = expected_nimcfg.read_text()
            if actual != expected:
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="success-fixture",
                    detail=_diff_summary("nim.cfg", expected, actual),
                ))
            else:
                normalized_outputs["expected/nim.cfg"] = actual

    # Workspace per-member nim.cfg: for each <member>/ subdir in expected_dir
    # that contains a nim.cfg.
    for member_dir in sorted(expected_dir.iterdir()):
        if not member_dir.is_dir():
            continue
        member_nimcfg = member_dir / "nim.cfg"
        if not member_nimcfg.exists():
            continue
        # This is a workspace member nim.cfg.
        rel = member_dir.name
        actual_member_nimcfg = scratch / rel / "nim.cfg"
        if not actual_member_nimcfg.exists():
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="success-fixture",
                detail=f"workspace member nim.cfg not produced: {rel}/nim.cfg",
            ))
        else:
            actual = actual_member_nimcfg.read_text()
            expected_text = member_nimcfg.read_text()
            key = f"expected/{rel}/nim.cfg"
            if actual != expected_text:
                failures.append(AssertionFailure(
                    fixture_name=run.fixture_name,
                    impl_name=run.impl_name,
                    kind="success-fixture",
                    detail=_diff_summary(f"{rel}/nim.cfg", expected_text, actual),
                ))
            else:
                normalized_outputs[key] = actual

    # _deps_structure.txt — normalize CAS paths before comparing.
    expected_deps = expected_dir / "_deps_structure.txt"
    if expected_deps.exists():
        normalized = _normalize_deps_structure(run.scratch_dir, run.cas_dir)
        if normalized is None:
            # _deps/ doesn't exist but fixture expects it.
            normalized = ""
        expected_text = expected_deps.read_text()
        if normalized != expected_text:
            failures.append(AssertionFailure(
                fixture_name=run.fixture_name,
                impl_name=run.impl_name,
                kind="success-fixture",
                detail=_diff_summary("_deps_structure.txt", expected_text, normalized),
            ))
        else:
            normalized_outputs["expected/_deps_structure.txt"] = normalized


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _diff_summary(filename: str, expected: str, actual: str) -> str:
    """Produce a short inline diff summary for a failure message."""
    exp_lines = expected.splitlines(keepends=True)
    act_lines = actual.splitlines(keepends=True)

    # Simple inline diff: show first diverging line.
    for i, (e, a) in enumerate(zip(exp_lines, act_lines)):
        if e != a:
            return (
                f"{filename} mismatch at line {i+1}: "
                f"expected {e!r}, got {a!r} "
                f"(total expected {len(exp_lines)} lines, got {len(act_lines)} lines)"
            )
    if len(exp_lines) != len(act_lines):
        return (
            f"{filename} mismatch: expected {len(exp_lines)} lines, "
            f"got {len(act_lines)} lines"
        )
    return f"{filename} mismatch (byte-level difference)"
