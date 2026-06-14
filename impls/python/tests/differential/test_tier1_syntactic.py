"""Tier-1 syntactic differential test — gated.

Gate: MILPA_DIFFERENTIAL_TESTS=1 AND the Rust binary must exist.
When skipped, does so cleanly so normal `uv run pytest` is unaffected.

The differential loop:
  1. Hypothesis generates a RawManifestInput (malformed milpa.kdl).
  2. serialize it to a fresh temp dir.
  3. Run it through ALL registered impls (subprocess, black-box).
  4. Assert they AGREE on exit-class + slug.

On failure Hypothesis shrinks the input natively (it is a structured
dataclass value — text field shrinks toward the empty string).
The assertion message prints per-impl outcomes + the minimized input.

Settings: max_examples=50, deadline=None (subprocess calls are slow).
"""

from __future__ import annotations

# Trigger the bridge (repo-root -> sys.path) before any harness import.
import differential  # noqa: F401

import os
import shutil
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings

from differential.loop import agreement, run_all_impls
from differential.strategies import RawManifestInput, malformed_manifest_st, write_raw_fixture
from harness.descriptors import build_descriptors

# ---------------------------------------------------------------------------
# Gate condition
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
_RUST_BIN = _REPO_ROOT / "impls" / "rust" / "target" / "release" / "milpa"

_DIFFERENTIAL_ENABLED = os.environ.get("MILPA_DIFFERENTIAL_TESTS") == "1"
_RUST_BIN_PRESENT = _RUST_BIN.exists()

_SKIP_REASON = (
    "set MILPA_DIFFERENTIAL_TESTS=1 (and ensure impls/rust/target/release/milpa exists) "
    "to run cross-impl differential tests"
    if not _RUST_BIN_PRESENT
    else "set MILPA_DIFFERENTIAL_TESTS=1 to run cross-impl differential tests"
)

pytestmark = pytest.mark.skipif(
    not (_DIFFERENTIAL_ENABLED and _RUST_BIN_PRESENT),
    reason=_SKIP_REASON,
)

# ---------------------------------------------------------------------------
# Descriptors (built once for the module)
# ---------------------------------------------------------------------------

_DESCRIPTORS = build_descriptors(_REPO_ROOT)


# ---------------------------------------------------------------------------
# Tier-1 differential test
# ---------------------------------------------------------------------------

@given(malformed_manifest_st())
@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_tier1_syntactic_agreement(inp: RawManifestInput) -> None:
    """All impls must agree on exit-class + slug for any malformed manifest input.

    Property: for every generated malformed milpa.kdl, all registered impls
    produce the SAME exit class AND (when both fail) the SAME error slug.

    On Hypothesis failure the assertion message includes:
      - The minimized input text
      - Per-impl: returncode, exit_class, slug
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="milpa-diff-t1-"))
    results: dict = {}
    try:
        write_raw_fixture(inp, tmp_dir)
        results = run_all_impls(tmp_dir, _DESCRIPTORS, timeout=30)
        div = agreement(results, fixture_id=f"tier1:{tmp_dir.name}", cmd=inp.cmd)

        if div is not None:
            # Build a detailed assertion message for human triage.
            detail_lines = [
                "",
                "=== DIFFERENTIAL DIVERGENCE FOUND ===",
                f"cmd:   {inp.cmd!r}",
                f"input: {inp.text!r}",
                "",
                "Per-impl outcomes:",
            ]
            for impl_name, result in results.items():
                from differential.loop import _exit_class
                detail_lines.append(
                    f"  {impl_name}: rc={result.returncode} "
                    f"class={_exit_class(result)!r} "
                    f"slug={result.slug!r}"
                )
                if result.stderr.strip():
                    # Show last 5 lines of stderr for context.
                    last_lines = result.stderr.strip().splitlines()[-5:]
                    detail_lines.append(f"    stderr (last {len(last_lines)} lines):")
                    for line in last_lines:
                        detail_lines.append(f"      {line}")
            detail_lines += [
                "",
                "Divergence JSON:",
                div.to_json(),
                "=== END DIVERGENCE ===",
            ]
            assert False, "\n".join(detail_lines)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        for run_result in results.values():
            run_result.cleanup()
