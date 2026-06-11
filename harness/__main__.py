"""Entry point: python3 -m harness

Runs the differential conformance corpus over all registered implementations
and prints the summary + divergence records.

Exits non-zero if any conformance assertion failed or any divergence was found.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Repo root is two levels up from harness/__main__.py.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"


def main() -> int:
    from harness.corpus import format_report, run_corpus
    from harness.descriptors import build_descriptors

    descriptors = build_descriptors(_REPO_ROOT)

    print(f"Conformance corpus: {_CONFORMANCE_ROOT}")
    print(f"Implementations: {[d.name for d in descriptors]}")
    print()

    report = run_corpus(_CONFORMANCE_ROOT, descriptors)
    print(format_report(report))

    return 0 if report.overall_passed() else 1


if __name__ == "__main__":
    sys.exit(main())
