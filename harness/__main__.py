"""Entry point: python3 -m harness

Without a subcommand: runs the differential conformance corpus over all
registered implementations and prints the summary + divergence records.
Exits non-zero if any conformance assertion failed or any divergence was found.

Subcommands
-----------
pin <input-dir>
    Run the pin promotion workflow: run both impls on <input-dir>, emit a
    candidate fixture dir + divergence.json, take a single interactive gate
    (which impl is spec-correct), write expected/ from the winner, confirm the
    pinned fixture passes, and report the candidate path.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Repo root is two levels up from harness/__main__.py.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFORMANCE_ROOT = _REPO_ROOT / "conformance"


def _main_corpus() -> int:
    """Run the full differential corpus (the original bare behavior)."""
    from harness.corpus import format_report, run_corpus
    from harness.descriptors import build_descriptors

    descriptors = build_descriptors(_REPO_ROOT)

    print(f"Conformance corpus: {_CONFORMANCE_ROOT}")
    print(f"Implementations: {[d.name for d in descriptors]}")
    print()

    report = run_corpus(_CONFORMANCE_ROOT, descriptors)
    print(format_report(report))

    return 0 if report.overall_passed() else 1


def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with optional subcommands."""
    parser = argparse.ArgumentParser(
        prog="python3 -m harness",
        description=(
            "Milpa differential conformance harness.\n\n"
            "Without a subcommand: run the full corpus against all registered impls.\n"
            "With a subcommand: see below."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="subcommand")

    pin_parser = sub.add_parser(
        "pin",
        help=(
            "Run the pin promotion workflow: run both impls on <input-dir>, "
            "emit a candidate fixture dir + divergence.json, take a single "
            "interactive gate (which impl is spec-correct), write expected/ "
            "from the winner, confirm the pinned fixture passes, and report "
            "the candidate path."
        ),
    )
    pin_parser.add_argument(
        "input_dir",
        metavar="<input-dir>",
        help=(
            "Fixture or input directory to run both impls against. "
            "Must contain at least a milpa.kdl and optionally cmd, env, "
            "mocked-fetches/, etc."
        ),
    )
    pin_parser.add_argument(
        "--candidate-dir",
        dest="candidate_dir",
        default=None,
        metavar="<dir>",
        help=(
            "Where to write the candidate fixture (default: "
            "<input-dir>-candidate/ as a sibling of <input-dir>)."
        ),
    )
    pin_parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        metavar="<seconds>",
        help="Per-impl subprocess timeout in seconds (default: 180).",
    )

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.subcommand == "pin":
        from harness.pin import cmd_pin
        return cmd_pin(args)

    # Default: no subcommand → run the full corpus.
    return _main_corpus()


if __name__ == "__main__":
    sys.exit(main())
