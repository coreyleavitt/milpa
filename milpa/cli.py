"""milpa CLI entry point.

argparse-based dispatch. v0 subcommands (fetch / lock / show / clean)
stub out as exit-code-1 with a "not yet implemented" message — they
get real bodies in their respective issues.
"""

import argparse
import sys

from . import __version__


SUBCOMMAND_HELP = {
    "fetch": "resolve manifest, clone deps, emit nim.cfg, write lockfile",
    "lock":  "resolve manifest and write lockfile without touching _deps/",
    "show":  "print the resolved dep tree",
    "clean": "remove _deps/ and nim.cfg (keeps milpa.lock)",
}


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="milpa",
        description="Nim dependency resolver. Reads milpa.kdl, emits nim.cfg.",
    )
    parser.add_argument(
        "--version", action="version", version=f"milpa {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    for name, help_text in SUBCOMMAND_HELP.items():
        subparsers.add_parser(name, help=help_text)
    return parser


def cmd_stub(name: str) -> int:
    """Placeholder for subcommands whose bodies arrive in later issues."""
    print(f"milpa {name}: not yet implemented", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    return cmd_stub(args.command)
