"""`milpa remove <name>` — drop a dep from manifest + regenerate lockfile (#17).

Uses apply_manifest_change_with_resolve for atomic two-file commit.
Orphaned transitives disappear naturally via full re-resolve from the
trimmed manifest.
"""

import pytest

from milpa.cli import cmd_remove
from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.lockfile import (
    GitProvenanceRecord, LockedDep, Lockfile,
    format_lockfile, load_lockfile,
)
from milpa.manifest import Manifest, UrlDep, parse_manifest
from milpa.manifest_writer import write_manifest
from milpa.solver import Strategy


def _setup_two_dep_project(tmp_path):
    """Manifest with chronos + results. No prior lockfile — the
    post-remove re-resolve generates one from scratch."""
    write_manifest(
        Manifest(
            kind="library", name="proj",
            deps=(
                UrlDep(name="chronos",
                       git="https://example.com/chronos.git", ref="main"),
                UrlDep(name="results",
                       git="https://example.com/results.git", ref="main"),
            ),
        ),
        tmp_path / "milpa.kdl",
    )


class StubFetcher:
    def __init__(self): self.fetched = []
    def can_handle(self, p): return isinstance(p, GitProvenance)
    def fetch(self, name, p, *, dest):
        self.fetched.append(name)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        return GitReceipt(commit_sha="abc")


def test_cmd_remove_drops_dep_from_manifest_and_regenerates_lockfile(tmp_path):
    """Tracer: cmd_remove drops chronos from manifest; the new lockfile
    has only results."""
    _setup_two_dep_project(tmp_path)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    rc = cmd_remove(
        tmp_path, name="chronos",
        fetcher=registry,
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )

    assert rc == 0
    reparsed = parse_manifest((tmp_path / "milpa.kdl").read_text())
    names = {d.name for d in reparsed.deps}
    assert "chronos" not in names
    assert "results" in names
    # Lockfile regenerated — chronos absent, results present
    locked = load_lockfile(tmp_path / "milpa.lock")
    locked_names = {d.name for d in locked.deps}
    assert "chronos" not in locked_names
    assert "results" in locked_names


def test_cmd_remove_unknown_name_exits_1_without_mutating(tmp_path, capsys):
    """Refuse cleanly when the named dep isn't in the manifest."""
    _setup_two_dep_project(tmp_path)
    original_text = (tmp_path / "milpa.kdl").read_text()

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    rc = cmd_remove(
        tmp_path, name="nonexistent",
        fetcher=registry,
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )

    assert rc == 1
    err = capsys.readouterr().err
    assert "nonexistent" in err
    assert "chronos" in err   # lists known
    # Manifest untouched
    assert (tmp_path / "milpa.kdl").read_text() == original_text
    # No fetches happened
    assert fetcher_impl.fetched == []


def test_argparse_routes_remove_to_cmd_remove():
    """CLI: `milpa remove NAME` parses and routes correctly."""
    from milpa.cli import make_parser

    parser = make_parser()
    args = parser.parse_args(["remove", "chronos"])
    assert args.command == "remove"
    assert args.dep_name == "chronos"
