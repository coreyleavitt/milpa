"""`milpa update [<name>]` — re-resolve with selective pin dropping (#18).

Targeted update: drop the named dep's pin so the resolver picks up
fresh upstream bytes. Untargeted update: drop all pins.

cmd_update does NOT mutate the manifest. Only the lockfile + _deps/
change.
"""

import pytest

from milpa.cli import cmd_update
from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.identity import compute_content_hash
from milpa.lockfile import (
    GitProvenanceRecord, LockedDep, Lockfile,
    format_lockfile, load_lockfile,
)
from milpa.manifest import Manifest, UrlDep
from milpa.manifest_writer import write_manifest
from milpa.solver import Strategy


def _setup_project_with_pinned_lockfile(tmp_path, bytes_pin: str):
    """Two-dep manifest + lockfile that pins both deps to `bytes_pin`
    identity (which won't match the fetcher's output)."""
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
    (tmp_path / "milpa.lock").write_text(format_lockfile(Lockfile(
        deps=(
            LockedDep(
                name="chronos", identity=bytes_pin, version="0.0.1",
                src_dir="", requires=(),
                provenances=(GitProvenanceRecord(
                    url="https://example.com/chronos.git", ref="main",
                    commit_sha="old",
                ),),
            ),
            LockedDep(
                name="results", identity=bytes_pin, version="0.0.1",
                src_dir="", requires=(),
                provenances=(GitProvenanceRecord(
                    url="https://example.com/results.git", ref="main",
                    commit_sha="old",
                ),),
            ),
        ),
    )))


class StubFetcher:
    """Returns generic bytes — won't match a hand-crafted bogus pin."""
    def __init__(self): self.fetched = []
    def can_handle(self, p): return isinstance(p, GitProvenance)
    def fetch(self, name, p, *, dest):
        self.fetched.append(name)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(f'srcDir = "src"  # {name}\n')
        return GitReceipt(commit_sha=f"new-{name}")


def test_cmd_update_with_name_drops_only_that_pin(tmp_path):
    """Tracer: cmd_update(name=chronos) drops chronos's pin so its
    fetch succeeds; results stays pinned and fails the pin check (so
    if pin is unaffected, results would block resolution)."""
    bogus = "sha256:" + "f" * 64
    _setup_project_with_pinned_lockfile(tmp_path, bogus)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    # Updating chronos alone — results's pin is still active and will
    # reject the fetcher's bytes. So this resolve MUST fail BECAUSE
    # of results, not chronos. That proves chronos's pin was dropped
    # (else BOTH would fail and we couldn't tell which).
    rc = cmd_update(
        tmp_path, name="chronos",
        fetcher=registry,
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )

    assert rc == 1  # results pin fails
    # chronos WAS attempted (pin was dropped, fetcher invoked)
    assert "chronos" in fetcher_impl.fetched


def test_cmd_update_without_name_drops_all_pins(tmp_path):
    """Tracer: cmd_update() — no name — drops every pin, full
    re-resolve succeeds against any bytes."""
    bogus = "sha256:" + "f" * 64
    _setup_project_with_pinned_lockfile(tmp_path, bogus)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    rc = cmd_update(
        tmp_path,
        name=None,    # no targeting → full refresh
        fetcher=registry,
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )

    assert rc == 0
    # Both deps re-fetched
    assert "chronos" in fetcher_impl.fetched
    assert "results" in fetcher_impl.fetched
    # New lockfile reflects fresh identities (not the bogus pin)
    new_lock = load_lockfile(tmp_path / "milpa.lock")
    for d in new_lock.deps:
        assert d.identity != bogus


def test_cmd_update_never_mutates_manifest(tmp_path):
    """The manifest text is byte-identical after cmd_update — update
    is a pure lockfile refresh."""
    bogus = "sha256:" + "f" * 64
    _setup_project_with_pinned_lockfile(tmp_path, bogus)
    pre = (tmp_path / "milpa.kdl").read_text()

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    rc = cmd_update(
        tmp_path,
        fetcher=registry,
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )
    assert rc == 0
    assert (tmp_path / "milpa.kdl").read_text() == pre


def test_cmd_update_unknown_name_exits_1(tmp_path, capsys):
    """Targeted update on a dep that isn't in the lockfile → exit 1."""
    bogus = "sha256:" + "f" * 64
    _setup_project_with_pinned_lockfile(tmp_path, bogus)
    pre_lock = (tmp_path / "milpa.lock").read_text()

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    rc = cmd_update(
        tmp_path, name="nonexistent",
        fetcher=registry,
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "nonexistent" in err
    # Lockfile untouched
    assert (tmp_path / "milpa.lock").read_text() == pre_lock
    # No fetches
    assert fetcher_impl.fetched == []


def test_cmd_update_no_lockfile_with_name_exits_1(tmp_path, capsys):
    """Targeted update needs a lockfile to filter."""
    from milpa.manifest_writer import write_manifest
    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )

    rc = cmd_update(
        tmp_path, name="anything",
        fetcher=FetcherRegistry(),
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "lockfile" in err.lower()


def test_argparse_routes_update_with_and_without_name():
    """CLI: `milpa update` (all) and `milpa update NAME` (targeted)."""
    from milpa.cli import make_parser

    parser = make_parser()
    # No name → dep_name is None
    args = parser.parse_args(["update"])
    assert args.command == "update"
    assert args.dep_name is None
    # Named → dep_name set
    args = parser.parse_args(["update", "chronos"])
    assert args.command == "update"
    assert args.dep_name == "chronos"
