"""`milpa add <name> --git <url> [--ref <ref>]` for brand-new deps (#16).

Validates by running a full resolve over the proposed manifest; only
commits manifest + lockfile if resolution succeeds. cargo / uv shape:
the manifest mutation is *contingent* on the full graph resolving.

Default branch is discovered via `git ls-remote --symref HEAD` when
--ref is omitted; users can override with --ref.
"""

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.cli import cmd_add
from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt
from milpa.lockfile import load_lockfile
from milpa.manifest import Manifest, UrlDep, parse_manifest
from milpa.manifest_writer import write_manifest
from milpa.solver import Strategy


def _setup_empty_project(tmp_path):
    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )


class StubFetcher:
    """Serves any GitProvenance with a minimal .nimble. Records calls
    for ordering assertions."""

    def __init__(self):
        self.calls: list[tuple[str, str]] = []   # (url, ref)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((p.url, p.ref))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
        return GitReceipt(commit_sha="abc")


def test_cmd_add_discovers_default_branch_and_appends_dep(tmp_path):
    """Tracer: cmd_add(name, git=URL) — without --ref — uses the
    default-branch discoverer to pick the ref, fetches, appends a
    UrlDep, writes both files."""
    _setup_empty_project(tmp_path)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    rc = cmd_add(
        tmp_path,
        name="chronos",
        git="https://example.com/chronos.git",
        ref=None,
        fetcher=registry,
        list_tags=lambda url: [],
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
        default_branch_discoverer=lambda url: "main",
    )

    assert rc == 0
    reparsed = parse_manifest((tmp_path / "milpa.kdl").read_text())
    assert len(reparsed.deps) == 1
    dep = reparsed.deps[0]
    assert isinstance(dep, UrlDep)
    assert dep.name == "chronos"
    assert dep.git == "https://example.com/chronos.git"
    assert dep.ref == "main"
    # Lockfile has the new dep
    lockfile = load_lockfile(tmp_path / "milpa.lock")
    assert any(d.name == "chronos" for d in lockfile.deps)
    # Fetcher was invoked with the discovered ref
    assert ("https://example.com/chronos.git", "main") in fetcher_impl.calls


def test_cmd_add_explicit_ref_skips_default_branch_discovery(tmp_path):
    """--ref REF: the discoverer is NEVER consulted; the explicit
    ref is used directly."""
    _setup_empty_project(tmp_path)

    fetcher_impl = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher_impl)

    def exploding_discoverer(url):
        raise AssertionError(
            "default-branch discovery must not run when --ref is given"
        )

    rc = cmd_add(
        tmp_path,
        name="chronos",
        git="https://example.com/chronos.git",
        ref="feat/contextvars",
        fetcher=registry,
        list_tags=lambda url: [],
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
        default_branch_discoverer=exploding_discoverer,
    )

    assert rc == 0
    reparsed = parse_manifest((tmp_path / "milpa.kdl").read_text())
    assert reparsed.deps[0].ref == "feat/contextvars"


def test_cmd_add_refuses_when_dep_name_already_declared(tmp_path, capsys):
    """Pre-existing dep with the same name → exit 1, manifest +
    lockfile unchanged."""
    write_manifest(
        Manifest(
            kind="library", name="proj",
            deps=(UrlDep(
                name="chronos",
                git="https://existing.example.com/chronos.git",
                ref="main",
            ),),
        ),
        tmp_path / "milpa.kdl",
    )
    original = (tmp_path / "milpa.kdl").read_text()

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError(
                "fetcher must not run when dep is duplicate"
            )

    registry = FetcherRegistry()
    registry.register(ExplodingFetcher())

    rc = cmd_add(
        tmp_path,
        name="chronos",
        git="https://other.example.com/chronos.git",
        ref="main",
        fetcher=registry,
        list_tags=lambda url: [],
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
        default_branch_discoverer=lambda url: "main",
    )

    assert rc == 1
    err = capsys.readouterr().err
    assert "chronos" in err
    assert "already" in err.lower() or "update" in err.lower()
    assert (tmp_path / "milpa.kdl").read_text() == original


def test_cmd_add_exits_when_default_branch_query_fails(tmp_path, capsys):
    """If the default-branch discoverer raises (offline / bad URL),
    cmd_add exits 1 BEFORE any disk writes and tells the user to
    pass --ref explicitly."""
    _setup_empty_project(tmp_path)
    original = (tmp_path / "milpa.kdl").read_text()

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError(
                "fetch must not run when default-branch query failed"
            )

    registry = FetcherRegistry()
    registry.register(ExplodingFetcher())

    def failing_discoverer(url):
        raise RuntimeError("simulated network failure")

    rc = cmd_add(
        tmp_path,
        name="x",
        git="https://broken.example.com/x.git",
        ref=None,
        fetcher=registry,
        list_tags=lambda url: [],
        registry_loader=lambda *, cache_path: {},
        strategy=Strategy.MAXVER,
        default_branch_discoverer=failing_discoverer,
    )

    assert rc == 1
    err = capsys.readouterr().err
    assert "default branch" in err.lower() or "--ref" in err
    assert (tmp_path / "milpa.kdl").read_text() == original
    assert not (tmp_path / "milpa.lock").exists()


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_argparse_routes_milpa_add_url_through_cmd_add_with_mutual_exclusion(
    tmp_path, capsys,
):
    """argparse wires `milpa add NAME --git URL --ref REF` to cmd_add,
    and rejects combinations of --git + --mirror as mutually exclusive."""
    from milpa.cli import make_parser

    parser = make_parser()
    # Valid: name + --git + --ref
    args = parser.parse_args(["add", "x", "--git", "https://x", "--ref", "main"])
    assert args.command == "add"
    assert args.dep_name == "x"
    assert args.git == "https://x"
    assert args.ref == "main"
    assert args.mirror is None

    # Mutually exclusive: --git + --mirror
    with pytest.raises(SystemExit):
        parser.parse_args([
            "add", "x", "--git", "https://a", "--mirror", "https://b",
        ])
