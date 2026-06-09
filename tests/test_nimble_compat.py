"""Tests for .nimble-as-manifest auto-promotion.

When a project has no milpa.kdl but does have a <name>.nimble, milpa
reads the requires lines and treats the .nimble as the manifest. This
removes the biggest adoption-friction blocker — existing Nim projects
don't need a parallel manifest to use milpa.
"""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.cli import cmd_fetch
from milpa.fetchers import FetcherRegistry
from milpa.tianguis_client import Index
from milpa.fetchers.git import GitProvenance, GitReceipt


@dataclass
class FakeFetch:
    """Fetcher protocol implementation. Fixture middle field
    (legacy content_hash) is ignored — milpa computes identity itself."""
    by_url_ref: dict[tuple[str, str], tuple[str, str, str]]
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def can_handle(self, p):
        return isinstance(p, GitProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append((name, p.url, p.ref))
        sha, _legacy_hash, nimble_text = self.by_url_ref[(p.url, p.ref)]
        dest.mkdir(parents=True, exist_ok=True)
        (dest / f"{name}.nimble").write_text(nimble_text)
        return GitReceipt(commit_sha=sha)


def _as_registry(fake: "FakeFetch") -> FetcherRegistry:
    reg = FetcherRegistry()
    reg.register(fake)
    return reg


_empty_index = lambda *, cache_dir: Index({})


def test_cmd_fetch_reads_nimble_when_no_milpa_kdl(tmp_path):
    # No milpa.kdl; a .nimble with one URL requires
    (tmp_path / "myproject.nimble").write_text(
        'requires "https://example.com/foo.git#main"\n'
    )
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc123", "hash_foo", 'srcDir = "src"\n',
        ),
    })
    rc = cmd_fetch(tmp_path, fetcher=_as_registry(fake), index_loader=_empty_index)
    assert rc == 0
    assert (tmp_path / "milpa.lock").exists()
    assert (tmp_path / "nim.cfg").exists()
    # Verify the dep landed
    assert "foo" in (tmp_path / "nim.cfg").read_text()


def test_no_manifest_at_all_errors_mentioning_both_filenames(tmp_path, capsys):
    # tmp_path is empty
    rc = cmd_fetch(tmp_path, index_loader=_empty_index)
    assert rc == 1
    err = capsys.readouterr().err
    assert "milpa.kdl" in err
    assert ".nimble" in err


def test_milpa_kdl_wins_when_both_present(tmp_path):
    # milpa.kdl declares "foo"; .nimble declares "bar". milpa.kdl wins.
    (tmp_path / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )
    (tmp_path / "myproject.nimble").write_text(
        'requires "https://example.com/bar.git#main"\n'
    )
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "fooo", "hash_foo", 'srcDir = "src"\n',
        ),
        # bar deliberately absent — if .nimble were read, the fetch would KeyError
    })
    rc = cmd_fetch(tmp_path, fetcher=_as_registry(fake), index_loader=_empty_index)
    assert rc == 0
    # Only foo got fetched, not bar
    assert [c[0] for c in fake.calls] == ["foo"]
    assert "foo" in (tmp_path / "nim.cfg").read_text()
    assert "bar" not in (tmp_path / "nim.cfg").read_text()


def test_nimble_with_named_dep_resolves_via_registry(tmp_path):
    """A .nimble with a named (registry-resolved) dep — milpa fetches it
    via the index path. Test injects a synthetic tianguis index."""
    from tests.indexkdl import make_index

    (tmp_path / "myproject.nimble").write_text(
        'requires "results >= 0.1.0"\n'
    )

    index = make_index([
        {"name": "results", "version": "0.5.0",
         "url": "https://example.com/results.git", "ref": "v0.5.0"},
    ])

    fake = FakeFetch({
        # Write the standard default nimble so make_index's auto-computed
        # content_hash matches the recomputed identity (H1 fix).
        ("https://example.com/results.git", "v0.5.0"): (
            "rsha", "rhash", 'srcDir = "src"\n',
        ),
    })

    rc = cmd_fetch(
        tmp_path,
        fetcher=_as_registry(fake),
        index_loader=lambda *, cache_dir: index,
    )
    assert rc == 0
    assert "results" in (tmp_path / "nim.cfg").read_text()


def test_nimble_with_mixed_url_and_named_deps(tmp_path):
    from tests.indexkdl import make_index

    (tmp_path / "myproject.nimble").write_text(
        'requires "https://example.com/foo.git#main", "results"\n'
    )

    index = make_index([
        {"name": "results", "version": "0.5.0",
         "url": "https://example.com/results.git", "ref": "v0.5.0"},
    ])
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash", 'srcDir = "src"\n',
        ),
        # Write the standard default nimble so make_index's auto-computed
        # content_hash matches the recomputed identity (H1 fix).
        ("https://example.com/results.git", "v0.5.0"): (
            "rsha", "rhash", 'srcDir = "src"\n',
        ),
    })

    rc = cmd_fetch(
        tmp_path,
        fetcher=_as_registry(fake),
        index_loader=lambda *, cache_dir: index,
    )
    assert rc == 0
    cfg = (tmp_path / "nim.cfg").read_text()
    assert "foo" in cfg
    assert "results" in cfg


def test_multiple_nimble_files_resolves_to_project_named_one(tmp_path):
    """If there are multiple .nimble files, milpa picks the one matching
    the project directory name. (The directory name is whatever tmp_path
    gives us — usually 'test_NNN0' under pytest.) Renaming the project
    dir for this test is awkward; instead we use the basename-match
    heuristic explicitly."""
    # Create a subdir we can rename for the test
    project = tmp_path / "myproj"
    project.mkdir()
    # Two .nimble files, one matches the dir name
    (project / "myproj.nimble").write_text(
        'requires "https://example.com/foo.git#main"\n'
    )
    (project / "other.nimble").write_text(
        'requires "https://example.com/bar.git#main"\n'
    )
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash", 'srcDir = "src"\n',
        ),
        # bar deliberately absent — only myproj.nimble should be read
    })
    rc = cmd_fetch(project, fetcher=_as_registry(fake), index_loader=_empty_index)
    assert rc == 0
    assert [c[0] for c in fake.calls] == ["foo"]


def test_ambiguous_nimble_files_with_no_match_errors(tmp_path, capsys):
    """If there are multiple .nimble files and none matches the project
    name, milpa won't guess — it errors with a clear message."""
    project = tmp_path / "myproj"
    project.mkdir()
    (project / "alpha.nimble").write_text(
        'requires "https://example.com/foo.git#main"\n'
    )
    (project / "beta.nimble").write_text(
        'requires "https://example.com/bar.git#main"\n'
    )
    rc = cmd_fetch(project, index_loader=_empty_index)
    assert rc == 1
    err = capsys.readouterr().err
    assert "multiple" in err.lower()
    assert "alpha.nimble" in err
    assert "beta.nimble" in err


def test_malformed_nimble_errors_with_context(tmp_path, capsys):
    # Create a .nimble file with content that the nimble parser will
    # accept structurally but where dep resolution fails downstream.
    # Most "malformed" cases in nimble are actually silent because the
    # line-scanner tolerates a lot — the realistic failure is the
    # parser ManifestError from load_or_discover_manifest. Test that
    # path: an UNREADABLE .nimble (we make it a directory).
    project = tmp_path / "myproj"
    project.mkdir()
    (project / "myproj.nimble").mkdir()  # not a regular file
    rc = cmd_fetch(project, index_loader=_empty_index)
    assert rc == 1
    err = capsys.readouterr().err
    assert "myproj.nimble" in err or "manifest" in err.lower()


def test_discovery_of_unreadable_nimble_raises_man_file_unreadable(tmp_path):
    """The discovery layer (load_or_discover_manifest → _load_manifest_from_nimble)
    delegates the read to load_nimble (the single .nimble reader) and translates
    its nimble-layer NimbleParseError into the discovery layer's ManifestError
    contract: an unreadable .nimble surfaces as MAN-FILE-UNREADABLE (the same
    generic 'manifest unreadable' code milpa.kdl reads use), NOT a leaked
    NimbleParseError. CLI callers catch `except ManifestError`, so the
    contract type matters."""
    from milpa.manifest import ManifestError, load_or_discover_manifest

    project = tmp_path / "proj"
    project.mkdir()
    (project / "proj.nimble").mkdir()  # exists but not a readable file
    with pytest.raises(ManifestError) as exc:
        load_or_discover_manifest(project)
    assert exc.value.code == "MAN-FILE-UNREADABLE"


def test_nimble_with_nim_compiler_requires_is_skipped(tmp_path):
    """`requires \"nim >= 2.0.0\"` is a compiler version constraint, not a
    source dep. milpa drops it at conversion time — handled by the v2
    toolchain RFC, not source resolution."""
    (tmp_path / "myproject.nimble").write_text(
        'requires "nim >= 2.0.0"\n'
        'requires "https://example.com/foo.git#main"\n'
    )
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash", 'srcDir = "src"\n',
        ),
    })
    rc = cmd_fetch(tmp_path, fetcher=_as_registry(fake), index_loader=_empty_index)
    assert rc == 0
    # nim should not appear as a dep
    cfg = (tmp_path / "nim.cfg").read_text()
    assert "_deps/nim" not in cfg
    # lockfile should not have a 'nim' dep either
    lock = (tmp_path / "milpa.lock").read_text()
    assert 'dep "nim"' not in lock
