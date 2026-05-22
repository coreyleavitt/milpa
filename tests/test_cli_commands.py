"""CLI command tests — exercise cmd_fetch / cmd_lock / cmd_show / cmd_clean
directly (no argparse roundtrip) so we can inject fake fetchers.

The tests in test_cli.py stay focused on argparse wiring + the surface."""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.cli import cmd_clean, cmd_fetch, cmd_lock, cmd_show


@dataclass
class FakeFetch:
    by_url_ref: dict[tuple[str, str], tuple[str, str, str]]
    calls: list[tuple[str, str, str]] = field(default_factory=list)

    def __call__(self, name, git, ref, *, deps_dir):
        from milpa.fetcher import FetchResult
        self.calls.append((name, git, ref))
        sha, content_hash, nimble_text = self.by_url_ref[(git, ref)]
        target = deps_dir / name
        target.mkdir(parents=True, exist_ok=True)
        (target / f"{name}.nimble").write_text(nimble_text)
        return FetchResult(
            name=name, path=target, sha=sha, content_hash=content_hash,
        )


def _write_minimal_manifest(project_dir: Path) -> None:
    (project_dir / "milpa.kdl").write_text(
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )


# Default no-op registry loader for tests that don't care about it.
# Without this, cmd_fetch's default loader hits the real network to
# fetch packages.json on each test run.
_empty_registry_loader = lambda *, cache_path: {}


def test_cmd_fetch_produces_lockfile_and_nimcfg(tmp_path):
    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc123", "hash_foo", 'srcDir = "src"\n',
        ),
    })
    rc = cmd_fetch(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    assert rc == 0
    assert (tmp_path / "milpa.lock").exists()
    assert (tmp_path / "nim.cfg").exists()
    assert (tmp_path / "_deps" / "foo").exists()
    # nim.cfg references the dep
    assert "foo" in (tmp_path / "nim.cfg").read_text()


def test_cmd_fetch_no_manifest_returns_1_with_stderr_message(tmp_path, capsys):
    # tmp_path has no milpa.kdl
    rc = cmd_fetch(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "milpa.kdl" in err
    assert "not" in err.lower() or "no manifest" in err.lower()


def test_cmd_fetch_malformed_manifest_returns_1_with_stderr_message(tmp_path, capsys):
    # Invalid KDL syntax
    (tmp_path / "milpa.kdl").write_text('deps }\nbad\n')
    rc = cmd_fetch(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "manifest" in err.lower()


def test_cmd_lock_writes_lockfile_but_not_nimcfg(tmp_path):
    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc", "hash_foo", 'srcDir = "src"\n',
        ),
    })
    rc = cmd_lock(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    assert rc == 0
    assert (tmp_path / "milpa.lock").exists()
    assert not (tmp_path / "nim.cfg").exists()


def test_cmd_show_prints_dep_names_from_existing_lockfile(tmp_path, capsys):
    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc", "hash_foo", 'srcDir = "src"\n',
        ),
    })
    cmd_fetch(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    capsys.readouterr()  # drain fetch's output

    rc = cmd_show(tmp_path)
    assert rc == 0
    out = capsys.readouterr().out
    assert "foo" in out


def test_cmd_show_labels_identity_and_provenance(tmp_path, capsys):
    """`milpa show` output positions content_hash as identity and
    URL/ref/sha as provenance — explicitly labeled, not implicit."""
    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc12345dead", "hash_foo_full_content", 'srcDir = "src"\n',
        ),
    })
    cmd_fetch(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    capsys.readouterr()

    rc = cmd_show(tmp_path)
    assert rc == 0
    out = capsys.readouterr().out

    # The model is explicit
    assert "identity" in out
    assert "provenance" in out
    # Identity value is a sha256-prefixed hash
    assert "sha256:" in out
    # Provenance shows the URL + ref + commit sha
    assert "https://example.com/foo.git" in out
    assert "main" in out


def test_cmd_show_truncates_hashes_for_readability(tmp_path, capsys):
    """`milpa show` shows truncated hashes (8 chars). Full values
    are in milpa.lock for machine-readable consumption."""
    _write_minimal_manifest(tmp_path)
    long_content_hash = "abcdef0123456789" * 4  # 64 hex chars
    long_sha = "deadbeefcafebabe" * 2 + "abcd1234"   # 40 hex chars
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            long_sha, long_content_hash, 'srcDir = "src"\n',
        ),
    })
    cmd_fetch(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    capsys.readouterr()
    cmd_show(tmp_path)
    out = capsys.readouterr().out
    # Full hashes should NOT appear in output
    assert long_content_hash not in out
    assert long_sha not in out
    # Prefix should appear
    assert long_content_hash[:8] in out
    assert long_sha[:8] in out


def test_cmd_show_requires_line_present_when_dep_has_requires(tmp_path, capsys):
    """The requires line stays as it is — it's about the dep graph,
    orthogonal to identity vs provenance."""
    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash",
            'srcDir = "src"\nrequires "https://example.com/bar.git#v1"\n',
        ),
        ("https://example.com/bar.git", "v1"): (
            "bsha", "bhash", 'srcDir = "src"\n',
        ),
    })
    cmd_fetch(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    capsys.readouterr()
    cmd_show(tmp_path)
    out = capsys.readouterr().out
    # foo lists bar as required
    assert "bar" in out
    assert "requires" in out


def test_cmd_show_registry_dep_shows_registry_provenance(tmp_path, capsys):
    """Registry-resolved deps' provenance reads `registry:<name>`."""
    from milpa.registry import RegistryEntry

    (tmp_path / "milpa.kdl").write_text(
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )

    def fake_loader(*, cache_path):
        return {
            "bar": RegistryEntry(
                name="bar", url="https://example.com/bar.git", method="git",
            ),
        }
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "fsha", "fhash", 'srcDir = "src"\nrequires "bar"\n',
        ),
        ("https://example.com/bar.git", "v0.1.0"): (
            "bsha", "bhash", '',
        ),
    })
    cmd_fetch(
        tmp_path, fetcher=fake,
        list_tags=lambda url: ["v0.1.0"],
        registry_loader=fake_loader,
    )
    capsys.readouterr()
    cmd_show(tmp_path)
    out = capsys.readouterr().out
    assert "registry:bar" in out
    # registry dep's ref is its resolved tag
    assert "v0.1.0" in out


def test_cmd_show_empty_lockfile_does_not_crash(tmp_path, capsys):
    """A lockfile with no deps prints nothing per-dep but still exits 0."""
    # Synthesize an empty lockfile directly
    from milpa.lockfile import Lockfile, format_lockfile
    empty = Lockfile(version=1, deps=())
    (tmp_path / "milpa.lock").write_text(format_lockfile(empty))
    rc = cmd_show(tmp_path)
    assert rc == 0


def test_cmd_show_no_lockfile_returns_1(tmp_path, capsys):
    # tmp_path has no milpa.lock
    rc = cmd_show(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "milpa.lock" in err or "lockfile" in err.lower()


def test_cmd_clean_removes_deps_and_nimcfg_keeps_lockfile(tmp_path):
    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc", "hash_foo", 'srcDir = "src"\n',
        ),
    })
    cmd_fetch(tmp_path, fetcher=fake, registry_loader=_empty_registry_loader)
    # Sanity: all three artifacts present
    assert (tmp_path / "_deps").exists()
    assert (tmp_path / "nim.cfg").exists()
    assert (tmp_path / "milpa.lock").exists()

    rc = cmd_clean(tmp_path)
    assert rc == 0
    assert not (tmp_path / "_deps").exists()
    assert not (tmp_path / "nim.cfg").exists()
    assert (tmp_path / "milpa.lock").exists()   # preserved


def test_cmd_clean_is_idempotent_when_nothing_to_remove(tmp_path):
    rc = cmd_clean(tmp_path)
    assert rc == 0


def test_cmd_fetch_loads_registry_and_resolves_named_transitive(tmp_path):
    """The CLI must load the registry so that named transitive deps
    (chronos's `requires "results"`, etc.) actually resolve."""
    from milpa.registry import RegistryEntry

    loader_calls: list = []

    def fake_loader(*, cache_path):
        loader_calls.append(cache_path)
        return {
            "bar": RegistryEntry(
                name="bar", url="https://example.com/bar.git", method="git",
            ),
        }

    (tmp_path / "milpa.kdl").write_text(
        'deps {\n'
        '    foo git="https://example.com/foo.git" ref="main"\n'
        '}\n'
    )

    fake_fetch = FakeFetch({
        # foo is a URL dep that requires 'bar' (a named dep)
        ("https://example.com/foo.git", "main"): (
            "abc", "hash_foo", 'requires "bar >= 0.1.0"\n',
        ),
        # bar is a named dep — registry says it's at example.com/bar.git;
        # we serve it at tag v0.1.0
        ("https://example.com/bar.git", "v0.1.0"): (
            "def", "hash_bar", '',
        ),
    })
    fake_list_tags = lambda url: ["v0.1.0"]

    rc = cmd_fetch(
        tmp_path,
        fetcher=fake_fetch,
        list_tags=fake_list_tags,
        registry_loader=fake_loader,
    )
    assert rc == 0
    assert loader_calls == [tmp_path / "_deps" / ".packages_official.json"]
    # bar appears in the lockfile (proves registry was used)
    lockfile_text = (tmp_path / "milpa.lock").read_text()
    assert "bar" in lockfile_text


def test_cmd_lock_also_loads_registry(tmp_path):
    """cmd_lock has the same need as cmd_fetch — named transitives only
    resolve if the registry is loaded."""
    from milpa.registry import RegistryEntry

    loader_calls: list = []

    def fake_loader(*, cache_path):
        loader_calls.append(cache_path)
        return {}

    _write_minimal_manifest(tmp_path)
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            "abc", "hash_foo", 'srcDir = "src"\n',
        ),
    })

    rc = cmd_lock(tmp_path, fetcher=fake, registry_loader=fake_loader)
    assert rc == 0
    assert len(loader_calls) == 1
