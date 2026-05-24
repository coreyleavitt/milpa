"""CLI command tests — exercise cmd_fetch / cmd_lock / cmd_show / cmd_clean
directly (no argparse roundtrip) so we can inject fake fetchers.

The tests in test_cli.py stay focused on argparse wiring + the surface."""

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from milpa.cli import cmd_clean, cmd_fetch, cmd_lock, cmd_show, cmd_verify
from milpa.fetchers import FetcherRegistry
from milpa.fetchers.git import GitProvenance, GitReceipt


@dataclass
class FakeFetch:
    """Fetcher protocol implementation. Fixtures are kept as 3-tuples
    `(sha, _legacy_content_hash, nimble_text)` for fixture-shape stability;
    the middle field is ignored since milpa computes content_hash from
    bytes itself via the registry.

    Calling FakeFetch(by_url_ref) returns a FetcherRegistry with the
    fake registered, so test sites read `fetcher=FakeFetch({...})`
    unchanged."""
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


def _write_minimal_manifest(project_dir: Path) -> None:
    (project_dir / "milpa.kdl").write_text(
        'name "test"\n'
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
    rc = cmd_fetch(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
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
    rc = cmd_lock(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
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
    cmd_fetch(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
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
    cmd_fetch(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
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
    from milpa.lockfile import load_lockfile
    _write_minimal_manifest(tmp_path)
    long_sha = "deadbeefcafebabe" * 2 + "abcd1234"   # 40 hex chars
    fake = FakeFetch({
        ("https://example.com/foo.git", "main"): (
            long_sha, "ignored", 'srcDir = "src"\n',
        ),
    })
    cmd_fetch(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
    # Read the actual content_hash milpa computed from the bytes.
    # Multihash form (#34) — `sha256:` + 64-char digest.
    locked = load_lockfile(tmp_path / "milpa.lock")
    actual_hash = locked.deps[0].identity
    assert actual_hash and actual_hash.startswith("sha256:")
    actual_digest = actual_hash.split(":", 1)[1]
    assert len(actual_digest) == 64

    capsys.readouterr()
    cmd_show(tmp_path)
    out = capsys.readouterr().out
    # Full hashes should NOT appear in output
    assert actual_digest not in out
    assert long_sha not in out
    # 8-char digest prefix shown (after the `sha256:` algorithm tag)
    assert actual_digest[:8] in out
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
    cmd_fetch(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
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
        'name "test"\n'
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
        tmp_path, fetcher=_as_registry(fake),
        list_tags=lambda url: ["v0.1.0"],
        registry_loader=fake_loader,
    )
    capsys.readouterr()
    cmd_show(tmp_path)
    out = capsys.readouterr().out
    # v2 schema displays registry provenance as `registry <name>` (kind
    # prefix + name); the tag appears after `@`
    assert "registry bar" in out
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
    cmd_fetch(tmp_path, fetcher=_as_registry(fake), registry_loader=_empty_registry_loader)
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


def _verify_test_registry(nimble_text='srcDir = "src"\n', sha="abc"):
    """Build a registry for the verify-test scenarios. Writes a synthetic
    nimble for the canonical 'foo' dep; the registry computes content_hash
    so the lockfile and on-disk bytes agree (verify won't flag drift)."""
    return _as_registry(FakeFetch({
        ("https://example.com/foo.git", "main"): (sha, "ignored", nimble_text),
    }))


def test_cmd_verify_clean_tree_exits_zero(tmp_path):
    """Right after a fresh fetch, every dep's bytes match its lockfile
    identity — verify should report no drift."""
    _write_minimal_manifest(tmp_path)

    cmd_fetch(tmp_path, fetcher=_verify_test_registry(sha="abc123"),
              registry_loader=_empty_registry_loader)

    rc = cmd_verify(tmp_path)
    assert rc == 0


def test_cmd_verify_detects_tampered_file(tmp_path, capsys):
    """A modified file in _deps/<dep>/ flips the content_hash; verify
    must detect this and name the affected dep."""
    _write_minimal_manifest(tmp_path)

    cmd_fetch(tmp_path, fetcher=_verify_test_registry(),
              registry_loader=_empty_registry_loader)
    capsys.readouterr()

    # Tamper: append to the .nimble file
    nimble = tmp_path / "_deps" / "foo" / "foo.nimble"
    nimble.write_text(nimble.read_text() + "# malicious comment\n")

    rc = cmd_verify(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "foo" in err
    assert "mismatch" in err


def test_cmd_verify_detects_missing_dep_directory(tmp_path, capsys):
    """A locked dep whose _deps/<name>/ directory has been removed
    surfaces as 'missing'."""
    import shutil
    _write_minimal_manifest(tmp_path)

    cmd_fetch(tmp_path, fetcher=_verify_test_registry(),
              registry_loader=_empty_registry_loader)
    capsys.readouterr()

    shutil.rmtree(tmp_path / "_deps" / "foo")

    rc = cmd_verify(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "foo" in err
    assert "missing" in err


def test_cmd_verify_detects_extra_dep_directory(tmp_path, capsys):
    """An extra directory in _deps/ that isn't a locked dep flags as
    'extra'. The user manually added something, or a stale dep
    wasn't cleaned up."""
    _write_minimal_manifest(tmp_path)

    cmd_fetch(tmp_path, fetcher=_verify_test_registry(),
              registry_loader=_empty_registry_loader)
    capsys.readouterr()

    # Plant a rogue dep dir
    rogue = tmp_path / "_deps" / "rogue"
    rogue.mkdir()
    (rogue / "evil.nim").write_text("# unauthorized\n")

    rc = cmd_verify(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "rogue" in err
    assert "extra" in err


def test_cmd_verify_ignores_dotfiles_in_deps_dir(tmp_path):
    """Dotfiles like .packages_official.json (registry cache) should
    NOT flag as extra."""
    _write_minimal_manifest(tmp_path)

    cmd_fetch(tmp_path, fetcher=_verify_test_registry(),
              registry_loader=_empty_registry_loader)

    # Plant a dotfile (the registry cache uses this pattern)
    (tmp_path / "_deps" / ".packages_official.json").write_text("{}")

    rc = cmd_verify(tmp_path)
    assert rc == 0


def test_cmd_verify_detects_in_place_edit_to_local_dep(tmp_path, capsys):
    """Acceptance from #42: editing a file in a LocalDep's source dir
    between fetch and verify must be detected. The lockfile records
    the identity at fetch time; verify recomputes from dest bytes; the
    user's in-place edit propagates to dest only on the next fetch, so
    the as-of-fetch hash and the live hash diverge.

    Actually subtler: copy semantics means dest is a SNAPSHOT, so an
    edit to SOURCE doesn't change dest's bytes — verify still passes.
    The user must edit DEST (or re-run fetch) to invalidate. So this
    test pins: edits to the dest tree (which is what _deps/<name> is
    after a local fetch) flip the verify result, same as for any
    other transport."""
    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "intonaco"
    source.mkdir()
    (source / "intonaco.nimble").write_text('srcDir = "src"\n')
    (project / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    intonaco local="../intonaco"\n'
        '}\n'
    )

    rc = cmd_fetch(project, registry_loader=_empty_registry_loader)
    assert rc == 0
    capsys.readouterr()

    # Tamper with the COPIED tree at _deps/intonaco
    nimble = project / "_deps" / "intonaco" / "intonaco.nimble"
    nimble.write_text(nimble.read_text() + "# tampered\n")

    rc = cmd_verify(project)
    assert rc == 1
    err = capsys.readouterr().err
    assert "intonaco" in err
    assert "mismatch" in err


def test_cmd_verify_warns_when_local_source_has_drifted(tmp_path, capsys):
    """For LocalDeps, verify additionally checks whether the source dir
    has drifted from the lockfile snapshot, even though dest is intact.

    Local provenance is the only transport where source can change
    between fetches without milpa knowing — git/tarball/etc fetch
    immutable refs. The warning hints the user to re-`milpa fetch` to
    refresh the snapshot.

    Warnings do NOT flip the exit code — they're informational. The
    snapshot at _deps/<name> still matches the lockfile; verify is
    correct to call that 'clean'."""
    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "intonaco"
    source.mkdir()
    (source / "intonaco.nimble").write_text('srcDir = "src"\n')
    (project / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    intonaco local="../intonaco"\n'
        '}\n'
    )

    cmd_fetch(project, registry_loader=_empty_registry_loader)
    capsys.readouterr()

    # Edit SOURCE (not dest). Dest snapshot still matches the lockfile.
    (source / "intonaco.nimble").write_text(
        'srcDir = "src"\n# edited after fetch\n'
    )

    rc = cmd_verify(project)
    # Exit 0 — dest is intact, lockfile matches dest
    assert rc == 0
    err = capsys.readouterr().err
    assert "warning" in err.lower()
    assert "intonaco" in err
    assert "drift" in err.lower() or "drifted" in err.lower()


def test_cmd_verify_does_not_warn_when_local_source_matches_snapshot(tmp_path, capsys):
    """No-op case: source unchanged since fetch → no warning."""
    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "intonaco"
    source.mkdir()
    (source / "intonaco.nimble").write_text('srcDir = "src"\n')
    (project / "milpa.kdl").write_text(
        'name "test"\n'
        'deps {\n'
        '    intonaco local="../intonaco"\n'
        '}\n'
    )

    cmd_fetch(project, registry_loader=_empty_registry_loader)
    capsys.readouterr()

    rc = cmd_verify(project)
    assert rc == 0
    err = capsys.readouterr().err
    assert "warning" not in err.lower()


def test_cmd_fetch_detects_workspace_root_and_runs_workspace_pipeline(tmp_path):
    """cmd_fetch on a workspace root → resolve_workspace + write
    per-member nim.cfgs + write shared lockfile at root."""
    # Workspace at tmp_path with one member; member has no deps so we
    # don't need a registry loader (the workspace pipeline reads its
    # own loader for any external deps).
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    (fresco_dir / "milpa.kdl").write_text(
        'name "fresco"\nkind "library"\n'
    )
    (fresco_dir / "fresco.nim").write_text("# fresco\n")

    rc = cmd_fetch(tmp_path, registry_loader=_empty_registry_loader)
    assert rc == 0
    # Shared lockfile at workspace root
    assert (tmp_path / "milpa.lock").exists()
    # Per-member nim.cfg at member's directory
    assert (fresco_dir / "nim.cfg").exists()
    # No top-level nim.cfg (workspace mode emits per-member only)
    assert not (tmp_path / "nim.cfg").exists()


def test_cmd_fetch_from_member_subdir_walks_up_to_workspace_root(tmp_path):
    """cmd_fetch invoked with project_dir pointed at the member dir
    walks up to the workspace root via workspace_containing, and
    operates against the workspace as a whole."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    (fresco_dir / "milpa.kdl").write_text(
        'name "fresco"\nkind "library"\n'
    )

    # Invoke cmd_fetch FROM the member dir
    rc = cmd_fetch(fresco_dir, registry_loader=_empty_registry_loader)
    assert rc == 0
    # Shared lockfile is at the WORKSPACE root, not the member dir
    assert (tmp_path / "milpa.lock").exists()
    assert not (fresco_dir / "milpa.lock").exists()
    # nim.cfg in the member
    assert (fresco_dir / "nim.cfg").exists()


def test_cmd_verify_workspace_branch_detects_member_drift(tmp_path, capsys):
    """cmd_verify on a workspace dispatches to verify_workspace_against_disk.
    Member-source drift is detected."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '}\n'
    )
    fresco_dir = tmp_path / "fresco"
    fresco_dir.mkdir()
    (fresco_dir / "milpa.kdl").write_text(
        'name "fresco"\nkind "library"\n'
    )
    (fresco_dir / "fresco.nim").write_text("# original\n")

    rc = cmd_fetch(tmp_path, registry_loader=_empty_registry_loader)
    assert rc == 0
    capsys.readouterr()

    # Edit the member's source
    (fresco_dir / "fresco.nim").write_text("# edited\n")

    rc = cmd_verify(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "fresco" in err
    assert "mismatch" in err


def test_cmd_clean_workspace_removes_deps_and_member_nimcfgs(tmp_path):
    """cmd_clean on a workspace removes <root>/_deps/ and each
    member's nim.cfg. Lockfile is preserved (symmetric with the
    single-project behavior)."""
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n'
        '    member "fresco"\n'
        '    member "intonaco"\n'
        '}\n'
    )
    for m in ["fresco", "intonaco"]:
        d = tmp_path / m
        d.mkdir()
        (d / "milpa.kdl").write_text(f'name "{m}"\nkind "library"\n')

    rc = cmd_fetch(tmp_path, registry_loader=_empty_registry_loader)
    assert rc == 0
    assert (tmp_path / "_deps").exists()
    assert (tmp_path / "fresco" / "nim.cfg").exists()
    assert (tmp_path / "intonaco" / "nim.cfg").exists()
    assert (tmp_path / "milpa.lock").exists()

    rc = cmd_clean(tmp_path)
    assert rc == 0
    assert not (tmp_path / "_deps").exists()
    assert not (tmp_path / "fresco" / "nim.cfg").exists()
    assert not (tmp_path / "intonaco" / "nim.cfg").exists()
    assert (tmp_path / "milpa.lock").exists()  # preserved


def test_cmd_verify_no_lockfile_returns_1(tmp_path, capsys):
    # _deps/ exists but no milpa.lock
    (tmp_path / "_deps").mkdir()
    rc = cmd_verify(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "milpa.lock" in err or "lockfile" in err.lower()


def test_cmd_verify_no_deps_dir_returns_1(tmp_path, capsys):
    # milpa.lock exists but no _deps/
    from milpa.lockfile import Lockfile, format_lockfile
    (tmp_path / "milpa.lock").write_text(format_lockfile(Lockfile(version=1, deps=())))
    rc = cmd_verify(tmp_path)
    assert rc == 1
    err = capsys.readouterr().err
    assert "_deps" in err or "deps" in err.lower()


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
        'name "test"\n'
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
        fetcher=_as_registry(fake_fetch),
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

    rc = cmd_lock(tmp_path, fetcher=_as_registry(fake), registry_loader=fake_loader)
    assert rc == 0
    assert len(loader_calls) == 1
