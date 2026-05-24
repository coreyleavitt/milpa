"""Manifest writer + mutation orchestration (#15).

format_manifest already handles Manifest → text. This module adds the
infrastructure callers need to safely PERSIST mutations:

  - write_manifest(m, path)              — atomic file write
  - mutate_manifest_file(path, fn)       — read-modify-write with comment-loss reporting
  - apply_manifest_change_with_resolve(...) — resolve-first transaction (cargo/uv shape)

The orchestration layer prevents future command authors from forgetting
the relock step or skipping pre-mutation validation. See cargo-add /
uv-add for the same overall pattern (we just codify it as a primitive
instead of relying on per-command convention).

Trivia preservation (comments / formatting) is out of scope here — see
#80 for the Python-specific gap.
"""

from pathlib import Path

import pytest

from milpa.manifest import (
    Manifest,
    ManifestError,
    UrlDep,
    parse_manifest,
)
from milpa.manifest_writer import (
    apply_manifest_change_with_resolve,
    mutate_manifest_file,
    write_manifest,
)


def test_write_manifest_round_trips_through_parse(tmp_path):
    """Tracer: write to a path, re-parse, compare to original. Parent
    dir is auto-created."""
    original = Manifest(
        kind="library",
        name="example",
        deps=(UrlDep(
            name="chronos",
            git="https://github.com/x/chronos.git",
            ref="main",
        ),),
    )
    target = tmp_path / "new" / "subdir" / "milpa.kdl"

    written = write_manifest(original, target)

    assert written == target
    assert target.exists()
    reparsed = parse_manifest(target.read_text())
    assert reparsed == original


def test_write_manifest_failed_format_leaves_existing_file_intact(tmp_path):
    """A failure during write must not corrupt or truncate an existing
    target — atomicity guarantee. We simulate failure by passing a
    Manifest that format_manifest rejects (here: a contrived bad-state
    we manufacture via monkeypatching), and assert the original file
    is unchanged."""
    target = tmp_path / "milpa.kdl"
    pre_existing = (
        '// hand-edited manifest\n'
        'name "before"\n'
        'kind "library"\n'
    )
    target.write_text(pre_existing)

    # Pre-existing parses successfully — sanity
    assert parse_manifest(target.read_text()).name == "before"

    # Inject a failure: monkeypatch format_manifest to raise mid-write.
    import milpa.manifest_writer as mw
    original_format = mw.format_manifest
    def boom(m):
        raise RuntimeError("synthetic format failure")
    mw.format_manifest = boom
    try:
        new_m = Manifest(kind="library", name="after", deps=())
        with pytest.raises(RuntimeError):
            write_manifest(new_m, target)
    finally:
        mw.format_manifest = original_format

    # File contents unchanged
    assert target.read_text() == pre_existing
    # No stray temp file in the directory
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".")]
    assert leftovers == [], f"unexpected leftover temp files: {leftovers}"


def test_write_manifest_cleans_temp_when_rename_fails(tmp_path, monkeypatch):
    """If os.replace fails after the temp file is written, the temp
    must be removed — never leave .milpa.kdl.tmp littering the
    project root."""
    target = tmp_path / "milpa.kdl"
    pre_existing = 'name "before"\nkind "library"\n'
    target.write_text(pre_existing)

    import milpa.manifest_writer as mw
    def boom(*a, **kw):
        raise OSError("synthetic rename failure")
    monkeypatch.setattr(mw.os, "replace", boom)

    new_m = Manifest(kind="library", name="after", deps=())
    with pytest.raises(OSError):
        write_manifest(new_m, target)

    # No temp leftovers
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".")]
    assert leftovers == [], f"unexpected leftover temp files: {leftovers}"
    # Target untouched
    assert target.read_text() == pre_existing


# ---------------------------------------------------------------------------
# mutate_manifest_file — read-modify-write
# ---------------------------------------------------------------------------


def test_mutate_manifest_file_applies_function_and_writes(tmp_path):
    """mutate_manifest_file(path, fn) reads the manifest, applies fn,
    writes the result. After return, the file contains fn's output."""
    from dataclasses import replace

    target = tmp_path / "milpa.kdl"
    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        target,
    )

    def add_chronos(m: Manifest) -> Manifest:
        return replace(
            m,
            deps=m.deps + (UrlDep(
                name="chronos",
                git="https://example.com/chronos.git",
                ref="main",
            ),),
        )

    mutate_manifest_file(target, add_chronos)

    reparsed = parse_manifest(target.read_text())
    assert len(reparsed.deps) == 1
    assert reparsed.deps[0].name == "chronos"


def test_mutate_manifest_file_raises_when_path_missing(tmp_path):
    """No file at path — clear error, no silent file creation."""
    with pytest.raises(ManifestError) as exc:
        mutate_manifest_file(tmp_path / "absent.kdl", lambda m: m)
    assert "absent.kdl" in str(exc.value) or "not found" in str(exc.value).lower()


def test_mutate_manifest_file_raises_when_path_is_nimble(tmp_path):
    """Refuse to mutate a .nimble file — that's a `milpa init`
    concern, not a mutation side effect."""
    nimble = tmp_path / "proj.nimble"
    nimble.write_text('requires "results"\n')
    with pytest.raises(ManifestError) as exc:
        mutate_manifest_file(nimble, lambda m: m)
    msg = str(exc.value).lower()
    assert ".nimble" in msg or "nimble" in msg


def test_mutate_manifest_file_raises_on_workspace_manifest(tmp_path):
    """Workspace manifests are pure containers — not mutation targets
    in this cycle."""
    target = tmp_path / "milpa.kdl"
    target.write_text(
        'workspace {\n'
        '    member "alpha"\n'
        '}\n'
    )
    with pytest.raises(ManifestError) as exc:
        mutate_manifest_file(target, lambda m: m)
    msg = str(exc.value).lower()
    assert "workspace" in msg


# ---------------------------------------------------------------------------
# WriteResult.comments_lost
# ---------------------------------------------------------------------------


def test_write_result_reports_zero_when_source_has_no_comments(tmp_path):
    """A manifest with no comments → comments_lost == 0."""
    target = tmp_path / "milpa.kdl"
    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        target,
    )
    # write_manifest's own output has the header comment, but for
    # comment-loss accounting we count comments in the SOURCE that
    # don't survive — first round the file just has the header,
    # which IS preserved (every format_manifest output starts with it).
    result = mutate_manifest_file(target, lambda m: m)
    assert result.comments_lost == 0


def test_write_result_reports_comment_lines_lost_in_source(tmp_path):
    """A hand-edited manifest with several // comments → comments_lost
    counts each line not in the formatter's output."""
    target = tmp_path / "milpa.kdl"
    target.write_text(
        '// project intent: experimental fork\n'
        '// see ../README for the migration plan\n'
        'name "proj"\n'
        'deps {\n'
        '    // chronos: we depend on the contextvars branch\n'
        '    chronos git="https://example.com/chronos.git" ref="main"\n'
        '}\n'
        'kind "library"\n'
    )

    result = mutate_manifest_file(target, lambda m: m)

    # 3 user comments existed in source; the formatter's auto-header
    # accounts for at most 1 in the output. Net loss: at least 2.
    assert result.comments_lost >= 2


# ---------------------------------------------------------------------------
# apply_manifest_change_with_resolve — resolve-then-commit (#16)
# ---------------------------------------------------------------------------


def _empty_registry_loader(*, cache_path):
    return {}


def test_apply_change_with_resolve_commits_both_files_atomically(tmp_path):
    """Tracer: build a proposed Manifest, run resolve, commit both
    milpa.kdl and milpa.lock. After return, both files exist and
    reflect the new state."""
    from dataclasses import replace

    from milpa.fetchers import FetcherRegistry
    from milpa.fetchers.git import GitProvenance, GitReceipt
    from milpa.lockfile import load_lockfile
    from milpa.solver import Strategy

    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )

    # Fake fetcher serves any git URL with a minimal .nimble
    class StubFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / f"{name}.nimble").write_text('srcDir = "src"\n')
            return GitReceipt(commit_sha="abc")

    registry = FetcherRegistry()
    registry.register(StubFetcher())

    proposed = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(name="x", git="https://example.com/x.git", ref="main"),),
    )

    apply_manifest_change_with_resolve(
        tmp_path,
        proposed_manifest=proposed,
        fetcher=registry,
        list_tags=lambda url: [],
        registry_loader=_empty_registry_loader,
        strategy=Strategy.MAXVER,
    )

    # Both files reflect the new state
    reparsed = parse_manifest((tmp_path / "milpa.kdl").read_text())
    assert reparsed.deps[0].name == "x"
    lockfile = load_lockfile(tmp_path / "milpa.lock")
    assert any(d.name == "x" for d in lockfile.deps)


def test_apply_change_with_resolve_aborts_on_resolve_failure(tmp_path):
    """If resolve raises, manifest + lockfile remain untouched —
    cargo/uv-style atomicity guarantee."""
    from milpa.fetchers import FetcherRegistry, FetchError
    from milpa.fetchers.git import GitProvenance
    from milpa.solver import Strategy

    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )
    original_manifest = (tmp_path / "milpa.kdl").read_text()
    # No pre-existing lockfile
    assert not (tmp_path / "milpa.lock").exists()

    class FailingFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            raise FetchError(f"synthetic failure for {p.url}")

    registry = FetcherRegistry()
    registry.register(FailingFetcher())

    proposed = Manifest(
        kind="library", name="proj",
        deps=(UrlDep(name="x", git="https://example.com/x.git", ref="main"),),
    )

    with pytest.raises(Exception):
        apply_manifest_change_with_resolve(
            tmp_path,
            proposed_manifest=proposed,
            fetcher=registry,
            list_tags=lambda url: [],
            registry_loader=_empty_registry_loader,
            strategy=Strategy.MAXVER,
        )

    # Manifest unchanged
    assert (tmp_path / "milpa.kdl").read_text() == original_manifest
    # No stray lockfile
    assert not (tmp_path / "milpa.lock").exists()


def test_apply_change_with_resolve_aborts_on_pre_validate_failure(tmp_path):
    """pre_resolve_validate raising short-circuits — resolve is never
    invoked, no disk writes happen."""
    from milpa.fetchers import FetcherRegistry
    from milpa.solver import Strategy

    write_manifest(
        Manifest(kind="library", name="proj", deps=()),
        tmp_path / "milpa.kdl",
    )
    original = (tmp_path / "milpa.kdl").read_text()

    class ExplodingFetcher:
        def can_handle(self, p): return True
        def fetch(self, name, p, *, dest):
            raise AssertionError(
                "resolve must not run when pre_validate failed"
            )

    registry = FetcherRegistry()
    registry.register(ExplodingFetcher())

    def pre_validate():
        raise RuntimeError("synthetic pre-validate failure")

    with pytest.raises(RuntimeError, match="synthetic pre-validate"):
        apply_manifest_change_with_resolve(
            tmp_path,
            proposed_manifest=Manifest(kind="library", name="proj", deps=()),
            fetcher=registry,
            list_tags=lambda url: [],
            registry_loader=_empty_registry_loader,
            strategy=Strategy.MAXVER,
            pre_resolve_validate=pre_validate,
        )

    assert (tmp_path / "milpa.kdl").read_text() == original
    assert not (tmp_path / "milpa.lock").exists()
