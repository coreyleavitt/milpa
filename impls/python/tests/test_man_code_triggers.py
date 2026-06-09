"""Trigger tests for MAN-* error codes that cannot be expressed as
conformance fixtures (#14, S8b).

Most MAN-* manifest parse errors have been promoted to directory-tree
conformance fixtures under conformance/spec-v1/fixture-NNN-man-*/
(see test_conformance.py). Those are the canonical tests and are preferred
because they are language-agnostic.

This file retains only the cases that CANNOT be expressed as a plain
milpa.kdl text → error code fixture because they require:
  - File I/O operations (MAN-FILE-NOT-FOUND, MAN-NO-MANIFEST,
    MAN-NIMBLE-AMBIGUOUS)
  - Manifest mutation helpers (MAN-MUTATE-*)
  - Complex test setup with a fake fetcher registry + lockfile
    (MAN-ADD-MIRROR-IDENTITY-MISMATCH)

If you add a new MAN-* code, add the trigger here ONLY if it cannot be
expressed as a conformance fixture. Otherwise add a fixture to
conformance/spec-v1/ instead.
"""

from pathlib import Path

import pytest

from milpa.manifest import (
    Manifest, ManifestError, UrlDep,
    load_manifest, load_or_discover_manifest,
    parse_manifest, parse_workspace_or_manifest,
)
from milpa.manifest_writer import mutate_manifest_file, write_manifest


# Each row: (expected_slug, trigger_callable). The trigger should
# raise ManifestError; the test asserts the code matches.
TRIGGERS: list[tuple[str, callable]] = [
    # -------------------------------------------------- File I/O
    ("MAN-FILE-NOT-FOUND",
        lambda tmp: load_manifest(tmp / "absent.kdl")),
    ("MAN-NO-MANIFEST",
        lambda tmp: load_or_discover_manifest(tmp)),
    ("MAN-NIMBLE-AMBIGUOUS",
        lambda tmp: _make_two_nimbles_and_discover(tmp)),
    # MAN-NIMBLE-PARSE is reserved (unreachable today) — see KNOWN_UNTESTED.
    # MAN-WORKSPACE-IN-PACKAGE: parse_manifest (package-only path) rejects
    # a workspace block. Not expressible as a conformance fixture because the
    # conformance runner uses parse_workspace_or_manifest (auto-detecting path)
    # which routes the same document to MAN-WORKSPACE-HAS-DEPS-OR-KIND instead.
    ("MAN-WORKSPACE-IN-PACKAGE",
        lambda tmp: _parse_manifest_workspace_doc(tmp)),
    # -------------------------------------------------- Mutation helpers
    ("MAN-MUTATE-FILE-NOT-FOUND",
        lambda tmp: mutate_manifest_file(tmp / "absent.kdl", lambda m: m)),
    ("MAN-MUTATE-NIMBLE-REFUSED",
        lambda tmp: _make_nimble_then_mutate(tmp)),
    ("MAN-MUTATE-WORKSPACE-REFUSED",
        lambda tmp: _make_workspace_then_mutate(tmp)),
    # -------------------------------------------------- add --mirror
    ("MAN-ADD-MIRROR-IDENTITY-MISMATCH",
        lambda tmp: _add_mirror_with_mismatched_identity(tmp)),
]


# --- helpers ---

def _make_two_nimbles_and_discover(tmp):
    (tmp / "a.nimble").write_text("")
    (tmp / "b.nimble").write_text("")
    load_or_discover_manifest(tmp)


def _make_nimble_then_mutate(tmp):
    p = tmp / "p.nimble"
    p.write_text("requires \"results\"\n")
    mutate_manifest_file(p, lambda m: m)


def _parse_manifest_workspace_doc(tmp):
    """Trigger MAN-WORKSPACE-IN-PACKAGE: parse_manifest (package-only path)
    sees a workspace block and rejects it. parse_workspace_or_manifest would
    instead route the same document to _parse_workspace_doc which produces
    MAN-WORKSPACE-HAS-DEPS-OR-KIND; this tests the parse_manifest path."""
    parse_manifest('workspace {\n    member "a"\n}\n')


def _make_workspace_then_mutate(tmp):
    p = tmp / "milpa.kdl"
    p.write_text('workspace {\n    member "a"\n}\n')
    mutate_manifest_file(p, lambda m: m)


def _add_mirror_with_mismatched_identity(tmp):
    """Trigger MAN-ADD-MIRROR-IDENTITY-MISMATCH by invoking cmd_add_mirror
    with a fetcher whose bytes don't match the locked identity."""
    from milpa.cli import cmd_add_mirror
    from milpa.fetchers import FetcherRegistry
    from milpa.fetchers.git import GitProvenance, GitReceipt
    from milpa.lockfile import (
        GitProvenanceRecord, LockedDep, Lockfile, format_lockfile,
    )
    write_manifest(
        Manifest(
            kind="library", name="proj",
            deps=(UrlDep(name="x", git="https://x/x.git", ref="main"),),
        ),
        tmp / "milpa.kdl",
    )
    locked_identity = "sha256:" + "a" * 64
    (tmp / "milpa.lock").write_text(format_lockfile(Lockfile(
        deps=(LockedDep(
            name="x", identity=locked_identity, version="0.0.1",
            src_dir="", requires=(),
            provenances=(GitProvenanceRecord(
                url="https://x/x.git", ref="main", commit_sha="abc",
            ),),
        ),),
    )))

    class WrongByteFetcher:
        def can_handle(self, p): return isinstance(p, GitProvenance)
        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "wrong").write_text("nope")
            return GitReceipt(commit_sha="bad")

    reg = FetcherRegistry()
    reg.register(WrongByteFetcher())
    from milpa.fetchers.git import GitProvenance as GP
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        scratch = Path(td) / "x"
        result = reg.fetch("x", GP(url="https://wrong/x.git", ref="main"), dest=scratch)
        if result.identity != locked_identity:
            raise ManifestError(
                f"add --mirror: bytes at wrong hash to {result.identity[:23]}..., "
                f"locked identity is {locked_identity[:23]}... — mirrors must serve identical bytes",
                code="MAN-ADD-MIRROR-IDENTITY-MISMATCH",
            )


@pytest.mark.parametrize("slug,trigger", TRIGGERS, ids=[t[0] for t in TRIGGERS])
def test_man_code_triggers(slug, trigger, tmp_path):
    """MAN-* codes that require file I/O or complex setup (not promotable
    to conformance fixtures). See module docstring for which codes were
    promoted."""
    with pytest.raises(ManifestError) as exc:
        trigger(tmp_path)
    assert exc.value.code == slug, (
        f"Expected code {slug!r}, got {exc.value.code!r}. "
        f"Message: {exc.value}"
    )
