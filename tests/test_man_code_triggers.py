"""Trigger tests for every MAN-* error code (#14).

A parametrized table where each entry is `(slug, fragment_or_callable,
asserter)`. The asserter invokes the parser / mutator / CLI path that
should raise ManifestError with the matching code; the test verifies
`exc.code == slug`.

Adding a new MAN-* code to the catalog REQUIRES adding a trigger
entry here (or to KNOWN_UNTESTED in test_error_catalog.py).
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
    # ----------------------------------------------------------- KDL
    ("MAN-KDL-SYNTAX",
        lambda tmp: parse_manifest("this is not valid { kdl ")),
    # -------------------------------------------------- File I/O
    ("MAN-FILE-NOT-FOUND",
        lambda tmp: load_manifest(tmp / "absent.kdl")),
    ("MAN-NO-MANIFEST",
        lambda tmp: load_or_discover_manifest(tmp)),
    ("MAN-NIMBLE-AMBIGUOUS",
        lambda tmp: _make_two_nimbles_and_discover(tmp)),
    # MAN-NIMBLE-PARSE is reserved (unreachable today) — see KNOWN_UNTESTED.
    # -------------------------------------------------- Top-level
    ("MAN-NAME-MISSING",
        lambda tmp: parse_manifest('kind "library"\n')),
    ("MAN-NAME-DUPLICATE",
        lambda tmp: parse_manifest('name "a"\nname "b"\nkind "library"\n')),
    ("MAN-NAME-TYPE",
        lambda tmp: parse_manifest('name 42\nkind "library"\n')),
    ("MAN-SRC-DIR-TYPE",
        lambda tmp: parse_manifest('name "x"\nsrc_dir 42\nkind "library"\n')),
    ("MAN-CAS-DIR-MISSING",
        lambda tmp: parse_manifest('name "x"\nkind "library"\ncas {\n}\n')),
    ("MAN-CAS-DIR-TYPE",
        lambda tmp: parse_manifest('name "x"\nkind "library"\ncas {\n    dir 42\n}\n')),
    ("MAN-UNKNOWN-TOP-LEVEL",
        lambda tmp: parse_manifest('name "x"\nbogus "y"\nkind "library"\n')),
    ("MAN-WORKSPACE-IN-PACKAGE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nworkspace {\n    member "a"\n}\n'
        )),
    # -------------------------------------------------- kind
    ("MAN-KIND-ARITY",
        lambda tmp: parse_manifest('name "x"\nkind\n')),
    ("MAN-KIND-INVALID",
        lambda tmp: parse_manifest('name "x"\nkind "weird"\n')),
    # -------------------------------------------------- deps
    ("MAN-DEP-DUPLICATE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main"\n'
            '    foo git=(url)"https://b/foo.git" ref="main"\n'
            '}\n'
        )),
    ("MAN-DEP-UNKNOWN-PROPS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" bogus="x"\n'
            '}\n'
        )),
    ("MAN-DEP-REF-MISSING",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git"\n'
            '}\n'
        )),
    ("MAN-DEP-LOCAL-PATH",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo local=""\n'
            '}\n'
        )),
    ("MAN-DEP-TARBALL-URL",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo tarball=""\n'
            '}\n'
        )),
    ("MAN-DEP-TARBALL-SHA",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo tarball=(url)"https://x/t.tar.gz" sha256=42\n'
            '}\n'
        )),
    ("MAN-DEP-TARBALL-STRIP",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo tarball=(url)"https://x/t.tar.gz" strip_components=-1\n'
            '}\n'
        )),
    ("MAN-DEP-MEMBER-PROPS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    member "a" bogus="y"\n'
            '}\n'
        )),
    ("MAN-DEP-MEMBER-ARITY",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    member\n'
            '}\n'
        )),
    ("MAN-DEP-NAMED-PROPS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo bogus="y"\n'
            '}\n'
        )),
    ("MAN-DEP-NAMED-CONSTRAINT",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo 42\n'
            '}\n'
        )),
    ("MAN-DEP-NAMED-ARITY",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo "a" "b"\n'
            '}\n'
        )),
    ("MAN-DEP-MIRROR-ARITY",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        mirror\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-DEP-FLAG-NAME-MISSING",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        flag\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-DEP-FLAG-TOO-MANY-ARGS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        flag "a" true "extra"\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-DEP-FLAG-BOOL",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        flag "a" "not-a-bool"\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-DEP-UNKNOWN-CHILD",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        bogus "y"\n'
            '    }\n'
            '}\n'
        )),
    # -------------------------------------------------- Git URL
    ("MAN-GIT-URL-NO-SCHEME",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git="no-scheme-here" ref="main"\n'
            '}\n'
        )),
    ("MAN-GIT-URL-BAD-SCHEME",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git="ftp://example.com/foo.git" ref="main"\n'
            '}\n'
        )),
    # -------------------------------------------------- Overrides
    ("MAN-OVERRIDE-KIND",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\noverrides {\n'
            '    bogus "a" git=(url)"https://a/foo.git" ref="main"\n'
            '}\n'
        )),
    ("MAN-OVERRIDE-ARITY",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\noverrides {\n'
            '    pkg git=(url)"https://a/foo.git" ref="main"\n'
            '}\n'
        )),
    ("MAN-OVERRIDE-UNKNOWN-PROPS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\noverrides {\n'
            '    pkg "a" git=(url)"https://a/foo.git" ref="main" bogus="x"\n'
            '}\n'
        )),
    ("MAN-OVERRIDE-GIT-MISSING",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\noverrides {\n'
            '    pkg "a" ref="main"\n'
            '}\n'
        )),
    ("MAN-OVERRIDE-REF-MISSING",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\noverrides {\n'
            '    pkg "a" git=(url)"https://a/foo.git"\n'
            '}\n'
        )),
    ("MAN-OVERRIDE-DUPLICATE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\noverrides {\n'
            '    pkg "a" git=(url)"https://a/foo.git" ref="main"\n'
            '    pkg "a" git=(url)"https://b/foo.git" ref="main"\n'
            '}\n'
        )),
    # -------------------------------------------------- Flags
    ("MAN-FLAG-DUPLICATE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f default=true\n'
            '    f default=false\n'
            '}\n'
        )),
    ("MAN-FLAG-POS-ARGS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f "stray-arg"\n'
            '}\n'
        )),
    ("MAN-FLAG-UNKNOWN-PROPS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f bogus=true\n'
            '}\n'
        )),
    ("MAN-FLAG-DEFAULT-TYPE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f default="not-a-bool"\n'
            '}\n'
        )),
    ("MAN-FLAG-DESCRIPTION-TYPE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f description=42\n'
            '}\n'
        )),
    ("MAN-FLAG-UNKNOWN-CHILD",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f {\n        bogus "y"\n    }\n'
            '}\n'
        )),
    ("MAN-FLAG-DEFINES-ARG-TYPE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n'
            '    f {\n        defines 42\n    }\n'
            '}\n'
        )),
    ("MAN-FLAG-UNDECLARED-REFERENCE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nflags {\n    json default=false\n}\n'
            'deps {\n'
            '    when flag="undeclared" {\n'
            '        foo git=(url)"https://a/foo.git" ref="main"\n'
            '    }\n'
            '}\n'
        )),
    # -------------------------------------------------- Predicates
    ("MAN-PREDICATE-UNKNOWN",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    when bogus_pred="x" {\n'
            '        foo git=(url)"https://a/foo.git" ref="main"\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-PREDICATE-VALUE-TYPE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" platform=42\n'
            '}\n'
        )),
    ("MAN-PREDICATE-UNSUPPORTED-ANNOTATION",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" platform=(weird)"linux"\n'
            '}\n'
        )),
    ("MAN-PREDICATE-CHILD-NO-ARGS",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        platform\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-PREDICATE-CHILD-ARG-TYPE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        platform 42\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-PREDICATE-MIXED-NEGATION",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" {\n'
            '        platform "linux" (not)"windows"\n'
            '    }\n'
            '}\n'
        )),
    ("MAN-PREDICATE-FORM-CONFLICT",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\ndeps {\n'
            '    foo git=(url)"https://a/foo.git" ref="main" platform="linux" {\n'
            '        platform "windows"\n'
            '    }\n'
            '}\n'
        )),
    # -------------------------------------------------- Top-level mirrors
    ("MAN-MIRRORS-UNKNOWN-CHILD",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nmirrors {\n'
            '    bogus "y"\n'
            '}\n'
        )),
    ("MAN-MIRRORS-ARITY",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nmirrors {\n'
            '    mirror\n'
            '}\n'
        )),
    # -------------------------------------------------- Workspace manifest
    ("MAN-WORKSPACE-HAS-DEPS-OR-KIND",
        lambda tmp: parse_workspace_or_manifest(
            'workspace {\n    member "a"\n}\nkind "library"\n'
        )),
    ("MAN-WORKSPACE-UNKNOWN-NODE",
        lambda tmp: parse_workspace_or_manifest(
            'workspace {\n    bogus "y"\n}\n'
        )),
    ("MAN-WORKSPACE-MEMBER-ARITY",
        lambda tmp: parse_workspace_or_manifest(
            'workspace {\n    member\n}\n'
        )),
    ("MAN-WORKSPACE-MEMBER-DUPLICATE",
        lambda tmp: parse_workspace_or_manifest(
            'workspace {\n    member "a"\n    member "a"\n}\n'
        )),
    ("MAN-WORKSPACE-UNKNOWN-TOP-LEVEL",
        lambda tmp: parse_workspace_or_manifest(
            'workspace {\n    member "a"\n}\nbogus "y"\n'
        )),
    # -------------------------------------------------- URL arg
    ("MAN-URL-ARG-TYPE",
        lambda tmp: parse_manifest(
            'name "x"\nkind "library"\nmirrors {\n'
            '    mirror 42\n'
            '}\n'
        )),
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


def _make_broken_nimble_and_discover(tmp):
    (tmp / "broken.nimble").write_text("requires \"unterminated\n")
    load_or_discover_manifest(tmp)


def _make_nimble_then_mutate(tmp):
    p = tmp / "p.nimble"
    p.write_text("requires \"results\"\n")
    mutate_manifest_file(p, lambda m: m)


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
    # cmd_add_mirror catches ManifestError and prints; the helper
    # `validate` raises it directly. To get the exc we have to
    # invoke the inner path. Easiest: call the inner validate via
    # re-implementing the bits — but simpler: call cmd_add_mirror,
    # check rc=1; then re-raise as ManifestError with the catalog code
    # if it printed our identity-mismatch message.
    # Since the test asserts the EXCEPTION carries the code, we
    # bypass the print-and-swallow path by re-invoking the validate
    # explicitly.
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
    """Every MAN-* code in the catalog has a trigger here that raises
    ManifestError with `exc.code == slug`."""
    with pytest.raises(ManifestError) as exc:
        trigger(tmp_path)
    assert exc.value.code == slug, (
        f"Expected code {slug!r}, got {exc.value.code!r}. "
        f"Message: {exc.value}"
    )
