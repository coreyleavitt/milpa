"""Error catalog — the normative spec of every milpa error (#14).

Each error condition milpa can produce has a stable code (semantic
kebab format like `MAN-NAME-MISSING`). The catalog is the conformance
surface: any milpa implementation (Python today, Rust next) must
produce identical codes for identical conditions.

The catalog is a Python dict (single source of truth). It generates
docs/spec/errors.md. Tests pin a bijection — every code in the
catalog has at least one test that triggers it; every raise in
production code references a code that's in the catalog.
"""

import pytest

from milpa.error_catalog import ErrorCode, ERROR_CATALOG, register


@pytest.fixture
def _ephemeral_test_code():
    """Register a throwaway code for the duration of a test, then
    remove it so the global catalog stays pristine for the docs-match
    check. Yields the registered ErrorCode."""
    slug = "TEST-EPHEMERAL"
    code = register(
        slug=slug, category="TEST",
        description="A throwaway code used by tests.",
        when="Only when a test that requests this fixture runs.",
    )
    try:
        yield code
    finally:
        ERROR_CATALOG.pop(slug, None)


def test_register_a_code_adds_it_to_the_catalog(_ephemeral_test_code):
    """Tracer: a registered ErrorCode appears in the global catalog
    and is retrievable by its slug."""
    assert isinstance(_ephemeral_test_code, ErrorCode)
    assert _ephemeral_test_code.slug == "TEST-EPHEMERAL"
    assert ERROR_CATALOG["TEST-EPHEMERAL"] is _ephemeral_test_code


def test_duplicate_code_registration_raises(_ephemeral_test_code):
    """Catalog integrity: defining the same slug twice is a bug —
    raises immediately at registration time, not silently overwrites."""
    with pytest.raises(ValueError) as exc:
        register(
            slug="TEST-EPHEMERAL",
            category="TEST",
            description="duplicate",
            when="never",
        )
    assert "TEST-EPHEMERAL" in str(exc.value)
    assert "duplicate" in str(exc.value).lower() or "already" in str(exc.value).lower()


def test_generate_errors_markdown_produces_sorted_normative_spec():
    """Catalog → markdown: deterministic, sorted by code slug, one
    section per code with description + trigger condition.
    Independent of catalog mutation order."""
    from milpa.error_catalog import generate_errors_markdown

    # Build a small isolated catalog for this test (don't depend on
    # global state)
    sample_catalog = {
        "ZZ-LAST-CODE": ErrorCode(
            slug="ZZ-LAST-CODE", category="ZZ",
            description="The last code alphabetically.",
            when="When something extremely rare happens.",
        ),
        "AA-FIRST-CODE": ErrorCode(
            slug="AA-FIRST-CODE", category="AA",
            description="The first code alphabetically.",
            when="When something common happens.",
        ),
    }
    md = generate_errors_markdown(sample_catalog)

    # Sections in sorted order
    aa_idx = md.index("AA-FIRST-CODE")
    zz_idx = md.index("ZZ-LAST-CODE")
    assert aa_idx < zz_idx

    # Each entry includes description + trigger
    assert "The first code alphabetically." in md
    assert "When something extremely rare happens." in md

    # Has a header
    assert md.startswith("#") or "milpa error" in md.lower()


def test_manifest_error_exposes_code_when_raised_with_one():
    """ManifestError accepts an optional `code=` kwarg; the value is
    accessible via `.code`. Existing single-arg raises still work
    (code is None when not provided)."""
    from milpa.manifest import ManifestError

    # New form: with code
    try:
        raise ManifestError("synthetic", code="MAN-TEST-CODE")
    except ManifestError as exc:
        assert exc.code == "MAN-TEST-CODE"
        assert str(exc) == "synthetic"

    # Legacy form: no code
    try:
        raise ManifestError("legacy")
    except ManifestError as exc:
        assert exc.code is None


# ---------------------------------------------------------------------------
# Bijection lints — keep catalog ↔ production-code in sync (#14)
# ---------------------------------------------------------------------------


def _man_code_slugs_in_source() -> set[str]:
    """Scan production source for every code= reference on a ManifestError
    raise, returning the set of slugs found."""
    import re
    from pathlib import Path

    slugs: set[str] = set()
    root = Path(__file__).parent.parent / "milpa"
    for py in root.rglob("*.py"):
        if py.name == "error_codes" or "/error_codes/" in str(py):
            continue   # the catalog file declares them; don't double-count
        text = py.read_text()
        # Look for code="MAN-..." within a ManifestError raise.
        # The regex permits whitespace + multi-line raises.
        for m in re.finditer(
            r'raise\s+ManifestError\([^)]*?code=["\'](MAN-[A-Z0-9-]+)["\']',
            text, re.DOTALL,
        ):
            slugs.add(m.group(1))
    return slugs


def test_every_man_code_in_source_is_in_the_catalog():
    """Every code= referenced in production code must be a registered
    catalog entry — no typos, no drift."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _man_code_slugs_in_source()
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("MAN-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_man_raise_in_source_carries_a_code():
    """Every `raise ManifestError(...)` in production code must
    include a `code=` kwarg. Source-scan lint."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        # Find each 'raise ManifestError(' and check the next ~800
        # chars include 'code='.
        for m in re.finditer(r'raise\s+ManifestError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise ManifestError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_every_man_code_has_at_least_one_test_that_triggers_it():
    """The strong bijection: every catalog entry should be exercised
    by at least one test in the suite.

    Implemented by source-scanning the tests/ directory for assertions
    on `exc.code == "MAN-..."` or `assertCode("MAN-...")`-style patterns,
    AND for tests that raise the condition via parse_manifest of a
    fragment that triggers the corresponding raise site. The latter is
    harder to detect statically, so this test currently checks the
    LOOSER bijection: every catalog code either appears in a test
    file's source OR has an entry in a known-untested list. New codes
    must be tested OR explicitly added to KNOWN_UNTESTED with a reason.
    """
    import re
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    # Codes intentionally not exercised by a direct trigger test —
    # typically internal defensive raises or extremely rare states.
    # Adding here requires a comment explaining why.
    KNOWN_UNTESTED: set[str] = {
        # File-IO failures depend on OS-level state (perms, etc.) and
        # are exercised in production rather than the unit suite.
        "MAN-FILE-UNREADABLE",
        # NimbleParseError is currently only raised on file-IO failures
        # in nimble_parse, which are caught and re-raised as
        # MAN-FILE-UNREADABLE by _load_manifest_from_nimble. The
        # MAN-NIMBLE-PARSE code is reserved for future content-level
        # parse failures.
        "MAN-NIMBLE-PARSE",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(
        p.read_text() for p in tests_dir.rglob("test_*.py")
    )

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("MAN-")}
    referenced_in_tests = set()
    for slug in catalog_slugs:
        if slug in test_text:
            referenced_in_tests.add(slug)

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test that triggers the condition "
        f"and asserts `exc.code == '<slug>'`, or add to KNOWN_UNTESTED "
        f"with a justification."
    )


def test_docs_spec_errors_md_matches_generator_output():
    """`docs/spec/errors.md` must equal `generate_errors_markdown()`
    output. CI catches stale documentation: if a code is added but
    docs aren't regenerated, this test fails with the diff."""
    from pathlib import Path
    from milpa.error_catalog import generate_errors_markdown

    repo_root = Path(__file__).parent.parent
    spec_path = repo_root / "docs" / "spec" / "errors.md"

    expected = generate_errors_markdown()
    if not spec_path.exists():
        pytest.fail(
            f"{spec_path} does not exist. Run:\n"
            f"  python -c 'from milpa.error_catalog import generate_errors_markdown; "
            f"open(\"{spec_path}\", \"w\").write(generate_errors_markdown())'"
        )
    actual = spec_path.read_text()
    if actual != expected:
        pytest.fail(
            f"{spec_path} is stale. Regenerate with:\n"
            f"  python -c 'from milpa.error_catalog import generate_errors_markdown; "
            f"open(\"{spec_path}\", \"w\").write(generate_errors_markdown())'\n"
        )
