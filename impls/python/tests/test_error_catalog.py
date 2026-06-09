"""Error catalog — the normative spec of every milpa error (#14).

Each error condition milpa can produce has a stable code (semantic
kebab format like `MAN-NAME-MISSING`). The catalog is the conformance
surface: any milpa implementation (Python today, Rust next) must
produce identical codes for identical conditions.

The catalog is a Python dict (single source of truth). It generates
spec/errors.md. Tests pin a bijection — every code in the
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


def _code_slugs_in_source(exc_class_name: str, prefix: str) -> set[str]:
    """Shared helper: scan production source for every ``code=`` reference on a
    ``raise <exc_class_name>(...)`` call, returning the set of slugs that start
    with ``prefix`` (e.g. ``"MAN-"``).

    Handles multi-line raise calls via ``re.DOTALL``.  Skips the
    ``error_codes/`` sub-package (catalog declarations, not raise sites)."""
    import re
    from pathlib import Path

    slugs: set[str] = set()
    root = Path(__file__).parent.parent / "milpa"
    pattern = re.compile(
        rf'raise\s+{re.escape(exc_class_name)}\([^)]*?code=["\'](({re.escape(prefix)})[A-Z0-9-]+)["\']',
        re.DOTALL,
    )
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in pattern.finditer(text):
            slugs.add(m.group(1))
    return slugs


def _man_code_slugs_in_source() -> set[str]:
    """Scan production source for every code= reference on a ManifestError
    raise, returning the set of slugs found."""
    return _code_slugs_in_source("ManifestError", "MAN-")


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
        # MAN-NIMBLE-PARSE is reserved for future content-level .nimble
        # parse validation. _load_manifest_from_nimble maps a non-IO
        # NimbleParseError from load_nimble to it, but parse_nimble is
        # currently tolerant and never raises on content, so there is no
        # trigger yet. (MAN-FILE-UNREADABLE is now directly tested via the
        # discovery-of-unreadable-.nimble path — see test_nimble_compat.)
        "MAN-NIMBLE-PARSE",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(
        p.read_text() for p in tests_dir.rglob("test_*.py")
    )
    # Also scan conformance fixture expected/error files — slug strings
    # there are just as normative as Python test assertions. Promoted
    # trigger-table cases live here (S8b).
    conformance_root = Path(__file__).parents[3] / "conformance"
    if conformance_root.exists():
        for error_file in conformance_root.rglob("expected/error"):
            test_text += "\n" + error_file.read_text()

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
    """`spec/errors.md` must equal `generate_errors_markdown()`
    output. CI catches stale documentation: if a code is added but
    docs aren't regenerated, this test fails with the diff."""
    from pathlib import Path
    from milpa.error_catalog import generate_errors_markdown

    repo_root = Path(__file__).parents[3]
    spec_path = repo_root / "spec" / "errors.md"

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


# ---------------------------------------------------------------------------
# Lockfile category bijection lints
# ---------------------------------------------------------------------------


def test_every_lock_code_in_source_is_in_the_catalog():
    """Every LOCK-* code= referenced in production code must be a registered
    catalog entry — no typos, no drift."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("LockfileError", "LOCK-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("LOCK-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references LOCK- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_lock_raise_in_source_carries_a_code():
    """Every `raise LockfileError(...)` in production code must include a
    `code=` kwarg. Source-scan lint."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+LockfileError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise LockfileError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_every_lock_code_has_at_least_one_test_that_triggers_it():
    """Every LOCK-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED with a justification."""
    import re
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = {
        # OS-level failures; exercised in production, not unit suite.
        "LOCK-FILE-UNREADABLE",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("LOCK-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"LOCK- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# Resolver category bijection lints
# ---------------------------------------------------------------------------


def test_every_res_code_in_source_is_in_the_catalog():
    """Every RES-* code= referenced in production code must be a registered
    catalog entry."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("ResolverError", "RES-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("RES-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references RES- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_res_raise_in_source_carries_a_code():
    """Every `raise ResolverError(...)` in production code must include
    a `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+ResolverError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise ResolverError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_every_res_code_has_at_least_one_test_that_triggers_it():
    """Every RES-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED with a justification."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = set()  # all RES- codes have trigger tests

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("RES-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"RES- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# Solver category bijection lints
# ---------------------------------------------------------------------------


def test_every_solve_code_in_source_is_in_the_catalog():
    """Every SOLVE-* code= referenced in production code must be a
    registered catalog entry.

    Note: SolverError uses a class-level ``code`` attribute (not a
    ``code=`` kwarg), so this test asserts the class attribute is present
    rather than scanning for raise-site kwarg patterns."""
    from milpa.solver import SolverError
    from milpa.error_catalog import ERROR_CATALOG

    assert hasattr(SolverError, "code"), "SolverError must have a .code class attribute"
    assert SolverError.code == "SOLVE-CONFLICT"
    assert "SOLVE-CONFLICT" in ERROR_CATALOG, (
        "SOLVE-CONFLICT must be registered in the error catalog"
    )


def test_solver_error_instance_has_code():
    """Every SolverError instance carries .code == 'SOLVE-CONFLICT'."""
    from milpa.solver import SolverError, ConflictChain, ConflictStep

    chain = ConflictChain(steps=(ConflictStep(
        consequent_package="pkg",
        consequent_description="no satisfying version",
        antecedents=(),
        antecedent_constraints=(),
        cause_tag="test",
    ),))
    err = SolverError(chain)
    assert err.code == "SOLVE-CONFLICT"


def test_every_solve_code_has_at_least_one_test_that_triggers_it():
    """Every SOLVE-* catalog entry must appear in at least one test source."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = set()

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("SOLVE-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"SOLVE- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# FetchError category bijection lints
# ---------------------------------------------------------------------------


def test_every_fetch_code_in_source_is_in_the_catalog():
    """Every FETCH-* code= referenced in production code must be a registered
    catalog entry — no typos, no drift."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("FetchError", "FETCH-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("FETCH-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references FETCH- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


# Exclusive-dispatch / no-candidates programmer-invariants — exempt from the
# error catalog by explicit decision (plugin-contract §5): they are call-site
# or registration bugs, not reachable from user input, so they carry no
# user-facing slug. Each entry is a stable identifying substring of the raised
# FetchError message. This is THE single exemption list (no separate unused
# set); the Rust catalog lint MUST mirror it (RFC §10/P4).
FETCH_UNCODED_INVARIANTS: set[str] = {
    "no candidates provided",        # fetch_any() with empty candidate list
    "ambiguous fetcher dispatch",    # >1 fetcher claims a provenance kind
    "no registered fetcher handles", # 0 fetchers claim a provenance kind
}


def test_every_fetch_raise_in_source_carries_a_code():
    """Every user-facing `raise FetchError(...)` in production code must
    include a `code=` kwarg. The exclusive-dispatch / no-candidates
    programmer-invariants are exempt — identified by FETCH_UNCODED_INVARIANTS
    (the single exemption list, per plugin-contract §5). A new uncoded raise
    that isn't one of those invariants fails this lint."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+FetchError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" in tail:
                continue
            snippet = tail[:200].replace("\n", " ")
            if any(token in snippet for token in FETCH_UNCODED_INVARIANTS):
                continue
            lineno = text[:m.start()].count("\n") + 1
            missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise FetchError(...) without code= (and not an exempt dispatch "
        "invariant in FETCH_UNCODED_INVARIANTS) at:\n  " + "\n  ".join(missing)
    )


def test_every_fetch_error_exposes_code_kwarg():
    """FetchError accepts a `code=` kwarg; value accessible via .code."""
    from milpa.fetchers.types import FetchError

    err = FetchError("test message", code="FETCH-GIT-FAILED")
    assert err.code == "FETCH-GIT-FAILED"
    assert str(err) == "test message"

    # Legacy form: no code
    err2 = FetchError("legacy")
    assert err2.code is None


def test_fetch_local_path_not_found_code(tmp_path):
    """LocalFetcher raises FetchError(code='FETCH-LOCAL-PATH-NOT-FOUND') when
    the source path doesn't exist."""
    from milpa.fetchers.local import LocalFetcher, LocalProvenance
    from milpa.fetchers.types import FetchError

    fetcher = LocalFetcher()
    p = LocalProvenance(path=tmp_path / "nonexistent")
    with pytest.raises(FetchError) as exc:
        fetcher.fetch("pkg", p, dest=tmp_path / "dest")
    assert exc.value.code == "FETCH-LOCAL-PATH-NOT-FOUND"


def test_fetch_local_path_not_dir_code(tmp_path):
    """LocalFetcher raises FetchError(code='FETCH-LOCAL-PATH-NOT-DIR') when
    the source path is a file, not a directory."""
    from milpa.fetchers.local import LocalFetcher, LocalProvenance
    from milpa.fetchers.types import FetchError

    src = tmp_path / "a_file.txt"
    src.write_text("hello")
    fetcher = LocalFetcher()
    p = LocalProvenance(path=src)
    with pytest.raises(FetchError) as exc:
        fetcher.fetch("pkg", p, dest=tmp_path / "dest")
    assert exc.value.code == "FETCH-LOCAL-PATH-NOT-DIR"


def test_fetch_git_failed_code(tmp_path):
    """GitFetcher raises FetchError(code='FETCH-GIT-FAILED') when git
    clone exits non-zero (bad URL)."""
    from milpa.fetchers.git import GitFetcher, GitProvenance
    from milpa.fetchers.types import FetchError

    fetcher = GitFetcher()
    p = GitProvenance(url="file:///nonexistent-repo", ref="main")
    with pytest.raises(FetchError) as exc:
        fetcher.fetch("pkg", p, dest=tmp_path / "dest")
    assert exc.value.code == "FETCH-GIT-FAILED"


def test_fetch_sha256_mismatch_code(tmp_path):
    """TarballFetcher raises FetchError(code='FETCH-SHA256-MISMATCH') when
    the archive's sha256 doesn't match expected_sha256."""
    import tarfile
    from milpa.fetchers.tarball import TarballFetcher, TarballProvenance
    from milpa.fetchers.types import FetchError

    # Build a minimal valid tarball.
    archive = tmp_path / "pkg.tar.gz"
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "file.txt").write_text("hello")
    with tarfile.open(archive, "w:gz") as tf:
        tf.add(src_dir, arcname="pkg")

    fetcher = TarballFetcher()
    p = TarballProvenance(
        url=archive.as_uri(),
        expected_sha256="a" * 64,   # wrong hash
    )
    with pytest.raises(FetchError) as exc:
        fetcher.fetch("pkg", p, dest=tmp_path / "dest")
    assert exc.value.code == "FETCH-SHA256-MISMATCH"


def test_fetch_download_failed_code(tmp_path):
    """TarballFetcher raises FetchError(code='FETCH-DOWNLOAD-FAILED') when
    the tarball URL is unreachable."""
    from milpa.fetchers.tarball import TarballFetcher, TarballProvenance
    from milpa.fetchers.types import FetchError

    fetcher = TarballFetcher()
    p = TarballProvenance(url="file:///nonexistent/path/to/archive.tar.gz")
    with pytest.raises(FetchError) as exc:
        fetcher.fetch("pkg", p, dest=tmp_path / "dest")
    assert exc.value.code == "FETCH-DOWNLOAD-FAILED"


def test_every_fetch_code_has_at_least_one_test_that_triggers_it():
    """Every FETCH-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED with a justification."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = {
        # Integration-only: requires a real network failure or a real OCI
        # registry to be unavailable.
        "FETCH-OCI-PULL-FAILED",
        "FETCH-OCI-NO-TARBALL",
        "FETCH-OCI-AMBIGUOUS-TARBALL",
        # FETCH-ALL-FAILED requires a running fetch_any() with real
        # provenance objects; covered in integration tests, not unit tests.
        "FETCH-ALL-FAILED",
        # FETCH-GIT-COMMIT-ABSENT: requires a real git repo where a specific
        # commit SHA is absent even after full history fetch.
        "FETCH-GIT-COMMIT-ABSENT",
        # FETCH-EXTRACT-FAILED: the tarball fetcher wraps ExtractionError as
        # FetchError; the ExtractionError itself is tested in EXTRACT- tests.
        "FETCH-EXTRACT-FAILED",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("FETCH-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"FETCH- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# CASError category bijection lints
# ---------------------------------------------------------------------------


def test_every_cas_code_in_source_is_in_the_catalog():
    """Every CAS-* code= referenced in production code must be a registered
    catalog entry."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("CASError", "CAS-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("CAS-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references CAS- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_cas_raise_in_source_carries_a_code():
    """Every `raise CASError(...)` in production code must include a
    `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+CASError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise CASError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_cas_identity_mismatch_code(tmp_path):
    """CAStore.admit raises CASError(code='CAS-IDENTITY-MISMATCH') when
    the src tree doesn't hash to the claimed identity."""
    from milpa.cas import CAStore, CASError

    store = CAStore(root=tmp_path / "cas")
    src = tmp_path / "src_tree"
    src.mkdir()
    (src / "file.txt").write_text("some content")
    wrong_identity = "sha256:" + "a" * 64

    with pytest.raises(CASError) as exc:
        store.admit(src, wrong_identity)
    assert exc.value.code == "CAS-IDENTITY-MISMATCH"


def test_cas_not_in_store_code(tmp_path):
    """CAStore.link raises CASError(code='CAS-NOT-IN-STORE') when the
    identity isn't present in the store."""
    from milpa.cas import CAStore, CASError

    store = CAStore(root=tmp_path / "cas")
    store.root.mkdir(parents=True)
    identity = "sha256:" + "a" * 64
    target = tmp_path / "dest"

    with pytest.raises(CASError) as exc:
        store.link(identity, target)
    assert exc.value.code == "CAS-NOT-IN-STORE"


def test_every_cas_code_has_at_least_one_test_that_triggers_it():
    """Every CAS-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = set()

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("CAS-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"CAS- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# IdentityError category bijection lints
# ---------------------------------------------------------------------------


def test_every_id_code_in_source_is_in_the_catalog():
    """Every ID-* code= referenced in production code must be a registered
    catalog entry."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("IdentityError", "ID-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("ID-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references ID- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_id_raise_in_source_carries_a_code():
    """Every `raise IdentityError(...)` in production code must include a
    `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+IdentityError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise IdentityError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_identity_error_exposes_code_kwarg():
    """IdentityError accepts a `code=` kwarg; value accessible via .code."""
    from milpa.identity import IdentityError

    err = IdentityError("bad identity", code="ID-NOT-A-STRING")
    assert err.code == "ID-NOT-A-STRING"
    assert str(err) == "bad identity"

    err2 = IdentityError("legacy")
    assert err2.code is None


def test_parse_identity_raises_with_codes():
    """parse_identity raises IdentityError with the correct code for each
    failure mode."""
    from milpa.identity import parse_identity, IdentityError

    # ID-NOT-A-STRING
    with pytest.raises(IdentityError) as exc:
        parse_identity(42)  # type: ignore[arg-type]
    assert exc.value.code == "ID-NOT-A-STRING"

    # ID-NO-ALGORITHM-PREFIX
    with pytest.raises(IdentityError) as exc:
        parse_identity("nocolon")
    assert exc.value.code == "ID-NO-ALGORITHM-PREFIX"

    # ID-UNSUPPORTED-ALGORITHM
    with pytest.raises(IdentityError) as exc:
        parse_identity("md5:abc123")
    assert exc.value.code == "ID-UNSUPPORTED-ALGORITHM"

    # ID-WRONG-DIGEST-LENGTH
    with pytest.raises(IdentityError) as exc:
        parse_identity("sha256:abc")
    assert exc.value.code == "ID-WRONG-DIGEST-LENGTH"

    # ID-NON-HEX-DIGEST
    with pytest.raises(IdentityError) as exc:
        parse_identity("sha256:" + "g" * 64)
    assert exc.value.code == "ID-NON-HEX-DIGEST"


def test_id_non_utf8_symlink_target(tmp_path):
    """A symlink whose target is not valid UTF-8 raises the coded error."""
    import os
    from milpa.identity import IdentityError, compute_content_hash

    # Create a symlink whose raw target bytes are not valid UTF-8.
    link = tmp_path / "bad-link"
    os.symlink(b"\xff\xfe", os.fsencode(link))
    with pytest.raises(IdentityError) as exc:
        compute_content_hash(tmp_path)
    assert exc.value.code == "ID-NON-UTF8-SYMLINK-TARGET"


def test_every_id_code_has_at_least_one_test_that_triggers_it():
    """Every ID-* catalog entry must appear in at least one test source."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = set()

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("ID-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"ID- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# NimbleParseError category bijection lints
# ---------------------------------------------------------------------------


def test_every_nimble_code_in_source_is_in_the_catalog():
    """Every NIMBLE-* code= referenced in production code must be a registered
    catalog entry."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("NimbleParseError", "NIMBLE-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("NIMBLE-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references NIMBLE- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_nimble_raise_in_source_carries_a_code():
    """Every `raise NimbleParseError(...)` in production code must include a
    `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+NimbleParseError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise NimbleParseError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_nimble_parse_error_exposes_code_kwarg():
    """NimbleParseError accepts a `code=` kwarg; value accessible via .code."""
    from milpa.nimble_parse import NimbleParseError

    err = NimbleParseError("not found", code="NIMBLE-FILE-NOT-FOUND")
    assert err.code == "NIMBLE-FILE-NOT-FOUND"
    assert str(err) == "not found"

    err2 = NimbleParseError("legacy")
    assert err2.code is None


def test_load_nimble_raises_file_not_found_with_code(tmp_path):
    """load_nimble raises NimbleParseError(code='NIMBLE-FILE-NOT-FOUND') when
    the path does not exist."""
    from milpa.nimble_parse import load_nimble, NimbleParseError

    with pytest.raises(NimbleParseError) as exc:
        load_nimble(tmp_path / "nonexistent.nimble")
    assert exc.value.code == "NIMBLE-FILE-NOT-FOUND"


def test_every_nimble_code_has_at_least_one_test_that_triggers_it():
    """Every NIMBLE-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    # Both NIMBLE-FILE-* codes are now directly tested: -NOT-FOUND and
    # -UNREADABLE via load_nimble (test_nimble_parse), and surfaced through
    # the discovery layer (test_nimble_compat). No exemptions needed.
    KNOWN_UNTESTED: set[str] = set()

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("NIMBLE-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"NIMBLE- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# NotFrozen category bijection lints
# ---------------------------------------------------------------------------


def test_every_frozen_code_in_source_is_in_the_catalog():
    """Every FROZEN-* code= referenced in production code must be a registered
    catalog entry."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("NotFrozen", "FROZEN-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("FROZEN-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references FROZEN- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_frozen_raise_in_source_carries_a_code():
    """Every `raise NotFrozen(...)` in production code must include a
    `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+NotFrozen\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise NotFrozen(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_not_frozen_exposes_code_kwarg():
    """NotFrozen accepts a `code=` kwarg; value accessible via .code."""
    from milpa.frozen import NotFrozen

    err = NotFrozen("strategy mismatch", code="FROZEN-STRATEGY-MISMATCH")
    assert err.code == "FROZEN-STRATEGY-MISMATCH"
    assert str(err) == "strategy mismatch"

    err2 = NotFrozen("legacy")
    assert err2.code is None


def test_frozen_strategy_mismatch_code(tmp_path):
    """_check_strategy raises NotFrozen(code='FROZEN-STRATEGY-MISMATCH')."""
    from milpa.frozen import NotFrozen, _check_strategy
    from milpa.solver import Strategy
    from milpa.lockfile import Lockfile

    lockfile = Lockfile(version=1, strategy="maxver", deps=())
    with pytest.raises(NotFrozen) as exc:
        _check_strategy(Strategy.MINVER, lockfile)
    assert exc.value.code == "FROZEN-STRATEGY-MISMATCH"


def test_frozen_manifest_dep_not_in_lock_code(tmp_path):
    """_check_manifest_alignment raises NotFrozen(code='FROZEN-MANIFEST-DEP-NOT-IN-LOCK')
    when a manifest dep has no lockfile entry."""
    from milpa.frozen import NotFrozen, _check_manifest_alignment
    from milpa.manifest import parse_manifest

    manifest = parse_manifest('name "pkg"\ndeps {\n  intonaco git="https://x" ref="main"\n}\n')
    with pytest.raises(NotFrozen) as exc:
        _check_manifest_alignment(manifest, locked_by_name={}, context_prefix="")
    assert exc.value.code == "FROZEN-MANIFEST-DEP-NOT-IN-LOCK"


def test_frozen_identity_not_in_store_code(tmp_path):
    """_link_external raises NotFrozen(code='FROZEN-IDENTITY-NOT-IN-STORE')
    when the dep's identity is absent from the CAS."""
    from milpa.frozen import NotFrozen, _link_external
    from milpa.cas import CAStore
    from milpa.lockfile import LockedDep, GitProvenanceRecord

    store = CAStore(root=tmp_path / "cas")
    store.root.mkdir(parents=True)
    locked = LockedDep(
        name="pkg",
        version="1.0.0",
        identity="sha256:" + "a" * 64,
        provenances=(GitProvenanceRecord(url="https://x", ref="main", commit_sha="abc"),),
        src_dir=None,
        requires=(),
    )
    with pytest.raises(NotFrozen) as exc:
        _link_external(locked, tmp_path / "_deps", store)
    assert exc.value.code == "FROZEN-IDENTITY-NOT-IN-STORE"


def test_every_frozen_code_has_at_least_one_test_that_triggers_it():
    """Every FROZEN-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = {
        # Require full workspace or frozen resolve setup; covered by
        # test_workspace_frozen.py integration-style tests.
        "FROZEN-MEMBER-DEP",
        "FROZEN-LOCAL-DEP",
        "FROZEN-MEMBER-NOT-IN-WORKSPACE",
        "FROZEN-MEMBER-IDENTITY-DRIFT",
        "FROZEN-CONSTRAINT-UNSATISFIED",
        "FROZEN-LOCKED-VERSION-UNPARSEABLE",
        "FROZEN-LEGACY-REGISTRY-PROVENANCE",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("FROZEN-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"FROZEN- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# WorkspaceError category bijection lints
# ---------------------------------------------------------------------------


def test_every_ws_code_in_source_is_in_the_catalog():
    """Every WS-* code= referenced in production code must be a registered
    catalog entry."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _code_slugs_in_source("WorkspaceError", "WS-")
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("WS-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references WS- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_ws_raise_in_source_carries_a_code():
    """Every `raise WorkspaceError(...)` in production code must include a
    `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in re.finditer(r'raise\s+WorkspaceError\(', text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise WorkspaceError(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_workspace_error_exposes_code_kwarg():
    """WorkspaceError accepts a `code=` kwarg; value accessible via .code."""
    from milpa.workspace import WorkspaceError

    err = WorkspaceError("no manifest", code="WS-NO-MANIFEST")
    assert err.code == "WS-NO-MANIFEST"
    assert str(err) == "no manifest"

    err2 = WorkspaceError("legacy")
    assert err2.code is None


def test_ws_no_manifest_code(tmp_path):
    """load_workspace raises WorkspaceError(code='WS-NO-MANIFEST') when
    no milpa.kdl is found at the workspace root."""
    from milpa.workspace import WorkspaceError, load_workspace

    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert exc.value.code == "WS-NO-MANIFEST"


def test_ws_not_a_workspace_code(tmp_path):
    """load_workspace raises WorkspaceError(code='WS-NOT-A-WORKSPACE') when
    the root milpa.kdl is a package manifest, not a workspace."""
    from milpa.workspace import WorkspaceError, load_workspace

    (tmp_path / "milpa.kdl").write_text('name "mypkg"\n')
    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert exc.value.code == "WS-NOT-A-WORKSPACE"


def test_ws_member_dir_missing_code(tmp_path):
    """load_workspace raises WorkspaceError(code='WS-MEMBER-DIR-MISSING') when
    a declared member directory doesn't exist."""
    from milpa.workspace import WorkspaceError, load_workspace

    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n  member "missing-pkg"\n}\n'
    )
    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert exc.value.code == "WS-MEMBER-DIR-MISSING"


def test_ws_member_no_manifest_code(tmp_path):
    """load_workspace raises WorkspaceError(code='WS-MEMBER-NO-MANIFEST') when
    a member dir exists but has no milpa.kdl."""
    from milpa.workspace import WorkspaceError, load_workspace

    member_dir = tmp_path / "pkg"
    member_dir.mkdir()
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n  member "pkg"\n}\n'
    )
    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert exc.value.code == "WS-MEMBER-NO-MANIFEST"


def test_ws_member_is_workspace_code(tmp_path):
    """load_workspace raises WorkspaceError(code='WS-MEMBER-IS-WORKSPACE') when
    a member's milpa.kdl is itself a workspace."""
    from milpa.workspace import WorkspaceError, load_workspace

    member_dir = tmp_path / "inner"
    member_dir.mkdir()
    (member_dir / "milpa.kdl").write_text(
        'workspace {\n  member "sub"\n}\n'
    )
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n  member "inner"\n}\n'
    )
    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert exc.value.code == "WS-MEMBER-IS-WORKSPACE"


def test_ws_member_duplicate_name_code(tmp_path):
    """load_workspace raises WorkspaceError(code='WS-MEMBER-DUPLICATE-NAME')
    when two members have the same package name."""
    from milpa.workspace import WorkspaceError, load_workspace

    for dirname in ("pkg_a", "pkg_b"):
        d = tmp_path / dirname
        d.mkdir()
        (d / "milpa.kdl").write_text('name "shared-name"\n')
    (tmp_path / "milpa.kdl").write_text(
        'workspace {\n  member "pkg_a"\n  member "pkg_b"\n}\n'
    )
    with pytest.raises(WorkspaceError) as exc:
        load_workspace(tmp_path)
    assert exc.value.code == "WS-MEMBER-DUPLICATE-NAME"


def test_every_ws_code_has_at_least_one_test_that_triggers_it():
    """Every WS-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = {
        # WS-MEMBER-DOT: the "." member path is rejected.  Test is in
        # test_workspace.py but doesn't reference the slug; KNOWN_UNTESTED
        # here; a direct trigger test would duplicate existing coverage.
        "WS-MEMBER-DOT",
        # WS-MEMBER-HAS-OVERRIDES: requires a member with overrides block.
        # Covered by test_workspace.py; KNOWN_UNTESTED here.
        "WS-MEMBER-HAS-OVERRIDES",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("WS-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"WS- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# ExtractionError category bijection lints
# ---------------------------------------------------------------------------


def test_every_extract_code_in_source_is_in_the_catalog():
    """Every EXTRACT-* code= referenced in production code must be a registered
    catalog entry.  The subclasses ZipSlipError, SymlinkEscapeError, and
    SizeLimitError all raise ExtractionError-family instances."""
    from milpa.error_catalog import ERROR_CATALOG

    # Scan for all three subclass names + the base class name.
    slugs: set[str] = set()
    for cls_name in ("ZipSlipError", "SymlinkEscapeError", "SizeLimitError",
                     "ExtractionError"):
        slugs |= _code_slugs_in_source(cls_name, "EXTRACT-")

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("EXTRACT-")}
    orphan_refs = slugs - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references EXTRACT- code(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_every_extract_raise_in_source_carries_a_code():
    """Every `raise <ExtractionError-subclass>(...)` in production code must
    include a `code=` kwarg."""
    import re
    from pathlib import Path

    root = Path(__file__).parent.parent / "milpa"
    pattern = re.compile(
        r'raise\s+(ZipSlipError|SymlinkEscapeError|SizeLimitError)\('
    )
    missing: list[str] = []
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in pattern.finditer(text):
            tail = text[m.start():m.start() + 800]
            if "code=" not in tail:
                lineno = text[:m.start()].count("\n") + 1
                missing.append(f"{py.relative_to(root)}:{lineno}")
    assert missing == [], (
        "raise <ExtractionError subclass>(...) without code= at:\n  "
        + "\n  ".join(missing)
    )


def test_extraction_error_subclasses_expose_code_kwarg():
    """ExtractionError subclasses accept a `code=` kwarg; accessible via .code."""
    from milpa.fetchers.safe_extract import (
        ZipSlipError, SymlinkEscapeError, SizeLimitError,
    )

    z = ZipSlipError("slip", code="EXTRACT-ZIP-SLIP")
    assert z.code == "EXTRACT-ZIP-SLIP"
    assert str(z) == "slip"

    s = SymlinkEscapeError("escape", code="EXTRACT-SYMLINK-ESCAPE")
    assert s.code == "EXTRACT-SYMLINK-ESCAPE"

    sl = SizeLimitError("too big", code="EXTRACT-SIZE-LIMIT")
    assert sl.code == "EXTRACT-SIZE-LIMIT"

    # Legacy (no code)
    z2 = ZipSlipError("legacy")
    assert z2.code is None


def test_extract_zip_slip_code(tmp_path):
    """extract_tar raises ZipSlipError(code='EXTRACT-ZIP-SLIP') when an entry
    escapes the destination."""
    import tarfile
    from milpa.fetchers.safe_extract import extract_tar, ZipSlipError

    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        info = tarfile.TarInfo(name="../../etc/evil")
        info.size = 5
        import io
        tf.addfile(info, io.BytesIO(b"hello"))

    dest = tmp_path / "dest"
    with pytest.raises(ZipSlipError) as exc:
        extract_tar(archive, dest)
    assert exc.value.code == "EXTRACT-ZIP-SLIP"


def test_extract_size_limit_code(tmp_path):
    """extract_tar raises SizeLimitError(code='EXTRACT-SIZE-LIMIT') when a file
    exceeds the per-file cap."""
    import tarfile, io
    from milpa.fetchers.safe_extract import extract_tar, SizeLimitError

    archive = tmp_path / "big.tar.gz"
    # Create a 10-byte file but set max_file_size to 5.
    with tarfile.open(archive, "w:gz") as tf:
        content = b"0123456789"
        info = tarfile.TarInfo(name="bigfile.txt")
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))

    dest = tmp_path / "dest"
    with pytest.raises(SizeLimitError) as exc:
        extract_tar(archive, dest, max_file_size=5)
    assert exc.value.code == "EXTRACT-SIZE-LIMIT"


def test_extract_symlink_escape_code(tmp_path):
    """extract_tar raises SymlinkEscapeError(code='EXTRACT-SYMLINK-ESCAPE') when
    a symlink entry's target resolves outside the destination."""
    import tarfile, io
    from milpa.fetchers.safe_extract import extract_tar, SymlinkEscapeError

    archive = tmp_path / "evil_sym.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        # Add a regular file as an anchor so the symlink has a parent.
        anchor = tarfile.TarInfo(name="anchor.txt")
        anchor.size = 1
        tf.addfile(anchor, io.BytesIO(b"x"))
        # Add a symlink pointing outside the destination.
        sym = tarfile.TarInfo(name="evil_link")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../../outside"
        tf.addfile(sym)

    dest = tmp_path / "dest"
    with pytest.raises(SymlinkEscapeError) as exc:
        extract_tar(archive, dest)
    assert exc.value.code == "EXTRACT-SYMLINK-ESCAPE"


def test_every_extract_code_has_at_least_one_test_that_triggers_it():
    """Every EXTRACT-* catalog entry must appear in at least one test source."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = set()

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("EXTRACT-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"EXTRACT- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


# ---------------------------------------------------------------------------
# TianguisError category bijection lints
# ---------------------------------------------------------------------------


def _tng_slugs_in_source() -> set[str]:
    """Scan production source for TNG-* slugs in ALL usage forms.

    TianguisError is raised in two patterns:
      1. ``raise TianguisError(code="TNG-...", ...)`` — the standard form.
      2. Positional-arg form via helpers like ``_validate_no_leading_dash``
         which receive the code as a plain string argument.

    The generic ``_slugs_in_source_for_prefix`` only catches ``code=`` kwargs.
    This helper also catches bare ``"TNG-..."`` string literals in source so
    that UNSAFE-REF, UNSAFE-URL, and UNSAFE-OCI-FIELD (passed positionally to
    _validate_no_leading_dash) are found."""
    import re
    from pathlib import Path

    slugs: set[str] = set()
    root = Path(__file__).parent.parent / "milpa"
    # Match any string literal that is a TNG-* slug.
    pattern = re.compile(r'["\'](?P<slug>TNG-[A-Z0-9-]+)["\']')
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in pattern.finditer(text):
            slugs.add(m.group("slug"))
    return slugs


def test_every_tng_code_in_source_is_in_the_catalog():
    """Every TNG-* slug referenced in production code must be a registered
    catalog entry — no typos, no drift."""
    from milpa.error_catalog import ERROR_CATALOG

    referenced = _tng_slugs_in_source()
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("TNG-")}

    orphan_refs = referenced - catalog_slugs
    assert orphan_refs == set(), (
        f"production code references TNG- slug(s) not in the catalog: "
        f"{sorted(orphan_refs)}"
    )


def test_tianguis_error_validates_code_against_catalog():
    """TianguisError.__init__ validates the code against ERROR_CATALOG;
    an unregistered code raises AssertionError."""
    from milpa.tianguis_client import TianguisError

    # Valid code: should not raise.
    err = TianguisError(code="TNG-NOT-FOUND", message="test")
    assert err.code == "TNG-NOT-FOUND"

    # Unknown code: must fail loudly at raise time.
    with pytest.raises(AssertionError) as exc:
        TianguisError(code="TNG-TOTALLY-BOGUS", message="bad")
    assert "TNG-TOTALLY-BOGUS" in str(exc.value)


def test_every_tng_code_has_at_least_one_test_that_triggers_it():
    """Every TNG-* catalog entry must appear in at least one test source
    or be listed in KNOWN_UNTESTED with a justification."""
    from pathlib import Path
    from milpa.error_catalog import ERROR_CATALOG

    KNOWN_UNTESTED: set[str] = {
        # TNG-BAD-VERSION is pre-reserved for a future strict-parse mode.
        # Unparseable version strings are currently silently skipped
        # (forward-compat); no raise site exists yet.
        "TNG-BAD-VERSION",
    }

    tests_dir = Path(__file__).parent
    test_text = "\n".join(p.read_text() for p in tests_dir.rglob("test_*.py"))

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("TNG-")}
    referenced_in_tests = {slug for slug in catalog_slugs if slug in test_text}

    untested = catalog_slugs - referenced_in_tests - KNOWN_UNTESTED
    assert untested == set(), (
        f"TNG- catalog code(s) without a direct test reference: "
        f"{sorted(untested)}. Add a test or add to KNOWN_UNTESTED."
    )


def test_tng_bidirectional_bijection():
    """Bidirectional bijection for TNG-*: every catalog slug has at least one
    reference in production source (code= OR positional string literal), or is
    tombstoned.

    Uses the broader ``_tng_slugs_in_source`` scanner (which catches both
    ``code="TNG-..."`` kwargs AND bare string literals like the positional arg to
    ``_validate_no_leading_dash``) rather than the generic
    ``_slugs_in_source_for_prefix`` helper that only catches ``code=`` kwargs."""
    from milpa.error_catalog import ERROR_CATALOG

    # Codes intentionally with no production raise site yet.
    TOMBSTONED: frozenset[str] = frozenset({
        # Reserved for a future strict-parse mode; silently skipped for now.
        "TNG-BAD-VERSION",
    })

    in_source = _tng_slugs_in_source()
    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith("TNG-")}

    orphaned = catalog_slugs - in_source - TOMBSTONED
    assert orphaned == set(), (
        f"TNG- catalog slug(s) with no production source reference and not "
        f"tombstoned: {sorted(orphaned)}"
    )

    still_live = TOMBSTONED & in_source
    assert still_live == set(), (
        f"tombstoned TNG- slug(s) still appear in production source: "
        f"{sorted(still_live)} — remove the reference or remove from TOMBSTONED."
    )


# ---------------------------------------------------------------------------
# Part B — Bidirectional slug-freeze validator
# ---------------------------------------------------------------------------
#
# The existing per-category "code_in_source_is_in_catalog" tests cover the
# ADDITION direction: a code= in a raise site must be in the catalog.
#
# The DELETION direction needs a separate check: a code REMOVED from all
# raise sites (but still in the catalog/errors.md) must fail the validator
# unless it's tombstoned.
#
# The bidirectional validator is implemented by
# `check_catalog_orphan_slugs(prefix, tombstoned)`:
#   - For each slug in ERROR_CATALOG with the given prefix:
#       * It must appear either in a production raise site (code=) OR
#         in the tombstoned set.
#   - A tombstoned slug that ALSO still appears in raise sites is an error
#     (tombstones model "intentionally removed", not "also present").
#
# This single mechanism covers both directions:
#   - Addition: handled by the existing "in_source_is_in_catalog" lint
#   - Deletion: covered by check_catalog_orphan_slugs
#
# The tombstone allow-list lets a deliberately retired slug avoid failing
# the deletion check (e.g. a code renamed in the spec — the old slug is
# tombstoned and the new slug's raise site is added).
# ---------------------------------------------------------------------------


def _slugs_in_source_for_prefix(prefix: str) -> set[str]:
    """Return all code= slugs starting with `prefix` found in production
    raise sites, across ALL exception class names (since we're looking for
    any slug with that prefix)."""
    import re
    from pathlib import Path

    slugs: set[str] = set()
    root = Path(__file__).parent.parent / "milpa"
    # Generic pattern: code="<PREFIX>..." inside any raise call.
    pattern = re.compile(
        rf'code=["\']({re.escape(prefix)}[A-Z0-9-]+)["\']',
        re.DOTALL,
    )
    for py in root.rglob("*.py"):
        if "/error_codes/" in str(py):
            continue
        text = py.read_text()
        for m in pattern.finditer(text):
            slugs.add(m.group(1))
    return slugs


def check_catalog_orphan_slugs(
    prefix: str,
    *,
    tombstoned: frozenset[str] = frozenset(),
) -> None:
    """Assert that every catalog slug with `prefix` is either:
    - present in at least one production raise site (code=), OR
    - present in `tombstoned` (intentionally retired).

    Also asserts that no tombstoned slug still appears in raise sites
    (a tombstone models "removed from code", not "also present").

    Raises AssertionError with a diagnostic on violation.
    """
    from milpa.error_catalog import ERROR_CATALOG

    catalog_slugs = {s for s in ERROR_CATALOG if s.startswith(prefix)}
    in_source = _slugs_in_source_for_prefix(prefix)

    orphaned = catalog_slugs - in_source - tombstoned
    assert orphaned == set(), (
        f"catalog slug(s) with prefix {prefix!r} have NO raise site in "
        f"production code and are not tombstoned: {sorted(orphaned)}\n"
        f"Either add a raise site or add to the tombstoned set."
    )

    still_live = tombstoned & in_source
    assert still_live == set(), (
        f"tombstoned slug(s) still appear in production raise sites: "
        f"{sorted(still_live)}\n"
        f"Remove the raise sites OR remove from tombstoned."
    )


def test_bidirectional_validator_deletion_direction():
    """RED→GREEN: the deletion direction — a catalog slug with no raise
    site fails check_catalog_orphan_slugs UNLESS tombstoned.

    We simulate this by temporarily registering a probe slug that has no
    raise site in any source file, then checking it fails.
    After tombstoning the probe, the check passes."""
    from milpa.error_catalog import ERROR_CATALOG, register

    probe_slug = "TEST-ORPHAN-PROBE"
    probe_prefix = "TEST-"

    # Register the probe (no matching raise site exists in production source).
    register(
        slug=probe_slug, category="TEST",
        description="Probe for the deletion-direction test.",
        when="Never — this is a test probe.",
    )
    try:
        # Without tombstone: should FAIL (the slug is orphaned).
        with pytest.raises(AssertionError) as exc:
            check_catalog_orphan_slugs(probe_prefix, tombstoned=frozenset())
        assert probe_slug in str(exc.value)

        # With tombstone: should PASS.
        check_catalog_orphan_slugs(
            probe_prefix,
            tombstoned=frozenset({probe_slug}),
        )
    finally:
        ERROR_CATALOG.pop(probe_slug, None)


def test_bidirectional_validator_tombstone_live_slug_fails():
    """Tombstoning a slug that still appears in raise sites is an error —
    the tombstone would be lying about the slug being retired."""
    # We can't add a real raise site in a test, but we CAN verify the
    # validator detects the contradiction when the same slug appears in
    # both 'tombstoned' AND is found by _slugs_in_source_for_prefix.
    #
    # Use a prefix that has real slugs in production code (NIMBLE- has
    # NIMBLE-FILE-NOT-FOUND which is wired in nimble_parse.py).  Passing
    # that slug as tombstoned while it still exists in source should fail.
    live_slug = "NIMBLE-FILE-NOT-FOUND"

    with pytest.raises(AssertionError) as exc:
        check_catalog_orphan_slugs("NIMBLE-", tombstoned=frozenset({live_slug}))
    assert live_slug in str(exc.value)


def test_bidirectional_validator_passes_for_all_catalogued_prefixes():
    """All existing catalog prefixes pass check_catalog_orphan_slugs with
    no tombstones — every slug has at least one raise site.

    Exception: SOLVE-CONFLICT uses a class-level attribute, not code=
    in a raise.  It's tombstoned here to acknowledge the special case and
    avoid false-positive failure.  The SOLVE- category has its own class-
    attribute test above."""
    for prefix, special_tombstones in [
        ("MAN-",     frozenset()),
        ("LOCK-",    frozenset()),
        ("RES-",     frozenset()),
        # SOLVE-CONFLICT is a class attribute on SolverError, not a
        # raise-site code= kwarg — acknowledged via tombstone.
        ("SOLVE-",   frozenset({"SOLVE-CONFLICT"})),
        ("FETCH-",   frozenset()),
        ("CAS-",     frozenset()),
        ("ID-",      frozenset()),
        ("NIMBLE-",  frozenset()),
        ("FROZEN-",  frozenset()),
        ("WS-",      frozenset()),
        ("EXTRACT-", frozenset()),
        # TNG- has three codes passed as positional args to
        # _validate_no_leading_dash (not code= kwargs), and one pre-reserved
        # code without a raise site yet — all tombstoned for the generic
        # code=-kwarg scanner.  The TNG-specific bidirectional test
        # (test_tng_bidirectional_bijection) uses a broader scanner that
        # catches both patterns and enforces the full bijection.
        ("TNG-",     frozenset({
            "TNG-UNSAFE-REF",        # positional arg to _validate_no_leading_dash
            "TNG-UNSAFE-URL",        # positional arg to _validate_no_leading_dash
            "TNG-UNSAFE-OCI-FIELD",  # positional arg to _validate_no_leading_dash
            "TNG-BAD-VERSION",       # pre-reserved, no raise site yet
        })),
    ]:
        check_catalog_orphan_slugs(prefix, tombstoned=special_tombstones)
