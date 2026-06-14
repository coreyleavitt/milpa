"""Tests for harness/dep_decl.py — S0 DepDecl spec + golden vector + S4-ii gate.

Run with:
    pytest harness/
from the repo root.

Behaviors:
  D1: golden vector sha256 equals recorded dep_decl_hash — the permanent oracle
      asserting that the committed bytes match the committed hash.
  D2: make_dep_decl_fixture produces parseable KDL with the correct top-level
      node and required fields — plausibility check for the helper.
  D3: make_dep_decl_fixture result round-trips: dep_decl_hash of the output
      can be re-verified from the bytes alone.
  D4: dep_decl_hash encoding matches spec/identity.md §2.1 form
      ("sha256:" + 64 lowercase hex chars).
  D5: canonical_serialize honors Rule 5 (constraint verbatim) — two EdgeSets
      differing only in constraint whitespace produce different hashes.
  D6: canonical_serialize honors Rule 6 (explicit src_dir "" when unset) —
      empty src_dir produces `src_dir ""`, not an absent field.
  D7: canonical_serialize honors Rule 4 (URL require form) — UrlRequire
      produces `require (url)"..." ref="..."`.
  D8: canonical_serialize honors Rule 2 (field order) — dep_decl_schema_version
      always precedes src_dir, which always precedes require nodes.
  D9: golden vector parses to the expected EdgeSet shape recorded in meta.json.

S4-ii — Differential gate (imperative cross-fixture lockfile equality):

  DG1: clean pair (fixture-135 vs fixture-136) — the DepDecl-attested arm and
       the .nimble-fallback arm of a package with a clean .nimble resolve to
       BYTE-IDENTICAL lockfiles under both impls (Rust required; Python
       included). Proves DepDecl translation is faithful for clean inputs.

  DG2: when-block pair (fixture-137 vs fixture-138) — the DepDecl-attested arm
       (tianguis excluded the platform-conditional dep) resolves to a DIFFERENT
       lockfile than the .nimble-fallback arm (which unconditionally includes the
       when-block dep). The DepDecl arm is AUTHORITATIVE (asserted against its own
       expected/); the two lockfiles MAY differ. Proves DepDecl authority over
       the .nimble heuristic for packages with when-blocks.

Design note: the twin-fixture lockfile equality test is a NEW imperative harness
capability — the per-fixture corpus runner resolves ONE fixture and checks it
against its own expected/; it CANNOT diff two fixtures' outputs against each other.
These tests add that cross-fixture comparison as pytest tests in harness/
(not as a new corpus directive — no new fixture-metadata format needed).

Fixture locations: conformance/spec-v1/fixture-135 through fixture-138.
Both arms' expected/ directories are also valid individual corpus fixtures,
so the normal corpus runner exercises them independently.

Spec authority: rfc-content-addressed-metadata.md §S4 "(ii) the differential gate".
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.dep_decl import (
    EdgeSet,
    NamedRequire,
    UrlRequire,
    canonical_serialize,
    dep_decl_hash,
    make_dep_decl_fixture,
)

_GOLDEN_DIR = _REPO_ROOT / "conformance" / "spec-v1" / "dep-decl-golden" / "v0"
_GOLDEN_KDL = _GOLDEN_DIR / "example.kdl"
_GOLDEN_META = _GOLDEN_DIR / "meta.json"

# S4-ii fixture directories.
_SPEC_V1 = _REPO_ROOT / "conformance" / "spec-v1"
_F135 = _SPEC_V1 / "fixture-135-depdecl-clean-attested"
_F136 = _SPEC_V1 / "fixture-136-depdecl-clean-fallback"
_F137 = _SPEC_V1 / "fixture-137-depdecl-when-attested"
_F138 = _SPEC_V1 / "fixture-138-depdecl-when-fallback"


class TestGoldenVector(unittest.TestCase):
    """D1: sha256(golden bytes) == recorded dep_decl_hash in meta.json."""

    def test_golden_hash_matches_recorded(self) -> None:
        """The permanent oracle: committed bytes ↔ committed hash."""
        golden_bytes = _GOLDEN_KDL.read_bytes()
        computed = "sha256:" + hashlib.sha256(golden_bytes).hexdigest()
        meta = json.loads(_GOLDEN_META.read_text())
        recorded = meta["dep_decl_hash"]
        self.assertEqual(
            computed,
            recorded,
            msg=(
                f"Golden vector hash mismatch:\n"
                f"  computed:  {computed}\n"
                f"  recorded:  {recorded}\n"
                f"The file at {_GOLDEN_KDL} does not match the recorded hash in "
                f"{_GOLDEN_META}. Either the .kdl was modified (→ update the hash) "
                f"or the hash was mis-recorded (→ recompute)."
            ),
        )

    def test_golden_file_exists(self) -> None:
        self.assertTrue(_GOLDEN_KDL.exists(), f"Golden vector missing: {_GOLDEN_KDL}")

    def test_golden_meta_exists(self) -> None:
        self.assertTrue(_GOLDEN_META.exists(), f"Golden meta missing: {_GOLDEN_META}")


class TestGoldenVectorEdgeSetShape(unittest.TestCase):
    """D9: golden vector KDL reflects the expected EdgeSet in meta.json."""

    def setUp(self) -> None:
        self.kdl_text = _GOLDEN_KDL.read_text()
        self.meta = json.loads(_GOLDEN_META.read_text())

    def test_has_dep_decl_top_node(self) -> None:
        self.assertIn("dep_decl {", self.kdl_text)

    def test_schema_version_is_zero(self) -> None:
        self.assertIn("dep_decl_schema_version 0", self.kdl_text)

    def test_src_dir_matches_meta(self) -> None:
        expected_src_dir = self.meta["expected_edge_set"]["src_dir"]
        self.assertIn(f'src_dir "{expected_src_dir}"', self.kdl_text)

    def test_require_count(self) -> None:
        """Number of require nodes matches meta.json requires list."""
        requires_in_meta = self.meta["expected_edge_set"]["requires"]
        require_nodes = [
            line.strip() for line in self.kdl_text.splitlines()
            if line.strip().startswith("require ")
        ]
        self.assertEqual(len(require_nodes), len(requires_in_meta))

    def test_named_requires_present(self) -> None:
        for entry in self.meta["expected_edge_set"]["requires"]:
            if "name" in entry:
                self.assertIn(
                    f'require "{entry["name"]}"',
                    self.kdl_text,
                )

    def test_url_require_form(self) -> None:
        """URL require uses (url) annotation and ref= property."""
        for entry in self.meta["expected_edge_set"]["requires"]:
            if "url" in entry:
                url = entry["url"]
                ref = entry["ref"]
                self.assertIn(f'(url)"{url}"', self.kdl_text)
                self.assertIn(f'ref="{ref}"', self.kdl_text)

    def test_trailing_newline(self) -> None:
        """Artifact ends with exactly one newline (0x0A) after the closing }."""
        golden_bytes = _GOLDEN_KDL.read_bytes()
        self.assertEqual(golden_bytes[-1:], b"\n", "File must end with 0x0A")
        self.assertFalse(
            golden_bytes.endswith(b"\n\n"),
            "File must NOT end with a blank line (double newline)",
        )


class TestMakeDepDeclFixture(unittest.TestCase):
    """D2 + D3: make_dep_decl_fixture produces plausible, re-hashable bytes."""

    def _simple_edge_set(self) -> EdgeSet:
        return EdgeSet(
            requires=[NamedRequire(name="foo", constraint_str=">= 1.0.0")],
            src_dir="src",
        )

    def test_output_is_bytes(self) -> None:  # D2
        es = self._simple_edge_set()
        result = make_dep_decl_fixture(es)
        self.assertIsInstance(result, bytes)

    def test_output_nonempty(self) -> None:  # D2
        result = make_dep_decl_fixture(self._simple_edge_set())
        self.assertGreater(len(result), 0)

    def test_output_has_dep_decl_node(self) -> None:  # D2
        result = make_dep_decl_fixture(self._simple_edge_set())
        text = result.decode("utf-8")
        self.assertIn("dep_decl {", text)

    def test_output_parseable_as_utf8(self) -> None:  # D2
        result = make_dep_decl_fixture(self._simple_edge_set())
        text = result.decode("utf-8")  # raises if not valid UTF-8
        self.assertIn("require", text)

    def test_dep_decl_hash_roundtrip(self) -> None:  # D3
        """dep_decl_hash(make_dep_decl_fixture(es)) is stable."""
        es = self._simple_edge_set()
        b = make_dep_decl_fixture(es)
        h1 = dep_decl_hash(b)
        h2 = dep_decl_hash(b)
        self.assertEqual(h1, h2)

    def test_dep_decl_hash_deterministic(self) -> None:  # D3
        """Same EdgeSet always produces same bytes and same hash."""
        es = self._simple_edge_set()
        h1 = dep_decl_hash(make_dep_decl_fixture(es))
        h2 = dep_decl_hash(make_dep_decl_fixture(es))
        self.assertEqual(h1, h2)


class TestDepDeclHashEncoding(unittest.TestCase):
    """D4: dep_decl_hash encoding matches spec/identity.md §2.1."""

    def test_hash_format(self) -> None:
        es = EdgeSet(requires=[], src_dir="")
        b = make_dep_decl_fixture(es)
        h = dep_decl_hash(b)
        # Must match "sha256:<64 lowercase hex>"
        self.assertRegex(h, r"^sha256:[0-9a-f]{64}$")

    def test_no_uppercase_in_hash(self) -> None:
        es = EdgeSet(requires=[NamedRequire("pkg", ">= 1.0")], src_dir="")
        h = dep_decl_hash(make_dep_decl_fixture(es))
        self.assertEqual(h, h.lower())


class TestConstraintVerbatim(unittest.TestCase):
    """D5: Rule 5 — whitespace in constraint_str is preserved."""

    def test_spaced_and_nospaced_produce_different_hashes(self) -> None:
        es1 = EdgeSet(requires=[NamedRequire("foo", ">= 1.0")], src_dir="")
        es2 = EdgeSet(requires=[NamedRequire("foo", ">=1.0")], src_dir="")
        b1 = canonical_serialize(es1)
        b2 = canonical_serialize(es2)
        self.assertNotEqual(b1, b2, "Different constraint whitespace must produce different bytes")
        self.assertNotEqual(dep_decl_hash(b1), dep_decl_hash(b2))

    def test_constraint_preserved_verbatim_in_bytes(self) -> None:
        constraint = ">= 0.1 & < 1.0"
        es = EdgeSet(requires=[NamedRequire("stew", constraint)], src_dir="")
        b = canonical_serialize(es)
        self.assertIn(constraint.encode("utf-8"), b)


class TestExplicitSrcDir(unittest.TestCase):
    """D6: Rule 6 — empty src_dir produces `src_dir ""`, not absent."""

    def test_empty_src_dir_emitted(self) -> None:
        es = EdgeSet(requires=[], src_dir="")
        text = canonical_serialize(es).decode("utf-8")
        self.assertIn('src_dir ""', text)

    def test_nonempty_src_dir_emitted(self) -> None:
        es = EdgeSet(requires=[], src_dir="src")
        text = canonical_serialize(es).decode("utf-8")
        self.assertIn('src_dir "src"', text)


class TestUrlRequireForm(unittest.TestCase):
    """D7: Rule 4 — UrlRequire produces `require (url)"..." ref="..."`."""

    def test_url_require_form(self) -> None:
        url = "https://github.com/status-im/nim-chronos.git"
        ref = "v3.2.0"
        es = EdgeSet(requires=[UrlRequire(url=url, ref=ref)], src_dir="")
        text = canonical_serialize(es).decode("utf-8")
        self.assertIn(f'(url)"{url}"', text)
        self.assertIn(f'ref="{ref}"', text)

    def test_url_require_node_name_is_require(self) -> None:
        es = EdgeSet(
            requires=[UrlRequire(url="https://example.com/foo.git", ref="main")],
            src_dir="",
        )
        text = canonical_serialize(es).decode("utf-8")
        # The line must start (after indent) with "require " not "requires " or the url
        require_lines = [
            l.strip() for l in text.splitlines() if l.strip().startswith("require ")
        ]
        self.assertTrue(len(require_lines) > 0)


class TestFieldOrder(unittest.TestCase):
    """D8: Rule 2 — field order: dep_decl_schema_version, src_dir, require*."""

    def test_schema_version_before_src_dir(self) -> None:
        es = EdgeSet(requires=[NamedRequire("foo", ">= 1.0")], src_dir="src")
        text = canonical_serialize(es).decode("utf-8")
        lines = text.splitlines()
        idx_schema = next(
            i for i, l in enumerate(lines) if "dep_decl_schema_version" in l
        )
        idx_src = next(i for i, l in enumerate(lines) if l.strip().startswith("src_dir"))
        idx_req = next(i for i, l in enumerate(lines) if l.strip().startswith("require "))
        self.assertLess(idx_schema, idx_src, "schema_version must precede src_dir")
        self.assertLess(idx_src, idx_req, "src_dir must precede require nodes")

    def test_source_fidelity_tag_not_in_output(self) -> None:
        """The in-memory 'source' field MUST NOT appear in serialized bytes."""
        es = EdgeSet(requires=[], src_dir="", source="nimble_fallback")
        text = canonical_serialize(es).decode("utf-8")
        self.assertNotIn("nimble_fallback", text)
        self.assertNotIn('"source"', text)
        self.assertNotIn("source ", text)

    def test_trailing_newline_only(self) -> None:
        """File ends with exactly one trailing newline."""
        es = EdgeSet(requires=[], src_dir="")
        b = canonical_serialize(es)
        self.assertEqual(b[-1:], b"\n")
        self.assertFalse(b.endswith(b"\n\n"))


# ===========================================================================
# S4-ii — Differential gate
# ===========================================================================
# Helper: resolve a fixture via one impl and return the lockfile text.
# Reuses harness/runner.py machinery (SSOT — does not re-implement subprocess
# invocation).  Cleans up scratch + CAS dirs after extraction.
# ===========================================================================


def _resolve_lockfile(
    fixture_dir: Path,
    impl_name: str,
) -> Optional[str]:
    """Run one (fixture, impl) pair and return the produced milpa.lock text.

    Returns ``None`` if the impl is not available (binary missing) or the
    fixture does not exist, so callers can skip gracefully.  Raises on
    unexpected subprocess failures.

    Design: reuses ``harness.runner.run_fixture`` (the SSOT for subprocess
    invocation) rather than re-implementing it.  The lockfile is extracted
    from the scratch dir before cleanup.

    This is the NEW harness capability added by S4-ii: cross-fixture lockfile
    comparison.  The per-fixture corpus runner checks ONE fixture against its
    own expected/; this helper lets a test compare TWO fixtures' outputs.
    """
    if not fixture_dir.is_dir():
        return None

    from harness.descriptors import build_descriptors
    from harness.runner import run_fixture

    descriptors = {d.name: d for d in build_descriptors(_REPO_ROOT)}
    desc = descriptors.get(impl_name)
    if desc is None:
        return None

    # Quick binary-presence check (avoids a slow subprocess timeout).
    if desc.argv and not Path(desc.argv[0]).exists():
        return None

    result = run_fixture(fixture_dir, desc, timeout=60)

    # Extract milpa.lock before cleanup.
    lock_path = Path(result.scratch_dir) / "milpa.lock"
    lock_text: Optional[str] = None
    if lock_path.exists():
        lock_text = lock_path.read_text(encoding="utf-8")

    # Cleanup scratch and CAS dirs (SSOT via RunResult.cleanup).
    result.cleanup()

    if result.returncode != 0:
        raise AssertionError(
            f"_resolve_lockfile: impl={impl_name!r} fixture={fixture_dir.name!r} "
            f"exited {result.returncode}; stderr={result.stderr[:300]!r}"
        )
    return lock_text


class TestDifferentialGate(unittest.TestCase):
    """S4-ii — cross-fixture lockfile equality / divergence assertions.

    DG1 (clean pair): fixture-135 (DepDecl-attested arm) and fixture-136
    (.nimble-fallback arm) must produce BYTE-IDENTICAL lockfiles, proving
    the DepDecl translation is faithful for clean .nimble inputs.

    DG2 (when-block pair): fixture-137 (DepDecl-attested arm) and
    fixture-138 (.nimble-fallback arm) are expected to produce DIFFERENT
    lockfiles.  The attested arm is authoritative (asserted against its own
    expected/); the fallback arm unconditionally includes the when-block dep.
    Divergence proves DepDecl authority over the .nimble heuristic.

    Impls covered: Rust (reference, required) and Python (active impl,
    included).
    """

    # -----------------------------------------------------------------------
    # DG1: clean pair — byte-identical lockfiles
    # -----------------------------------------------------------------------

    @staticmethod
    def _strip_dep_decl_lines(lock_text: str) -> str:
        """Remove `dep_decl "sha256:..."` lines before comparison.

        S6 adds dep_decl pins to the lockfile when the edge source is
        DepDecl-attested.  The DG1 invariant checks that DepDecl-attested
        and .nimble-fallback arms produce identical *resolution outcomes*
        (same requires, src_dir, versions, identity, provenance).  The
        dep_decl field records WHICH artifact was used — it is expected to
        differ between the attested and fallback arms (attested arm pins the
        hash; fallback arm has no pin).  Strip it before the edge comparison.
        """
        import re
        return re.sub(r"^\s+dep_decl \"sha256:[0-9a-f]+\"\n", "", lock_text, flags=re.MULTILINE)

    def _assert_clean_pair_identical(self, impl_name: str) -> None:
        """Resolve both clean arms via impl_name; assert identical resolution outcomes.

        The dep_decl pin field is stripped before comparison (S6): it records
        which artifact was used, not the resolution outcome, so it is expected
        to differ between the attested (dep_decl present) and fallback
        (dep_decl absent) arms.
        """
        lock_135 = _resolve_lockfile(_F135, impl_name)
        lock_136 = _resolve_lockfile(_F136, impl_name)

        if lock_135 is None or lock_136 is None:
            self.skipTest(
                f"impl {impl_name!r} not available or fixtures not found; "
                f"lock_135={'present' if lock_135 is not None else 'missing'}, "
                f"lock_136={'present' if lock_136 is not None else 'missing'}"
            )

        stripped_135 = self._strip_dep_decl_lines(lock_135)
        stripped_136 = self._strip_dep_decl_lines(lock_136)

        self.assertEqual(
            stripped_135,
            stripped_136,
            msg=(
                f"DG1 FAILED for impl={impl_name!r}: clean pair resolution outcomes differ.\n"
                f"  fixture-135 (DepDecl-attested, dep_decl stripped):\n{stripped_135}\n"
                f"  fixture-136 (.nimble-fallback, dep_decl stripped):\n{stripped_136}\n"
                f"The DepDecl translation must produce identical resolution outcomes "
                f"for a clean .nimble (no when-block).\n"
                f"Either the DepDecl artifact has wrong edges OR the .nimble "
                f"scanner diverges from it."
            ),
        )

    def test_dg1_clean_pair_rust(self) -> None:
        """DG1 (Rust): DepDecl-attested and .nimble-fallback arms → identical lockfile."""
        self._assert_clean_pair_identical("rust")

    def test_dg1_clean_pair_python(self) -> None:
        """DG1 (python): DepDecl-attested and .nimble-fallback arms → identical lockfile."""
        self._assert_clean_pair_identical("python")

    # -----------------------------------------------------------------------
    # DG2: when-block pair — DepDecl arm is authoritative; divergence allowed
    # -----------------------------------------------------------------------

    def _assert_when_attested_correctness(self, impl_name: str) -> None:
        """Resolve the when-block attested arm; assert it matches its expected/ lockfile.

        The DepDecl (attested) arm has edges = {bar} only (tianguis excluded the
        platform-conditional 'extra' dep from the when-block).  The lockfile MUST
        contain 'bar' and 'qux' only, NOT 'extra'.

        This asserts DepDecl authority: the resolver used the attested DepDecl
        rather than the .nimble heuristic (which would include 'extra').
        """
        lock_137 = _resolve_lockfile(_F137, impl_name)
        if lock_137 is None:
            self.skipTest(f"impl {impl_name!r} not available or fixture-137 not found")

        # Load the canonical expected lockfile from the corpus.
        expected_lock = (_F137 / "expected" / "milpa.lock").read_text(encoding="utf-8")

        self.assertEqual(
            lock_137,
            expected_lock,
            msg=(
                f"DG2a FAILED for impl={impl_name!r}: when-block attested arm "
                f"lockfile does not match expected/milpa.lock.\n"
                f"  got:\n{lock_137}\n"
                f"  expected:\n{expected_lock}\n"
                f"The DepDecl (attested) arm must use the DepDecl edges (bar only) "
                f"rather than falling back to the .nimble heuristic (which would "
                f"include 'extra' unconditionally from the when-block)."
            ),
        )

    def _assert_when_pair_diverges(self, impl_name: str) -> None:
        """Resolve both when-block arms; assert their lockfiles differ.

        fixture-137 (DepDecl-attested): only bar in qux's edges → lockfile has qux+bar.
        fixture-138 (.nimble-fallback): .nimble includes bar+extra unconditionally
            from the when-block → lockfile has qux+bar+extra.

        The divergence PROVES DepDecl is authoritative (resolver used DepDecl for
        fixture-137, .nimble for fixture-138) and that the two edge sources disagree
        for when-block packages.

        NOTE: frozen Python is excluded from this test (known-failing on fixture-137).
        Only Rust and Python are tested here.
        """
        lock_137 = _resolve_lockfile(_F137, impl_name)
        lock_138 = _resolve_lockfile(_F138, impl_name)

        if lock_137 is None or lock_138 is None:
            self.skipTest(
                f"impl {impl_name!r} not available; "
                f"lock_137={'present' if lock_137 is not None else 'missing'}, "
                f"lock_138={'present' if lock_138 is not None else 'missing'}"
            )

        self.assertNotEqual(
            lock_137,
            lock_138,
            msg=(
                f"DG2b FAILED for impl={impl_name!r}: when-block pair lockfiles are "
                f"identical but MUST differ.\n"
                f"  fixture-137 (DepDecl-attested): 2 deps (qux+bar)\n"
                f"  fixture-138 (.nimble-fallback): 3 deps (qux+bar+extra)\n"
                f"If the lockfiles are identical, the resolver is NOT using the "
                f"DepDecl for fixture-137 — it falls back to .nimble for both arms."
            ),
        )

        # Sanity: attested arm MUST NOT contain 'extra' (DepDecl excluded it).
        self.assertNotIn(
            'dep "extra"',
            lock_137,
            msg=(
                f"DG2b FAILED for impl={impl_name!r}: fixture-137 (DepDecl-attested) "
                f"lockfile contains 'dep \"extra\"' but the DepDecl excluded it.\n"
                f"Lockfile:\n{lock_137}"
            ),
        )

        # Sanity: fallback arm MUST contain 'extra' (from when-block).
        self.assertIn(
            'dep "extra"',
            lock_138,
            msg=(
                f"DG2b FAILED for impl={impl_name!r}: fixture-138 (.nimble-fallback) "
                f"lockfile does NOT contain 'dep \"extra\"', but the .nimble scanner "
                f"includes when-block deps unconditionally.\n"
                f"Lockfile:\n{lock_138}"
            ),
        )

    def test_dg2a_when_attested_correctness_rust(self) -> None:
        """DG2a (Rust): DepDecl-attested arm lockfile matches expected/ (bar only, no extra)."""
        self._assert_when_attested_correctness("rust")

    def test_dg2a_when_attested_correctness_python(self) -> None:
        """DG2a (python): DepDecl-attested arm lockfile matches expected/ (bar only, no extra)."""
        self._assert_when_attested_correctness("python")

    def test_dg2b_when_pair_diverges_rust(self) -> None:
        """DG2b (Rust): when-block pair lockfiles differ; extra absent from attested, present in fallback."""
        self._assert_when_pair_diverges("rust")

    def test_dg2b_when_pair_diverges_python(self) -> None:
        """DG2b (python): when-block pair lockfiles differ; extra absent from attested, present in fallback."""
        self._assert_when_pair_diverges("python")
