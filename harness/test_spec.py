"""stdlib unittest tests for harness/spec.py — slice 3a.

Tests the FixtureSpec structured value, url_key convention, and serialize().

Run with:
    python3 -m unittest discover -s harness -p 'test_*.py'
from the repo root.

Behaviors:
  S1: minimal FixtureSpec (one git dep) serializes correct layout.
  S2: consistency invariant — git dep lacking FetchEntry raises ValueError.
  S3: url_key matches §2.3 convention on a real corpus key.
  S4: cmd=frozen serializes 'frozen' into the cmd file.
  S5: index rows serialize index.kdl with correct schema_version.
"""

from __future__ import annotations

import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from harness.spec import (
    DepSpec,
    FetchEntry,
    FixtureSpec,
    IndexRow,
    IndexVersionEntry,
    serialize,
    url_key,
)


class TestUrlKey(unittest.TestCase):
    """S3: url_key matches the §2.3 normative convention."""

    def test_github_main(self) -> None:
        """url_key('https://github.com/example/foo.git', 'main') matches corpus."""
        # Real corpus key: https___github.com_example_foo.git@main
        key = url_key("https://github.com/example/foo.git", "main")
        self.assertEqual(key, "https___github.com_example_foo.git@main")

    def test_separates_url_and_ref_with_at(self) -> None:
        """The @ separating url-part and ref-part is literal, not substituted."""
        key = url_key("https://example.com/a.git", "main")
        self.assertIn("@", key)
        parts = key.split("@")
        self.assertEqual(len(parts), 2)

    def test_ref_at_sign_becomes_underscore(self) -> None:
        """A @ within the ref itself is substituted to _, per the spec note."""
        key = url_key("https://example.com/pkg.git", "v1@beta")
        # url_part @ ref_part, and v1@beta -> v1_beta
        self.assertTrue(key.endswith("@v1_beta"), key)

    def test_version_ref_with_dots(self) -> None:
        """Dots in ref are preserved (they're in [A-Za-z0-9._-])."""
        key = url_key("https://github.com/example/bar.git", "v1.0.0")
        self.assertEqual(key, "https___github.com_example_bar.git@v1.0.0")

    def test_matches_real_corpus_fixture(self) -> None:
        """Computed key matches an actual corpus mocked-fetches dir name."""
        corpus_dir = (
            _REPO_ROOT
            / "conformance"
            / "spec-v1"
            / "fixture-003-single-url-dep"
            / "mocked-fetches"
        )
        # Should have exactly one entry
        entries = list(corpus_dir.iterdir())
        self.assertEqual(len(entries), 1, f"Expected 1 entry, got {entries}")
        real_dir_name = entries[0].name  # https___github.com_example_foo.git@main

        computed = url_key("https://github.com/example/foo.git", "main")
        self.assertEqual(
            computed,
            real_dir_name,
            f"url_key produced {computed!r}, corpus has {real_dir_name!r}",
        )


class TestFixtureSpecInvariant(unittest.TestCase):
    """S2: consistency invariant — git dep without FetchEntry raises ValueError."""

    def test_missing_fetch_entry_raises(self) -> None:
        """FixtureSpec with a git dep but no corresponding FetchEntry raises."""
        dep = DepSpec.git("foo", "https://github.com/example/foo.git", "main")
        with self.assertRaises(ValueError) as ctx:
            FixtureSpec(
                package_name="myapp",
                kind="application",
                deps=[dep],
                fetch_map={},  # empty — dep has no entry
            )
        self.assertIn("foo", str(ctx.exception))

    def test_named_dep_without_fetch_entry_is_valid(self) -> None:
        """Named/index deps don't require a FetchEntry (no url@ref key)."""
        dep = DepSpec.named("bar", ">= 2.0.0")
        # Should not raise — named deps pull from the index, not mocked-fetches
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[dep],
            fetch_map={},
        )
        self.assertEqual(len(spec.deps), 1)

    def test_all_git_deps_covered_is_valid(self) -> None:
        """FixtureSpec is valid when every git dep has a FetchEntry."""
        dep = DepSpec.git("foo", "https://github.com/example/foo.git", "main")
        entry = FetchEntry(
            sha="abcdef1234567890abcdef1234567890abcdef12",
            content_files={"foo.nim": b"# hello\n"},
            nimble_text='version = "1.0.0"\nauthor = "example"\ndescription = "foo"\nlicense = "MIT"\n',
        )
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[dep],
            fetch_map={(dep.git_url, dep.ref): entry},
        )
        self.assertIsNotNone(spec)


class TestSerializeMinimal(unittest.TestCase):
    """S1: minimal FixtureSpec (one git dep, cmd=resolve) serializes correct layout."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp(prefix="milpa-spec-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_minimal_spec(self) -> FixtureSpec:
        dep = DepSpec.git("foo", "https://github.com/example/foo.git", "main")
        entry = FetchEntry(
            sha="abcdef1234567890abcdef1234567890abcdef12",
            content_files={"foo.nim": b"# minimal Nim source\nproc hello*() = discard\n"},
            nimble_text=(
                '# Package\n'
                'version = "1.0.0"\n'
                'author = "example"\n'
                'description = "foo"\n'
                'license = "MIT"\n'
                'srcDir = "src"\n'
            ),
        )
        return FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[dep],
            fetch_map={(dep.git_url, dep.ref): entry},
        )

    def test_cmd_file_written(self) -> None:
        """cmd file is written with 'resolve' (the default)."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        cmd_file = dest / "cmd"
        self.assertTrue(cmd_file.exists(), "cmd file not written")
        self.assertEqual(cmd_file.read_text().strip(), "resolve")

    def test_milpa_kdl_written(self) -> None:
        """milpa.kdl is written and contains the package name and dep."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        manifest = dest / "milpa.kdl"
        self.assertTrue(manifest.exists(), "milpa.kdl not written")
        text = manifest.read_text()
        self.assertIn('name "myapp"', text)
        self.assertIn('kind "application"', text)
        self.assertIn("foo", text)
        self.assertIn("https://github.com/example/foo.git", text)
        self.assertIn('ref="main"', text)

    def test_milpa_kdl_url_annotation(self) -> None:
        """milpa.kdl emits git URL with (url) type annotation per grammar."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        text = (dest / "milpa.kdl").read_text()
        # Matches: foo git=(url)"https://..."
        self.assertIn('git=(url)"https://github.com/example/foo.git"', text)

    def test_mocked_fetches_sha_written(self) -> None:
        """mocked-fetches/<key>/sha is written with the commit SHA."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        key = url_key("https://github.com/example/foo.git", "main")
        sha_file = dest / "mocked-fetches" / key / "sha"
        self.assertTrue(sha_file.exists(), f"sha not found at {sha_file}")
        self.assertEqual(
            sha_file.read_text().strip(),
            "abcdef1234567890abcdef1234567890abcdef12",
        )

    def test_mocked_fetches_content_written(self) -> None:
        """mocked-fetches/<key>/content/<files> are written."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        key = url_key("https://github.com/example/foo.git", "main")
        content_file = dest / "mocked-fetches" / key / "content" / "foo.nim"
        self.assertTrue(content_file.exists(), f"content file not found: {content_file}")
        self.assertIn(b"hello", content_file.read_bytes())

    def test_mocked_fetches_nimble_written(self) -> None:
        """mocked-fetches/<key>/<name>.nimble is written."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        key = url_key("https://github.com/example/foo.git", "main")
        nimble_file = dest / "mocked-fetches" / key / "foo.nimble"
        self.assertTrue(nimble_file.exists(), f"nimble not found: {nimble_file}")
        self.assertIn("1.0.0", nimble_file.read_text())

    def test_key_matches_convention(self) -> None:
        """mocked-fetches directory name matches §2.3 url_key convention."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        mocked = dest / "mocked-fetches"
        dirs = [d.name for d in mocked.iterdir() if d.is_dir()]
        self.assertEqual(dirs, ["https___github.com_example_foo.git@main"])

    def test_no_index_kdl_without_index_rows(self) -> None:
        """index.kdl is NOT written when there are no index rows."""
        spec = self._make_minimal_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        self.assertFalse((dest / "index.kdl").exists())


class TestSerializeFrozenCmd(unittest.TestCase):
    """S4: cmd=frozen serializes 'frozen' into the cmd file."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp(prefix="milpa-spec-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_frozen_cmd_written(self) -> None:
        """cmd file contains 'frozen' when spec.cmd='frozen'."""
        dep = DepSpec.git("foo", "https://github.com/example/foo.git", "main")
        entry = FetchEntry(
            sha="abcdef1234567890abcdef1234567890abcdef12",
            content_files={},
            nimble_text=None,
        )
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[dep],
            fetch_map={(dep.git_url, dep.ref): entry},
            cmd="frozen",
        )
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        self.assertEqual((dest / "cmd").read_text().strip(), "frozen")

    def test_parse_lockfile_cmd_written(self) -> None:
        """cmd file contains 'parse-lockfile' when spec.cmd='parse-lockfile'."""
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[],
            fetch_map={},
            cmd="parse-lockfile",
        )
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        self.assertEqual((dest / "cmd").read_text().strip(), "parse-lockfile")

    def test_invalid_cmd_raises(self) -> None:
        """An unknown cmd value raises ValueError."""
        with self.assertRaises(ValueError):
            FixtureSpec(
                package_name="myapp",
                kind="application",
                deps=[],
                fetch_map={},
                cmd="bad-cmd",
            )


class TestSerializeIndexRows(unittest.TestCase):
    """S5: IndexRow list serializes index.kdl with correct shape."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp(prefix="milpa-spec-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_index_kdl_written_when_index_rows_present(self) -> None:
        """index.kdl is written when index_rows is non-empty."""
        row = IndexRow(
            name="bar",
            versions=[
                IndexVersionEntry(
                    version="2.0.0",
                    content_hash="sha256:94103e1c378d5b8e034414bf69bfa128e780407aa36276f8b3dd395c1e9f4468",
                    git_url="https://github.com/example/bar.git",
                    ref="v2.0.0",
                    commit_sha="cafef00dcafef00dcafef00dcafef00dcafef00d",
                )
            ],
        )
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("bar", ">= 2.0.0")],
            fetch_map={},
            index_rows=[row],
        )
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)

        index_file = dest / "index.kdl"
        self.assertTrue(index_file.exists(), "index.kdl not written")
        text = index_file.read_text()
        self.assertIn("schema_version 1", text)
        self.assertIn('package "bar"', text)
        self.assertIn('"2.0.0"', text)
        self.assertIn("content_hash", text)
        self.assertIn("sha256:94103e1c", text)

    def test_index_kdl_matches_corpus_shape(self) -> None:
        """The emitted index.kdl matches the structural shape of fixture-061's index.kdl."""
        # Load the real corpus index for comparison
        corpus_index = (
            _REPO_ROOT
            / "conformance"
            / "spec-v1"
            / "fixture-061-named-dep"
            / "index.kdl"
        )
        self.assertTrue(corpus_index.exists(), f"corpus index not found: {corpus_index}")
        corpus_text = corpus_index.read_text()

        # fixture-061 has a "bar" package with version "2.0.0"
        row = IndexRow(
            name="bar",
            versions=[
                IndexVersionEntry(
                    version="2.0.0",
                    content_hash="sha256:94103e1c378d5b8e034414bf69bfa128e780407aa36276f8b3dd395c1e9f4468",
                    git_url="https://github.com/example/bar.git",
                    ref="v2.0.0",
                    commit_sha="cafef00dcafef00dcafef00dcafef00dcafef00d",
                )
            ],
        )
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("bar", ">= 2.0.0")],
            fetch_map={},
            index_rows=[row],
        )
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)
        emitted = (dest / "index.kdl").read_text()

        # Both must have schema_version and the package block
        self.assertIn("schema_version 1", emitted)
        self.assertIn('package "bar"', emitted)
        # The corpus has these fields; our emitter must too
        for field in ("content_hash", "provenance", "commit_sha"):
            self.assertIn(field, emitted, f"Missing field {field!r} in emitted index.kdl")


class TestImportClean(unittest.TestCase):
    """harness.spec must import with no 3rd-party deps."""

    def test_import_is_clean(self) -> None:
        """import harness.spec works; no ImportError for stdlib modules."""
        import harness.spec  # noqa: F401
        # If we got here without ImportError, the import is clean.
        self.assertIsNotNone(harness.spec)


class TestIndexFetchMap(unittest.TestCase):
    """S6: index_fetch_map — named dep mocked-fetches entries are written."""

    def setUp(self) -> None:
        self._tmpdir = Path(tempfile.mkdtemp(prefix="milpa-spec-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _make_named_dep_spec(self) -> FixtureSpec:
        """A FixtureSpec with a named dep + index_fetch_map entry."""
        ve = IndexVersionEntry(
            version="2.0.0",
            content_hash="sha256:94103e1c378d5b8e034414bf69bfa128e780407aa36276f8b3dd395c1e9f4468",
            git_url="https://github.com/example/bar.git",
            ref="v2.0.0",
            commit_sha="cafef00dcafef00dcafef00dcafef00dcafef00d",
        )
        row = IndexRow(name="bar", versions=[ve])
        entry = FetchEntry(
            sha="cafef00dcafef00dcafef00dcafef00dcafef00d",
            content_files={"bar.nim": b"# bar\n"},
            nimble_text='version = "2.0.0"\nauthor = "example"\ndescription = "bar"\nlicense = "MIT"\nsrcDir = "src"\n',
        )
        return FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("bar", ">= 2.0.0")],
            fetch_map={},
            index_rows=[row],
            index_fetch_map={(ve.git_url, ve.ref): ("bar", entry)},
        )

    def test_index_fetch_map_writes_mocked_fetches(self) -> None:
        """index_fetch_map entries are written to mocked-fetches/."""
        spec = self._make_named_dep_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)

        mocked = dest / "mocked-fetches"
        self.assertTrue(mocked.exists(), "mocked-fetches not created")
        dirs = [d.name for d in mocked.iterdir() if d.is_dir()]
        # Should have one entry for bar v2.0.0
        self.assertEqual(len(dirs), 1, f"Expected 1 entry, got {dirs}")
        # The key should match url_key(ve.git_url, ve.ref)
        from harness.spec import url_key
        expected_key = url_key("https://github.com/example/bar.git", "v2.0.0")
        self.assertIn(expected_key, dirs)

    def test_index_fetch_map_sha_written(self) -> None:
        """mocked-fetches/<key>/sha is written from the FetchEntry."""
        spec = self._make_named_dep_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)

        from harness.spec import url_key
        key = url_key("https://github.com/example/bar.git", "v2.0.0")
        sha_file = dest / "mocked-fetches" / key / "sha"
        self.assertTrue(sha_file.exists())
        self.assertEqual(sha_file.read_text().strip(), "cafef00dcafef00dcafef00dcafef00dcafef00d")

    def test_index_fetch_map_nimble_written(self) -> None:
        """mocked-fetches/<key>/<pkg>.nimble is written from the FetchEntry."""
        spec = self._make_named_dep_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)

        from harness.spec import url_key
        key = url_key("https://github.com/example/bar.git", "v2.0.0")
        nimble = dest / "mocked-fetches" / key / "bar.nimble"
        self.assertTrue(nimble.exists(), f"bar.nimble not found at {nimble}")
        self.assertIn("2.0.0", nimble.read_text())

    def test_index_fetch_map_content_written(self) -> None:
        """mocked-fetches/<key>/content/<files> are written from the FetchEntry."""
        spec = self._make_named_dep_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)

        from harness.spec import url_key
        key = url_key("https://github.com/example/bar.git", "v2.0.0")
        nim_file = dest / "mocked-fetches" / key / "content" / "bar.nim"
        self.assertTrue(nim_file.exists())

    def test_matches_fixture_061_layout(self) -> None:
        """The generated fixture matches fixture-061-named-dep's exact layout."""
        # fixture-061 has bar 2.0.0 via mocked-fetches
        spec = self._make_named_dep_spec()
        dest = self._tmpdir / "fixture-out"
        serialize(spec, dest)

        # milpa.kdl should have the named dep constraint
        manifest = (dest / "milpa.kdl").read_text()
        self.assertIn('bar ">= 2.0.0"', manifest)

        # index.kdl should have the version
        index = (dest / "index.kdl").read_text()
        self.assertIn('package "bar"', index)
        self.assertIn('"2.0.0"', index)

        # mocked-fetches should have the entry
        from harness.spec import url_key
        key = url_key("https://github.com/example/bar.git", "v2.0.0")
        self.assertTrue((dest / "mocked-fetches" / key).exists())


class TestValidate(unittest.TestCase):
    """S7: FixtureSpec.validate() — consistency invariants 2–4."""

    def setUp(self) -> None:
        self._base_ve = IndexVersionEntry(
            version="1.0.0",
            content_hash="sha256:aaa",
            git_url="https://example.com/foo.git",
            ref="v1.0.0",
            commit_sha="a" * 40,
        )
        self._base_entry = FetchEntry(
            sha="a" * 40,
            content_files={},
            nimble_text='version = "1.0.0"\nauthor = "x"\ndescription = "x"\nlicense = "MIT"\n',
        )

    def _make_spec(self, **overrides) -> FixtureSpec:
        """Build a minimal valid spec; override fields with kwargs."""
        row = IndexRow(name="foo", versions=[self._base_ve])
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("foo", ">= 1.0.0")],
            fetch_map={},
            index_rows=[row],
            index_fetch_map={
                (self._base_ve.git_url, self._base_ve.ref): ("foo", self._base_entry),
            },
            **overrides,
        )
        return spec

    def test_valid_spec_has_no_violations(self) -> None:
        """A properly constructed spec has no validate() violations."""
        spec = self._make_spec()
        violations = spec.validate()
        self.assertEqual(violations, [], f"Expected no violations, got: {violations}")

    def test_missing_index_fetch_entry_is_a_violation(self) -> None:
        """Invariant 2: an index version with no fetch entry is a violation."""
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("foo", ">= 1.0.0")],
            fetch_map={},
            index_rows=[IndexRow(name="foo", versions=[self._base_ve])],
            index_fetch_map={},  # missing entry!
        )
        violations = spec.validate()
        self.assertTrue(len(violations) >= 1)
        self.assertTrue(any("foo" in v for v in violations))

    def test_named_dep_not_in_index_is_a_violation(self) -> None:
        """Invariant 3: a named dep that names a package not in index_rows."""
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("bar", ">= 1.0.0")],  # "bar" not in index
            fetch_map={},
            index_rows=[IndexRow(name="foo", versions=[self._base_ve])],
            index_fetch_map={
                (self._base_ve.git_url, self._base_ve.ref): ("foo", self._base_entry),
            },
        )
        violations = spec.validate()
        self.assertTrue(len(violations) >= 1)
        self.assertTrue(any("bar" in v for v in violations))

    def test_transitive_dep_not_in_index_is_a_violation(self) -> None:
        """Invariant 4: a requires line naming a package not in index_rows."""
        entry_with_transitive = FetchEntry(
            sha="a" * 40,
            content_files={},
            nimble_text=(
                'version = "1.0.0"\nauthor = "x"\ndescription = "x"\nlicense = "MIT"\n'
                'requires "baz >= 1.0.0"\n'  # "baz" not in index
            ),
        )
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("foo", ">= 1.0.0")],
            fetch_map={},
            index_rows=[IndexRow(name="foo", versions=[self._base_ve])],
            index_fetch_map={
                (self._base_ve.git_url, self._base_ve.ref): ("foo", entry_with_transitive),
            },
        )
        violations = spec.validate()
        self.assertTrue(len(violations) >= 1)
        self.assertTrue(any("baz" in v for v in violations))

    def test_transitive_dep_in_index_is_valid(self) -> None:
        """A requires line naming a package that IS in index_rows is valid."""
        bar_ve = IndexVersionEntry(
            version="1.0.0",
            content_hash="sha256:bbb",
            git_url="https://example.com/bar.git",
            ref="v1.0.0",
            commit_sha="b" * 40,
        )
        bar_entry = FetchEntry(
            sha="b" * 40,
            content_files={},
            nimble_text='version = "1.0.0"\nauthor = "x"\ndescription = "x"\nlicense = "MIT"\n',
        )
        entry_with_transitive = FetchEntry(
            sha="a" * 40,
            content_files={},
            nimble_text=(
                'version = "1.0.0"\nauthor = "x"\ndescription = "x"\nlicense = "MIT"\n'
                'requires "bar >= 1.0.0"\n'  # "bar" IS in index
            ),
        )
        spec = FixtureSpec(
            package_name="myapp",
            kind="application",
            deps=[DepSpec.named("foo", ">= 1.0.0")],
            fetch_map={},
            index_rows=[
                IndexRow(name="foo", versions=[self._base_ve]),
                IndexRow(name="bar", versions=[bar_ve]),
            ],
            index_fetch_map={
                (self._base_ve.git_url, self._base_ve.ref): ("foo", entry_with_transitive),
                (bar_ve.git_url, bar_ve.ref): ("bar", bar_entry),
            },
        )
        violations = spec.validate()
        self.assertEqual(violations, [], f"Expected no violations, got: {violations}")


if __name__ == "__main__":
    unittest.main()
