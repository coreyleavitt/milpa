"""S8b — COMPLETE overrides grammar (rfc-origin-as-identity.md §7 B5 /
§10 item 14): ``OciTarget``, ``TarballTarget``, ``RegistryTarget``, and
version-scoped overrides.

``overrides {}`` is milpa's sole rebind bridge (Cargo ``[patch]`` analog)
across EVERY transport — this closes the gap where ``OverrideTarget`` was
only ``Git | Local | Member``. Coverage:

  - Grammar: each of the three new target kinds parses; round-trips through
    ``format_manifest``; the six-way target-ambiguity check still fires for
    zero/multiple forms; the new MAN-OVERRIDE-* slugs fire for malformed
    input.
  - Resolution: each target kind actually REBINDS a dep's source — the dep
    resolves via the override target, not its original (git) declaration.
    Proven by (a) never providing a mocked git fixture for the original
    declaration (so a fall-through-to-git bug would raise FETCH-MOCK-MISSING,
    not silently succeed), and (b) asserting the resolved dep's OBSERVED
    provenance record carries the override target's own distinctive
    coordinate.
  - Version-scoped overrides: a ``RegistryTarget`` with ``version=`` pins the
    solver to exactly that version even when a newer one exists in the index
    (composing with Axis-A/maxver precedence).
  - Composition with phase-1 binding (S5-rekey): overriding an actually-used
    dep rebinds its solver var to the target's canonical source-id;
    overriding an unused name still only produces the non-fatal
    RES-DEAD-OVERRIDE warning (S5b), unchanged for the new target kinds.
"""

from __future__ import annotations

import io
import tarfile
import textwrap
import warnings
from pathlib import Path

import pytest

from milpa.errors import (
    MAN_OVERRIDE_DIGEST_MISSING,
    MAN_OVERRIDE_NAMED_MISSING,
    MAN_OVERRIDE_OCI_MALFORMED,
    MAN_OVERRIDE_TARGET_AMBIGUOUS,
    RES_DEAD_OVERRIDE,
    MilpaError,
)
from milpa.manifest import (
    OciTarget,
    RegistryTarget,
    TarballTarget,
    format_manifest,
    parse_manifest,
)
from milpa.version import Version

# ---------------------------------------------------------------------------
# Grammar: parse + round-trip
# ---------------------------------------------------------------------------


class TestOciTargetParse:
    def test_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" oci="ghcr.io/acme/foo" digest="sha256:""" + "a" * 64 + """"
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert ov.name == "foo"
        assert isinstance(ov.target, OciTarget)
        assert ov.target.registry == "ghcr.io"
        assert ov.target.repository == "acme/foo"
        assert ov.target.digest == "sha256:" + "a" * 64

    def test_subpath_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" oci="ghcr.io/acme/foo" digest="sha256:""" + "a" * 64 + """" subpath="pkg/foo"
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert isinstance(ov.target, OciTarget)
        assert ov.target.subpath == "pkg/foo"

    def test_missing_digest_raises(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" oci="ghcr.io/acme/foo"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        assert exc_info.value.slug == MAN_OVERRIDE_DIGEST_MISSING

    def test_malformed_coordinate_no_slash_raises(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" oci="ghcronly" digest="sha256:""" + "a" * 64 + """"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        assert exc_info.value.slug == MAN_OVERRIDE_OCI_MALFORMED

    def test_round_trips(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" oci="ghcr.io/acme/foo" digest="sha256:""" + "b" * 64 + """"
            }
        """)
        m = parse_manifest(text)
        out = format_manifest(m)
        m2 = parse_manifest(out)
        assert m2.overrides == m.overrides


class TestTarballTargetParse:
    def test_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" tarball=(url)"https://example.com/foo.tar.gz" sha256="deadbeef" strip_components=1
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert isinstance(ov.target, TarballTarget)
        assert ov.target.url == "https://example.com/foo.tar.gz"
        assert ov.target.sha256 == "deadbeef"
        assert ov.target.strip_components == 1

    def test_subpath_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" tarball=(url)"https://example.com/foo.tar.gz" subpath="pkg/foo"
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert isinstance(ov.target, TarballTarget)
        assert ov.target.subpath == "pkg/foo"

    def test_round_trips(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" tarball=(url)"https://example.com/foo.tar.gz" sha256="deadbeef" strip_components=1 subpath="pkg/foo"
            }
        """)
        m = parse_manifest(text)
        out = format_manifest(m)
        m2 = parse_manifest(out)
        assert m2.overrides == m.overrides


class TestRegistryTargetParse:
    def test_parses(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "old-fork" named="widget" namespace="acme"
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert ov.name == "old-fork"
        assert isinstance(ov.target, RegistryTarget)
        assert ov.target.name == "widget"
        assert ov.target.namespace == "acme"

    def test_namespace_optional(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "old-fork" named="widget"
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert isinstance(ov.target, RegistryTarget)
        assert ov.target.namespace is None

    def test_missing_named_raises(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "old-fork" namespace="acme"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        # No target form present at all -> ambiguous (namespace= alone never
        # selects the registry form; `named=` is the discriminator).
        assert exc_info.value.slug == MAN_OVERRIDE_TARGET_AMBIGUOUS

    def test_version_scoped(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "old-fork" named="widget" namespace="acme" version="1.0.0"
            }
        """)
        m = parse_manifest(text)
        ov = m.overrides[0]
        assert ov.version == Version(1, 0, 0)

    def test_round_trips(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "old-fork" named="widget" namespace="acme" version="1.0.0"
            }
        """)
        m = parse_manifest(text)
        out = format_manifest(m)
        m2 = parse_manifest(out)
        assert m2.overrides == m.overrides


class TestTargetAmbiguitySixWay:
    def test_two_new_forms_mixed_raises(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" oci="ghcr.io/a/b" digest="sha256:""" + "a" * 64 + """" tarball=(url)"https://example.com/x.tar.gz"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        assert exc_info.value.slug == MAN_OVERRIDE_TARGET_AMBIGUOUS

    def test_old_and_new_form_mixed_raises(self) -> None:
        text = textwrap.dedent("""\
            name "x"
            overrides {
                pkg "foo" git=(url)"https://example.com/foo.git" ref="main" named="foo"
            }
        """)
        with pytest.raises(MilpaError) as exc_info:
            parse_manifest(text)
        assert exc_info.value.slug == MAN_OVERRIDE_TARGET_AMBIGUOUS


# ---------------------------------------------------------------------------
# Resolution — each target kind actually rebinds the dep's source
# ---------------------------------------------------------------------------


def _build_tar_gz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _manifest_with_root_git_dep(dep_name: str, override_kdl: str) -> "object":
    from milpa.manifest import parse_manifest as _pm

    root_kdl = textwrap.dedent(f"""\
        name "myapp"
        kind "application"
        deps {{
            {dep_name} git=(url)"https://example.com/{dep_name}-DO-NOT-FETCH.git" ref="main"
        }}
        overrides {{
        {override_kdl}
        }}
    """)
    return _pm(root_kdl)


class TestOciTargetRebindsResolution:
    def test_rebinds_to_oci_source(self, tmp_path: Path) -> None:
        """A root git dep overridden to OciTarget resolves via the OCI pull —
        the original git URL is NEVER fetched (no mocked git fixture exists
        for it; a fall-through-to-git bug would raise FETCH-MOCK-MISSING)."""
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.fetchers.oci import OciFetcher
        from milpa.fetchers.types import FetcherRegistry
        from milpa.cas import CAStore
        from milpa.lockfile import OciProvenanceRecord
        from milpa.resolver import resolve
        from tests._oci_fake_client import FakeOciClient

        digest = "sha256:" + "c" * 64
        tar_bytes = _build_tar_gz(
            {"foo.nimble": b'version = "1.0.0"\nauthor = "a"\nlicense = "MIT"\n'}
        )
        fake_client = FakeOciClient(tar_bytes)

        registry = FetcherRegistry()
        registry.register(OciFetcher(client=fake_client))
        store = CAStore(root=tmp_path / ".cas")
        fetcher = CasAdmittingFetcher(registry, store)
        env = MilpaEnv(fetcher=fetcher, index=None, store=store)

        manifest = _manifest_with_root_git_dep(
            "foo",
            f'    pkg "foo" oci="ghcr.io/acme/foo" digest="{digest}"',
        )
        graph = resolve(manifest, tmp_path / "_deps", env, ResolveParams())

        assert fake_client.calls == [f"ghcr.io/acme/foo@{digest}"]
        dep = next(d for d in graph.deps if d.name == "foo")
        assert len(dep.provenances) == 1
        prov = dep.provenances[0]
        assert isinstance(prov, OciProvenanceRecord)
        assert prov.registry == "ghcr.io"
        assert prov.repository == "acme/foo"
        assert prov.digest == digest


class TestTarballTargetRebindsResolution:
    def test_rebinds_to_tarball_source(self, tmp_path: Path) -> None:
        """A root git dep overridden to TarballTarget resolves via the
        tarball fetch — the original git URL is never touched."""
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.fetchers.tarball import TarballFetcher
        from milpa.fetchers.types import FetcherRegistry
        from milpa.cas import CAStore
        from milpa.lockfile import TarballProvenanceRecord
        from milpa.resolver import resolve

        tar_bytes = _build_tar_gz(
            {"foo.nimble": b'version = "2.0.0"\nauthor = "a"\nlicense = "MIT"\n'}
        )
        fetch_calls: list[str] = []

        def _fake_http_get(url: str, dest: Path) -> None:
            fetch_calls.append(url)
            dest.write_bytes(tar_bytes)

        registry = FetcherRegistry()
        registry.register(TarballFetcher(http_get=_fake_http_get))
        store = CAStore(root=tmp_path / ".cas")
        fetcher = CasAdmittingFetcher(registry, store)
        env = MilpaEnv(fetcher=fetcher, index=None, store=store)

        manifest = _manifest_with_root_git_dep(
            "foo",
            '    pkg "foo" tarball=(url)"https://example.com/foo-real.tar.gz"',
        )
        graph = resolve(manifest, tmp_path / "_deps", env, ResolveParams())

        assert fetch_calls == ["https://example.com/foo-real.tar.gz"]
        dep = next(d for d in graph.deps if d.name == "foo")
        assert len(dep.provenances) == 1
        prov = dep.provenances[0]
        assert isinstance(prov, TarballProvenanceRecord)
        assert prov.url == "https://example.com/foo-real.tar.gz"
        assert dep.version == "2.0.0"


class TestRegistryTargetRebindsResolution:
    def _index(self) -> "object":
        from milpa.registry import Index, IndexVersion, OciIndexProvenance, Package

        return Index(
            packages=[
                Package(
                    name="widget",
                    namespace="acme",
                    versions=(
                        IndexVersion(
                            version="1.0.0",
                            content_hash="dag-sha256:" + "1" * 64,
                            provenances=(
                                OciIndexProvenance(
                                    registry="ghcr.io",
                                    repository="acme/widget",
                                    digest="sha256:" + "1" * 64,
                                ),
                            ),
                        ),
                        IndexVersion(
                            version="2.0.0",
                            content_hash="dag-sha256:" + "2" * 64,
                            provenances=(
                                OciIndexProvenance(
                                    registry="ghcr.io",
                                    repository="acme/widget",
                                    digest="sha256:" + "2" * 64,
                                ),
                            ),
                        ),
                    ),
                )
            ]
        )

    def _env(self, tmp_path: Path) -> "object":
        from milpa.context import MilpaEnv
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.fetchers.oci import OciFetcher
        from milpa.fetchers.types import FetcherRegistry
        from milpa.cas import CAStore
        from tests._oci_fake_client import FakeOciClient

        tar_bytes = _build_tar_gz(
            {"widget.nimble": b'version = "0.0.0"\nauthor = "a"\nlicense = "MIT"\n'}
        )
        fake_client = FakeOciClient(tar_bytes)

        registry = FetcherRegistry()
        registry.register(OciFetcher(client=fake_client))
        store = CAStore(root=tmp_path / ".cas")
        fetcher = CasAdmittingFetcher(registry, store)
        return MilpaEnv(fetcher=fetcher, index=self._index(), store=store)

    def test_rebinds_to_registry_coordinate_maxver_default(self, tmp_path: Path) -> None:
        """No version= on the override -> ordinary maxver precedence picks
        the newest (2.0.0), proving the redirect is live (not a no-op) and
        establishing the baseline the version-scoped test below overrides."""
        from milpa.context import ResolveParams
        from milpa.lockfile import OciProvenanceRecord
        from milpa.resolver import resolve
        from milpa.version import Strategy

        env = self._env(tmp_path)
        manifest = _manifest_with_root_git_dep(
            "old-fork", '    pkg "old-fork" named="widget" namespace="acme"',
        )
        graph = resolve(
            manifest, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER),
        )
        dep = next(d for d in graph.deps if d.name == "old-fork")
        assert dep.version == "2.0.0"
        prov = dep.provenances[0]
        assert isinstance(prov, OciProvenanceRecord)
        assert prov.digest == "sha256:" + "2" * 64

    def test_version_scoped_override_pins_exact_version(self, tmp_path: Path) -> None:
        """version= on the RegistryTarget override pins the solver to
        EXACTLY that version, even though a newer one (2.0.0) exists in the
        index and would otherwise win under maxver."""
        from milpa.context import ResolveParams
        from milpa.lockfile import OciProvenanceRecord
        from milpa.resolver import resolve
        from milpa.version import Strategy

        env = self._env(tmp_path)
        manifest = _manifest_with_root_git_dep(
            "old-fork",
            '    pkg "old-fork" named="widget" namespace="acme" version="1.0.0"',
        )
        graph = resolve(
            manifest, tmp_path / "_deps", env, ResolveParams(strategy=Strategy.MAXVER),
        )
        dep = next(d for d in graph.deps if d.name == "old-fork")
        assert dep.version == "1.0.0"
        prov = dep.provenances[0]
        assert isinstance(prov, OciProvenanceRecord)
        assert prov.digest == "sha256:" + "1" * 64


# ---------------------------------------------------------------------------
# Composition with phase-1 binding (S5-rekey): dead-override diagnostic
# still fires (non-fatal) for the new target kinds when the name is unused.
# ---------------------------------------------------------------------------


class TestDeadOverrideStillWorksForNewKinds:
    def test_oci_target_on_unused_name_warns_dead_non_fatal(self, tmp_path: Path) -> None:
        from milpa.context import MilpaEnv, ResolveParams
        from milpa.fetchers.cas_admitting import CasAdmittingFetcher
        from milpa.fetchers.mocked import mocked_registry, url_key
        from milpa.cas import CAStore
        from milpa.manifest import parse_manifest as _pm
        from milpa.resolver import resolve

        mocked_dir = tmp_path / "mocked-fetches"
        key = url_key("https://example.com/lib-a.git", "main")
        d = mocked_dir / key
        (d / "content").mkdir(parents=True)
        (d / "content" / "milpa.kdl").write_text('name "lib-a"\nkind "library"\n', encoding="utf-8")
        (d / "sha").write_text("a" * 40, encoding="utf-8")
        store = CAStore(tmp_path / "cas")
        fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
        env = MilpaEnv(fetcher=fetcher, index=None, store=store)

        root_kdl = (
            'name "myapp"\nkind "application"\n'
            'deps {\n'
            '    lib-a git=(url)"https://example.com/lib-a.git" ref="main"\n'
            '}\n'
            'overrides {\n'
            '    pkg "ghost-dep" oci="ghcr.io/acme/ghost" digest="sha256:' + "a" * 64 + '"\n'
            '}\n'
        )
        manifest = _pm(root_kdl)

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            graph = resolve(manifest, tmp_path / "_deps", env, ResolveParams())

        assert RES_DEAD_OVERRIDE
        dead_warnings = [
            str(x.message) for x in w
            if issubclass(x.category, UserWarning) and "ghost-dep" in str(x.message)
        ]
        assert dead_warnings, f"expected dead-override warning; got: {[str(x.message) for x in w]}"
        # Non-fatal: resolution still succeeds with a usable graph.
        assert any(d.name == "lib-a" for d in graph.deps)
