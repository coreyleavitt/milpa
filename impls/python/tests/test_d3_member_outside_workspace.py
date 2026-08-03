"""D3 (rfc-origin-as-identity.md §4.4.1, code-review): a `member "<name>"`
dep declared in a single-package (non-workspace) manifest must fail closed
with the coded slug ``RES-MEMBER-OUTSIDE-WORKSPACE`` rather than being
silently dropped.  The Rust impl raises the SAME slug at its root-seed arm
(``oci_override_malformed_digest``-style parity is asserted in
``resolver_tests.rs``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.errors import RES_MEMBER_OUTSIDE_WORKSPACE, MilpaError
from milpa.manifest import Manifest, MemberDep, NamedDep
from milpa.resolver import resolve


def _env(tmp_path: Path) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    return MilpaEnv(fetcher=None, index=None, store=CAStore(cas_root))  # type: ignore[arg-type]


def _manifest(*deps) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=list(deps),
    )


class TestMemberDepOutsideWorkspace:
    def test_member_dep_in_single_package_manifest_raises_coded_error(
        self, tmp_path: Path
    ) -> None:
        manifest = _manifest(MemberDep(name="sibling"))
        with pytest.raises(MilpaError) as exc:
            resolve(manifest, deps_dir=tmp_path / "_deps", env=_env(tmp_path),
                    params=ResolveParams())
        assert exc.value.slug == RES_MEMBER_OUTSIDE_WORKSPACE
        # The offending member name is carried as structured context.
        assert exc.value.context.get("name") == "sibling"

    def test_member_dep_in_dev_deps_also_raises(self, tmp_path: Path) -> None:
        """A `member` reference is workspace-only regardless of which section
        it appears in — a dev-deps member in a single-package manifest is the
        same category error."""
        manifest = Manifest(
            name="testapp",
            kind="application",
            src_dir="",
            deps=[],
            dev_deps=[MemberDep(name="sibling")],
        )
        with pytest.raises(MilpaError) as exc:
            resolve(manifest, deps_dir=tmp_path / "_deps", env=_env(tmp_path),
                    params=ResolveParams())
        assert exc.value.slug == RES_MEMBER_OUTSIDE_WORKSPACE
