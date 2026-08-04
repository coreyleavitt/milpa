"""S5 (rfc-origin-as-identity.md §7.1 D2/D3): the two new frozen-path
preconditions —

    FROZEN-SOURCE-ID-MISMATCH        (D2, declared-AFTER-override)
    FROZEN-REGISTRY-ALIAS-UNRESOLVED (D3, checked FIRST, short-circuits)

Both reuse ``binding.reconcile_root_claims`` — the SAME override-application
helper ``BindingResolver.__init__`` uses — so an ``overrides {}``-redirected
root dep is compared against its override TARGET, never its raw declaration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv
from milpa.errors import (
    FROZEN_REGISTRY_ALIAS_UNRESOLVED,
    FROZEN_SOURCE_ID_MISMATCH,
    MilpaError,
)
from milpa.frozen import resolve_frozen
from milpa.lockfile import GitProvenanceRecord, LockedDep, Lockfile
from milpa.manifest import GitTarget, Manifest, Override, UrlDep
from milpa.source_id import GitSourceId, RegistrySourceId, normalize_source

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _env_with_tree(tmp_path: Path) -> tuple[MilpaEnv, str]:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    seed = tmp_path / "seed"
    seed.mkdir()
    (seed / "foo.nim").write_text("# minimal nim source\n", encoding="utf-8")
    from milpa.identity import compute_content_hash

    identity = compute_content_hash(seed)
    store.admit(seed, identity)
    return MilpaEnv(fetcher=None, index=None, store=store), identity  # type: ignore[arg-type]


def _locked_git_dep(name: str, url: str, identity: str) -> LockedDep:
    return LockedDep(
        name=name,
        identity=identity,
        version="0.0.1",
        src_dir="",
        requires=(),
        provenances=(GitProvenanceRecord(url=url, ref="main", commit_sha="a" * 40),),
        source_id=normalize_source(GitSourceId(url=url, ref="main")),  # DE2-ref: pin
    )


def _manifest_with_git_dep(name: str, url: str, *, overrides: tuple = ()) -> Manifest:
    return Manifest(
        name="testapp",
        kind="application",
        src_dir="",
        deps=(UrlDep(name=name, git=url, ref="main", mirrors=(), predicates=(), flag_requests=()),),
        overrides=overrides,
    )


class TestFrozenSourceIdMismatch:
    def test_edited_git_url_without_refetch_raises_mismatch(self, tmp_path: Path) -> None:
        """The manifest's git= URL was edited but milpa fetch never re-ran —
        the lockfile still records the OLD origin. Frozen must fail closed."""
        env, identity = _env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_git_dep("foo", "https://example.com/foo.git", identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_git_dep("foo", "https://example.com/DIFFERENT-foo.git")

        with pytest.raises(MilpaError) as exc_info:
            resolve_frozen(manifest, lockfile, env, deps_dir)
        assert exc_info.value.slug == FROZEN_SOURCE_ID_MISMATCH

    def test_unedited_git_url_passes(self, tmp_path: Path) -> None:
        """The common case: manifest and lockfile agree — no mismatch."""
        env, identity = _env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        url = "https://example.com/foo.git"
        locked = _locked_git_dep("foo", url, identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_git_dep("foo", url)

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert graph.deps[0].name == "foo"

    def test_overridden_root_dep_compares_against_override_target_not_raw_declaration(
        self, tmp_path: Path
    ) -> None:
        """D2 (declared-AFTER-override): the raw milpa.kdl dep declaration
        disagrees with the lockfile, but an `overrides {}` rule redirects it
        to the SAME origin the lockfile records — this must NOT false-
        positive as a mismatch (a naive pre-override check would)."""
        env, identity = _env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        override_target_url = "https://example.com/foo-fork.git"
        locked = _locked_git_dep("foo", override_target_url, identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_git_dep(
            "foo",
            "https://example.com/foo-ORIGINAL.git",  # raw decl disagrees
            overrides=(Override(name="foo", target=GitTarget(git=override_target_url, ref="main")),),
        )

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert graph.deps[0].name == "foo"

    def test_overridden_root_dep_still_catches_a_real_mismatch(self, tmp_path: Path) -> None:
        """The override target itself was edited without re-fetching — the
        precondition must still catch THAT disagreement."""
        env, identity = _env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = _locked_git_dep("foo", "https://example.com/foo-fork.git", identity)
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = _manifest_with_git_dep(
            "foo",
            "https://example.com/foo-ORIGINAL.git",
            overrides=(
                Override(
                    name="foo",
                    target=GitTarget(git="https://example.com/foo-fork-EDITED.git", ref="main"),
                ),
            ),
        )

        with pytest.raises(MilpaError) as exc_info:
            resolve_frozen(manifest, lockfile, env, deps_dir)
        assert exc_info.value.slug == FROZEN_SOURCE_ID_MISMATCH


class TestFrozenRegistryAliasUnresolved:
    def test_unresolved_alias_raises_before_mismatch_is_even_attempted(
        self, tmp_path: Path
    ) -> None:
        """D3: a lockfile record naming a registry alias this machine's
        config doesn't recognize raises FROZEN-REGISTRY-ALIAS-UNRESOLVED —
        checked FIRST, so it is never misreported as a coordinate mismatch
        (the comparison is not even attempted)."""
        env, identity = _env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        from milpa.manifest import NamedDep

        locked = LockedDep(
            name="foo",
            identity=identity,
            version="1.0.0",
            src_dir="",
            requires=(),
            provenances=(),
            source_id=RegistrySourceId(registry="some-other-registry", namespace=None, name="foo"),
        )
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = Manifest(
            name="testapp",
            kind="application",
            src_dir="",
            deps=(NamedDep(name="foo", constraint=None),),
        )

        with pytest.raises(MilpaError) as exc_info:
            resolve_frozen(manifest, lockfile, env, deps_dir)
        assert exc_info.value.slug == FROZEN_REGISTRY_ALIAS_UNRESOLVED

    def test_default_alias_passes(self, tmp_path: Path) -> None:
        from milpa.manifest import NamedDep

        env, identity = _env_with_tree(tmp_path)
        deps_dir = tmp_path / "_deps"

        locked = LockedDep(
            name="foo",
            identity=identity,
            version="1.0.0",
            src_dir="",
            requires=(),
            provenances=(),
            source_id=RegistrySourceId(registry="tianguis", namespace=None, name="foo"),
        )
        lockfile = Lockfile(deps=(locked,), strategy="maxver")
        manifest = Manifest(
            name="testapp",
            kind="application",
            src_dir="",
            deps=(NamedDep(name="foo", constraint=None),),
        )

        graph = resolve_frozen(manifest, lockfile, env, deps_dir)
        assert graph.deps[0].name == "foo"


class TestFrozenRegistryTargetOverride:
    """P2 (code-review): a RegistryTarget override renames the dep to the
    target coordinate, so the subject-keyed comparison can never match the
    locked dep — the FROZEN-SOURCE-ID-MISMATCH check was structurally
    unreachable for this one target kind. Detect from the declared side."""

    def _locked_widget(self, name: str) -> LockedDep:
        return LockedDep(
            name=name,
            namespace="acme",
            identity=None,
            version="0.0.1",
            src_dir="",
            requires=(),
            provenances=(),
            source_id=RegistrySourceId(registry="tianguis", namespace="acme", name=name),
        )

    def _manifest(self, target_name: str) -> Manifest:
        from milpa.manifest import RegistryTarget

        return Manifest(
            name="testapp",
            kind="application",
            src_dir="",
            deps=(UrlDep(name="old-fork", git="https://example.com/x.git", ref="main",
                         mirrors=(), predicates=(), flag_requests=()),),
            overrides=(Override(name="old-fork",
                                target=RegistryTarget(name=target_name, namespace="acme")),),
        )

    def test_edited_registry_target_without_refetch_raises(self) -> None:
        from milpa.frozen import check_source_id_preconditions_standalone

        # Lockfile pinned to acme/widget; override now points at acme/widget-evil.
        locked = self._locked_widget("widget")
        with pytest.raises(MilpaError) as exc:
            check_source_id_preconditions_standalone(self._manifest("widget-evil"), (locked,))
        assert exc.value.slug == FROZEN_SOURCE_ID_MISMATCH

    def test_unchanged_registry_target_passes(self) -> None:
        from milpa.frozen import check_source_id_preconditions_standalone

        locked = self._locked_widget("widget")
        # No raise: the override target coordinate is present in the lockfile.
        check_source_id_preconditions_standalone(self._manifest("widget"), (locked,))
