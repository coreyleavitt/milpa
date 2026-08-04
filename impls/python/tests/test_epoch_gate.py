"""Tests for the S-EpochGate per-entry membership predicate (entry_trust.py).

RFC: docs/rfc-attestation-v1-normative.md §6 S-EpochGate, D14/D17.
Spec: spec/registry-protocol.md §3.4.8 (membership is a local set lookup)
and §3.6.3 (EntryGateOutcome / EpochMembership NORMATIVE clauses).

Covers:
  - classify_epoch_membership: Armed+member -> PreEpoch, Armed+non-member ->
    PostEpoch, Unarmed -> None
  - effective_epoch_policy: the warn-cap downgrade matrix
  - the full impl-level unit matrix (RFC §6 *Test*):
    {PreEpoch, PostEpoch, Unarmed} x {warn, strict} x {attested, unattested}
  - a fresh-clone/ephemeral-CI case (no ~/.cache/milpa) proving classification
    has zero dependency on index_ratchet_seam's baseline sidecar (br7)
  - a workspace-resolve case exercising classification on a member-pulled
    registry dep (br9)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.cas import CAStore
from milpa.context import MilpaEnv, ResolveParams
from milpa.entry_trust import (
    BundleMissing,
    EntryGateOutcome,
    EntryTrustConfig,
    EpochMembership,
    MockEntryVerifier,
    PostEpoch,
    PreEpoch,
    Trusted,
    Unattested,
    classify_epoch_membership,
    effective_epoch_policy,
    enforce_entry_trust,
    evaluate_entry_attestation,
    _reset_warned_entries,
)
from milpa.epoch_commitment import Armed, PreEpochIdentity, Unarmed
from milpa.errors import TNG_ENTRY_UNATTESTED, MilpaError
from milpa.fetchers.cas_admitting import CasAdmittingFetcher
from milpa.fetchers.mocked import mocked_registry
from milpa.index_trust import TrustBundle
from milpa.manifest import Manifest, NamedDep
from milpa.registry import GitIndexProvenance, Index, IndexVersion, Package
from milpa.resolver import resolve_workspace
from milpa.workspace import LoadedMember, LoadedWorkspace, WorkspaceManifest


@pytest.fixture(autouse=True)
def _reset_dedup():
    _reset_warned_entries()
    yield
    _reset_warned_entries()


def _id(namespace: str, name: str, version: str, content_hash: str) -> PreEpochIdentity:
    return PreEpochIdentity(namespace=namespace, name=name, version=version, content_hash=content_hash)


_CH = "dag-sha256:" + "a" * 64
_OTHER_CH = "dag-sha256:" + "b" * 64
_IDENTITY = _id("ns1", "foo", "1.0.0", _CH)


# ---------------------------------------------------------------------------
# classify_epoch_membership — the local set-lookup (D17)
# ---------------------------------------------------------------------------


class TestClassifyEpochMembership:
    def test_armed_member_is_pre_epoch(self) -> None:
        status = Armed(identities=frozenset([_IDENTITY]), integrated_time=1700000000)
        assert classify_epoch_membership(status, _IDENTITY) is PreEpoch

    def test_armed_non_member_is_post_epoch(self) -> None:
        status = Armed(identities=frozenset([_id("ns1", "other", "2.0.0", _OTHER_CH)]), integrated_time=1700000000)
        assert classify_epoch_membership(status, _IDENTITY) is PostEpoch

    def test_armed_empty_set_is_post_epoch(self) -> None:
        """An armed-but-empty S: every candidate is (vacuously) post-epoch."""
        status = Armed(identities=frozenset(), integrated_time=1700000000)
        assert classify_epoch_membership(status, _IDENTITY) is PostEpoch

    def test_unarmed_is_none(self) -> None:
        assert classify_epoch_membership(Unarmed(), _IDENTITY) is None

    def test_membership_is_sensitive_to_every_field_of_the_identity(self) -> None:
        """D16: namespace, name, version, AND content_hash all participate —
        changing any single field of a member's identity must reclassify it
        as PostEpoch (the tamper-detection property S-EpochGate relies on)."""
        status = Armed(identities=frozenset([_IDENTITY]), integrated_time=1700000000)
        assert classify_epoch_membership(status, _id("ns2", "foo", "1.0.0", _CH)) is PostEpoch
        assert classify_epoch_membership(status, _id("ns1", "bar", "1.0.0", _CH)) is PostEpoch
        assert classify_epoch_membership(status, _id("ns1", "foo", "2.0.0", _CH)) is PostEpoch
        assert classify_epoch_membership(status, _id("ns1", "foo", "1.0.0", _OTHER_CH)) is PostEpoch


# ---------------------------------------------------------------------------
# effective_epoch_policy — the warn-cap downgrade (spec §3.6.3 NORMATIVE)
# ---------------------------------------------------------------------------


class TestEffectiveEpochPolicy:
    @pytest.mark.parametrize("policy", ["off", "warn", "strict"])
    def test_post_epoch_is_unchanged(self, policy: str) -> None:
        assert effective_epoch_policy(policy, PostEpoch) == policy

    @pytest.mark.parametrize("membership", [PreEpoch, None])
    def test_off_stays_off(self, membership) -> None:
        assert effective_epoch_policy("off", membership) == "off"

    @pytest.mark.parametrize("membership", [PreEpoch, None])
    def test_warn_stays_warn(self, membership) -> None:
        assert effective_epoch_policy("warn", membership) == "warn"

    @pytest.mark.parametrize("membership", [PreEpoch, None])
    def test_strict_downgrades_to_warn(self, membership) -> None:
        assert effective_epoch_policy("strict", membership) == "warn"


# ---------------------------------------------------------------------------
# Full impl-level unit matrix (RFC §6 S-EpochGate *Test*):
# {PreEpoch, PostEpoch, Unarmed} x {warn, strict} x {attested, unattested}
# ---------------------------------------------------------------------------


def _status_for(membership: "EpochMembership | None") -> "Armed | Unarmed":
    if membership is None:
        return Unarmed()
    if membership is PreEpoch:
        return Armed(identities=frozenset([_IDENTITY]), integrated_time=1700000000)
    return Armed(identities=frozenset([_id("ns1", "other", "9.9.9", _OTHER_CH)]), integrated_time=1700000000)


def _evaluate_attested(tmp_path: Path, membership: "EpochMembership | None") -> EntryGateOutcome:
    """The 'attested' half of the matrix: a real bundle_pin present, backed
    by a FileEntryBundleStore, verified Trusted by MockEntryVerifier."""
    import hashlib

    from milpa.entry_bundle_store import FileEntryBundleStore
    from milpa.registry import EntryAttestation, MilpaVendored

    bundle_bytes = b"any-bytes-mock-does-not-inspect"
    pin = hashlib.sha256(bundle_bytes).hexdigest()
    (tmp_path / f"{pin}.bundle").write_bytes(bundle_bytes)
    store = FileEntryBundleStore(tmp_path)
    attestation = EntryAttestation(kind=MilpaVendored(), bundle_pin=pin)
    status = _status_for(membership)
    return evaluate_entry_attestation(
        attestation=attestation,
        content_hash=_CH,
        namespace="ns1",
        name="foo",
        version="1.0.0",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=store,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="vendor-bot",
        epoch_status=status,
    )


class TestFullMatrix:
    """RFC §6 S-EpochGate key rows, both directions (raise vs warn)."""

    def test_post_epoch_strict_unattested_hard_fails(self) -> None:
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=_status_for(PostEpoch),
        )
        assert outcome.result is Unattested
        assert outcome.epoch_membership is PostEpoch
        with pytest.raises(MilpaError) as exc_info:
            enforce_entry_trust(outcome, "strict", namespace="ns1", name="foo", version="1.0.0")
        assert exc_info.value.slug == TNG_ENTRY_UNATTESTED

    def test_pre_epoch_strict_unattested_warns_not_raises(self, capsys) -> None:
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=_status_for(PreEpoch),
        )
        assert outcome.result is Unattested
        assert outcome.epoch_membership is PreEpoch
        enforce_entry_trust(outcome, "strict", namespace="ns1", name="foo", version="1.0.0")
        err = capsys.readouterr().err
        assert "entry-trust warning" in err
        assert "grandfathered" in err

    def test_unarmed_strict_unattested_warns_not_raises(self, capsys) -> None:
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=Unarmed(),
        )
        assert outcome.result is Unattested
        assert outcome.epoch_membership is None
        enforce_entry_trust(outcome, "strict", namespace="ns1", name="foo", version="1.0.0")
        err = capsys.readouterr().err
        assert "entry-trust warning" in err

    @pytest.mark.parametrize("membership", [PreEpoch, PostEpoch, None])
    def test_attested_passes_under_strict_regardless_of_membership(
        self, tmp_path: Path, membership
    ) -> None:
        outcome = _evaluate_attested(tmp_path, membership)
        assert outcome.result is Trusted
        # Trusted never raises/warns under any policy, any membership.
        enforce_entry_trust(outcome, "strict", namespace="ns1", name="foo", version="1.0.0")

    @pytest.mark.parametrize("membership", [PreEpoch, PostEpoch, None])
    def test_warn_policy_never_raises_regardless_of_membership(self, membership, capsys) -> None:
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=_status_for(membership),
        )
        enforce_entry_trust(outcome, "warn", namespace="ns1", name="foo", version="1.0.0")
        err = capsys.readouterr().err
        assert "entry-trust warning" in err

    @pytest.mark.parametrize("membership", [PreEpoch, PostEpoch, None])
    def test_off_policy_never_raises_or_warns_regardless_of_membership(
        self, membership, capsys
    ) -> None:
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=_status_for(membership),
        )
        enforce_entry_trust(outcome, "off", namespace="ns1", name="foo", version="1.0.0")
        assert capsys.readouterr().err == ""

    def test_post_epoch_mandate_hint_is_pinned(self) -> None:
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=_status_for(PostEpoch),
        )
        with pytest.raises(MilpaError) as exc_info:
            enforce_entry_trust(outcome, "strict", namespace="ns1", name="foo", version="1.0.0")
        assert (
            "not in the registry's committed pre-epoch set" in exc_info.value.message
        ), exc_info.value.message
        assert "must carry a verifiable attestation" in exc_info.value.message


# ---------------------------------------------------------------------------
# Fresh-clone / ephemeral-CI case (br7): classification has zero dependency
# on index_ratchet_seam's baseline sidecar — no ~/.cache/milpa, no baseline
# file on disk at all. classify_epoch_membership / evaluate_entry_attestation
# are pure functions; this test proves it by running them against an Armed
# status built purely in-memory while HOME/XDG_CACHE_HOME point at an EMPTY
# directory with no cache tree whatsoever, and by asserting the module does
# not import index_ratchet_seam.
# ---------------------------------------------------------------------------


class TestFreshCloneEphemeralCI:
    def test_classification_succeeds_with_no_cache_dir_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty_home = tmp_path / "fresh-clone-home"
        empty_home.mkdir()
        # No .cache/milpa anywhere under this HOME — an ephemeral CI runner's
        # exact starting condition.
        monkeypatch.setenv("HOME", str(empty_home))
        monkeypatch.setenv("XDG_CACHE_HOME", str(empty_home / ".cache"))
        assert not (empty_home / ".cache" / "milpa").exists()

        status = Armed(identities=frozenset([_IDENTITY]), integrated_time=1700000000)
        outcome = evaluate_entry_attestation(
            attestation=None,
            content_hash=_CH,
            namespace="ns1",
            name="foo",
            version="1.0.0",
            verifier=MockEntryVerifier(default=Trusted),
            bundle_store=None,
            trust_bundle=TrustBundle.test(),
            expected_vendor_signer="vendor-bot",
            epoch_status=status,
        )
        assert outcome.epoch_membership is PreEpoch
        # Still no cache directory materialized as a side effect of classification.
        assert not (empty_home / ".cache" / "milpa").exists()

    def test_entry_trust_module_does_not_import_index_ratchet_seam(self) -> None:
        """Structural proof (br7): the gate's own module never references the
        S-EpochCommitment-adjacent baseline-sidecar seam — the 'unify the
        parsers' instruction that motivated D16's shared \\x1f/\\x1e encoding
        must not leak a baseline-file DEPENDENCY into this pure gate."""
        import milpa.entry_trust as entry_trust_module

        assert "index_ratchet_seam" not in entry_trust_module.__dict__
        src_path = Path(entry_trust_module.__file__)
        assert "index_ratchet_seam" not in src_path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Workspace-resolve case (br9): classification on a member-pulled registry dep.
# ---------------------------------------------------------------------------


def _write_mock_fetch_milpa_kdl(mocked_dir: Path, url: str, ref: str, dep_name: str, kdl_body: str, sha: str) -> None:
    import re

    def _safe(s: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", s)

    key = f"{_safe(url)}@{_safe(ref)}"
    content_dir = mocked_dir / key / "content"
    content_dir.mkdir(parents=True, exist_ok=True)
    (content_dir / "milpa.kdl").write_text(kdl_body, encoding="utf-8")
    (mocked_dir / key / "sha").write_text(sha, encoding="utf-8")


def _member_manifest(name: str) -> Manifest:
    return Manifest(
        name=name,
        kind="library",
        src_dir="src",
        deps=[NamedDep(name="bar", constraint=None)],
        dev_deps=[],
        overrides=[],
        flags=[],
        self_mirrors=[],
        cas_dir="",
        spec_version=1,
        spec_version_explicit=False,
        attestation_policy=None,
    )


def _make_workspace(tmp_path: Path) -> LoadedWorkspace:
    member_dir = tmp_path / "member-a"
    member_dir.mkdir()
    (member_dir / "milpa.kdl").write_text(
        'name "pkg-a"\nkind "library"\nsrc_dir "src"\n', encoding="utf-8"
    )
    ws_manifest = WorkspaceManifest(members=("member-a",), overrides=())
    members = (
        LoadedMember(rel_path="member-a", abs_dir=member_dir, manifest=_member_manifest("pkg-a")),
    )
    return LoadedWorkspace(root_dir=tmp_path, workspace_manifest=ws_manifest, members=members)


def _make_index_with_named_dep(*, content_hash: str) -> Index:
    return Index(
        packages=[
            Package(
                name="bar",
                namespace="ns1",
                versions=(
                    IndexVersion(
                        version="1.0.0",
                        content_hash=content_hash,
                        namespace="ns1",
                        provenances=(
                            GitIndexProvenance(
                                url="https://example.com/bar.git", ref="main", commit_sha=None
                            ),
                        ),
                    ),
                ),
            )
        ]
    )


def _make_env(mocked_dir: Path, tmp_path: Path, index: Index) -> MilpaEnv:
    cas_root = tmp_path / ".cas"
    cas_root.mkdir(parents=True, exist_ok=True)
    store = CAStore(cas_root)
    fetcher = CasAdmittingFetcher(mocked_registry(mocked_dir), store)
    return MilpaEnv(fetcher=fetcher, index=index, store=store)


def _entry_trust_config(policy: str) -> EntryTrustConfig:
    return EntryTrustConfig(
        policy=policy,
        trust_bundle=TrustBundle.test(),
        expected_vendor_signer="vendor-bot",
        verifier=MockEntryVerifier(default=Trusted),
        bundle_store=None,
    )


class TestWorkspaceResolveEpochGate:
    """A workspace member pulls a NAMED (registry) dep; the epoch-gate
    classification and effective-policy downgrade must fire exactly as in
    the standalone resolve() path (br9)."""

    _KDL = 'name "bar"\nkind "library"\nsrc_dir "src"\n'
    _URL = "https://example.com/bar.git"

    def _discover_identity(self, tmp_path: Path) -> str:
        """Run once with entry_trust=None (gate disabled) to discover the
        real observed content_hash the resolver computes for this fetched
        tree — the same value classify_epoch_membership must be compared
        against downstream."""
        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, self._URL, "main", "bar", self._KDL, "sha-bar")
        index = _make_index_with_named_dep(content_hash="dag-sha256:" + "0" * 64)
        env = _make_env(mocked_dir, tmp_path / "discover", index)
        ws = _make_workspace(tmp_path / "discover")
        deps_dir = tmp_path / "discover" / "_deps"
        graph = resolve_workspace(ws, deps_dir, env, ResolveParams(entry_trust=None))
        bar_deps = [d for d in graph.deps if d.name == "bar"]
        assert len(bar_deps) == 1, [d.name for d in graph.deps]
        identity = bar_deps[0].identity
        assert identity is not None
        return identity

    def test_post_epoch_member_dep_strict_hard_fails(self, tmp_path: Path) -> None:
        real_identity = self._discover_identity(tmp_path)

        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, self._URL, "main", "bar", self._KDL, "sha-bar")
        index = _make_index_with_named_dep(content_hash="dag-sha256:" + "0" * 64)
        # Armed with an S that does NOT contain this member's real identity
        # -> PostEpoch -> the mandate applies.
        index.epoch_commitment_status = Armed(
            identities=frozenset([_id("ns1", "someone-else", "9.9.9", "dag-sha256:" + "f" * 64)]),
            integrated_time=1700000000,
        )
        env = _make_env(mocked_dir, tmp_path, index)
        ws = _make_workspace(tmp_path)
        deps_dir = tmp_path / "_deps"

        with pytest.raises(MilpaError) as exc_info:
            resolve_workspace(ws, deps_dir, env, ResolveParams(entry_trust=_entry_trust_config("strict")))
        assert exc_info.value.slug == TNG_ENTRY_UNATTESTED
        assert real_identity  # sanity: discovery step actually produced a value

    def test_pre_epoch_member_dep_strict_only_warns(self, tmp_path: Path) -> None:
        real_identity = self._discover_identity(tmp_path)

        mocked_dir = tmp_path / "mocked-fetches"
        _write_mock_fetch_milpa_kdl(mocked_dir, self._URL, "main", "bar", self._KDL, "sha-bar")
        index = _make_index_with_named_dep(content_hash="dag-sha256:" + "0" * 64)
        # Armed with an S that DOES contain this member's real identity
        # -> PreEpoch -> capped at warn even under strict.
        index.epoch_commitment_status = Armed(
            identities=frozenset([_id("ns1", "bar", "1.0.0", real_identity)]),
            integrated_time=1700000000,
        )
        env = _make_env(mocked_dir, tmp_path, index)
        ws = _make_workspace(tmp_path)
        deps_dir = tmp_path / "_deps"

        # Must NOT raise (grandfathered) — completes and returns a graph.
        graph = resolve_workspace(
            ws, deps_dir, env, ResolveParams(entry_trust=_entry_trust_config("strict"))
        )
        assert any(d.name == "bar" for d in graph.deps), [d.name for d in graph.deps]
