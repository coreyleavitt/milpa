"""Tests for the append-only ratchet's index-cache seam wiring (A2d,
``rfc-registry-append-only.md`` §2; registry-protocol §3.5.2/§3.5.3).

Drives the FULL seam through ``milpa.index_cache.load_index`` (both the
ordinary State-2 network-fetch body and the bounded crash-recovery refetch)
with injected ``http_get`` + ``now_unix``, mirroring ``test_index_cache.py``'s
harness patterns — no network, no real sleep, isolated ``tmp_path`` cache
dirs.

``milpa.index_ratchet_seam`` (the pure parse/diff/decide layer) already has
its own unit coverage transitively via ``test_ratchet.py`` (the underlying
``Baseline.check`` engine, A2b) — this file is deliberately about the SEAM:
baseline sidecar lifecycle, write ordering, policy branching, and the
parse-at-gate no-clobber guarantee, all observed through the same public
``load_index`` entry point production code calls.

Covers (per the A2d test plan):
  - TOFU establishment (first-ever contact for a URL).
  - Clean append advances the baseline; ``established_at`` stays anchored.
  - Rollback under ``warn``: reported to stderr, baseline stays sticky.
  - Rollback under ``strict``: raises, zero cache mutation.
  - Recurring vs. new violation digest (habituation defense).
  - ``off`` preserves existing baseline/meta files untouched and never reads
    them (a violating candidate is served silently).
  - Corrupt baseline sidecar hard-fails under ``warn`` AND ``strict``, with
    a distinct slug from ordinary parse errors.
  - An unparseable candidate never clobbers a good cache (parse-at-gate),
    regardless of ``index_history_policy``.
  - The bounded crash-recovery refetch is gated identically to the ordinary
    network-fetch path.
  - Unique temp names: no fixed ``.tmp`` sibling collision hazard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from milpa.errors import (
    TNG_ENTRY_MUTATED,
    TNG_INDEX_BASELINE_CORRUPT,
    TNG_INDEX_ROLLBACK,
    TNG_SCHEMA_UNKNOWN,
    MilpaError,
)
from milpa.index_cache import DEFAULT_TTL_SECONDS, cache_path_for, load_index
from milpa.index_ratchet_seam import parse_baseline_meta
from milpa.index_trust import (
    IndexTrustConfig,
    MockVerifier,
    TrustBundle,
    Trusted,
    _reset_warned_urls,
)

URL = "https://example.test/index.kdl"


def _pkg_block(*versions: str) -> str:
    header = 'schema_version 1\n\npackage "bar" {\n    namespace "example"\n'
    return header + "".join(versions) + "}\n"


def _version_block(ver: str, content_hash_suffix: str) -> str:
    return f"""    version "{ver}" {{
        content_hash "sha256:{content_hash_suffix.rjust(64, '0')}"
        provenance {{
            kind "git"
            url "https://example.com/bar.git"
            ref "v{ver}"
        }}
    }}
"""


V1_ONLY = _pkg_block(_version_block("1.0.0", "1"))
V1_AND_V2 = _pkg_block(_version_block("1.0.0", "1"), _version_block("2.0.0", "2"))
V2_ONLY = _pkg_block(_version_block("2.0.0", "2"))  # v1.0.0 disappeared: rollback
V1_MUTATED = _pkg_block(_version_block("1.0.0", "ee1"))  # same version, different content_hash
V1_MUTATED_AGAIN = _pkg_block(_version_block("1.0.0", "ee2"))  # a SECOND, distinct mutation

BASELINE_CORRUPT_TEXT = "this is not valid kdl {{{ ][\n"
BASELINE_SCHEMA_SKEW_TEXT = "schema_version 99\n"


def make_get(body: str):
    calls: list[int] = [0]
    body_bytes = body.encode("utf-8")

    def get(url: str) -> bytes:
        calls[0] += 1
        return body_bytes

    return get, calls


def _baseline_file(tmp_path: Path) -> Path:
    return Path(str(cache_path_for(URL, tmp_path)) + ".baseline")


def _meta_file(tmp_path: Path) -> Path:
    return Path(str(cache_path_for(URL, tmp_path)) + ".baseline.meta")


# ---------------------------------------------------------------------------
# TOFU establishment
# ---------------------------------------------------------------------------


class TestTofuEstablishment:
    def test_first_contact_establishes_baseline(self, tmp_path: Path) -> None:
        get, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, index_history_policy="warn")

        baseline = _baseline_file(tmp_path)
        assert baseline.is_file()
        assert baseline.read_bytes() == V1_ONLY.encode("utf-8")

    def test_first_contact_writes_established_at_no_reported_digest(self, tmp_path: Path) -> None:
        get, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, index_history_policy="warn")

        meta = parse_baseline_meta(_meta_file(tmp_path).read_text(encoding="utf-8"))
        assert meta.established_at is not None
        assert meta.reported_digest is None
        assert meta.reported_at is None

    def test_tofu_emits_no_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        get, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, index_history_policy="strict")
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_off_policy_never_writes_baseline(self, tmp_path: Path) -> None:
        get, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, index_history_policy="off")
        assert not _baseline_file(tmp_path).is_file()
        assert not _meta_file(tmp_path).is_file()


# ---------------------------------------------------------------------------
# Clean advance (sticky-advance on a clean diff)
# ---------------------------------------------------------------------------


class TestCleanAdvance:
    def test_clean_append_advances_baseline_bytes(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        get2, _ = make_get(V1_AND_V2)
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")  # stale -> refetch

        assert _baseline_file(tmp_path).read_bytes() == V1_AND_V2.encode("utf-8")

    def test_clean_advance_preserves_established_at_clears_reported(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")
        first_meta = parse_baseline_meta(_meta_file(tmp_path).read_text(encoding="utf-8"))

        get2, _ = make_get(V1_AND_V2)
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")
        second_meta = parse_baseline_meta(_meta_file(tmp_path).read_text(encoding="utf-8"))

        assert second_meta.established_at == first_meta.established_at
        assert second_meta.reported_digest is None

    def test_clean_advance_emits_no_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")
        capsys.readouterr()  # drain

        get2, _ = make_get(V1_AND_V2)
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")
        assert capsys.readouterr().err == ""


# ---------------------------------------------------------------------------
# Rollback under warn: reported, baseline stays sticky
# ---------------------------------------------------------------------------


class TestRollbackWarn:
    def test_warn_reports_violation_to_stderr(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")
        capsys.readouterr()

        get2, _ = make_get(V2_ONLY)  # v1.0.0 disappears
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")

        err = capsys.readouterr().err
        assert "TNG-INDEX-ROLLBACK" in err
        assert "milpa index accept" in err  # remediation hint required

    def test_warn_serves_new_index_but_baseline_stays_sticky(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        get2, _ = make_get(V2_ONLY)
        idx = load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")

        # Served cache advances (ordinary warn semantics)...
        assert {v.version for p in idx.packages for v in p.versions} == {"2.0.0"}
        cache_file = cache_path_for(URL, tmp_path)
        assert cache_file.read_bytes() == V2_ONLY.encode("utf-8")
        # ...but the comparison baseline does NOT (sticky-advance).
        assert _baseline_file(tmp_path).read_bytes() == V1_ONLY.encode("utf-8")

    def test_warn_does_not_raise(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        get2, _ = make_get(V2_ONLY)
        # Must not raise.
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")


# ---------------------------------------------------------------------------
# Strict: hard fail, zero cache mutation
# ---------------------------------------------------------------------------


class TestStrictHardFail:
    def test_strict_raises_rollback_slug(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="strict")

        get2, _ = make_get(V2_ONLY)
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="strict")
        assert exc_info.value.slug == TNG_INDEX_ROLLBACK

    def test_strict_mutated_field_raises_entry_mutated(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="strict")

        get2, _ = make_get(V1_MUTATED)  # same version, content_hash changed
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="strict")
        assert exc_info.value.slug == TNG_ENTRY_MUTATED

    def test_strict_violation_causes_zero_cache_mutation(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="strict")

        cache_file = cache_path_for(URL, tmp_path)
        stamp_file = cache_file.with_suffix(".kdl.at")
        pre_index_bytes = cache_file.read_bytes()
        pre_stamp = stamp_file.read_text()
        pre_baseline = _baseline_file(tmp_path).read_bytes()

        get2, _ = make_get(V2_ONLY)
        with pytest.raises(MilpaError):
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="strict")

        assert cache_file.read_bytes() == pre_index_bytes
        assert stamp_file.read_text() == pre_stamp
        assert _baseline_file(tmp_path).read_bytes() == pre_baseline
        # No leftover temp files from the aborted attempt.
        assert list(tmp_path.glob("*.tmp.*")) == []

    def test_strict_payload_carries_structured_violations(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="strict")

        get2, _ = make_get(V2_ONLY)
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="strict")

        violations = exc_info.value.context["violations"]
        assert len(violations) == 1
        assert violations[0]["class"] == TNG_INDEX_ROLLBACK
        assert violations[0]["name"] == "bar"
        assert violations[0]["version"] == "1.0.0"
        assert "digest" in exc_info.value.context


# ---------------------------------------------------------------------------
# Recurring vs. new violation digest (habituation defense)
# ---------------------------------------------------------------------------


class TestRecurringVsNewDigest:
    def test_same_violation_reported_as_recurring(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        get2, _ = make_get(V1_MUTATED)
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")
        capsys.readouterr()  # drain the first (new) warning

        # Same mutated content again (stale refetch, unchanged digest).
        get3, _ = make_get(V1_MUTATED)
        load_index(URL, tmp_path, get3, 100, 1202, index_history_policy="warn")
        err = capsys.readouterr().err
        assert "recurring" in err

    def test_new_mutation_while_first_unresolved_is_reported_new(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        get2, _ = make_get(V1_MUTATED)
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")
        meta_after_first = parse_baseline_meta(_meta_file(tmp_path).read_text(encoding="utf-8"))
        capsys.readouterr()

        # A SECOND, DIFFERENT mutation (V2 -> V3 while V1 -> V2 is still unresolved).
        get3, _ = make_get(V1_MUTATED_AGAIN)
        load_index(URL, tmp_path, get3, 100, 1202, index_history_policy="warn")
        err = capsys.readouterr().err
        assert "recurring" not in err

        meta_after_second = parse_baseline_meta(_meta_file(tmp_path).read_text(encoding="utf-8"))
        assert meta_after_second.reported_digest != meta_after_first.reported_digest


# ---------------------------------------------------------------------------
# off: preserves existing files untouched, never reads them
# ---------------------------------------------------------------------------


class TestOffPolicy:
    def test_off_preserves_existing_baseline_and_meta_untouched(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")
        pre_baseline = _baseline_file(tmp_path).read_bytes()
        pre_meta = _meta_file(tmp_path).read_bytes()

        # A violating refetch under "off": would rollback under warn/strict,
        # but off never reads/compares/writes the baseline pair at all.
        get2, _ = make_get(V2_ONLY)
        idx = load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="off")

        assert {v.version for p in idx.packages for v in p.versions} == {"2.0.0"}
        assert _baseline_file(tmp_path).read_bytes() == pre_baseline
        assert _meta_file(tmp_path).read_bytes() == pre_meta

    def test_off_does_not_raise_on_what_would_be_a_violation(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="off")

        get2, _ = make_get(V2_ONLY)
        # Must not raise, must not warn-print a ratchet violation.
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="off")


# ---------------------------------------------------------------------------
# Corrupt baseline: hard-fail under warn AND strict, distinct slug
# ---------------------------------------------------------------------------


class TestCorruptBaseline:
    @pytest.mark.parametrize("policy", ["warn", "strict"])
    def test_corrupt_baseline_hard_fails_regardless_of_policy(
        self, tmp_path: Path, policy: str
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        _baseline_file(tmp_path).write_text(BASELINE_CORRUPT_TEXT, encoding="utf-8")

        get2, _ = make_get(V1_ONLY)
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy=policy)
        assert exc_info.value.slug == TNG_INDEX_BASELINE_CORRUPT

    def test_schema_skewed_baseline_is_baseline_corrupt_not_schema_unknown(
        self, tmp_path: Path
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")

        _baseline_file(tmp_path).write_text(BASELINE_SCHEMA_SKEW_TEXT, encoding="utf-8")

        get2, _ = make_get(V1_ONLY)
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")
        assert exc_info.value.slug == TNG_INDEX_BASELINE_CORRUPT
        assert exc_info.value.slug != TNG_SCHEMA_UNKNOWN

    def test_corrupt_baseline_causes_zero_cache_mutation(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")
        cache_file = cache_path_for(URL, tmp_path)
        pre_bytes = cache_file.read_bytes()

        _baseline_file(tmp_path).write_text(BASELINE_CORRUPT_TEXT, encoding="utf-8")

        get2, _ = make_get(V1_AND_V2)
        with pytest.raises(MilpaError):
            load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="warn")
        assert cache_file.read_bytes() == pre_bytes

    def test_off_never_reads_corrupt_baseline(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="warn")
        _baseline_file(tmp_path).write_text(BASELINE_CORRUPT_TEXT, encoding="utf-8")

        get2, _ = make_get(V1_AND_V2)
        # off never reads the baseline, so its corruption is invisible.
        load_index(URL, tmp_path, get2, 100, 1101, index_history_policy="off")


# ---------------------------------------------------------------------------
# Parse-at-gate: unparseable candidate never clobbers a good cache
# ---------------------------------------------------------------------------


class TestParseAtGateNoClobber:
    @pytest.mark.parametrize("policy", ["off", "warn", "strict"])
    def test_unparseable_candidate_leaves_cache_byte_identical(
        self, tmp_path: Path, policy: str
    ) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy=policy)

        cache_file = cache_path_for(URL, tmp_path)
        stamp_file = cache_file.with_suffix(".kdl.at")
        pre_index = cache_file.read_bytes()
        pre_stamp = stamp_file.read_text()

        get_bad, _ = make_get("not valid kdl {{{ ][\n")
        with pytest.raises(MilpaError):
            load_index(URL, tmp_path, get_bad, 100, 1101, index_history_policy=policy)

        assert cache_file.read_bytes() == pre_index, (
            "index file must be byte-identical to pre-fetch state"
        )
        assert stamp_file.read_text() == pre_stamp, "freshness stamp must not advance"

    def test_schema_unknown_candidate_no_clobber(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get1, 100, 1000, index_history_policy="off")
        cache_file = cache_path_for(URL, tmp_path)
        pre_index = cache_file.read_bytes()

        get_bad, _ = make_get("schema_version 99\n")
        with pytest.raises(MilpaError) as exc_info:
            load_index(URL, tmp_path, get_bad, 100, 1101, index_history_policy="off")
        assert exc_info.value.slug == TNG_SCHEMA_UNKNOWN
        assert cache_file.read_bytes() == pre_index


# ---------------------------------------------------------------------------
# Crash-recovery refetch: gated identically to the ordinary fetch path
# ---------------------------------------------------------------------------

_DUMMY_BUNDLE = TrustBundle(raw_json=b'{"__test__": true}', label="test:dummy")
_DEFAULT_SIGNER = (
    "https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml@refs/heads/main"
)
_FAKE_BUNDLE_BYTES = b'{"fake_bundle": true}'


def _trust_config(policy: str) -> IndexTrustConfig:
    return IndexTrustConfig(
        policy=policy,  # type: ignore[arg-type]
        trust_bundle=_DUMMY_BUNDLE,
        expected_signer=_DEFAULT_SIGNER,
        max_age_seconds=604800,
    )


def _bundle_get(url: str) -> bytes:
    return _FAKE_BUNDLE_BYTES


class TestCrashRecoverySeamGated:
    def test_recovery_refetch_strict_violation_raises(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        config = _trust_config("strict")
        _reset_warned_urls()

        # First load: TOFU baseline + populates cache + bundle.
        load_index(
            URL, tmp_path, get1, DEFAULT_TTL_SECONDS, 1000,
            config=config, verifier=MockVerifier(Trusted), bundle_http_get=_bundle_get,
            index_history_policy="strict",
        )

        # Simulate an interrupted write: bundle sidecar goes missing.
        cache_file = cache_path_for(URL, tmp_path)
        Path(str(cache_file) + ".bundle").unlink()
        pre_index_bytes = cache_file.read_bytes()

        # Fresh-cache read (age=0) but bundle missing -> bounded recovery
        # refetch; the recovery transport serves a ROLLBACK candidate.
        get2, calls2 = make_get(V2_ONLY)
        _reset_warned_urls()
        with pytest.raises(MilpaError) as exc_info:
            load_index(
                URL, tmp_path, get2, DEFAULT_TTL_SECONDS, 1000,
                config=config, verifier=MockVerifier(Trusted), bundle_http_get=_bundle_get,
                index_history_policy="strict",
            )
        assert exc_info.value.slug == TNG_INDEX_ROLLBACK
        assert calls2[0] == 1, "exactly one bounded recovery refetch"
        # No mutation: the index file must remain what the first load wrote.
        assert cache_file.read_bytes() == pre_index_bytes

    def test_recovery_refetch_clean_diff_advances_baseline(self, tmp_path: Path) -> None:
        get1, _ = make_get(V1_ONLY)
        config = _trust_config("strict")
        _reset_warned_urls()

        load_index(
            URL, tmp_path, get1, DEFAULT_TTL_SECONDS, 1000,
            config=config, verifier=MockVerifier(Trusted), bundle_http_get=_bundle_get,
            index_history_policy="warn",
        )

        cache_file = cache_path_for(URL, tmp_path)
        Path(str(cache_file) + ".bundle").unlink()

        get2, calls2 = make_get(V1_AND_V2)  # clean append via the recovery path
        _reset_warned_urls()
        idx = load_index(
            URL, tmp_path, get2, DEFAULT_TTL_SECONDS, 1000,
            config=config, verifier=MockVerifier(Trusted), bundle_http_get=_bundle_get,
            index_history_policy="warn",
        )
        assert calls2[0] == 1
        assert {v.version for p in idx.packages for v in p.versions} == {"1.0.0", "2.0.0"}
        assert _baseline_file(tmp_path).read_bytes() == V1_AND_V2.encode("utf-8")


# ---------------------------------------------------------------------------
# Unique temp names — the concurrency fix (§3.5.2 NORMATIVE (concurrency))
# ---------------------------------------------------------------------------


class TestUniqueTempNames:
    def test_unique_temp_path_never_repeats(self) -> None:
        import milpa.index_cache as ic

        target = Path("/nonexistent/dir/some.index.kdl")
        names = {ic._unique_temp_path(target) for _ in range(200)}
        assert len(names) == 200, "temp sibling names must be per-write-unique, not fixed"

    def test_two_interleaved_writers_never_tear(self, tmp_path: Path) -> None:
        """Deterministic simulation of the fixed-name race the RFC calls out:
        two writers targeting the SAME path must never observe each other's
        temp file, because each gets its own unique sibling name."""
        import milpa.index_cache as ic

        target = tmp_path / "shared.index.kdl"
        content_a = b"A" * 5000
        content_b = b"B" * 5000

        tmp_a = ic._unique_temp_path(target)
        tmp_b = ic._unique_temp_path(target)
        assert tmp_a != tmp_b, (
            "the RFC's fixed-name hazard: two writers must not share a temp sibling"
        )

        # Simulate interleaving: both writers' "in-flight" writes coexist on
        # disk simultaneously without corrupting each other (impossible with
        # the pre-fix shared ".tmp" name, where the second write() could
        # land mid-write of the first).
        tmp_a.write_bytes(content_a)
        tmp_b.write_bytes(content_b)
        assert tmp_a.read_bytes() == content_a
        assert tmp_b.read_bytes() == content_b

        # Whichever renames last wins; the target is always one COMPLETE
        # writer's content, never a torn mix.
        import os
        os.replace(tmp_b, target)
        assert target.read_bytes() == content_b
        os.replace(tmp_a, target)
        assert target.read_bytes() == content_a

    def test_baseline_and_index_writes_use_distinct_temp_names(self, tmp_path: Path) -> None:
        """After a TOFU-establishing load, no stray ``*.tmp.*`` siblings are
        left behind for either the index file or the baseline pair."""
        get, _ = make_get(V1_ONLY)
        load_index(URL, tmp_path, get, DEFAULT_TTL_SECONDS, 1000, index_history_policy="warn")
        assert list(tmp_path.glob("*.tmp.*")) == []
