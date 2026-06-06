"""FetcherRegistry.fetch_any — try candidate provenances in order (#37).

When a dep has multiple known provenances (manifest-declared mirrors,
lockfile-recorded mirrors), the registry tries them in order and
returns the first success. All-fail surfaces a composite FetchError.

This is the consumption side of multi-provenance. The production side
is `milpa add --mirror` (later cycles in this issue).
"""

from dataclasses import dataclass

import pytest

from milpa.fetchers import (
    FetcherRegistry,
    FetchError,
    Provenance,
    ProvenanceReceipt,
)


@dataclass(frozen=True)
class StubProvenance(Provenance):
    """Test provenance: identified by `name` to distinguish candidates."""
    name: str
    fail: bool = False


@dataclass(frozen=True)
class StubReceipt(ProvenanceReceipt):
    name: str


class StubFetcher:
    """Fetches StubProvenance: writes `name` to dest, or raises if
    `p.fail` is set. Records every call site for ordering assertions."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def can_handle(self, p):
        return isinstance(p, StubProvenance)

    def fetch(self, name, p, *, dest):
        self.calls.append(p.name)
        if p.fail:
            raise FetchError(f"stub fetcher: {p.name} failed")
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "file.txt").write_text(p.name)
        return StubReceipt(name=p.name)


def test_fetch_any_tries_candidates_in_order_and_returns_first_success(tmp_path):
    """Tracer: [p1=fails, p2=succeeds] → p1 attempted first, p2's
    bytes land at dest, receipt reflects p2."""
    fetcher = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher)

    candidates = [
        StubProvenance(name="primary", fail=True),
        StubProvenance(name="mirror_a", fail=False),
    ]
    result = registry.fetch_any(
        "chronos", candidates, dest=tmp_path / "chronos",
    )

    assert fetcher.calls == ["primary", "mirror_a"]
    assert result.receipt.name == "mirror_a"
    assert (tmp_path / "chronos" / "file.txt").read_text() == "mirror_a"


def test_fetch_any_single_candidate_equivalent_to_fetch(tmp_path):
    """A single-element candidate list behaves identically to fetch().
    Same bytes at dest, same FetchResult shape."""
    fetcher = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher)

    result_any = registry.fetch_any(
        "alpha", [StubProvenance(name="solo")], dest=tmp_path / "via_any",
    )
    result_direct = registry.fetch(
        "alpha", StubProvenance(name="solo"), dest=tmp_path / "via_fetch",
    )

    # Same identity (same bytes), same name; only path differs
    assert result_any.identity == result_direct.identity
    assert result_any.name == result_direct.name
    assert result_any.receipt == result_direct.receipt


def test_fetch_any_all_fail_raises_composite_error(tmp_path):
    """Every candidate fails → FetchError naming each failure so the
    user can see what was tried."""
    fetcher = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher)

    with pytest.raises(FetchError) as exc:
        registry.fetch_any(
            "x",
            [
                StubProvenance(name="primary", fail=True),
                StubProvenance(name="mirror_a", fail=True),
                StubProvenance(name="mirror_b", fail=True),
            ],
            dest=tmp_path / "x",
        )

    msg = str(exc.value)
    # All three were attempted
    assert fetcher.calls == ["primary", "mirror_a", "mirror_b"]
    # All three named in the composite message
    assert "primary" in msg
    assert "mirror_a" in msg
    assert "mirror_b" in msg
    # The number of candidates is surfaced
    assert "3" in msg


def test_fetch_any_first_success_does_not_try_remaining_candidates(tmp_path):
    """Once a candidate succeeds, later candidates must not be
    invoked — fall-through is cost-sensitive (each fetch is expensive)."""
    fetcher = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher)

    registry.fetch_any(
        "x",
        [
            StubProvenance(name="primary"),       # succeeds
            StubProvenance(name="never_tried"),   # should NOT be invoked
        ],
        dest=tmp_path / "x",
    )

    assert fetcher.calls == ["primary"]


def test_fetch_any_rejects_candidate_whose_identity_does_not_match_expected(tmp_path):
    """When expected_identity is set, fetch_any treats any candidate
    whose bytes don't hash to it as a failure — drops the bytes,
    tries the next candidate. This is the safety guarantee for
    mirror fall-through: a hostile mirror serving different bytes
    cannot substitute itself for the locked dep."""
    from milpa.identity import compute_content_hash

    class TwoFlavorFetcher:
        """Two candidates with the SAME name but DIFFERENT payloads.
        We'll claim we expect the second one's identity; the first
        should be tried and rejected."""

        def __init__(self):
            self.calls: list[str] = []

        def can_handle(self, p):
            return isinstance(p, StubProvenance)

        def fetch(self, name, p, *, dest):
            self.calls.append(p.name)
            dest.mkdir(parents=True, exist_ok=True)
            # Each candidate writes its OWN distinct bytes
            (dest / "file.txt").write_text(p.name)
            return StubReceipt(name=p.name)

    fetcher = TwoFlavorFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher)

    # Compute the identity we'd get from the SECOND candidate's bytes
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        from pathlib import Path as P
        td_p = P(td) / "x"
        td_p.mkdir()
        (td_p / "file.txt").write_text("mirror_a")
        expected = compute_content_hash(td_p)

    result = registry.fetch_any(
        "x",
        [
            StubProvenance(name="primary"),   # bytes = "primary"
            StubProvenance(name="mirror_a"),  # bytes = "mirror_a"
        ],
        dest=tmp_path / "x",
        expected_identity=expected,
    )

    # Primary was tried (and rejected), mirror_a succeeded
    assert fetcher.calls == ["primary", "mirror_a"]
    assert result.identity == expected
    assert (tmp_path / "x" / "file.txt").read_text() == "mirror_a"


def test_fetch_any_warns_on_identity_mismatch_before_falling_through(tmp_path, capsys):
    """#102: a candidate whose bytes fail the identity gate is a possible
    supply-chain signal, not just an unavailable mirror. Before falling
    through to the next candidate, fetch_any must emit a warning naming the
    candidate + the expected/actual identity — so a mismatched primary
    masked by a matching mirror doesn't pass silently."""
    from milpa.identity import compute_content_hash

    class TwoFlavorFetcher:
        def can_handle(self, p):
            return isinstance(p, StubProvenance)

        def fetch(self, name, p, *, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "file.txt").write_text(p.name)
            return StubReceipt(name=p.name)

    registry = FetcherRegistry()
    registry.register(TwoFlavorFetcher())

    import tempfile
    from pathlib import Path as P
    with tempfile.TemporaryDirectory() as td:
        good = P(td) / "x"
        good.mkdir()
        (good / "file.txt").write_text("mirror_a")
        expected = compute_content_hash(good)

    result = registry.fetch_any(
        "chronos",
        [StubProvenance(name="primary"), StubProvenance(name="mirror_a")],
        dest=tmp_path / "chronos",
        expected_identity=expected,
    )

    # The mirror still served the locked bytes (fall-through still works)…
    assert result.identity == expected
    # …but the mismatched primary was announced, not swallowed.
    err = capsys.readouterr().err
    assert "warning:" in err
    assert "chronos" in err
    assert "identity" in err
    # the expected hash prefix is surfaced for the user to compare
    assert expected[:23] in err


def test_fetch_any_raises_when_no_candidate_matches_expected_identity(tmp_path):
    """All candidates produce wrong-identity bytes → composite
    FetchError citing each mismatch."""
    fetcher = StubFetcher()
    registry = FetcherRegistry()
    registry.register(fetcher)

    bogus_identity = "sha256:" + "0" * 64

    with pytest.raises(FetchError) as exc:
        registry.fetch_any(
            "x",
            [StubProvenance(name="a"), StubProvenance(name="b")],
            dest=tmp_path / "x",
            expected_identity=bogus_identity,
        )

    msg = str(exc.value)
    assert "identity" in msg.lower()
    # Both attempted
    assert fetcher.calls == ["a", "b"]
