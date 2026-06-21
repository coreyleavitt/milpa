"""Slice C part c3 (rfc-conformance-parity §4): the black-box runner must seed
the CAS for frozen fixtures, mirroring the in-process adapter's _seed_cas.

Frozen fixtures carry a `cas-seed/<name>/` tree whose content the frozen path
expects to already be in the store; without seeding the run fails with
FROZEN-IDENTITY-NOT-IN-STORE (Finding 4, docs/rfc-conformance-parity.baseline.md).

The harness is impl-neutral, so it cannot call the impl's content-hash function.
Instead it places each seed tree at the spec-normative CAS layout path
(<root>/sha256/<hex>/, spec/identity.md §3) using the identity the fixture's own
milpa.lock already records for that dep name — verified faithful (the seed tree's
real content hash equals the recorded identity).
"""

from __future__ import annotations

from pathlib import Path

from harness.assertions import assert_conformance
from harness.descriptors import build_descriptors
from harness.runner import _parse_lock_identities, run_fixture

_REPO = Path(__file__).resolve().parents[1]


def test_parse_lock_identities_pairs_name_to_identity() -> None:
    lock = (
        'version 1\n'
        'dep "foo" {\n'
        '    identity "sha256:' + "a" * 64 + '"\n'
        '    aliases "bar"\n'
        '    provenance {\n        kind "git"\n    }\n'
        '}\n'
        'dep "baz" {\n'
        '    identity "sha256:' + "b" * 64 + '"\n'
        '}\n'
    )
    assert _parse_lock_identities(lock) == {
        "foo": "sha256:" + "a" * 64,
        "baz": "sha256:" + "b" * 64,
    }


def _run_python_black_box(name: str):
    fx = _REPO / "conformance" / "spec-v1" / name
    py = next(d for d in build_descriptors(_REPO) if d.name == "python")
    run = run_fixture(fx, py)
    res = assert_conformance(run, fx)
    run.cleanup()
    return res


def test_fixture_177_frozen_dedup_aliases_passes_black_box() -> None:
    res = _run_python_black_box("fixture-177-frozen-dedup-aliases")
    assert res.passed, [f.detail for f in res.failures]


def test_fixture_208_frozen_member_override_passes_black_box() -> None:
    res = _run_python_black_box("fixture-208-s8b-frozen-member-override-passes")
    assert res.passed, [f.detail for f in res.failures]
