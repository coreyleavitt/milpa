#!/usr/bin/env python3
"""Mint milpa's Layer-2 (per-entry) real-crypto conformance fixtures (RFC
`docs/rfc-attestation-v1-normative.md`, slice S6).

This is the Layer-2 analogue of `.github/workflows/generate-attestation-
fixture.yaml` (which mints the Layer-1 whole-index `_oracle/attestation/
index.kdl.bundle`). It is a **one-time / regenerate-only** test-fixture
generator over **synthetic** subjects — NOT a production signer. The real,
recurring per-package signing lives in tianguis (`vendor.yaml` /
`backfill-attestation.yaml`); those sign real packages, these sign fixed
test subjects whose bundles are committed and replay offline forever
(verified against their own Rekor `integratedTime`, never wall-clock).

## Signer parity (the S6 round-2 prerequisite)

Production per-entry bundles come through tianguis via **sigstore-python
`Signer.sign_dsse`** (`tianguis/scripts/sign_statement.py`), NOT `cosign`.
`cosign` and a Python DSSE signer can emit byte-different envelope
serializations (field order, `keyid`) — the #183 class of bug and milpa's
documented differential blind spot. So these fixtures are minted with the
IDENTICAL `sign_dsse` recipe, copied verbatim below (the two repos cannot
share code across the boundary; kept byte-for-byte in sync with
tianguis `scripts/sign_statement.py::sign_dsse` — update both together).

## What it mints

Two genuinely-signed bundles (every S7 FAIL vector is derived from these by
tampering — a wrong-signer vector just verifies the PASS bundle against a
different expected signer, no second identity needed):

1. `entry-attested-pkg.bundle` — a valid POST-epoch per-entry attestation:
   subject name `pkg:tianguis/testns/attested-pkg@1.0.0`, subject digest =
   `content_hash` (sha256). Verifies Trusted under `entry-trust "strict"`.
2. `commitment.bundle` — the arming-commitment sidecar bundle: subject
   digest = `C`, the commitment over the synthetic pre-epoch set `S`
   (`{testns/legacy-pkg@0.9.0}`). Drives the `EpochCommitmentStatus = Armed`
   path and the `pre-epoch => warn` row.

The signer SAN of both is this repo's minting-workflow GHA identity; that
SAN is what the S6 conformance fixtures pin as `expected_signer`.

## Running

- In CI (real signing): `python3 mint_entry_fixtures.py --out <dir>` inside a
  GitHub Actions job with `id-token: write`. Emits the two `.bundle` files +
  a `manifest.json` recording every subject, `content_hash`, `C`, the set
  `S`, and the signer SAN.
- Locally (validate the statement shape, no signing):
  `python3 mint_entry_fixtures.py --out <dir> --dry-run` writes the in-toto
  statements + `manifest.json` (no `.bundle` files) so the subject wiring can
  be reviewed without an OIDC credential.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# The synthetic fixture subjects (computed via milpa's own
# `epoch_commitment.commitment_digest`; see the S6 slice). Kept as literals so
# this generator has no import dependency on the milpa package in CI, but the
# values are reproducible: content hashes are `sha256("milpa-s6-fixture:<id>")`
# and `C` is milpa's canonical commitment over `S`.
# ---------------------------------------------------------------------------

_PASS_NAMESPACE = "testns"
_PASS_NAME = "attested-pkg"
_PASS_VERSION = "1.0.0"
# sha256("milpa-s6-fixture:attested-pkg@1.0.0")
_PASS_CONTENT_HASH_HEX = "9141345c8bfa2251a85bd540e15f365d2dbdf02abd76d8b37d0ea727f5955772"

# The synthetic pre-epoch set S (one grandfathered legacy entry). The PASS
# entry above is deliberately NOT in S, so it classifies POST-epoch.
_S = [
    {
        "namespace": "testns",
        "name": "legacy-pkg",
        "version": "0.9.0",
        # sha256("milpa-s6-fixture:legacy-pkg@0.9.0"), prefixed as milpa's identity
        "content_hash": "dag-sha256:862bb412668033e2f5665980220f9da2df20a3bb651dfe31b3cdae23725e06e4",
    }
]
# milpa `commitment_digest(_S)` — the sidecar bundle's subject digest.
_COMMITMENT_C = "7d51aa499ecba42a73c3dda5d0a2cb4b8200d8d6f7d5ab38b6b87d66ca4e2e8b"

_ENTRY_PREDICATE_TYPE = "https://milpa.dev/attestation/entry/v1"
_COMMITMENT_PREDICATE_TYPE = "https://milpa.dev/attestation/preepoch-commitment/v1"


def _statement(subject_name: "str | None", digest_hex: str, predicate_type: str) -> bytes:
    """A minimal in-toto Statement v1 over one subject. milpa verifies only the
    subject digest (and, for a per-entry bundle, the subject name); the
    predicate content is not checked, so it is a fixed marker."""
    subject: dict[str, object] = {"digest": {"sha256": digest_hex}}
    if subject_name is not None:
        subject["name"] = subject_name
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [subject],
        "predicateType": predicate_type,
        "predicate": {"generated_by": "milpa-s6-entry-fixture"},
    }
    # Compact, deterministic separators (the exact bytes are what sign_dsse
    # wraps as the DSSE payload; milpa base64-decodes and reads `subject`).
    return json.dumps(statement, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# sign_dsse — VERBATIM from tianguis/scripts/sign_statement.py (signer parity).
# Keep byte-for-byte in sync with tianguis; update both together.
# ---------------------------------------------------------------------------


def sign_dsse(statement_bytes: bytes) -> str:
    """Sign `statement_bytes` (raw in-toto Statement JSON) under ambient
    GH-Actions OIDC and return the Sigstore Bundle as JSON text. CI-only:
    talks to Fulcio + Rekor and raises if no ambient OIDC credential exists."""
    from sigstore.dsse import Statement
    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import SigningContext

    raw_token = detect_credential()
    if raw_token is None:
        raise RuntimeError(
            "no ambient OIDC credential detected; this script must run inside a "
            "GitHub Actions workflow with `id-token: write` permission, not on a "
            "local machine"
        )
    identity_token = IdentityToken(raw_token)
    trust_config = ClientTrustConfig.production()
    context = SigningContext.from_trust_config(trust_config)
    statement = Statement(contents=statement_bytes)
    with context.signer(identity_token) as signer:
        bundle = signer.sign_dsse(statement)
    return bundle.to_json()


def _signer_san() -> str:
    """The GHA-OIDC SAN the minted bundles will carry (from the ambient env),
    or a placeholder in dry-run. This is what the S6 fixtures pin as the
    expected signer."""
    import os

    repo = os.environ.get("GITHUB_REPOSITORY", "coreyleavitt/milpa")
    ref = os.environ.get("GITHUB_REF_NAME", "main")
    wf = ".github/workflows/generate-entry-attestation-fixtures.yaml"
    return f"https://github.com/{repo}/{wf}@refs/heads/{ref}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, type=Path, help="output directory for bundles + manifest")
    ap.add_argument("--dry-run", action="store_true", help="build statements only; do not sign")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    jobs = [
        {
            "bundle": "entry-attested-pkg.bundle",
            "kind": "entry",
            "subject_name": f"pkg:tianguis/{_PASS_NAMESPACE}/{_PASS_NAME}@{_PASS_VERSION}",
            "digest_hex": _PASS_CONTENT_HASH_HEX,
            "predicate_type": _ENTRY_PREDICATE_TYPE,
        },
        {
            "bundle": "commitment.bundle",
            "kind": "commitment",
            "subject_name": None,  # the commitment binds by digest only (like Layer-1)
            "digest_hex": _COMMITMENT_C,
            "predicate_type": _COMMITMENT_PREDICATE_TYPE,
        },
    ]

    manifest: dict[str, object] = {
        "signer_san": _signer_san(),
        "issuer": "https://token.actions.githubusercontent.com",
        "pass_entry": {
            "namespace": _PASS_NAMESPACE,
            "name": _PASS_NAME,
            "version": _PASS_VERSION,
            "content_hash": f"dag-sha256:{_PASS_CONTENT_HASH_HEX}",
        },
        "pre_epoch_set": _S,
        "commitment_c": _COMMITMENT_C,
        "bundles": [],
    }

    for job in jobs:
        stmt = _statement(job["subject_name"], job["digest_hex"], job["predicate_type"])
        (args.out / (job["bundle"] + ".statement.json")).write_bytes(stmt)
        if args.dry_run:
            print(f"[dry-run] built statement for {job['bundle']}: {stmt.decode()}", file=sys.stderr)
        else:
            bundle_json = sign_dsse(stmt)
            (args.out / job["bundle"]).write_text(bundle_json, encoding="utf-8")
            print(f"signed {job['bundle']}", file=sys.stderr)
        manifest["bundles"].append({"file": job["bundle"], "kind": job["kind"], "subject_name": job["subject_name"], "digest": job["digest_hex"]})

    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"signer SAN: {manifest['signer_san']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
