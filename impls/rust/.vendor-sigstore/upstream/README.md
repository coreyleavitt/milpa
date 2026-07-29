# Upstream sigstore-rs contribution — DSSE envelopeHash false-rejection

Contributing milpa's vendored `.vendor-sigstore` fix back to
[sigstore/sigstore-rs](https://github.com/sigstore/sigstore-rs).

**Status — FILED (2026-07-29):**
- Issue: https://github.com/sigstore/sigstore-rs/issues/608
- PR: https://github.com/sigstore/sigstore-rs/pull/609 (`Fixes #608`; DCO passing, mergeable)
- Branch: `coreyleavitt/sigstore-rs@fix/dsse-envelopehash-reserialization`

The local `[patch.crates-io]` in `impls/rust/Cargo.toml` **stays** until an upstream release ships
the fix; then delete `.vendor-sigstore/` and the patch stanza. If the maintainers prefer the
warn-only remedy (issue option 2) over removal, update the PR branch accordingly.

## Files

- `ISSUE.md` — the bug report to file at sigstore-rs.
- `PR-BODY.md` — the PR description (implements remedy 1, remove), plus a suggested commit message.
  Replace `#<ISSUE_NUMBER>` after the issue is filed.
- `remove-dsse-envelopehash-check.patch` — the change, as a `git diff` generated against
  **`main`** (the PR base). Verified to apply cleanly to both current `main` and the `v0.14.0`
  tag we vendor, and to be `rustfmt --edition 2024 --check` clean (the crate is edition 2024;
  the destructuring is collapsed to satisfy it). Apply to a fresh checkout:
  `git apply remove-dsse-envelopehash-check.patch`. No embedded author metadata.

## Before opening the PR (hard gates)

- **DCO sign-off is required** — sigstore-rs enforces it (40/40 recent non-merge commits carry
  `Signed-off-by`). Commit the patch with `git commit -s`, using a git identity whose name +
  email match the GitHub account opening the PR.
- **Issue first, then PR** — the remedy (remove vs. warn-only vs. reproduce-Rekor-bytes) is the
  maintainers' call; file `ISSUE.md`, then open the PR with `Fixes #N`.
- **Run upstream CI locally before opening** — only `rustfmt --edition 2024 --check` has been run
  on this patch (clean). `cargo clippy --all-targets` and `cargo test` were NOT run here (the
  crate pins a toolchain via `rust-toolchain.toml` and pulls its full dep set); run them on the
  fork first to avoid a bounced PR.
- `reproduce-evidence.py` — recomputes the evidence from a bundle JSON. Run against the committed
  fixture: `python reproduce-evidence.py` from repo root (reads
  `conformance/spec-v1/_oracle/attestation/index.kdl.bundle`).

## Evidence (reproduced)

- Rekor logIndex `2086326142`
- recorded `envelopeHash` `d66676bef2f8207987d1063f66a56892c62e7bbe975ea3b245681d25820e977d`
- `sha256(cosign Go json.Marshal form)` == the recorded value (match)
- `sha256(protobuf-JSON form)` `3e4b489b6b9186c8e5acd74b2eaf8baecb0230c04796b1354a8c299339391b44`
  (no match — this is what sigstore-rs 0.14.0 recomputes)

Local (milpa-side) regression that goes red if the check is ever restored:
`milpa-core index_trust::tests::s5_real_bundle_verifies_trusted_end_to_end`.
