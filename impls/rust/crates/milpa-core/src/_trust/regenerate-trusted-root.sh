#!/usr/bin/env bash
# Regenerate the embedded Sigstore production trust root (trusted_root.json).
#
# RFC rfc-attestation-verifier S1.5 — the concrete tool that operationalizes the
# committed maintainer rotation process (Part-1 rfc-registry-trust-federation §12.3).
#
# NETWORK-ONLY, MAINTAINER-RUN. Never invoked by `cargo test` / `./dev-rust test`; the
# hermetic suite reads only the committed bytes. Run this by hand when Sigstore rotates
# Fulcio/Rekor/CTFE material.
#
# Why a script, not a `cargo run --example`: sigstore-rs's `SigstoreTrustRoot` holds a
# *parsed* `TrustedRoot` behind a private field with no byte accessor, so a Rust example
# could only re-serialize a lossy parse (field-ordering / default-value drift from the
# canonical file). `cosign trusted-root create` emits the verbatim canonical JSON the TUF
# repo publishes, which is what we embed. rfc-attestation-verifier S1.5.
#
# ── RETENTION DISCIPLINE (load-bearing) ─────────────────────────────────────────────
# The standard trusted_root.json carries Fulcio CAs / Rekor keys / CTFE keys as arrays,
# each with a `validFor` range. On rotation the fresh document APPENDS new material and
# keeps the old. **Do not hand-prune old entries**: milpa verifies bundles offline at each
# bundle's own `integratedTime` and looks Rekor keys up by explicit hex(log_id.key_id), so
# a historical (now-rotated) key MUST remain present or committed S5 fixtures signed under
# it stop verifying. If cosign ever emits a document that dropped a still-referenced key,
# merge the old entry back in by hand. See trust_root.rs (the no-time-filter mapper).
# ─────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${here}/trusted_root.json"

if ! command -v cosign >/dev/null 2>&1; then
  echo "error: cosign not found. Install cosign (https://docs.sigstore.dev/cosign/) or copy" >&2
  echo "       the pinned trust_root/prod/trusted_root.json from a sigstore-rs release." >&2
  exit 1
fi

echo "Fetching current Sigstore Public Good trusted root via cosign…"
cosign trusted-root create >"${out}.new"

# Sanity: must be JSON with the four expected top-level members before we overwrite.
python3 - "${out}.new" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
need = {"tlogs", "certificateAuthorities", "ctlogs"}
missing = need - set(d)
if missing:
    raise SystemExit(f"regenerated trusted root missing members: {sorted(missing)}")
if not d["certificateAuthorities"]:
    raise SystemExit("regenerated trusted root has no Fulcio CAs")
print(f"ok: tlogs={len(d['tlogs'])} ctlogs={len(d['ctlogs'])} CAs={len(d['certificateAuthorities'])}")
PY

mv "${out}.new" "${out}"
echo "Wrote ${out}."
echo "REVIEW the diff for the retention discipline above, then rebuild:"
echo "  ./dev-rust test -p milpa-core   # trust_root.rs mapper tests must stay green"
