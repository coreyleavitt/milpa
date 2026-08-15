//! `GatedIndex` — the trust-boundary witness type (RFC: `rfc-trusted-index-invariant.md`).
//!
//! Possessing a `GatedIndex` proves the index-level gates (index-trust verification
//! + enforcement, and — once the epoch-commitment fold lands in S1a-ii — the
//! epoch-commitment phase) *ran under the effective `index-trust` policy and their
//! outcome was applied*. It is **not** a claim that the wrapped content is
//! cryptographically trusted — see the per-policy invariant below and
//! [`GatedIndex::is_cryptographically_trusted`].
//!
//! # S1a-i scope (this module)
//!
//! This slice is purely additive: it introduces the type, its constructors, and
//! its accessors. Nothing in the rest of the crate consumes `GatedIndex` yet —
//! `load_index` / `load_index_with_history` / `maybe_index` and the `resolve*`
//! family still take/return plain `Index` (that big-bang retype is S1a-ii). The
//! privileged [`GatedIndex::mint`] constructor is therefore unused outside this
//! module's own tests for now; that is expected and not dead-code debt — S1a-ii
//! wires it into the ~4 production mint points inside `index_cache` /
//! `index_ratchet_seam`.
//!
//! # NORMATIVE per-policy invariant (RFC §2.3)
//!
//! `GatedIndex` ⇒ acquisition completed under the effective `index-trust` policy:
//! - `strict` ⇒ cryptographically verified (`Trusted`), else no `GatedIndex` exists;
//! - `warn` ⇒ verified, or a non-`Trusted` result was recorded as a warning;
//! - `off` ⇒ verification was explicitly disabled; no trust claim is asserted.
//!
//! # Why `verification` is `Option<VerificationResult>` (RFC §2.4)
//!
//! Under `off` the verifier is never invoked, so there is no [`VerificationResult`]
//! to store — `None` means exactly "policy was `off`, verification deliberately
//! skipped." This is deliberately NOT an 8th `VerificationResult` variant:
//! `VerificationResult` is a closed 7-variant type with a *total* `to_slug()`
//! match, and a slug-less variant would both break that totality and conflate
//! "not checked" with "checked and failed."
//!
//! # Why `.index()`, not `Deref` (RFC §2.5)
//!
//! A `Deref<Target = Index>` coercion is invisible at the call site: any future
//! `fn f(idx: &Index)` would silently accept and downgrade a gated value with no
//! signal. `.index()` is grep-able (`grep -rn '\.index()'` enumerates every
//! extraction point) and costs nothing extra at the ~3-4 entry-point unwrap sites
//! that need it.

use crate::index_trust::{IndexBundleInfo, VerificationResult};
use crate::registry::Index;

/// The trust-boundary witness type. See the module docs for the NORMATIVE
/// per-policy invariant and the rationale for each field/accessor.
///
/// Fields are private — the only way to build a non-empty, non-test
/// `GatedIndex` is [`GatedIndex::mint`], which is `pub(crate)` (privileged to
/// the gate modules, per RFC §2.1).
#[derive(Debug, Clone)]
pub struct GatedIndex {
    index: Index,
    verification: Option<VerificationResult>,
    bundle_info: Option<IndexBundleInfo>,
}

impl GatedIndex {
    /// Mint a `GatedIndex` from a parsed [`Index`] and the verification outcome
    /// already computed for it by the gate.
    ///
    /// `pub(crate)`: privileged to the gate modules (`index_cache`,
    /// `index_ratchet_seam`) per RFC §2.1 — "the mint point is the production
    /// gate, not a leaf `acquire`." No public path from bytes to a
    /// resolver-consumable index may skip the gate.
    ///
    /// `verification: None` asserts the `off`-policy case (verifier never
    /// called); `Some(result)` asserts `strict`/`warn` (verifier ran and
    /// produced `result`, already enforced by the caller per policy before
    /// minting).
    ///
    /// S1a-i (this slice) is purely additive: no production call site is
    /// wired to `mint` yet — that lands in S1a-ii, which retypes the ~4
    /// `index_cache` / `index_ratchet_seam` mint points and the `load_*` /
    /// `maybe_index` return types. Until then this is only exercised by this
    /// module's own tests, hence the explicit `allow`.
    #[allow(dead_code)]
    pub(crate) fn mint(
        index: Index,
        verification: Option<VerificationResult>,
        bundle_info: Option<IndexBundleInfo>,
    ) -> GatedIndex {
        GatedIndex { index, verification, bundle_info }
    }

    /// The single sanctioned extraction point for the wrapped [`Index`].
    /// Grep-able by design — see the module docs on why this is not `Deref`.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// The verification outcome recorded at mint time, or `None` if policy was
    /// `off` (verifier never invoked).
    pub fn verification(&self) -> Option<&VerificationResult> {
        self.verification.as_ref()
    }

    /// The observable bundle claims (Rekor time/log-index, signer SAN, etc.)
    /// recorded at mint time, if a bundle was fetched and parsed.
    ///
    /// A `Some` value here is NOT an endorsement of trust — under `warn`, a
    /// `DigestMismatch` (tampering) still warns-and-continues and still
    /// populates `bundle_info` from the mismatched sidecar. Use
    /// [`GatedIndex::is_cryptographically_trusted`] to ask the trust question.
    pub fn bundle_info(&self) -> Option<&IndexBundleInfo> {
        self.bundle_info.as_ref()
    }

    /// The ONLY sanctioned "is this index cryptographically trusted?" question
    /// (RFC §2.4). `true` if and only if verification ran and produced
    /// `VerificationResult::Trusted`.
    ///
    /// Do NOT read trust off `bundle_info().is_some()` — see [`GatedIndex::bundle_info`].
    pub fn is_cryptographically_trusted(&self) -> bool {
        matches!(self.verification, Some(VerificationResult::Trusted))
    }

    /// An empty, trust-neutral `GatedIndex`. An empty index asserts no trust
    /// claim, so this is sound under every policy (RFC §2.6) — used at the
    /// resolver's default/frozen anchors, which never load a real index.
    pub fn empty() -> GatedIndex {
        GatedIndex { index: Index::default(), verification: None, bundle_info: None }
    }

    /// Test-only escape hatch: wrap an arbitrary [`Index`] without going
    /// through the gate. `#[cfg(test)]`-gated so it cannot ship in a release
    /// build (RFC §2.6) — Rust enforces this at compile time, unlike Python's
    /// `for_test`, which needs a runtime containment story.
    #[cfg(test)]
    pub(crate) fn for_test(index: Index) -> GatedIndex {
        GatedIndex { index, verification: None, bundle_info: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bundle_info() -> IndexBundleInfo {
        IndexBundleInfo {
            integrated_time: 1_735_000_000,
            rekor_log_index: "98765432".to_string(),
            subject_sha256: Some("deadbeef".to_string()),
            signer_san: Some("signer@example.com".to_string()),
            oidc_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        }
    }

    #[test]
    fn empty_is_not_trusted_and_wraps_default_index() {
        let gated = GatedIndex::empty();
        assert!(!gated.is_cryptographically_trusted());
        assert_eq!(gated.index(), &Index::default());
        assert!(gated.verification().is_none());
        assert!(gated.bundle_info().is_none());
    }

    #[test]
    fn mint_trusted_is_cryptographically_trusted_and_round_trips_index() {
        let idx = Index { packages: vec![], ..Default::default() };
        let bundle_info = sample_bundle_info();
        let gated =
            GatedIndex::mint(idx.clone(), Some(VerificationResult::Trusted), Some(bundle_info));

        assert!(gated.is_cryptographically_trusted());
        assert_eq!(gated.index(), &idx);
        assert_eq!(gated.verification(), Some(&VerificationResult::Trusted));
    }

    #[test]
    fn mint_non_trusted_is_not_trusted_even_with_bundle_info_present() {
        let idx = Index { packages: vec![], ..Default::default() };
        let bundle_info = sample_bundle_info();
        // warn-policy shape: a DigestMismatch (tampering) still warns-and-continues
        // and still populates bundle_info from the mismatched sidecar. Trust must
        // NOT be read off bundle_info presence.
        let gated = GatedIndex::mint(
            idx,
            Some(VerificationResult::DigestMismatch),
            Some(bundle_info),
        );

        assert!(!gated.is_cryptographically_trusted());
        assert!(gated.bundle_info().is_some());
        assert_eq!(gated.verification(), Some(&VerificationResult::DigestMismatch));
    }

    #[test]
    fn mint_off_policy_has_no_verification_and_is_not_trusted() {
        let idx = Index { packages: vec![], ..Default::default() };
        let gated = GatedIndex::mint(idx, None, None);

        assert!(!gated.is_cryptographically_trusted());
        assert!(gated.verification().is_none());
        assert!(gated.bundle_info().is_none());
    }

    #[test]
    fn for_test_wraps_without_verification_or_bundle_info() {
        let idx = Index { packages: vec![], ..Default::default() };
        let gated = GatedIndex::for_test(idx.clone());

        assert!(!gated.is_cryptographically_trusted());
        assert_eq!(gated.index(), &idx);
        assert!(gated.verification().is_none());
        assert!(gated.bundle_info().is_none());
    }
}
