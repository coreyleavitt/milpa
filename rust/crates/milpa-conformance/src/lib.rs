//! `milpa-conformance` — the Rust fixture harness (RFC §4.4). One corpus, two
//! readers: this consumes the *same* `tests/conformance/spec-v<N>/` fixtures
//! the Python runner does, reproducing the `conformance-fixtures.md` contract.
//!
//! S1 (scaffold): the crate exists and links `milpa-core`. S2 builds the real
//! harness — `FixtureContext::load`, `cmd` dispatch, byte-diff/`expected/error`,
//! urlkey encoding, `<CAS_ROOT>` normalization, the error-parity `#[test]`
//! against `docs/spec/errors.md`, and `known_failing.txt` — proven against two
//! hand-authored synthetic fixtures (one pass, one fail).

/// Relative path from this crate's manifest dir to the shared corpus root.
/// Resolved against `CARGO_MANIFEST_DIR` (= `rust/crates/milpa-conformance`)
/// so it is robust to CWD (RFC §4.6: anchor at the manifest dir, not a build
/// script). The exact discovery walk lands in S2.
pub const CORPUS_REL: &str = "../../../tests/conformance";

#[cfg(test)]
mod tests {
    #[test]
    fn links_milpa_core() {
        // Smoke: the harness can name the boundary error type it will assert on.
        let _ = std::any::type_name::<milpa_core::MilpaError>();
    }
}
