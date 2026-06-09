//! `milpa-conformance` — the Rust fixture harness (RFC §4.4). One corpus, two
//! readers: this consumes the *same* `conformance/spec-v<N>/` fixtures the
//! Python runner does, reproducing the `conformance-fixtures.md` contract.
//!
//! The harness is a **black-box byte-diff runner** (conformance-fixtures.md §5):
//! it reads a fixture's input files, hands them to an *implementation under test*
//! (the [`Target`] trait), and diffs the produced `milpa.lock` / `nim.cfg` /
//! `_deps_structure.txt` against `expected/` — or asserts `expected/error`. It
//! never imports milpa's internals beyond the `Target` it drives.
//!
//! Layering (the coexistence linchpin, RFC §4.4):
//!   * [`fixture`] — pure fixture *I/O*: discovery, `cmd` dispatch, `expected/`
//!     reading. No parsing of milpa inputs (that is the impl-under-test's job —
//!     keeping the oracle from baking in the parser it is meant to validate).
//!   * [`runner`] — [`Target`], [`Scratch`], the diff/normalization engine
//!     ([`run_fixture`]), and [`MilpaTarget`] (delegates to `milpa-core`, wired
//!     slice by slice).
//!   * [`fake_fetcher`] — [`FakeFetcher`], a `milpa_core::Fetcher` backed by a
//!     fixture's `mocked-fetches/`.
//!   * [`urlkey`] — the `mocked-fetches/<key>` encoding (§2.3.1).
//!
//! S2 proves the engine against two hand-authored synthetic fixtures (one pass,
//! one fail) through a stub `Target` (see `tests/self_test.rs`); the real corpus
//! runs through [`MilpaTarget`] gated by `known_failing.txt` (`tests/corpus.rs`).

pub mod fake_fetcher;
pub mod fixture;
pub mod runner;
pub mod urlkey;

pub use fake_fetcher::FakeFetcher;
pub use fixture::{discover, Cmd, Expected, Fixture};
pub use runner::{
    read_deps_structure, run_fixture, MilpaTarget, Outputs, Produced, Scratch, Target, Verdict,
};

/// Relative path from this crate's manifest dir to the shared corpus root.
/// Resolved against `CARGO_MANIFEST_DIR` (= `impls/rust/crates/milpa-conformance`)
/// so it is robust to CWD (RFC §4.6: anchor at the manifest dir, not a build
/// script). The corpus is read by both runners; neither owns it.
pub const CORPUS_REL: &str = "../../../../conformance";
