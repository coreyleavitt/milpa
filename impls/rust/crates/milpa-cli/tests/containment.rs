//! CI/lint pin: `GatedIndex`'s test-only mint escape hatch stays out of the
//! shipped `milpa` binary's source tree (RFC `rfc-trusted-index-invariant.md`
//! §2.1, §2.6).
//!
//! `GatedIndex::for_test` is real, linkable code once the `test-support`
//! Cargo feature is enabled (`milpa-core/Cargo.toml`) — and Cargo's resolver
//! v2 feature unification means a workspace-wide build (`cargo build
//! --workspace`, `cargo test` at the workspace root, `./dev-rust test`
//! without `-p`) unifies milpa-conformance's `test-support` request into the
//! SAME `milpa-core` compilation unit that `milpa-cli` links against — so
//! `for_test`'s symbol is present in a workspace-built `milpa` binary too.
//! `#[cfg(feature = "test-support")]` alone is therefore NOT a guarantee that
//! a *workspace* build never links the escape hatch; it only guarantees that
//! a package-scoped release build (`cargo build -p milpa-cli`, what actually
//! ships) never enables the feature, since `milpa-cli/Cargo.toml` does not
//! request it and unification only unions requested features across the
//! packages actually being built.
//!
//! The real guarantee is a boundary + lint, not a pure compile-time gate:
//! nothing under `milpa-cli/src/` may reference the test-only mint points at
//! all, checked here by a static grep over the source tree — the Rust
//! analogue of Python's `tests/test_gated_index_containment.py`. If a future
//! contributor adds a call site (even one that would silently compile clean
//! under a workspace build thanks to feature unification), this test fails.

use std::path::{Path, PathBuf};

/// Forbidden substrings: the test-only mint constructor, the privileged
/// production mint point (which `milpa-cli` should never call directly
/// either — it must go through the real `index_cache` / `index_ratchet_seam`
/// gate), and the feature flag that unlocks `for_test` outside `cfg(test)`.
const FORBIDDEN: &[&str] = &["GatedIndex::for_test", "GatedIndex::mint", "test-support"];

fn cli_src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rs_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read_dir milpa-cli/src") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            out.extend(rs_files_under(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out
}

#[test]
fn gated_index_test_only_mint_never_referenced_from_milpa_cli() {
    let root = cli_src_root();
    let mut offenders: Vec<String> = Vec::new();

    for path in rs_files_under(&root) {
        let text = std::fs::read_to_string(&path).expect("read source file");
        for needle in FORBIDDEN {
            if text.contains(needle) {
                offenders.push(format!("{}: {needle}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "GatedIndex test-only escape hatch referenced from milpa-cli/src: \
         {offenders:?}. milpa-cli must never call `GatedIndex::for_test` \
         (test-only, RFC §2.6), `GatedIndex::mint` directly (privileged to \
         the gate modules in milpa-core — index_cache / \
         index_ratchet_seam, RFC §2.1), or enable the `test-support` \
         feature. Cargo feature unification means a workspace-wide build \
         can link `for_test` into the `milpa` binary even though \
         milpa-cli/Cargo.toml never requests `test-support` directly — this \
         grep-lint, not the feature gate alone, is what keeps the shipped \
         CLI's source tree free of the bypass. If milpa-cli needs a \
         GatedIndex, it must go through the real gate."
    );
}
