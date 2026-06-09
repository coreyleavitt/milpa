//! `milpa` CLI binary (RFC §4.1). The CLI contract (the eight verbs, exit
//! codes, stdout/stderr discipline) lands in S13 with its own integration
//! tests; no spec-v1 fixture invokes the binary as a subprocess.
//!
//! S1 (scaffold): a binary that builds and links against `milpa-core`.

fn main() {
    // S13 wires argparse + the verbs. Until then, keep the link real so the
    // workspace's binary target compiles.
    let _ = milpa_core::error::MilpaError::code;
    eprintln!("milpa: CLI not yet implemented (S13)");
    std::process::exit(2);
}
