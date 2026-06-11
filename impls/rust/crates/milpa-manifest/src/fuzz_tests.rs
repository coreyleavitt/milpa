//! RFC §2d parser-fuzz tests — manifest parsers (issue #4c).
//!
//! Invariant (RFC §2d): for ANY input string, each parser returns `Ok(_)` or
//! an `Err(e)` where `e.code()` is a slug present in `MAN_CODES`. A panic
//! inside the parser body is automatically a test failure (cargo test converts
//! panics to failures), which is the crash-detection mechanism.
//!
//! No external dependencies. A tiny 64-bit xorshift PRNG is embedded here so
//! the inputs are deterministic (failures reproduce on re-run) and the test
//! needs no `rand` crate.

use super::*;

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64 — period 2^64-1, sufficient for a few thousand
// inputs, no deps required).
// ---------------------------------------------------------------------------

struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        // Ensure state is non-zero.
        Xorshift64(if seed == 0 { 0xdeadbeef_cafebabe } else { seed })
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next() as usize) % max
    }
}

// ---------------------------------------------------------------------------
// Input generators
// ---------------------------------------------------------------------------

/// Generate `count` arbitrary byte strings (rendered losslessly to UTF-8).
fn arbitrary_inputs(rng: &mut Xorshift64, count: usize, max_len: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let len = rng.next_usize(max_len);
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u8()).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .collect()
}

/// Generate `count` structurally KDL-ish strings (short identifier-like tokens
/// mixed with KDL punctuation and common KDL-value chars).
fn kdl_garbage(rng: &mut Xorshift64, count: usize) -> Vec<String> {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz_-01234567890 \n\t{}\"=()\\";
    (0..count)
        .map(|_| {
            let len = rng.next_usize(120);
            let bytes: Vec<u8> = (0..len)
                .map(|_| CHARSET[rng.next_usize(CHARSET.len())])
                .collect();
            // Safe: CHARSET is ASCII.
            String::from_utf8(bytes).unwrap()
        })
        .collect()
}

/// Generate deep-nesting inputs: `{`.repeat(n) for n in 1..=max_depth.
/// The milpa-side depth guard (see `KDL_MAX_NESTING_DEPTH`) means inputs above
/// the limit are converted to a clean catalog `Err` before reaching kdl-rs's
/// recursive-descent parser; no OS stack overflow can occur regardless of depth.
/// Tests call this with 1000 to verify the guard holds well above the former
/// unsafe threshold (≈50 in debug builds).
fn deep_nesting_inputs(max_depth: usize) -> Vec<String> {
    (1..=max_depth)
        .map(|n| "{".repeat(n))
        .collect()
}

// ---------------------------------------------------------------------------
// Assertion helper
// ---------------------------------------------------------------------------

fn assert_manifest_clean(input: &str) {
    match parse_manifest(input) {
        Ok(_) => {}
        Err(e) => assert!(
            MAN_CODES.contains(&e.code()),
            "parse_manifest returned out-of-catalog code {:?} for input {:?}",
            e.code(),
            // Truncate very long inputs in the assert message.
            if input.len() > 200 { &input[..200] } else { input },
        ),
    }
}

fn assert_document_clean(input: &str) {
    match parse_document(input) {
        Ok(_) => {}
        Err(e) => assert!(
            MAN_CODES.contains(&e.code()),
            "parse_document returned out-of-catalog code {:?} for input {:?}",
            e.code(),
            if input.len() > 200 { &input[..200] } else { input },
        ),
    }
}

fn assert_workspace_clean(input: &str) {
    match parse_workspace(input) {
        Ok(_) => {}
        Err(e) => assert!(
            MAN_CODES.contains(&e.code()),
            "parse_workspace returned out-of-catalog code {:?} for input {:?}",
            e.code(),
            if input.len() > 200 { &input[..200] } else { input },
        ),
    }
}

// ---------------------------------------------------------------------------
// Fuzz tests
// ---------------------------------------------------------------------------

#[test]
fn fuzz_parse_manifest_arbitrary_bytes() {
    let mut rng = Xorshift64::new(0x1234_5678_9abc_def0);
    for input in arbitrary_inputs(&mut rng, 2000, 256) {
        assert_manifest_clean(&input);
    }
}

#[test]
fn fuzz_parse_manifest_kdl_garbage() {
    let mut rng = Xorshift64::new(0xfeed_face_dead_beef);
    for input in kdl_garbage(&mut rng, 2000) {
        assert_manifest_clean(&input);
    }
}

#[test]
fn fuzz_parse_manifest_deep_nesting() {
    for input in deep_nesting_inputs(1000) {
        assert_manifest_clean(&input);
    }
}

#[test]
fn fuzz_parse_document_arbitrary_bytes() {
    let mut rng = Xorshift64::new(0xc0ff_ee00_1234_abcd);
    for input in arbitrary_inputs(&mut rng, 2000, 256) {
        assert_document_clean(&input);
    }
}

#[test]
fn fuzz_parse_document_kdl_garbage() {
    let mut rng = Xorshift64::new(0xbaad_f00d_cafe_babe);
    for input in kdl_garbage(&mut rng, 2000) {
        assert_document_clean(&input);
    }
}

#[test]
fn fuzz_parse_workspace_arbitrary_bytes() {
    let mut rng = Xorshift64::new(0x0102_0304_0506_0708);
    for input in arbitrary_inputs(&mut rng, 2000, 256) {
        assert_workspace_clean(&input);
    }
}

#[test]
fn fuzz_parse_workspace_kdl_garbage() {
    let mut rng = Xorshift64::new(0xa5a5_a5a5_5a5a_5a5a);
    for input in kdl_garbage(&mut rng, 2000) {
        assert_workspace_clean(&input);
    }
}
