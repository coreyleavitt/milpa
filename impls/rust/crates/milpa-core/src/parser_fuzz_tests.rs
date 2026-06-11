//! RFC §2d parser-fuzz tests — lockfile + index parsers (issue #4c).
//!
//! Invariant (RFC §2d): for ANY input string, each parser returns `Ok(_)` or
//! an `Err(e)` where `e.code()` is a slug present in `CoreError::all_codes()`.
//! A panic inside the parser body is automatically a test failure (cargo test
//! converts panics to failures), which is the crash-detection mechanism.
//!
//! No external dependencies. A tiny 64-bit xorshift PRNG is embedded here so
//! inputs are deterministic (failures reproduce on re-run).

use crate::error::CoreError;
use crate::lockfile::parse_lockfile;
use crate::registry::Index;

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64 — period 2^64-1).
// ---------------------------------------------------------------------------

struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
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

fn arbitrary_inputs(rng: &mut Xorshift64, count: usize, max_len: usize) -> Vec<String> {
    (0..count)
        .map(|_| {
            let len = rng.next_usize(max_len);
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u8()).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        })
        .collect()
}

fn kdl_garbage(rng: &mut Xorshift64, count: usize) -> Vec<String> {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz_-01234567890 \n\t{}\"=()\\";
    (0..count)
        .map(|_| {
            let len = rng.next_usize(120);
            let bytes: Vec<u8> = (0..len)
                .map(|_| CHARSET[rng.next_usize(CHARSET.len())])
                .collect();
            String::from_utf8(bytes).unwrap()
        })
        .collect()
}

fn deep_nesting_inputs(max_depth: usize) -> Vec<String> {
    // The milpa-side depth guard (milpa_manifest::KDL_MAX_NESTING_DEPTH) means
    // inputs above the limit are converted to a clean catalog Err before
    // reaching kdl-rs's recursive-descent parser; no OS stack overflow can
    // occur regardless of depth.  Tests call this with 1000.
    (1..=max_depth).map(|n| "{".repeat(n)).collect()
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

fn assert_lockfile_clean(input: &str) {
    let catalog = CoreError::all_codes();
    match parse_lockfile(input) {
        Ok(_) => {}
        Err(e) => assert!(
            catalog.contains(&e.code()),
            "parse_lockfile returned out-of-catalog code {:?} for input {:?}",
            e.code(),
            if input.len() > 200 { &input[..200] } else { input },
        ),
    }
}

fn assert_index_clean(input: &str) {
    let catalog = CoreError::all_codes();
    match Index::parse(input) {
        Ok(_) => {}
        Err(e) => assert!(
            catalog.contains(&e.code()),
            "Index::parse returned out-of-catalog code {:?} for input {:?}",
            e.code(),
            if input.len() > 200 { &input[..200] } else { input },
        ),
    }
}

// ---------------------------------------------------------------------------
// Lockfile fuzz tests
// ---------------------------------------------------------------------------

#[test]
fn fuzz_parse_lockfile_arbitrary_bytes() {
    let mut rng = Xorshift64::new(0x1111_2222_3333_4444);
    for input in arbitrary_inputs(&mut rng, 2000, 256) {
        assert_lockfile_clean(&input);
    }
}

#[test]
fn fuzz_parse_lockfile_kdl_garbage() {
    let mut rng = Xorshift64::new(0x5555_6666_7777_8888);
    for input in kdl_garbage(&mut rng, 2000) {
        assert_lockfile_clean(&input);
    }
}

#[test]
fn fuzz_parse_lockfile_deep_nesting() {
    for input in deep_nesting_inputs(1000) {
        assert_lockfile_clean(&input);
    }
}

// ---------------------------------------------------------------------------
// Index fuzz tests
// ---------------------------------------------------------------------------

#[test]
fn fuzz_index_parse_arbitrary_bytes() {
    let mut rng = Xorshift64::new(0x9999_aaaa_bbbb_cccc);
    for input in arbitrary_inputs(&mut rng, 2000, 256) {
        assert_index_clean(&input);
    }
}

#[test]
fn fuzz_index_parse_kdl_garbage() {
    let mut rng = Xorshift64::new(0xdddd_eeee_ffff_0000);
    for input in kdl_garbage(&mut rng, 2000) {
        assert_index_clean(&input);
    }
}

#[test]
fn fuzz_index_parse_deep_nesting() {
    for input in deep_nesting_inputs(1000) {
        assert_index_clean(&input);
    }
}
