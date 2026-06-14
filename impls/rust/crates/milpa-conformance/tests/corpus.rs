//! The real corpus run (RFC §4.3/§4.4) + error-catalog parity (§4.6).
//!
//! Every `conformance/spec-v<N>/fixture-*` is discovered and run through
//! [`MilpaTarget`]. Because `MilpaTarget` is wired incrementally, at S2 they all
//! fail and every id is parked in `known_failing.txt`; as slices land, fixtures
//! green and their entries are removed. The xfail/xpass policy (§4.3): a parked
//! fixture that *fails* is expected (xfail); one that *passes* is an
//! `UNEXPECTED PASS` — a warning locally, a hard failure under `CI` (the entry
//! must be removed before merge). An *un-parked* fixture that fails is a real
//! regression and always fails the build. `known_failing.txt` must be empty for
//! the suite to be Done (§6).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use milpa_conformance::{discover, run_fixture, MilpaTarget, Scratch, Verdict, CORPUS_REL};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_REL)
}

/// Parse `known_failing.txt`: one fixture id per line; `#` starts a comment;
/// blank lines ignored.
fn known_failing() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("known_failing.txt");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect()
}

fn in_ci() -> bool {
    std::env::var_os("CI").is_some()
}

#[test]
fn conformance_corpus() {
    let fixtures = discover(&corpus_root());
    assert!(
        !fixtures.is_empty(),
        "no fixtures discovered under {}",
        corpus_root().display()
    );
    let kf = known_failing();
    let discovered: BTreeSet<String> = fixtures.iter().map(|f| f.id.clone()).collect();

    // Stale parks (renamed/deleted fixtures still listed) rot silently — reject.
    let stale: Vec<&String> = kf.difference(&discovered).collect();
    assert!(
        stale.is_empty(),
        "known_failing.txt lists fixtures that no longer exist: {stale:?}"
    );

    let mut passed = 0usize;
    let mut xfail = 0usize;
    let mut skipped = 0usize;
    let mut xpass: Vec<String> = Vec::new();
    let mut regressions: Vec<String> = Vec::new();

    for fx in &fixtures {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(tmp.path()).unwrap();
        let verdict = run_fixture(fx, &MilpaTarget, &scratch);
        let parked = kf.contains(&fx.id);
        match (verdict, parked) {
            // CLI-only verb fixtures are not assertable in-process — skipped
            // here, covered by the black-box CLI harness (harness/).
            (Verdict::Skip(_), _) => skipped += 1,
            (Verdict::Pass, false) => passed += 1,
            (Verdict::Pass, true) => xpass.push(fx.id.clone()),
            (Verdict::Fail(_), true) => xfail += 1,
            (Verdict::Fail(reason), false) => regressions.push(format!("{}: {reason}", fx.id)),
        }
    }

    eprintln!(
        "conformance: {} fixtures — {passed} pass, {xfail} xfail (parked), {skipped} skip (cli-only), {} xpass, {} regressions",
        fixtures.len(),
        xpass.len(),
        regressions.len()
    );
    for id in &xpass {
        eprintln!("UNEXPECTED PASS: {id} (remove from known_failing.txt)");
    }

    assert!(
        regressions.is_empty(),
        "un-parked fixtures failed (real regressions):\n{}",
        regressions.join("\n")
    );
    if in_ci() {
        assert!(
            xpass.is_empty(),
            "fixtures parked in known_failing.txt unexpectedly passed (CI blocks this); \
             remove them:\n{}",
            xpass.join("\n")
        );
    }
}

/// Extract the error slugs from `spec/errors.md` (one `### \`SLUG\`` per
/// code).
fn spec_error_codes() -> BTreeSet<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../spec/errors.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("### `")?;
            let slug = rest.split('`').next()?;
            Some(slug.to_string())
        })
        .collect()
}

/// Spec codes not yet emittable, tagged with the slice that will wire them. As
/// each slice lands its codes move into `implemented_error_codes()` and leave
/// this list; when it is empty the catalog is a pure bijection with the spec
/// (modulo [`EXEMPT`]). This is the honest S12 "bijection lint": every spec code
/// has exactly one home — implemented, deferred-to-a-known-slice, or exempt.
/// No codes remain deferred — every spec code is implemented or exempt, so the
/// catalog is a pure bijection (`implemented ∪ exempt == spec`).
/// Spec codes this implementation has deferred to a future slice (S3b+).
/// S1 moved all five TNG-DEPDECL-* codes to `implemented_error_codes()` in
/// `milpa-core::error::CoreError::all_codes()` — they are registered there
/// as S3b targets even though not all raise sites are wired yet.
const DEFERRED: &[&str] = &[
    // No codes currently deferred — all spec codes are implemented or exempt.
];

/// Spec codes this implementation intentionally never emits.
const EXEMPT: &[&str] = &[
    // The type system enforces it: `parse_identity` takes a `&str`, so a
    // non-string identity is unrepresentable (Python guards a `dict` value).
    "ID-NOT-A-STRING",
    // Reserved in the catalog; raised by neither the Python nor the Rust impl.
    "TNG-BAD-VERSION",
    // Unrepresentable in the Rust model: a fetcher returns a typed `Receipt`
    // (struct), so a "receipt with no transport evidence" — which the Python
    // dict-based receipt guards against — cannot occur (same kind of
    // type-enforced exemption as ID-NOT-A-STRING).
    "FETCH-RECEIPT-EMPTY",
    // The Rust `.nimble` line-form parser is a *total* heuristic scan (it never
    // raises), so a `.nimble` is never a "parse error" — discovery surfaces a
    // `.nimble` file-read failure as MAN-FILE-UNREADABLE instead. So MAN-NIMBLE-PARSE
    // is unreachable and the standalone NIMBLE-FILE-* codes are never emitted (the
    // Python `load_nimble` that raises them is dead outside its own tests — P2).
    "MAN-NIMBLE-PARSE",
    "NIMBLE-FILE-NOT-FOUND",
    "NIMBLE-FILE-UNREADABLE",
];

/// Error-catalog bijection lint (RFC §4.6). Every code in `spec/errors.md`
/// must have exactly one home — emittable now ([`implemented_error_codes`]),
/// [`DEFERRED`] to a named slice, or [`EXEMPT`] — and every emittable code must
/// be in the spec (no orphans). The three sets are pairwise disjoint and their
/// union is exactly the spec. (The non-catalog `MILPA-INTERNAL-IO` sentinel is in
/// none of them — it is deliberately absent from `errors.md`.)
#[test]
fn rust_error_catalog_is_a_bijection_with_the_spec() {
    let spec = spec_error_codes();
    assert!(
        spec.len() > 50,
        "errors.md parse looks wrong: only {} slugs found",
        spec.len()
    );

    let implemented: BTreeSet<String> = milpa_core::implemented_error_codes()
        .into_iter()
        .map(str::to_string)
        .collect();
    let deferred: BTreeSet<String> = DEFERRED.iter().map(|s| s.to_string()).collect();
    let exempt: BTreeSet<String> = EXEMPT.iter().map(|s| s.to_string()).collect();

    // No orphans: every emittable code is in the spec.
    let orphans: Vec<&String> = implemented.difference(&spec).collect();
    assert!(
        orphans.is_empty(),
        "Rust emits error codes absent from spec/errors.md: {orphans:?}"
    );

    // Pairwise disjoint: a code is in exactly one bucket.
    let imp_def: Vec<&String> = implemented.intersection(&deferred).collect();
    assert!(
        imp_def.is_empty(),
        "codes both implemented and DEFERRED: {imp_def:?}"
    );
    let imp_ex: Vec<&String> = implemented.intersection(&exempt).collect();
    assert!(
        imp_ex.is_empty(),
        "codes both implemented and EXEMPT: {imp_ex:?}"
    );
    let def_ex: Vec<&String> = deferred.intersection(&exempt).collect();
    assert!(
        def_ex.is_empty(),
        "codes both DEFERRED and EXEMPT: {def_ex:?}"
    );

    // DEFERRED / EXEMPT must reference real spec codes (no stale entries).
    let stale_def: Vec<&String> = deferred.difference(&spec).collect();
    assert!(
        stale_def.is_empty(),
        "DEFERRED lists non-spec codes: {stale_def:?}"
    );
    let stale_ex: Vec<&String> = exempt.difference(&spec).collect();
    assert!(
        stale_ex.is_empty(),
        "EXEMPT lists non-spec codes: {stale_ex:?}"
    );

    // Exhaustive: the three buckets cover the whole spec.
    let covered: BTreeSet<String> = implemented
        .union(&deferred)
        .cloned()
        .collect::<BTreeSet<_>>()
        .union(&exempt)
        .cloned()
        .collect();
    let uncovered: Vec<&String> = spec.difference(&covered).collect();
    assert!(
        uncovered.is_empty(),
        "spec codes with no home (add to implemented, DEFERRED, or EXEMPT): {uncovered:?}"
    );
}
