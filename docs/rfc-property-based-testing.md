# RFC: property-based testing as spec-fixture pipeline

**Status**: Proposed (commitment for v0.x+; tier A delivered before spec extraction)
**Author**: Corey Leavitt
**Date**: 2026-05-22

## Why this RFC exists

milpa's `rfc-multi-impl-strategy.md` commits the project to a spec +
multiple reference implementations + conformance test suite as the
v1.5+ artifact set. The implementations are validated against each
other through black-box fixtures: input manifests + registries +
mocked fetches, expected output lockfiles + nim.cfgs + content hashes.

The honest problem with the conformance suite as currently planned:
**fixtures are written by hand**. Whoever extracts the spec sits down
and types example inputs. Hand-written suites miss edge cases by
construction — humans don't think about empty intervals, boundary
versions, Unicode normalization, empty source trees, single-character
filenames, U+0000 in paths, or the 47 ways `>= 0.0.0 & < 1.0.0` can
behave weirdly when versions cluster at the boundary.

The fix: **property-based testing produces conformance fixtures
mechanically**. We declare invariants ("VersionSet intersection is
commutative"); Hypothesis generates hundreds of random inputs trying
to break them; counterexamples it finds become checked-in fixtures
that every implementation must handle correctly. The spec's test
corpus grows by *discovery*, not by typing.

This RFC commits milpa to property-based testing as a first-class
discipline, not just a quality boost. The Python reference
implementation gets the test scaffolding; the conformance suite
inherits every counterexample as a JSON fixture; the future Rust
implementation must pass them.

## The principle

> A counterexample Hypothesis finds is a hole in the spec, not just
> a bug in the implementation. Fixing the implementation without
> recording the counterexample as a fixture means the next
> implementation will hit the same hole.

Concretely:

1. We declare *properties* — invariants the system should preserve
   over all valid inputs.
2. Hypothesis searches the input space for counterexamples.
3. Each counterexample is fixed in the implementation AND recorded as
   a JSON fixture in `tests/fixtures/property-counterexamples/`.
4. Conformance fixtures (per `rfc-multi-impl-strategy.md`) include
   every property-found counterexample.
5. Future implementations (Rust, Nim) run the same fixtures and must
   produce identical output bytes.

The result: the spec's edge-case coverage grows mechanically as we
exercise the system. Each Hypothesis run that finds something is a
free contribution to the spec's robustness across implementations.

## Tooling

**Python (current reference)**: [Hypothesis](https://hypothesis.readthedocs.io/) —
the standard property-testing library. Mature, integrates with pytest,
has `@given` decorators for property definitions, automatically
shrinks counterexamples to minimal reproductions, supports
deterministic replay via database of past findings.

**Rust (v2 reference)**: [proptest](https://github.com/proptest-rs/proptest) —
direct Hypothesis-equivalent for Rust. Same API shape; same shrinking;
same `.proptest-regressions` database pattern.

**Counterexample exchange format**: counterexamples found by either
implementation are checked in as JSON fixtures. JSON is the LCD format
for cross-implementation tooling. The shrinking-to-minimum step
guarantees the fixture itself is small and human-readable.

## What modules property-test well in milpa

| Module | Properties | Tier |
|---|---|---|
| `solver.VersionSet` algebra | De Morgan, idempotency, commutativity, double-complement, distributivity | A |
| `lockfile` parse↔format | round-trip identity for all valid Lockfiles | B |
| `manifest` parse↔format | round-trip identity for all valid Manifests | B |
| `identity.compute_content_hash` | determinism, file-order-independence, .git-invariance, mode discrimination | B |
| `solver.match_constraint` ↔ `VersionSet.contains` | the two paths compute the same predicate | C |
| `nimble_parse` invariants | requires extracted match what was declared (modulo nimscript surface) | C |
| `solver.solve` soundness | any well-formed provider yields a consistent assignment or correctly errors | research |
| `resolver.resolve` integration | round-trip resolver→lockfile→reload→resolve produces same graph | research |

These are *not* a substitute for the example tests we have today.
Example tests pin specific behaviors and document intent. Property
tests find the class of bugs example tests don't think to look for.
The two together are the right discipline.

## The four tiers

### Tier A — immediate (~1-2 days, ships in v0.x)

**Properties on `VersionSet` algebra.** This is the algebraic core of
the solver and the place where Hypothesis adds the most leverage
fastest.

Properties to verify:
- `intersect` is commutative: `a.intersect(b) == b.intersect(a)`
- `intersect` is associative: `(a.intersect(b)).intersect(c) == a.intersect(b.intersect(c))`
- `intersect` is idempotent: `a.intersect(a) == a`
- `intersect` identity: `a.intersect(full()) == a`
- `intersect` zero: `a.intersect(empty()) == empty()`
- Same five for `union`
- Double-complement: `a.complement().complement() == a`
- De Morgan: `a.intersect(b).complement() == a.complement().union(b.complement())`
- `contains` agrees with `intersect`: `a.contains(v) == a.intersect(eq(v)) != empty()`
- `is_subset_of` agrees with intersect: `a.is_subset_of(b) == a.intersect(b) == a`

Hypothesis strategy: generate `VersionSet`s from random unions of
random intervals over a bounded version space (e.g.
major/minor/patch in [0, 99]). Bounded space keeps shrinking fast
without losing meaningful coverage of edge cases (boundary versions,
empty intervals, overlapping intervals).

**Acceptance:** all ten properties verified by Hypothesis under
default settings (100 examples each) — any failure becomes a
checked-in counterexample fixture + an example-test regression
covering the same input.

### Tier B — next (~1-2 days each, ships during v0.x → v1)

**`lockfile` parse ↔ format round-trip.** Property: for any valid
`Lockfile`, `parse_lockfile(format_lockfile(L)) == L`. Hypothesis
strategy generates random `LockedDep` lists with realistic-shaped
SHAs, content_hashes, names, source URLs.

**`manifest` parse ↔ format round-trip.** Same shape, against the
manifest grammar. Includes both `UrlDep` and `NamedDep` variants
generated together.

**`identity.compute_content_hash` invariants.**
- Determinism: `compute(T) == compute(T)` (trivial; included as a
  smoke test)
- File-order-independence: generating files in different `os.walk`
  orders produces the same hash (the canonical sort guarantees this)
- `.git` exclusion: adding arbitrary `.git/` content to a tree
  doesn't change the hash
- Mode discrimination: flipping the exec bit on any file changes the
  hash
- Symlink vs file discrimination: same content bytes as file vs
  symlink target produce different hashes

Hypothesis strategy: generate random "trees" as Python dicts
(`{relpath: (mode, content)}`), materialize them to tmp directories,
hash, compare.

### Tier C — moderate (~2-3 days each)

**`match_constraint` ↔ `VersionSet.contains` equivalence.** Property:
for any constraint string `c` and version `v`,
`match_constraint(c, v) == VersionSet.from_constraint(c).contains(v)`.
The two paths in our codebase computing the same predicate should
agree on every input. If they disagree, one of them is wrong (or the
constraint grammar is ambiguous, which is its own bug).

Hypothesis strategy: generate constraint strings from a grammar
(combinators of `>=`, `<=`, `==`, `>`, `<` over random version tuples,
plus the `&` combinator), generate random version tuples to test
against.

**`nimble_parse` round-trip invariants.** Stricter than the others
because `.nimble` files are nimscript and we don't fully parse them.
The achievable property: for any line-formatted requires we generate,
the extracted `Requirement` list reflects what was declared. We don't
test for parser robustness against malicious nimscript — that's by
construction out of scope.

Hypothesis strategy: generate nimble-file-shaped strings from a
grammar covering the actual `requires` forms we handle (single-line,
comma-separated, multi-line continuation). Don't generate arbitrary
nimscript — we don't claim to parse it.

### Research tier — open-ended

**Solver soundness.** Property: for any well-formed `PackageProvider`
that has at least one consistent assignment, `solve()` returns an
assignment that satisfies every declared constraint. Conversely, if
no consistent assignment exists, `solve()` raises `SolverError`.

The hard part: generating *well-formed* `PackageProvider`s that
satisfy structural invariants (acyclic in some sense, finite version
space, constraints reference packages that exist). This is research
territory — Hypothesis strategies for "random valid dep graphs" are
the topic of multiple papers. Cargo's solver tests have a similar
generator that took multiple engineer-years to mature.

For milpa: defer until v1+, scope as a research direction
contribution. The output is publishable — a paper-grade Hypothesis
strategy for valid PubGrub providers, validated against milpa's
solver, is a real contribution to the field.

**`resolver.resolve` integration round-trip.** Property: given a
manifest M, resolve(M) → graph G; lockfile = from_graph(G);
`resolve(M, locked_against=lockfile)` produces the same G. This is
the "lockfile-aware re-resolution" feature crossed with property
testing. Hard because the resolver currently doesn't have a
locked-against mode (that's a future feature).

**Fuzzing-as-property-testing.** Treat the manifest parser, lockfile
parser, and nimble parser as fuzz targets. Property: malformed input
either parses successfully or raises a typed error — never crashes
with `KeyError`, `AttributeError`, or unhandled exceptions. This is
adjacent to American Fuzzy Lop-style fuzzing; Hypothesis's
`from_regex` strategy gets us partway there.

## Counterexample lifecycle

When Hypothesis finds a counterexample:

1. **Shrink to minimum** — Hypothesis does this automatically; the
   final reproduction is the smallest input that breaks the property.
2. **Triage** — is this a property bug (we asserted something that
   isn't actually true) or an implementation bug?
3. **Fix** — typically a code change in the failing module.
4. **Pin** — add the minimum counterexample as an example-style test
   in the same test file, with a comment noting the Hypothesis run
   that found it.
5. **Promote to fixture** — once spec extraction lands (v1.5), the
   counterexample is serialized to JSON in
   `tests/fixtures/property-counterexamples/<module>/<property>.json`
   and runs against every implementation in the conformance suite.

The serialization format for a counterexample fixture:

```json
{
  "property": "VersionSet.intersect is commutative",
  "discovered_by": "milpa-python 0.1.0 / hypothesis 6.x",
  "discovered_at": "2026-05-22",
  "input": {
    "a": {"intervals": [["1.2.0", "2.0.0"]]},
    "b": {"intervals": [["1.5.0", null]]}
  },
  "expected": {
    "result": {"intervals": [["1.5.0", "2.0.0"]]}
  }
}
```

Format details settle at spec-extraction time; the principle is what
matters now.

## Cost-benefit honest assessment

**Costs:**
- One dev dep (`hypothesis`, ~MB, pure Python)
- Test runs slow down: with 100 examples × 10 properties on
  VersionSet alone, ~1000 strategy evaluations per `pytest` invocation.
  Default settings give us ~5-10s of additional test time.
- Learning curve: writing good Hypothesis strategies takes some
  thinking; bad strategies generate degenerate inputs that don't
  exercise the system meaningfully.
- Counterexample maintenance: shrunken examples can be cryptic;
  debugging requires reading the property and the strategy together.

**Benefits:**
- Bug class coverage: every property tested covers the class of
  inputs satisfying its preconditions, not just one example.
- **Conformance fixture pipeline**: this is the load-bearing argument.
  Property-found counterexamples become spec test corpus.
- Documentation: a well-written property is a precise statement of
  what the code should do — frequently sharper than docstrings.
- Multi-impl validation: Rust impl runs the same fixtures Python
  found; disagreements between implementations on Hypothesis-discovered
  inputs are spec bugs, surfaced concretely.
- Algebraic-thinking forcing function: writing properties forces you
  to articulate the algebra (commutativity, identity, etc.). This
  catches design errors before they become bugs (e.g., "wait, why ISN'T
  intersect commutative? oh, because we have this weird normalization
  step that...").

**Net**: positive at every scale. The investment is front-loaded; the
payoff compounds through every implementation we ever ship.

## Open questions

### How aggressive should Hypothesis be by default?

Hypothesis's default is 100 examples per property. We could tune up to
1000+ for higher coverage at the cost of CI time, or use
`@settings(max_examples=N)` per property. Recommendation: 100 default,
nightly CI runs with `max_examples=5000`, counterexamples checked in
regardless of where they came from.

### Where do counterexample fixtures live?

Two options:
- **In-tree** under `tests/fixtures/property-counterexamples/`
- **In the spec repo** when it gets extracted at v1.5

Until v1.5: in-tree. At v1.5: lifted to the spec repo so Python and
Rust both consume them.

### What about the `.hypothesis/` database directory?

Hypothesis persists a database of past examples for replay. By
default it lives at `.hypothesis/` in the project root. Gitignore it
— it's a cache of which inputs are interesting, not a source of truth.
The source-of-truth artifacts are the JSON fixtures we check in.

### Should we ship Hypothesis at runtime or only as dev?

Dev only. `hypothesis` is in the `dev` dependency group; production
milpa doesn't depend on it. Same for `proptest` in the eventual Rust
impl.

### What about flaky tests from Hypothesis's randomness?

Hypothesis is **not flaky by default**: it derives example generation
from a deterministic seed unless you opt into randomization. Once a
counterexample is found, it's persisted (via the database or the
checked-in fixture) and runs every time. Flakiness only appears if
you actively introduce environmental nondeterminism in the property
definitions (e.g., depending on the current time). Avoid that and
flakiness isn't a concern.

## What this RFC does NOT commit milpa to

- A specific test count target (`max_examples` is tunable per property)
- A formal spec for the JSON fixture format (settled at spec extraction)
- Property tests for the toolchain RFC features (#54–62) — those land
  alongside their implementation
- Property tests as a *replacement* for example tests (they're
  complementary)
- A specific Rust property-testing library (proptest is the obvious
  choice but the multi-impl RFC's Rust impl design will settle this)

## Acceptance: how do we know this is working?

The discipline is healthy when:

1. Every module with algebraic structure has at least one property
   test.
2. Counterexamples found by Hypothesis are checked in as fixtures,
   not just fixed and forgotten.
3. The conformance suite (post-spec-extraction) has more fixtures
   from Hypothesis discoveries than from hand-written examples.
4. Property tests catch regressions that example tests miss — this is
   self-documenting in commit messages.
5. The pattern survives a Rust port: proptest properties on the Rust
   side match Hypothesis properties on the Python side, and both
   produce the same counterexamples for the same input space.

## Issues this RFC will spawn

Filed against new milestone "property-based testing
(rfc-property-based-testing)" on GitHub:

- **Tier A**: Hypothesis on VersionSet algebra
- **Tier B-1**: Hypothesis on lockfile round-trip
- **Tier B-2**: Hypothesis on manifest round-trip
- **Tier B-3**: Hypothesis on content_hash invariants
- **Tier C-1**: Hypothesis on `match_constraint` ↔ `VersionSet.contains` equivalence
- **Tier C-2**: Hypothesis on nimble_parse line-form invariants
- **Research**: Hypothesis strategy for valid PubGrub providers + solver soundness
- **Research**: lockfile-aware re-resolution round-trip property
- **Research**: fuzzing-as-property-testing for parsers
- **Infrastructure**: counterexample fixture format + tooling for promoting Hypothesis findings to the spec corpus (lands at spec extraction, v1.5)
