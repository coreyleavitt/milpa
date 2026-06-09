# The milpa specification — v1.0

This directory is the **normative specification** of milpa: the language-
agnostic contract that any conformant implementation (the Python reference
impl, the planned Rust reference impl, a future Nim dogfood impl, or a
third-party port) must satisfy. The spec is the durable artifact; an
implementation is correct insofar as it conforms to this spec and passes
the conformance suite. See `../rfc-multi-impl-strategy.md` for why the spec
is factored out from any one implementation.

> **Spec version: 1.0.** This is a frozen surface. Changes are governed by
> the amendment process in §4 below.

## 1. Normative documents

The following documents are normative. Each carries `> NORMATIVE:` clauses
(the binding requirements) and `> NOTE:` blocks (non-binding rationale or
implementation observations), and opens with a "Normative surface" summary.

| Document | Scope |
|---|---|
| [`manifest-grammar.md`](manifest-grammar.md) (S4) | `milpa.kdl` grammar — package + workspace forms, the four dep kinds, `(url)` convention, conditional `when`/predicate blocks, feature flags, `.nimble` compatibility, the `spec-version` epoch, manifest serialization |
| [`lockfile-schema.md`](lockfile-schema.md) (S5) | `milpa.lock` schema — per-kind provenance records, version negotiation, the canonical byte-exact serialization, and `nim.cfg` emission |
| [`resolver-semantics.md`](resolver-semantics.md) (S6) | engine-agnostic resolution — completeness, the canonical-solution selection function, **canonical emission order**, **workspace resolution**, mirror fallback, conditional-dep evaluation, the `--frozen` path, result certificates |
| [`identity.md`](identity.md) (S12) | the byte-exact content-hash algorithm (identity) and the CAS layout, admission, and scratch lifecycle |
| [`registry-protocol.md`](registry-protocol.md) (S14) | the tianguis `index.kdl` read contract, field validators, and index-cache semantics |
| [`plugin-contract.md`](plugin-contract.md) (S10) | the fetcher/transport extension contract — obligations, receipts, exclusive dispatch, `cas_admissible`, extraction limits |
| [`cli-contract.md`](cli-contract.md) (S15) | the CLI surface — conformance verbs, flags, exit codes, stdout/stderr discipline, environment variables, workspace detection |
| [`conformance-fixtures.md`](conformance-fixtures.md) (S8a) | the conformance fixture format — the executable definition of "conformant" |
| [`errors.md`](errors.md) | the error catalog — every coded, user-facing error. **Generated** from `milpa/error_codes/`; do not hand-edit |

## 2. What "conformant" means

An implementation is **conformant with milpa spec v1** if and only if it
passes every fixture in `conformance/spec-v1/`. The conformance suite
is the **executable arbiter**: the prose documents above specify *intent*,
but where prose and a fixture disagree, that is a spec bug to be reconciled
(§4) — the fixtures define the observable contract.

Each fixture is black-box: given the inputs (`milpa.kdl`, optional
`index.kdl`, `milpa.lock`, mocked fetches, `cas-seed/`, `env`), a conformant
implementation MUST produce either the byte-identical `expected/` outputs
(`milpa.lock` + `nim.cfg` + `_deps_structure.txt`) or the `expected/error`
code. Byte-identical means exactly that: the canonical emission order
(resolver-semantics §4.4) and the canonical serialization (lockfile-schema
§2.4, identity §1) leave no freedom in the output bytes.

A small number of error codes are not exercisable through a black-box
fixture (filesystem-I/O conditions, the `verify` path, or codes reserved for
future use). These are enumerated with rationale in
`conformance-fixtures.md` §4; a conformant implementation must still raise
them where applicable, but they are validated by implementation-level tests
rather than fixtures.

## 3. Version namespaces

Four independent version numbers exist; they MUST NOT be conflated:

| Namespace | Lives in | Governs |
|---|---|---|
| **manifest `spec-version` epoch** | `milpa.kdl` (`MANIFEST_SPEC_VERSION`) | breaking semantic redefinitions of manifest syntax; absent ⇒ epoch 1 |
| **lockfile schema** | `milpa.lock` (`LOCKFILE_SCHEMA_VERSION`) | the lockfile wire format |
| **registry index schema** | `index.kdl` (`TIANGUIS_INDEX_SCHEMA_VERSION`) | the tianguis index wire format |
| **conformance spec version** | `conformance/spec-v<N>/` | this specification as a whole |

This README and the conformance suite directory together pin the
**conformance spec version** (currently `1`, surfaced as `spec-v1/`).

## 4. Amendment and governance

The spec outlives any implementation, so changes are deliberate.

**Change taxonomy.** A change is one of:
- **Additive** — a new dep kind, manifest node, error code, or behavior that
  does not alter the meaning of any existing conformant input. Additive
  changes do NOT bump the conformance spec version; forward-compatibility
  (P3 layering) absorbs them. New fixtures are added under the current
  `spec-v<N>/`.
- **Breaking** — any change that alters the observable result of an input
  that was already conformant (a redefinition of existing syntax, a changed
  emission, a removed/renamed code). Breaking changes REQUIRE a new
  conformance spec version `spec-v<N+1>/` and, where the manifest grammar is
  redefined, a `MANIFEST_SPEC_VERSION` bump.

**Process.** A change is proposed as an RFC (`../rfc-*.md`), lands as a
normative diff to the relevant document(s) here, and is accompanied by
fixtures that exercise it. The error catalog is edited only in
`milpa/error_codes/` and `errors.md` is regenerated (a round-trip test pins
the bijection).

**Arbiter rule.** If a prose `> NORMATIVE:` clause and a conformance fixture
disagree, that is a spec defect: open an RFC/issue and reconcile them. Do not
silently follow one over the other.

**Freeze policy.** Within spec v1, no new `> NORMATIVE:` requirement is added
that would invalidate a currently-conformant implementation. Tightening
ambiguity (making an already-implied requirement explicit) is permitted and
preferred; changing a requirement is a v2 matter.

## 5. Reference implementation

The Python package in `../../milpa/` is the current reference
implementation and the oracle that generates the conformance fixtures. It is
not normative — this specification is. Where the reference impl lags the
spec, the gap is tracked as an issue and noted inline (`> NOTE:`). The
multi-impl lifecycle (Python design vehicle → Rust reference → clean rewrites)
is described in `../rfc-multi-impl-strategy.md`.
