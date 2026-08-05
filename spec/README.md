# The milpa specification — pre-v1 working draft

This directory is the **normative specification** of milpa: the language-
agnostic contract that any conformant implementation (the Python and Rust
reference impls, a future Nim dogfood impl, or a third-party port) must
satisfy. The spec is the durable artifact; an implementation is correct
insofar as it conforms to this spec and passes the conformance suite. See
`../rfc-multi-impl-strategy.md` for why the spec is factored out from any one
implementation.

> **Status: pre-v1, not frozen.** The spec is still being written toward a v1
> that no implementation fully covers yet. Until stabilization there are **no
> external consumers**, so the working surface under `conformance/spec-v1/` is
> mutated **in place** — a breaking change edits the normative docs and
> regenerates the affected fixtures directly, without an epoch bump. The
> additive-vs-breaking governance in §4 is what the spec commits to **once v1
> is stamped**; it describes the future contract, not a freeze that is already
> in force. v1 is stamped when a reference impl fully implements the spec and
> the surface has settled.

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
| [`errors.md`](errors.md) | the error catalog — every coded, user-facing error. **Spec-owned and hand-maintained**; each implementation bijection-checks its own slug catalog against this file |

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

The spec outlives any implementation, so changes are deliberate. **This
section is the governance that takes effect at v1 stabilization.** Pre-v1
(the current phase, per the status note above) there are no external
consumers and the `spec-v1/` surface is mutated in place: a breaking change
edits the normative docs and regenerates the affected fixtures in the same
change, with no new `spec-v<N+1>/` directory and no epoch bump. The taxonomy
below defines how that discipline tightens the moment v1 is stamped.

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
fixtures that exercise it. The error catalog `errors.md` is spec-owned and
edited directly; each implementation bijection-checks its own slug catalog
against it (a round-trip test pins the bijection).

**Arbiter rule.** If a prose `> NORMATIVE:` clause and a conformance fixture
disagree, that is a spec defect: open an RFC/issue and reconcile them. Do not
silently follow one over the other.

**Freeze policy.** Once v1 is stamped, within spec v1 no new `> NORMATIVE:` requirement is added
that would invalidate a currently-conformant implementation. Tightening
ambiguity (making an already-implied requirement explicit) is permitted and
preferred; changing a requirement is a v2 matter.

## 5. Reference implementation

Two reference implementations co-exist: the Python package in
`../../impls/python/milpa/` and the Rust workspace in `../../impls/rust/`.
Neither is normative — this specification is. The Python impl is currently
the design vehicle and the oracle that generates the conformance fixtures
(`impls/python/tools/regen_corpus.py`); it is **slated for a clean rewrite
once the spec has solidified**, so its internal structure is deliberately
treated as provisional. Where an impl lags the spec, the gap is tracked as
an issue and noted inline (`> NOTE:`). The multi-impl lifecycle (Python
design vehicle → Rust reference → clean rewrites → future Nim dogfood) is
described in `../rfc-multi-impl-strategy.md`.
