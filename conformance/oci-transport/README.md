# `conformance/oci-transport/` — OCI canned-transport contract fixtures

This directory holds **unit-tier** cross-impl contract fixtures for milpa's
native OCI pull (RFC `docs/rfc-native-oci-fetch.md`). It is **not** part of the
black-box conformance corpus.

## Why this is outside `spec-v<N>/`

The spec-conformance corpus (`conformance/spec-v1/`) is black-box: it drives a
whole `milpa` invocation and compares `expected/` outputs. Under
`MILPA_MOCKED_FETCHES` the OCI fetcher is replaced **wholesale** (keyed by
`oci_key(registry, repository, digest)`, staging a pre-extracted tree), so the
token → manifest → blob transport state machine — auth challenges, phase
errors, digest verification, redirect Authorization-stripping — is
**structurally invisible** to the corpus and to the differential harness. Both
conformance runners scan only `spec-v<N>/fixture-*`; this directory is ignored
by them by construction.

That coverage gap is a **known, accepted limitation** (RFC §3.7), not an
oversight. To recover cross-impl parity at the unit tier, the Python and Rust
OCI-client unit tests each **replay the same transcripts from this directory**
through their injected transport. Same bytes on both sides ⇒ same behavior by
construction. This is the *only* cross-impl guarantee the transport gets;
transport phases are otherwise impl-local unit tests.

The single-threaded replay here **cannot** exercise the concurrent token-cache
behavior (stampede coalescing, expiry/401-refresh, RFC §3.6) — those are
impl-local concurrency unit tests, deliberately out of scope for this fixture
family.

## Format

Each fixture is a `*.json` file validating against
[`schema.json`](schema.json): an object with a `description` and an ordered
`exchanges` list of request/response pairs. The fake transport answers each
request the client issues, in order, matching on `(method, url)`; a `3xx` +
`Location` response is followed by the impl's **real** redirect handler, which
issues the next request in the list. `expect_request_headers` asserts on the
request the client sends — mapping a header to its expected value, or to `null`
to assert it is **absent** (how the redirect-strip test proves the bearer token
is not forwarded cross-origin).

Response bodies are inline UTF-8 (`body`, for token/manifest JSON), base64
(`body_base64`, for binary blobs), or a sibling file reference (`body_file`,
for large blobs). At most one may be present.

Authored once, read by both impls: the schema is fixed in slice **S0** so that
S5 (Python, first) and S7 (Rust) author against one shape rather than
reverse-engineering an ad hoc one.
