# milpa registry protocol (S14)

Normative spec for how milpa **reads** the tianguis registry `index.kdl`
to resolve named deps. This is the **read contract only** — how a
`(name, constraint)` pair maps to candidate `(version, provenance)` records.
Index-deps resolution policy (the solver's strategy over those candidates) is
deferred to #98/#86 and is explicitly out of scope here.

Every parser that claims milpa conformance MUST implement the rules marked
`> NORMATIVE:`. Items marked `> NOTE:` describe the reference Python
implementation; conformant alternatives MAY differ in those details.

Related specs:

- `spec/errors.md` — every `TNG-*` error code this protocol can produce
- `spec/manifest-grammar.md` — P3 provenance-descriptor model (§4), which
  this spec cross-references normatively
- `spec/lockfile-schema.md` (S5) — lockfile representation of provenance
- `spec/resolver-semantics.md` (S6) — how candidate lists feed the solver
- `spec/cli-contract.md` (S15) — environment variables including
  `MILPA_INDEX_URL`

---

## Normative surface

A conformant implementation of this spec MUST:

1. Parse `index.kdl` as a valid KDL 2.0 document.
2. Reject (`TNG-SCHEMA-UNKNOWN`) any document whose declared `schema_version`
   integer exceeds `TIANGUIS_INDEX_SCHEMA_VERSION` (currently `1`).
3. Treat provenance records inside index entries as **strict subsets of the
   manifest provenance-descriptor grammar** (§4 of `manifest-grammar.md`); MUST
   NOT define a second, parallel grammar.
4. Validate all security-critical fields at parse time, before any string flows
   into subprocess argv or the filesystem (§4 of this document).
5. Implement the named-dep lookup contract: name → candidate list, ordered
   descending by semver, constraint-filtered (§5).
6. Treat unknown version-node children (including `rekor`, `attestation`,
   `signed_by`, `published_at`, `upstream`, `namespace`) as forward-compat
   metadata: parse MUST succeed, fields MUST be ignored.
7. Treat unknown provenance `kind` values as forward-compat: skip the
   provenance record rather than failing, provided at least one known-kind
   provenance remains on the version.
8. Raise `TNG-NO-IDENTITY` for any index entry whose `content_hash` is absent
   or empty; MUST NOT attempt to fetch a version without a verifiable identity
   (§3.2).
9. Use `DEFAULT_INDEX_URL` when no override is configured; honor
   `MILPA_INDEX_URL` when set (§1).
10. Implement the four-state cache freshness model: fresh-serve / stale-refetch
    / offline-fallback / no-cache-error (§6).
11. Verify the whole-index Sigstore attestation bundle before trusting any
    claim in the index; honour the `index-trust` trust-policy from the
    manifest and `MILPA_INDEX_TRUST` env var (§3.4).

---

## 1  Document structure

An `index.kdl` document is a flat sequence of top-level nodes. The parser
recognises two kinds of top-level node:

- `schema_version <int>` — optional schema-version declaration (§2).
- `package "<name>" { … }` — a named-package entry (§3).

All other top-level nodes MUST be silently skipped (forward-compat).

> NORMATIVE: The default index URL is
> `https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl`.
> This is the `DEFAULT_INDEX_URL` constant in the reference implementation.
> Conformant implementations MUST use this URL when no override is configured.

> NORMATIVE: The environment variable `MILPA_INDEX_URL`, when set to a
> non-empty string, MUST override the default index URL for all index-fetching
> operations in that invocation. This allows air-gapped, mirrored, or
> enterprise deployments to substitute a private index. See
> `spec/cli-contract.md` (S15) §8 for the full environment variable
> table.

> NOTE: The live index is a flat KDL file of `package` nodes with no nesting
> beyond the package/version/provenance hierarchy.

---

## 2  Schema-version negotiation

> NORMATIVE: The `index.kdl` document MAY carry a top-level
> `schema_version <int>` node. When absent the document is treated as version
> 1 (legacy/minimal indexes predate the field).

> NORMATIVE: A conformant implementation MUST define a constant
> `TIANGUIS_INDEX_SCHEMA_VERSION` (spec v1.0 value: `1`). When the document
> declares a `schema_version` integer **strictly greater than** this constant,
> the implementation MUST raise `TNG-SCHEMA-UNKNOWN` and MUST NOT attempt to
> parse the rest of the document. The error message MUST name both the declared
> version and the maximum understood version and MUST direct the user to upgrade
> milpa.

> NORMATIVE: When the declared `schema_version` is **less than or equal to**
> `TIANGUIS_INDEX_SCHEMA_VERSION`, the document MUST be parsed
> forward-compatibly — unknown nodes and fields are silently skipped; no error
> is raised for unrecognised top-level nodes.

> NOTE: The `schema_version` value is parsed as an integer. The reference
> implementation (`_scalar_int`) handles the KDL-library quirk of emitting bare
> integers as float: a whole-number float is coerced to `int`; a fractional
> float returns `None` (treated as absent). A boolean is explicitly rejected
> (bool is an int subclass in Python).

---

## 3  Package entry structure

A package entry has the KDL form:

```kdl
package "<name>" {
    namespace "<org-or-user>"
    upstream (url)"<canonical-URL>"
    version "<semver>" {
        content_hash "<algorithm>:<hex>"
        provenance {
            kind "<git|oci|…>"
            // kind-specific fields (§3.2)
        }
        [provenance { … }]           // additional provenances, preference-ordered
        attestation "<label>"        // e.g. "author-signed" or "milpa-vendored"
        signed_by "<identity>"
        published_at "<ISO-8601>"
        rekor {                      // durable Rekor reference; optional
            uuid "<hex>"
            log_index "<decimal-string>"
            integrated_time "<decimal-string>"
        }
    }
    [version "…" { … }]             // additional versions
}
```

### 3.1  Package-level fields

**`name`** (positional arg on the `package` node, required) — the bare package
name, as a KDL string.

> NORMATIVE: A `package` node whose first positional argument is not a string
> MUST emit a `UserWarning` and be silently skipped. It MUST NOT raise a hard
> error — forward-compat (a malformed double entry does not block others).

> NORMATIVE: A `package` name that contains path-traversal characters (`..`,
> `/`, `\`, or that is an absolute path) MUST raise `TNG-UNSAFE-NAME` at parse
> time. This check applies before the entry is stored or any fetch attempted,
> because names flow directly into `_deps/<name>/` on the filesystem.

**`namespace`** (child node, optional) — the registry namespace (typically a
GitHub org or user). Together with `name` it forms the unique `(namespace,
name)` identity key.

> NOTE: Two packages MAY share a bare `name` under different namespaces (e.g.
> a library that has been forked). The internal store is keyed on
> `(namespace, name)`; a bare-name lookup that matches multiple namespaces
> returns `AmbiguousName` rather than silently picking one.

**`upstream`** (child node, optional) — the canonical source URL for the
package. Accepted in plain-string and `(url)`-annotated form. Informational;
not used during fetch.

### 3.2  Version entry structure

Each `version "<semver>" { … }` child of a `package` node records one
published version.

> NORMATIVE: A `version` node whose first positional argument is not a string
> MUST be silently skipped.

> NORMATIVE: If a `package` node declares the same version string more than
> once, the first occurrence MUST be kept and subsequent duplicates MUST emit a
> `UserWarning` and be skipped. Duplicate versions MUST NOT raise a hard error.

**`content_hash`** (child node, string, **required and non-empty**) — the
content identity of the source tree, as an `<algorithm>:<hex>` identity string.
The canonical scheme is the one `spec/identity.md` (S12) defines: under epoch 2
that is `dag-sha256:<64-hex>` (the canonical content Merkle DAG, `identity.md`
§1.8 / §2.1). A conformant reader MUST accept the `dag-sha256:` scheme here.
Validation is **epoch-gated** — it tracks `spec/identity.md`'s current canonical
scheme — and MUST NOT be a fixed `sha256:`-only regex. This is the value milpa
recomputes after fetching to enforce Invariant 1 (identity gate). See
`spec/identity.md` (S12) for the canonical byte algorithm.

> NORMATIVE: An index entry whose `content_hash` is absent or empty string
> MUST raise `TNG-NO-IDENTITY` on the resolution read path. Identity is
> non-negotiable in milpa: a fetch without a content_hash to verify against
> provides no supply-chain integrity guarantee. The resolver MUST NOT
> attempt to fetch a version whose `content_hash` is absent or empty.

> NOTE: Legacy index entries from before the identity mandate may carry an
> empty `content_hash`. The reference implementation stores it as `""` after
> parsing but raises `TNG-NO-IDENTITY` before any fetch is attempted
> (`_resolve_named_version` in `tianguis_client.py`). There is no "identity
> not recorded" permissive path on the resolution read path.

**`provenance`** (child node, zero or more) — a provenance descriptor (§3.3)
describing how to fetch this version's source tree. Multiple `provenance` nodes
on the same version are **preference-ordered** by index-document order: the
first is canonical, the rest are mirrors. A fetcher MUST attempt them in order.

> NORMATIVE: Provenance records inside an index entry are a **strict subset of
> the manifest provenance-descriptor grammar** defined in
> `spec/manifest-grammar.md` §4. The meta-grammar, kind-set, and field
> shapes are the same. Index entries add only index-specific metadata
> (`content_hash`, attestation fields, Rekor block) alongside the provenance;
> they do not introduce a new or parallel provenance grammar. Implementations
> MUST NOT write a second provenance parser for the index — one parser, shared.

**`attestation`** (child node, string, optional) — a label indicating the trust
path: `"author-signed"` (package author signed the OCI artifact via cosign) or
`"milpa-vendored"` (tianguis vendor-en-absentia bot signed on the author's
behalf). MAY be absent on legacy entries.

> NOTE: milpa's reader treats `attestation` as forward-compat metadata: it is
> parsed and then ignored. The trust value is displayed by tianguis.dev; milpa
> does not enforce it during resolution.

**`signed_by`** (child node, string, optional) — the identity (GitHub Actions
workflow URL or bot identifier) that produced the attestation. Informational;
not enforced by milpa.

**`published_at`** (child node, string, optional) — ISO 8601 timestamp of when
the version was published. Informational.

**`rekor`** (child node, optional block) — a durable Rekor transparency-log
reference captured at publish time. Fields:

| Child | Type | Meaning |
|---|---|---|
| `uuid` | string | Rekor entry UUID (80-char hex in the reference index) |
| `log_index` | string | Rekor log index, as a decimal string |
| `integrated_time` | string | Unix timestamp (seconds) when the entry was integrated, as a decimal string |

> NORMATIVE: A conformant milpa reader MUST tolerate a `rekor` block on a
> version node. The block MUST NOT cause a parse error. milpa does not
> validate or enforce Rekor entries during resolution; the block is
> forward-compat metadata for the tianguis.dev site and auditing tooling.
> `IndexVersion` carries no `rekor` field; Rekor data is inert to the
> resolver.

> NOTE: The test fixture `REKOR_INDEX` in `tests/test_tianguis_client.py`
> (test `test_rekor_block_is_tolerated_and_ignored`) is the regression pin
> for this forward-compat requirement. It verifies that `IndexVersion` has no
> `rekor` attribute after parsing.

**`dep_decl`** (child node, string, optional) — a `sha256:<64-hex>` hash
pointer to the DepDecl artifact for this version. The DepDecl artifact encodes
the package's dependency declarations as a content-addressed blob, enabling
verifiable dependency graphs without re-fetching source (see
`rfc-content-addressed-metadata.md` §3 and `spec/dep-decl.md`).

> NORMATIVE: When present, `dep_decl` MUST be a string in exactly
> `sha256:[0-9a-f]{64}` form (the `sha256:` prefix followed by exactly 64
> lowercase hexadecimal characters). A conformant milpa reader validates this
> format at index-parse time and raises `TNG-BAD-DEP-DECL` for any value that
> does not match — including path-traversal payloads such as
> `sha256:../../etc/passwd`, wrong-length hex, uppercase hex, or a different
> algorithm prefix. Validation MUST occur at the parse boundary, before the
> value can reach any downstream consumer (filesystem path, URL path segment,
> or hash-verify site). A conformant reader surfaces the validated value on the
> in-memory `IndexVersion` type. It does NOT verify the hash, fetch the
> artifact, or check schema-version agreement during index parsing — those are
> resolver operations performed only when the version is selected (S3b and
> later slices of the DepDecl RFC). When absent, `dep_decl` is `None` on the
> in-memory type (forward-compat: old index entries omit it). A malformed
> non-string value (e.g. an integer or boolean) MUST be treated with the same
> robustness posture the parser already applies to other optional string
> children (`attestation`, `signed_by`): silently skip / surface as absent.
> Conformance gate: `conformance/spec-v1/fixture-149-tng-bad-dep-decl`.

**`dep_decl_schema_version`** (child node, integer, optional) — the DepDecl
schema version integer that produced the `dep_decl` hash (v0 = `{ requires,
src_dir }`; see `rfc-content-addressed-metadata.md §3.2.1`). When present,
must be a non-negative integer. When absent, `None` on the in-memory type.

> NORMATIVE: These two fields are **forward-compat optional** under the current
> index `schema_version`. Their addition does NOT bump the index `schema_version`
> (that bump is deferred per `rfc-content-addressed-metadata.md §3.9 F3`). An
> index entry that carries `dep_decl` and `dep_decl_schema_version` is valid
> under the current schema version; a reader that does not yet use these fields
> MUST silently skip them without error. An index entry that omits them is also
> valid. Conformance gate: `conformance/spec-v1/fixture-129-index-dep-decl-pointer`
> exercises a version node with both fields set; both impls must parse it and
> produce the same resolution output as without the fields.

### 3.3  Provenance record shapes (index form)

Index provenance records use the same kind-set and field shapes as the manifest
grammar's §4.2, with the additional acceptance of `(url)`-annotated URL values
(the milpa KDL url convention — see `manifest-grammar.md` §2).

#### `git` provenance

```kdl
provenance {
    kind "git"
    url (url)"<https-or-http-or-ssh-or-git URL>"
    ref "<git-ref>"
    commit_sha "<40-hex>"    // optional — immutable pin
}
```

Fields: `url` (required), `ref` (required), `commit_sha` (optional).

> NORMATIVE: `url` MUST be accepted in both plain-string and `(url)`-annotated
> form (the live tianguis index uses `(url)` annotation). The value is
> normalized to a plain URL string before use.

> NORMATIVE: When `commit_sha` is present it MUST be a 40-character lowercase
> hexadecimal string (`[0-9a-f]{40}`). A non-conforming value MUST raise
> `TNG-BAD-COMMIT-SHA` at parse time. When absent, the fetcher falls back to
> the tip of `ref`.

> NORMATIVE: `url` MUST NOT begin with `-`. A leading dash MUST raise
> `TNG-UNSAFE-URL` at parse time (flag-injection prevention).

> NORMATIVE: `ref` MUST NOT begin with `-`. A leading dash MUST raise
> `TNG-UNSAFE-REF` at parse time (flag-injection prevention).

#### `oci` provenance

```kdl
provenance {
    kind "oci"
    registry "<hostname>"
    repository "<org/name>"
    digest "sha256:<64-hex>"
}
```

Fields: `registry` (required), `repository` (required), `digest` (required).

> NORMATIVE: `digest` MUST be in `sha256:<64 lowercase hex>` form. Any other
> format MUST raise `TNG-BAD-OCI-DIGEST` at parse time.

> NORMATIVE: `registry` and `repository` MUST NOT begin with `-`. A leading
> dash on either field MUST raise `TNG-UNSAFE-OCI-FIELD` at parse time
> (flag-injection prevention; these values flow into `oras` argv).

#### Unknown kinds

> NORMATIVE: A `provenance` node whose `kind` value is not `"git"` or `"oci"` MUST
> be silently skipped (forward-compat: a future transport the index records but this
> milpa cannot fetch is non-fatal provided other provenances on the same version
> remain fetchable).

### 3.4  Whole-index attestation gate (Layer 1)

Layer 1 verifies the Sigstore attestation over the complete `index.kdl`
document before any claim in the index is trusted. This section is orthogonal
to the per-entry attestation fields in §3.2 (`attestation`, `signed_by`,
`rekor`): those fields' "parsed and ignored" normative clauses remain in full
force under Layer 1. Per-entry Layer 2 verification is a future extension that
inverts those clauses; it is explicitly out of scope here.

#### 3.4.1  When the gate fires

> NORMATIVE: The gate MUST fire on every index load — fresh cache read
> (State 1), stale-refetch (State 2), and offline-fallback (State 3, as
> defined in §6) — immediately after the index bytes are obtained and BEFORE
> the bytes are decoded or parsed. No index claim (schema_version, package
> entry, version, provenance) may be used before the gate passes or produces
> a `warn`-policy warning.

> NORMATIVE: The gate MUST NOT fire on frozen-path invocations (`fetch
> --frozen`, or any path that reconstructs the dep graph from `milpa.lock`
> without loading the index). When `--no-index` is active, no index is loaded
> and the gate is not invoked; `MILPA_INDEX_TRUST` and
> `--require-attested-index` are effectively no-ops in that case.

> NORMATIVE: `milpa remove` and `milpa clean` do NOT load the index and MUST
> NOT invoke the gate. `milpa show` invokes the gate ONLY when it actually
> loads the index; a lockfile-only `show` (no index load needed) does NOT
> invoke the gate. `milpa verify` invokes the gate in crypto-only mode (steps
> 1–2 and 4–7, skipping step 3 (freshness), §3.4.4) but MUST NOT assert the
> wall-clock freshness bound, preserving offline audit capability.

#### 3.4.2  Bundle acquisition and URL derivation

> NORMATIVE: The bundle URL is derived from the index URL by: strip any query
> string and fragment from the index URL; append `.bundle` to the URL PATH
> component; then reattach the original query string and fragment. Naive string
> suffixing (e.g. appending `.bundle` to the full URL string including any
> `?ref=main` query) is INCORRECT and MUST NOT be implemented.

For the default index URL the derived bundle URL is:

```
https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl.bundle
```

> NORMATIVE: `MILPA_INDEX_BUNDLE_URL` (§8 of `spec/cli-contract.md`) overrides
> the derived URL entirely when set. This is required for deployments where the
> bundle is served from a separate host or where suffix-derivation is not viable.

> NORMATIVE: The bundle is cached as a sidecar alongside the index:
> `<cache-key>.index.kdl.bundle`. The bundle MUST use a SEPARATE injectable
> transport from the index transport, so that per-transport mock state and
> failure injection can be applied independently.

> NORMATIVE (crash recovery): On a pure cache read (States 1 or 3) that finds
> the bundle sidecar missing or whose digest does not match the index (e.g. from
> an interrupted write), the implementation MUST silently delete both sidecars and
> perform ONE recovery re-fetch. If the network-fetched (index, bundle) pair ALSO
> fails verification on the recovery re-fetch, the implementation MUST hard-fail
> regardless of policy. A second consecutive mismatch indicates an active adversary
> signal, not an interrupted write; the implementation MUST NOT loop.

#### 3.4.3  Bundle format

The Sigstore bundle is a JSON document carrying:
- `verificationMaterial.x509CertificateChain` — the signing certificate chain.
- `verificationMaterial.tlogEntries[]` — one or more Rekor transparency-log
  entries, each carrying an inclusion proof and a signed entry timestamp (SET).
- `dsseEnvelope` — a DSSE envelope whose JSON payload is an in-toto attestation
  statement. The statement's subject is the sha256 digest of the signed file.

> NORMATIVE: The signature covers the DSSE envelope payload (an in-toto
> statement), NOT the raw index bytes directly. A conformant implementation MUST
> verify by extracting `statement.subject[0].digest.sha256` from the DSSE payload
> and asserting it equals `sha256(index_bytes)`.

#### 3.4.4  Verification steps

A conformant implementation MUST execute the following seven steps in order:

**Step 1 — Parse the bundle JSON.** If the bundle is not valid JSON or does not
conform to the Sigstore bundle schema, MUST raise `TNG-INDEX-BUNDLE-MALFORMED`.
This is a pre-cryptographic failure — no signature check has been attempted.

**Step 2 — Extract `integratedTime`.** Extract the Rekor SET `integratedTime`
from `verificationMaterial.tlogEntries[0].integratedTime`. If the field is
absent or non-integer, MUST raise `TNG-INDEX-BUNDLE-MALFORMED`. This timestamp
is required for both the freshness check (step 3) and cert-at-SET-time
validation (step 4).

**Step 3 — Freshness assertion (network-fetch paths only).** On a network-fetch
path (State 2 or recovery re-fetch), MUST assert
`now - SET.integratedTime < MILPA_INDEX_MAX_AGE` (default 7 days; configurable
via `MILPA_INDEX_MAX_AGE` in `spec/cli-contract.md §8`). `integratedTime` is
embedded in the bundle; no live Rekor network query is needed. On exceed, MUST
raise `TNG-INDEX-BUNDLE-STALE`. Freshness is placed here — after integratedTime
extraction (step 2) and before cryptographic verification (steps 4–7) — because
it needs only the parsed timestamp; failing fast on staleness is fail-closed
regardless of which crypto failures may also be present.

> NORMATIVE: On a PURE CACHE READ (States 1 and 3), step 3 (freshness) MUST
> NOT be asserted. Steps 1–2 and 4–7 MUST still be executed. Rationale: the
> rollback attack is a network-delivery attack; defending at the fetch boundary
> fully closes it. Re-asserting wall-clock freshness on cache reads would break
> air-gapped deployments without adding security.

**Step 4 — Validate the certificate chain against the embedded Fulcio root.**
Certificate validity MUST be checked at the Rekor SET `integratedTime`, NOT
current wall-clock time. Fulcio issues short-lived (~10-minute) certificates;
checking `cert.NotAfter >= now` is INCORRECT and MUST NOT be implemented. A
certificate now-expired by wall-clock but valid at its `integratedTime` MUST
verify successfully. `TNG-INDEX-SIGNATURE-INVALID` is raised ONLY when the
certificate was expired AT its own `integratedTime`.

**Step 5 — Confirm the signer identity.** The certificate's SubjectAltName MUST
match the expected signer identity. The pinned default identity is:

- Issuer: `https://token.actions.githubusercontent.com`
- SAN: `https://github.com/coreyleavitt/tianguis/.github/workflows/reindex.yaml@refs/heads/main`

This identity is overridable via `MILPA_INDEX_TRUST_SIGNER` or the
`index-trust-signer` manifest node. A SAN mismatch MUST raise
`TNG-INDEX-SIGNER-MISMATCH`. When `MILPA_INDEX_URL` is non-default and no
signer override is configured, `warn` policy proceeds with a
`TNG-INDEX-SIGNER-MISMATCH` warning; `strict` policy raises the error.

**Step 6 — Verify the DSSE envelope and subject digest.** The envelope signature
MUST be verified against the certificate's public key. After successful signature
verification, the in-toto statement's subject digest
(`statement.subject[0].digest.sha256`) MUST equal `sha256(index_bytes)`. A
digest mismatch MUST raise `TNG-INDEX-DIGEST-MISMATCH`.

> NORMATIVE: A payload whose `subject` list is absent or empty, or whose
> `subject[0].digest.sha256` field is absent or unextractable (including
> non-parseable payload JSON), MUST raise `TNG-INDEX-DIGEST-MISMATCH`. The
> subject digest is the sole binding between the attestation and the index
> bytes; absence of a subject claim means the attestation makes no assertion
> about the index content. Treating absence as "OK" would allow any DSSE
> bundle signed by the trusted identity (e.g. a different predicate from the
> same CI workflow) to bind to arbitrary tampered index bytes.

> NOTE: The slug `TNG-INDEX-DIGEST-MISMATCH` uses "digest", not "identity".
> The term "identity" is reserved in milpa for the `content_hash` of a source
> tree (see `spec/identity.md`); using it for a bundle-subject mismatch would
> create a false collision with milpa's identity model.

> NOTE: Subject-digest comparison is performed on the verified payload returned
> by the DSSE verification step, NOT by inspecting exception message text. A
> conformant implementation MUST NOT infer `TNG-INDEX-DIGEST-MISMATCH` from
> error-string patterns — the digest comparison is a deterministic check on
> the signed payload bytes.

**Step 7 — Verify the Rekor inclusion proof** against the embedded Rekor public
key. Failure MUST raise `TNG-INDEX-SIGNATURE-INVALID`.

> NORMATIVE (failure–slug mapping): The mapping from verification failure to
> error slug is pinned as follows, independent of the cryptographic library's
> exception hierarchy:
>
> - `TNG-INDEX-BUNDLE-MALFORMED` — steps 1–2 (pre-cryptographic parse failure).
> - `TNG-INDEX-BUNDLE-STALE` — step 3 (freshness exceeded on network-fetch path).
> - `TNG-INDEX-SIGNATURE-INVALID` — steps 4 and 7 (bad cert chain, cert expired
>   at `integratedTime`, or invalid Rekor inclusion proof). Also the safe default
>   for any cryptographic failure not positively identified as a distinct variant.
> - `TNG-INDEX-SIGNER-MISMATCH` — step 5 (SubjectAltName ≠ expected signer).
>   The variant distinction MUST NOT be inferred from exception message text; it
>   MUST come from the verification library's typed error model or an equivalent
>   structural mechanism (e.g., recording whether the identity-policy check itself
>   failed).
> - `TNG-INDEX-DIGEST-MISMATCH` — step 6 (DSSE subject digest ≠ sha256(index_bytes)).
>   Implementations MUST detect this from the verified payload, not from exception
>   message text.

> NORMATIVE (first-failure precedence): When multiple failure conditions coexist,
> the reported variant MUST be the FIRST failure encountered in the §3.4.4
> evaluation order (steps 1–7). In particular: a bundle that is both stale (step 3)
> and has an invalid signature (steps 4+) MUST report `TNG-INDEX-BUNDLE-STALE`,
> not `TNG-INDEX-SIGNATURE-INVALID`.

> NORMATIVE: Verification MUST NOT use hand-rolled cryptographic code.
> Implementations MUST delegate to `sigstore-python` (Python) or `sigstore-rs`
> (Rust). Verification MUST work without live Rekor network access — the bundle
> carries all material needed for offline verification (inclusion proof + SET).

> NORMATIVE (TOCTOU): The index bytes MUST be read ONCE. The same in-memory
> bytes object MUST be passed to both bundle verification and the KDL parser.
> There MUST NOT be a second disk read between verification and parsing.

> NOTE: The six error slugs referenced above — `TNG-INDEX-BUNDLE-MISSING`,
> `TNG-INDEX-BUNDLE-MALFORMED`, `TNG-INDEX-SIGNATURE-INVALID`,
> `TNG-INDEX-DIGEST-MISMATCH`, `TNG-INDEX-SIGNER-MISMATCH`,
> `TNG-INDEX-BUNDLE-STALE` — are defined in `spec/errors.md` and first raised
> in S5 (Python) and S6 (Rust) of the registry-trust-federation RFC.

#### 3.4.5  Trust policy

> NORMATIVE: The `index-trust` field in `milpa.kdl` and the `MILPA_INDEX_TRUST`
> environment variable (see `spec/cli-contract.md §8`) govern behaviour on
> verification failure:
>
> | Policy value | Behaviour on any verification failure |
> |---|---|
> | `warn` (default) | Resolve proceeds; MUST emit exactly one warning to stderr per unique index URL per invocation, including the applicable `TNG-INDEX-*` slug as the machine-readable signal. Exit code remains 0. |
> | `strict` | Hard fail; MUST raise the appropriate `TNG-INDEX-*` error and exit 1. |
> | `off` | Gate is skipped entirely; no bundle is fetched or verified. |

> NORMATIVE: Under `warn`, the warning MUST include the applicable `TNG-INDEX-*`
> slug. CI systems MAY match the `TNG-INDEX-` prefix to detect index-trust
> failures non-intrusively. Exit code MUST remain 0 under `warn`. The dedup key
> for warning emission is the index URL; at most one warning is emitted per unique
> index URL per invocation.

> NORMATIVE: Under `warn`, a bundle fetch that returns 404 MAY cache the index
> with a `.kdl.no-bundle` degraded-marker sidecar so the normal TTL governs
> re-fetch cadence. The degraded marker applies only to a definitive 404/not-found
> response; transient transport failures (e.g. HTTP 500, connection reset) MUST NOT
> write the marker — the next fresh-cache read MUST go through crash-recovery refetch
> instead of settling into degraded mode indefinitely. Under `strict`, a bundle 404
> MUST raise `TNG-INDEX-BUNDLE-MISSING` and MUST NOT write partial cache state.

> NORMATIVE (effective policy): The effective policy is computed as follows:
>
> 1. If the manifest declares `index-trust "off"`, the effective policy is `off`
>    unconditionally. No environment variable or CLI flag can override a manifest
>    `off`. `off` is an auditable opt-out that MUST ONLY be declared in `milpa.kdl`
>    (committed to version control). `MILPA_INDEX_TRUST=off` in the environment is
>    a no-op floor — it CANNOT weaken a manifest `warn` or `strict` policy.
> 2. Otherwise: `base = max(manifest_policy or "warn", env_policy)` over
>    `{warn, strict}`. `MILPA_INDEX_TRUST=off` in the environment is ignored in
>    this step.
> 3. If `--require-attested-index` is given: effective policy is `strict` (unless
>    rule 1 applies; the flag MUST NOT set or clear `off`).

#### 3.4.6  Per-URL signer resolution

> NORMATIVE: The signer identity and trust-bundle overrides are resolved PER index
> URL (per cache key), not globally. The pinned default signer identity (§3.4.4
> step 5) applies only to the default tianguis index URL. A user running a custom
> `MILPA_INDEX_URL` MUST configure the expected signer via `MILPA_INDEX_TRUST_SIGNER`
> or the `index-trust-signer` manifest node, or accept the `TNG-INDEX-SIGNER-MISMATCH`
> warning/error depending on policy.

> NORMATIVE: The `MILPA_INDEX_TRUST_SIGNER` variable overrides the signer IDENTITY
> only (a SubjectAltName string). It MUST NOT accept `file://` trust-bundle paths.
> The `MILPA_INDEX_TRUST_BUNDLE` variable overrides the trust ROOT (Fulcio CA +
> Rekor public key) and is orthogonal to signer identity — changing one does not
> imply the other. Both are defined in `spec/cli-contract.md §8`.

#### 3.4.7  Workspace requirements

> NORMATIVE (workspace policy merge): In a workspace invocation, the effective
> `index-trust` policy is the MAX over the root manifest's policy and all member
> manifests' policies (`strict > warn > off`), computed BEFORE the index is first
> loaded. A workspace where the root declares `warn` and any member declares `strict`
> MUST resolve under `strict`.
>
> NOTE (root contribution): the workspace-root manifest grammar carries only the
> `workspace { member … }` block and cannot declare `index-trust`; the root therefore
> always contributes the default (`warn`) to the merge. A consequence of the MAX merge
> is that a workspace has no manifest-level path to an effective `off` — even when
> every member declares `off`, the merged policy is `warn`. (Whether the workspace
> root block should be allowed to declare `index-trust` is an open design question,
> deliberately not resolved here.)

> NORMATIVE (conflicting-signers validation error): If two or more workspace members
> declare DIFFERENT signer identities (via `index-trust-signer` in `milpa.kdl`) or
> different trust-bundle overrides (via `index-trust-bundle`) for the SAME index URL,
> the implementation MUST raise a hard validation error BEFORE any index fetch. This
> check fires at workspace-load time. The workspace-conflicting-signers validation
> error is distinct from the six `TNG-INDEX-*` error slugs; it is a manifest-
> consistency error that does not involve cryptographic verification.

> NOTE (per-URL scoping — current invariant): Per-URL signer grouping is currently
> vacuous because the index URL is process-global (`MILPA_INDEX_URL` or
> `DEFAULT_INDEX_URL`). The manifest grammar has no per-member `index-url` node, so
> exactly one index URL exists per invocation. The global comparison implemented by
> both impls is therefore equivalent to the normative per-URL requirement above: only
> one URL group ever exists. If per-member index URLs are introduced in a future
> slice, the conflicting-signers check MUST be updated to group members by their
> effective index URL before comparing signer identities.

---

## 4  Security validators

All validators are applied **at parse time**, at the trust boundary, before any
index-supplied string can reach subprocess argv or the filesystem. This is the
single source of truth for these checks; the rest of the system may trust that
strings passing these validators are safe.

| Code | What it checks | Rejects |
|---|---|---|
| `TNG-UNSAFE-NAME` | Package `name` (positional arg on `package` node) | Names containing `..`, `/`, `\`, or that are absolute paths — these would escape `_deps/<name>/` |
| `TNG-BAD-COMMIT-SHA` | `commit_sha` in a `git` provenance | Any value not matching `^[0-9a-f]{40}$` — removes flag-injection vector and abbreviated-SHA ambiguity |
| `TNG-UNSAFE-URL` | `url` in a `git` provenance | Any value beginning with `-` — prevents flag injection into git subprocess argv |
| `TNG-UNSAFE-REF` | `ref` in a `git` provenance | Any value beginning with `-` — prevents flag injection into git subprocess argv |
| `TNG-BAD-OCI-DIGEST` | `digest` in an `oci` provenance | Any value not matching `^sha256:[0-9a-f]{64}$` — enforces OCI digest format, prevents malformed reference string in oras argv |
| `TNG-UNSAFE-OCI-FIELD` | `registry` and `repository` in an `oci` provenance | Any value beginning with `-` — prevents flag injection into oras subprocess argv |
| `TNG-BAD-DEP-DECL` | `dep_decl` in a version node | Any value not matching `^sha256:[0-9a-f]{64}$` — prevents path-traversal (e.g. `sha256:../../etc/passwd`) reaching `FileDepDeclStore` (filesystem path) or `HttpDepDeclStore` (URL path segment) |
| `TNG-SCHEMA-UNKNOWN` | Top-level `schema_version` integer | Any value strictly greater than `TIANGUIS_INDEX_SCHEMA_VERSION` |

> NORMATIVE: All seven field-level validators (`TNG-UNSAFE-NAME`,
> `TNG-BAD-COMMIT-SHA`, `TNG-UNSAFE-URL`, `TNG-UNSAFE-REF`,
> `TNG-BAD-OCI-DIGEST`, `TNG-UNSAFE-OCI-FIELD`, `TNG-BAD-DEP-DECL`) MUST be
> applied during `parse_index`, not deferred to fetch time. An index entry that
> fails validation MUST raise the corresponding error immediately.

> NOTE: The `is_safe_name` predicate is also used by the resolver's
> URL-derived name check (`_name_from_url`) — one predicate, two call sites.
> This is the single source of truth for the safe-name rule.

---

## 5  Named-dep resolution read-contract

This section specifies the contract by which a `(name, constraint)` pair maps
to a candidate list via the index. This is the **index read contract** only;
how the solver selects among candidates is specified in
`spec/resolver-semantics.md` (S6).

### 5.1  Bare-name lookup

The index stores packages keyed on `(namespace, name)`. The resolution
entry point uses a bare-name lookup (no namespace qualifier) via
`Index.lookup_bare`.

> NORMATIVE: A bare-name lookup that matches **no** package MUST raise
> `TNG-NOT-FOUND`.

> NORMATIVE: A bare-name lookup that matches packages under **more than one**
> namespace MUST raise `TNG-AMBIGUOUS-NAME`. The error message MUST list all
> matching namespaces.

> NOTE: The `AmbiguousName` result type is distinct from the raised error: the
> registry primitive `Index.lookup_bare` returns `AmbiguousName` (a typed
> value, not an exception) so that a future multi-version provider
> (P3.2/#100) can enumerate all candidates during backtracking without a hard
> stop. The policy layer (`resolve_named`, `resolve_named_all`) converts
> `AmbiguousName` to `TNG-AMBIGUOUS-NAME`.

### 5.1a  Qualified lookup (S5b)

When a NamedDep carries a `namespace=` attribute (or uses the slash shorthand
`"<ns>/<name>"`), the resolver uses a **qualified lookup** instead of the
bare-name path.

> NORMATIVE (S5b): A qualified lookup MUST match the exact `(namespace, name)`
> pair. It MUST NOT raise `TNG-AMBIGUOUS-NAME` (the namespace is already
> specified). It MUST raise `TNG-NOT-FOUND` when no package with that exact
> `(namespace, name)` pair exists.

> NORMATIVE (S5b): The entry point for qualified lookup is
> `Index.lookup_qualified(namespace, name)`. Implementations MUST provide this
> primitive in addition to `Index.lookup_bare`.

### 5.2  Constraint filtering and ordering

Once a package is found, its versions are filtered by the constraint.

> NORMATIVE: Versions are ordered **descending by semver** (newest first)
> before constraint filtering. Parseable semver versions precede unparseable
> ones (in stable input order). This ordering MUST be applied at parse time
> (`parse_index`), not at lookup time.

> NORMATIVE: Versions whose version string is not a parseable semver triple
> (`X.Y.Z`) MUST be silently skipped during constraint filtering. They are
> stored in the index (in stable input order, after parseable versions) but
> are not candidates for constraint-based resolution.

> NORMATIVE: Given a constraint string, a conformant implementation MUST
> apply `VersionSet.from_constraint(constraint).contains(version)` to each
> candidate. Versions that do not satisfy the constraint MUST be excluded. A
> `None` constraint means "any version" — all parseable versions are
> candidates.

> NOTE: `VersionSet.from_constraint` is defined in `milpa/solver.py` and is
> the single source of truth for constraint matching. `registry-protocol.md`
> does not define constraint syntax; cross-reference
> `spec/resolver-semantics.md` (S6) for the constraint grammar.

### 5.3  Provenance-less version handling

> NORMATIVE: A version entry with no `provenance` child nodes (or whose only
> `provenance` nodes have unknown kinds and were skipped) MUST be excluded from
> the satisfying candidate list with a `UserWarning`. It MUST NOT raise an
> immediate error — older valid versions on the same package should still be
> reachable.

> NORMATIVE: If every satisfying version was excluded for lack of provenance,
> the implementation MUST raise `TNG-NO-PROVENANCE` (not
> `TNG-NO-SATISFYING-VERSION`). The error message MUST list the excluded
> version strings.

### 5.4  No-satisfying-version

> NORMATIVE: If no version satisfies the constraint (and no provenance-less
> exclusions occurred), the implementation MUST raise
> `TNG-NO-SATISFYING-VERSION`. The error message MUST list all available
> version strings.

### 5.5  Result: `resolve_named_all` vs `resolve_named`

Two resolution entry points are specified:

**`resolve_named_all(index, name, constraint) → list[IndexVersion]`** — returns
ALL satisfying `IndexVersion` records, ordered descending by semver. This is
the Phase-A enumerate step for P3.2's two-phase model: the caller registers the
full candidate set into the solver provider so the solver can choose and
backtrack.

**`resolve_named(index, name, constraint) → IndexVersion`** — returns the
single highest-semver satisfying `IndexVersion`. Equivalent to
`resolve_named_all(…)[0]`.

> NORMATIVE: Both entry points MUST apply the same structural error policy:
> `TNG-NOT-FOUND`, `TNG-AMBIGUOUS-NAME`, `TNG-NO-SATISFYING-VERSION`,
> `TNG-NO-PROVENANCE` (in that precedence order).

---

## 6  Index caching

> NORMATIVE: A conformant implementation MUST cache the fetched `index.kdl`
> under a stable per-URL cache location. The **cache key** MUST be a
> deterministic function of the index URL (the reference uses the first 16 hex
> characters of `sha256(url.encode("utf-8"))`). Using a deterministic cache key
> is normative so that two concurrent invocations share the same cache entry
> and air-gapped deployments that substitute `MILPA_INDEX_URL` cache the
> substitute correctly.

> NORMATIVE: Cache freshness model — a conformant implementation MUST implement
> the following four-state behavior:
>
> 1. **Fresh cache** (cache present and age < TTL) → serve cached bytes without
>    any network access.
> 2. **Stale cache** (cache present and age ≥ TTL) → attempt re-fetch; on
>    success overwrite the cache and serve fresh bytes.
> 3. **Network failure with stale-but-present cache** → serve the stale cache
>    as an offline fallback and emit a warning to stderr indicating the index
>    may be out of date. MUST NOT raise an error in this case.
> 4. **Network failure with no cache** → propagate the error; MUST NOT proceed
>    without an index.

> NORMATIVE: Cache writes MUST be atomic. The implementation MUST write to a
> sibling temporary file and rename it into place (`os.replace` / `rename(2)`)
> to prevent a concurrent reader from observing a partial write.

> NORMATIVE: The index cache lives outside the project directory. `milpa clean`
> MUST NOT remove the index cache. Multiple concurrent `milpa` invocations MAY
> share the same cache file safely because cache writes are atomic.

> NOTE: The reference implementation caches under
> `$XDG_CACHE_HOME/milpa/index/` (default `~/.cache/milpa/index/`). The
> default TTL is 24 hours — generous enough to avoid hammering tianguis on
> every invocation, short enough that the vendor-en-absentia daily pass is
> visible within the same cycle. Conformant implementations MAY use a different
> default TTL; the four-state behavior model above is normative, the 24h value
> is not.

---

## Appendix A  Error-code summary (TNG-* domain)

All tianguis-domain errors use stable slug codes. Consumers (CI scripts, IDE
integrations, alternate implementations) MAY rely on slugs; MUST NOT rely on
message wording.

| Code | When raised |
|---|---|
| `TNG-SCHEMA-UNKNOWN` | Declared `schema_version` > `TIANGUIS_INDEX_SCHEMA_VERSION` |
| `TNG-UNSAFE-NAME` | Package name contains path-traversal characters |
| `TNG-BAD-COMMIT-SHA` | `commit_sha` not exactly 40 lowercase hex chars |
| `TNG-UNSAFE-URL` | Git `url` begins with `-` |
| `TNG-UNSAFE-REF` | Git `ref` begins with `-` |
| `TNG-BAD-OCI-DIGEST` | OCI `digest` not in `sha256:<64 hex>` form |
| `TNG-UNSAFE-OCI-FIELD` | OCI `registry` or `repository` begins with `-` |
| `TNG-NOT-FOUND` | Bare-name lookup matches no package |
| `TNG-AMBIGUOUS-NAME` | Bare-name lookup matches multiple namespaces |
| `TNG-NO-SATISFYING-VERSION` | No version satisfies the constraint |
| `TNG-NO-PROVENANCE` | All satisfying versions lack provenance |
| `TNG-NO-IDENTITY` | Index entry's `content_hash` is absent or empty string; raised before any fetch is attempted |

The following six codes are raised by the whole-index attestation gate (§3.4).
They are defined in `spec/errors.md` and first added to `errors.py` / `errors.rs`
in S5/S6 of the registry-trust-federation RFC alongside their raise sites.

| Code | When raised |
|---|---|
| `TNG-INDEX-BUNDLE-MISSING` | No bundle sidecar is available. Under `strict`: hard fail. Under `warn`: proceed with warning and remediation hint. |
| `TNG-INDEX-BUNDLE-MALFORMED` | Bundle JSON fails to parse or is not a valid Sigstore bundle (pre-cryptographic failure, before any signature check). |
| `TNG-INDEX-SIGNATURE-INVALID` | Cryptographic verification failed — bad cert chain, wrong Fulcio CA root, or certificate expired AT its own `integratedTime`. A cert now-expired but valid at `integratedTime` MUST NOT trigger this. |
| `TNG-INDEX-DIGEST-MISMATCH` | The bundle's in-toto statement subject digest does not match `sha256(index_bytes)`. Indicates tampering or a mismatched bundle/index pair. |
| `TNG-INDEX-SIGNER-MISMATCH` | The bundle's certificate SubjectAltName does not match the expected signer identity (§3.4.4 step 5). |
| `TNG-INDEX-BUNDLE-STALE` | `now - SET.integratedTime >= MILPA_INDEX_MAX_AGE`. Bundle is cryptographically valid but was signed beyond the maximum allowed age. Asserted on network-fetch paths only; NOT asserted on pure cache reads. |

---

## Appendix B  Minimal `index.kdl` example

```kdl
schema_version 1

package "nimkdl" {
    namespace "coreyleavitt"
    upstream (url)"https://github.com/coreyleavitt/nimkdl"
    version "0.1.4" {
        content_hash "dag-sha256:1aaf2a95f53681c86f6dcd4c1267144401ba923f31afa42da3c5ae783dc7ab61"
        provenance {
            kind "oci"
            registry "ghcr.io"
            repository "coreyleavitt/nimkdl"
            digest "sha256:e51aab085ef4f58ed3827742f3314cadb901ac1da36988cae05bb221f3652c24"
        }
        attestation "author-signed"
        signed_by "https://github.com/coreyleavitt/tianguis/.github/workflows/publish.yaml"
        published_at "2026-05-26T04:49:44Z"
        rekor {
            uuid "108e9186e8c5677abce5a62d285437741218f878474a02d9a4dac01dc12e39b979336e712890d636"
            log_index "1753541583"
            integrated_time "1780881469"
        }
    }
}

package "chronos" {
    namespace "status-im"
    upstream (url)"https://github.com/status-im/nim-chronos"
    version "4.0.3" {
        content_hash "dag-sha256:abc123…"
        provenance {
            kind "git"
            url (url)"https://github.com/status-im/nim-chronos"
            ref "HEAD"
            commit_sha "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        }
        attestation "milpa-vendored"
    }
}
```
