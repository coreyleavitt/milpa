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
6. Treat unrecognized version-node children (children this spec does not
   define) as forward-compat metadata: parse MUST succeed, unknown fields
   MUST be ignored. `upstream` and `namespace` remain informational fields
   under this clause. `attestation`, `signed_by`, `rekor`, `bundle`,
   `published_at`, `yanked`, `yanked_at`, and `yanked_reason` are **not**
   covered by this clause — they parse into typed fields on `IndexVersion`
   (§3.2) rather than being silently ignored. `attestation` (with its
   siblings `signed_by`/`rekor`/`bundle`) parses into the closed-set
   `EntryAttestation` tagged record and MUST collapse conservatively to
   *unattested* (with an observable parse diagnostic) on an unrecognized
   `kind` or a structurally invalid record (§3.2). `published_at` and the
   `yanked`/`yanked_at`/`yanked_reason` triple use the parser's ordinary
   optional-scalar robustness posture instead (a malformed value surfaces as
   absent, no collapse diagnostic, no hard error — §3.2). Layer 2
   enforcement over the parsed attestation record — the `entry-trust` gate —
   is a separate, later normative surface (§3.2, "gate lands separately");
   likewise, enforcement of the append-only consumer ratchet over
   `published_at` and the yank fields (§3.5) is staged to
   `rfc-registry-append-only.md`'s A2/A5 slices, not this spec-only
   amendment.
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
        attestation "<label>"        // "author-signed" or "milpa-vendored"; closed set (§3.2)
        signed_by "<identity>"       // required when attestation is "author-signed"
        published_at "<ISO-8601>"
        rekor {                      // durable Rekor reference; optional
            uuid "<hex>"
            log_index "<decimal-string>"
            integrated_time "<decimal-string>"
        }
        bundle sha256="<64-hex>"     // per-entry attestation bundle delivery pin; optional (§3.2)
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

**`published_at`** (child node, string, optional) — ISO 8601 timestamp of when
the version was published.

> NORMATIVE: `published_at` is a parse-to-typed field on `IndexVersion`
> (`published_at: <timestamp> | None`, parsed from ISO 8601). A malformed
> value MUST NOT raise a hard parse error — it uses the same robustness
> posture as the parser's other optional scalar children: surfaced as
> absent. This amends the item-6 forward-compat clause above:
> `published_at` was previously listed as tolerate-and-ignore metadata; as
> of this amendment it is typed, not ignored. The parse-to-typed contract
> is normative as of this amendment; enforcement of the checks that consume
> the typed value (below) lands with `rfc-registry-append-only.md`'s A2/A2a
> slice.

> NORMATIVE: In the field-class taxonomy §3.5 defines over successive index
> states, `published_at` is **Frozen** (set-once): backfilling an
> absent-or-empty `published_at` to a value is legal exactly once per
> observed history; a `value → value′` change or a `value → absent`
> regression on an already-published entry is a ratchet violation (§3.5.1).
> `published_at` is also the anchor for the publication watermark (§3.5.4)
> — the append-only ratchet's backdating check. Per Part 2's epoch mandate
> (`rfc-per-entry-attestation.md` open question 2), `published_at` becomes
> REQUIRED on post-epoch entries once the attestation epoch ships; that
> requirement is not yet in force as of this amendment.

#### Per-entry attestation record (`attestation` / `signed_by` / `rekor` / `bundle`)

These four sibling child nodes on a `version` node record Layer 2's per-entry
author-attribution CLAIM (attribution, not integrity — the whole-index
integrity gate is Layer 1, §3.4). They parse into **one** optional tagged
record on `IndexVersion`, not four independently-nullable fields — the
correlation between `kind`, `signer`, `rekor`, and `bundle_pin` is a
structural invariant of the data model:

```
EntryAttestation = {
  rekor: RekorRef | None,             # kind-independent
  bundle_pin: Sha256Hex | None,       # sha256 of the bundle BYTES — the
                                       # delivery-integrity pin (`bundle` node).
                                       # None is a normal, expected state before
                                       # per-entry bundle delivery ships.
  kind: AuthorSigned { signer: str }  # signer REQUIRED for this kind
      | MilpaVendored,
}
# IndexVersion.attestation: EntryAttestation | None
```

Wire form:

```kdl
version "<semver>" {
    …
    attestation "<label>"        // discriminates `kind`: "author-signed" | "milpa-vendored"
    signed_by "<identity>"       // REQUIRED when attestation is "author-signed"
    rekor {                      // optional, kind-independent
        uuid "<hex>"
        log_index "<decimal-string>"
        integrated_time "<decimal-string>"
    }
    bundle sha256="<64-hex>"     // optional; sha256 of the attestation bundle BYTES
}
```

> NORMATIVE (closed kind set): The `attestation` value set is CLOSED —
> `"author-signed"` and `"milpa-vendored"` are the only recognized values. A
> conformant reader MUST parse these into the corresponding
> `EntryAttestation.kind` variant: `"author-signed"` → `AuthorSigned{signer}`
> (from the sibling `signed_by` node); `"milpa-vendored"` → `MilpaVendored`
> (no signer field — the effective signer for this kind is derived at
> verification time from Layer 1's resolved vendor-bot identity, never read
> from a per-entry field; see `rfc-per-entry-attestation.md` §5).

> NORMATIVE (conservative collapse): Any `attestation` value outside the
> closed set, and any structurally invalid record (e.g. `attestation
> "author-signed"` with no sibling `signed_by`), MUST normalize to
> `IndexVersion.attestation = None` (*unattested*) — an unrecognized or
> malformed attestation claim MUST NEVER parse as attested, in an older
> client or otherwise. The collapse MUST be observable: the parser emits a
> diagnostic naming the affected `(namespace, name, version)`, distinct from
> a hard parse error, so a vendor-bot bug surfaces to the operator instead of
> silently degrading. Persisted state (index cache, lockfile) does NOT
> distinguish "collapsed due to malformed input" from "never attested" — the
> Layer-1-verified index snapshot already held in the local cache is the
> forensic record for what the bot actually emitted, so the collapse loses
> no auditable information. A malformed `bundle` `sha256=` value (see below)
> is narrower: it normalizes only `bundle_pin` to `None` and does NOT collapse
> an otherwise well-formed `kind`/`signer` pairing, because an absent bundle
> pin is itself the ordinary, expected state before per-entry bundle
> delivery ships (`rfc-per-entry-attestation.md` §7) — unlike a malformed
> `kind`/`signer` pairing, it is not evidence of a malformed claim.

> NORMATIVE (parse boundary shape): The version-node parse function in both
> impls MUST return `(typed index, collapse diagnostics)` — the parsed
> `IndexVersion` paired with the list of collapse diagnostics produced while
> parsing it — rather than a bare typed value. This is a small, explicit,
> cross-impl signature change at the version-node parse boundary (both
> impls' version-node parsers are pure functions today); callers thread the
> diagnostics to the warning channel. This clause specifies the parse-time
> contract only. It does NOT specify a policy gate over the result — no
> gate exists at this spec layer; enforcement (`entry-trust`) is specified
> separately and lands with a later slice of `rfc-per-entry-attestation.md`
> (§3.4 intro).

> NORMATIVE (subject binding — requirement on bundle producers and the
> future verifier, not this parser): once a bundle exists at the address the
> `bundle` pin commits to (`rfc-per-entry-attestation.md` §7), it MUST be a
> Sigstore bundle whose in-toto statement subject binds BOTH
> `subject[0].digest.sha256` (the entry's `content_hash`, hex form) AND
> `subject[0].name` (`pkg:tianguis/<namespace>/<name>@<version>`). Digest
> binding alone is insufficient: `content_hash` is name-independent by
> design, so with a digest-only subject a byte-identical republish of one
> package under a different `(namespace, name)` coordinate could point at
> the original package's genuine, publicly-logged bundle (Rekor is a
> transparency log) and inherit its signature — earning an attribution the
> signer never made for that coordinate. Binding both coordinates makes one
> bundle vouch for exactly one `(namespace, name, version)`, which is the
> attribution claim this record exists to carry. This clause is a
> requirement on what a conformant bundle must contain; it does not itself
> verify anything — no verifier is specified by this document. Verification
> (subject-binding checks, cryptographic checks, and the `entry-trust`
> policy gate) is specified separately and lands with a later slice of
> `rfc-per-entry-attestation.md`; nothing in this section implies that gate
> exists yet.

> NOTE: `EntryAttestation` records the CLAIM only. Whether the claim is
> cryptographically true is a question this section does not answer — see
> `spec/lockfile-schema.md` §3.9 for the same claim-not-outcome framing at
> the lockfile layer, and `rfc-per-entry-attestation.md` for the verifier
> design (not yet part of any spec surface).

> NOTE: This subsection **inverts** the prior "parsed and ignored"
> forward-compat treatment of `attestation`, `signed_by`, and `rekor`
> (formerly tolerate-and-ignore metadata; see item 6 of "Normative surface"
> above). Both reference impls conform to the tolerate-and-ignore behavior
> as of this spec amendment; the parse-to-typed behavior specified here is
> the target for `rfc-per-entry-attestation.md`'s P2 slice. A spec amendment
> preceding the implementation that satisfies it is expected RFC-flow
> sequencing, not a spec/impl mismatch bug.

**`attestation`** (child node, string, optional) — see the tagged record
above. MAY be absent on legacy entries (parses as `IndexVersion.attestation
= None`).

**`signed_by`** (child node, string, conditionally required) — the identity
(GitHub Actions workflow URL or bot identifier) that produced the
attestation. REQUIRED when `attestation` is `"author-signed"` (its absence
there makes the record structurally invalid — collapse rule above). Ignored
when `attestation` is `"milpa-vendored"` (the vendored kind carries no
per-entry signer field by design — see the closed-set clause above).

**`rekor`** (child node, optional block) — a durable Rekor transparency-log
reference captured at publish time, folded into `EntryAttestation.rekor`
when an attestation record is present. Fields:

| Child | Type | Meaning |
|---|---|---|
| `uuid` | string | Rekor entry UUID (80-char hex in the reference index) |
| `log_index` | string | Rekor log index, as a decimal string |
| `integrated_time` | string | Unix timestamp (seconds) when the entry was integrated, as a decimal string |

> NORMATIVE: A conformant reader MUST tolerate a `rekor` block on a version
> node whether or not `attestation` is present. When `attestation` is
> present (and the record is not collapsed), `rekor` folds into
> `EntryAttestation.rekor`. When `attestation` is absent, a `rekor` block
> alone does not construct an `EntryAttestation` — there is no `kind` to tag
> it with — and MUST be ignored, the same forward-compat posture as before
> this amendment.

**`bundle`** (child node, `sha256=` property, optional) — the delivery
integrity pin for the per-entry attestation bundle: the sha256 hex digest of
the bundle BYTES (not of the bundle's semantic content), folded into
`EntryAttestation.bundle_pin`. Expected absent during the claim-only window
that precedes `rfc-per-entry-attestation.md`'s bundle-delivery slice — a
present `attestation` with no `bundle` pin is a well-formed, ordinary claim;
a future verifier reports this state as bundle-unavailable, not malformed.

> NORMATIVE: `bundle`'s `sha256=` property, when present, MUST be exactly 64
> lowercase hexadecimal characters. A malformed value MUST normalize to
> `bundle_pin = None` (with a collapse diagnostic per the rule above) rather
> than raising a parse error or collapsing the enclosing `kind`/`signer`
> pairing — `bundle` is independently-nullable delivery metadata layered on
> the same forward-compat posture as the rest of this record.

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

#### Yank triple (`yanked` / `yanked_at` / `yanked_reason`)

The sanctioned in-band removal story: the append-only invariant (§3.5)
forbids deleting a published entry, so the registry needs a legal way to
retire a version from *new* candidate selection without rewriting history.
These three optional sibling child nodes on a `version` node record that
state, aligned with tianguis#13's contract:

```kdl
version "1.4.2" {
    content_hash "dag-sha256:…"
    yanked #true
    yanked_at "2026-07-01T12:00:00Z"                    // optional
    yanked_reason "ships a vulnerable bearssl pin"      // optional
}
```

**`yanked`** (child node, boolean, optional) — marks the version as yanked.
Absent is equivalent to `#false`.

**`yanked_at`** (child node, string, optional) — ISO 8601 timestamp of the
most recent yank-state transition. Informational.

**`yanked_reason`** (child node, string, optional) — free-text explanation
(e.g. `"ships a vulnerable bearssl pin"`). Informational; surfaced in
ratchet notices (§3.5.3) and in the `TNG-NO-SATISFYING-VERSION` message
when relevant (§5.2).

> NORMATIVE: `yanked`, `yanked_at`, and `yanked_reason` are parse-to-typed
> fields on `IndexVersion` (`yanked: bool`, default `false`;
> `yanked_at: <timestamp> | None`; `yanked_reason: str | None`). A
> malformed value (e.g. a non-boolean `yanked`) MUST NOT raise a hard parse
> error — it uses the parser's ordinary optional-scalar robustness posture
> (surfaced as absent / default `false`), the same posture `published_at`
> uses above. Older milpa versions that predate these fields tolerate and
> ignore them (item 6 of "Normative surface").

> NORMATIVE: In the field-class taxonomy §3.5 defines over successive index
> states, the yank triple is **advisory-mutable-but-surfaced**: both a yank
> and an un-yank are legal transitions in either direction (a mistaken yank
> must be reversible — cargo precedent), and the entry's other fields
> (`content_hash`, `provenance`, `dep_decl`, …) remain frozen while
> yanked — yanking hides nothing and rewrites nothing. Unlike the rest of
> the advisory-mutable class, every yank-state transition observed between
> a consumer's ratchet baseline and a candidate index MUST be reported as a
> non-fatal notice — never an error, never silent (§3.5.3).

> NORMATIVE (staged — enforcement lands at `rfc-registry-append-only.md`'s
> A5 slice): once `yanked` is `#true`, the version MUST be excluded from
> *new* candidate enumeration — §5.2 amendment below specifies the
> selection semantics. This clause specifies only the parse-to-typed
> contract and the field's semantic status as of this spec-only amendment
> (A1); selection-time exclusion is not yet enforced.

> NOTE: There is no `--allow-yanked` escape hatch in milpa v1 — reproducing
> an already-locked yanked version is fully covered by the frozen path
> (which never consults `yanked`); a resolution-time override would
> reintroduce, as a user flag, exactly the silent-downgrade selection the
> yank notice exists to surface. Recorded as a deliberate delta from
> tianguis#13's sketch. A non-blocking yanked-but-locked advisory in
> `verify`/`show` is deferred follow-up scope, filed as #186 — it must not
> touch resolution behavior.

### 3.3  Provenance record shapes (index form)

Index provenance records use the same kind-set and field shapes as the manifest
grammar's §4.2, with the additional acceptance of `(url)`-annotated URL values
(the milpa KDL url convention — see `manifest-grammar.md` §2).

> NOTE (invariant this spec leans on elsewhere): a version's `content_hash`
> (§3.2) is a property of the ENTRY, not of any individual `provenance`
> record — every provenance listed on one version MUST yield source bytes
> that hash to that same `content_hash`. This already follows from the
> identity gate: milpa recomputes the content hash after fetching from
> whichever provenance it used and treats a mismatch as `CAS-IDENTITY-MISMATCH`
> (`spec/identity.md`), so a mirror serving different bytes than another
> provenance on the same entry is a hard error regardless of which
> provenance was tried. `rfc-per-entry-attestation.md` §1 depends on this:
> because `content_hash` is well-defined per entry independent of delivery
> path, a per-entry attestation subject can bind to it without needing to
> know which mirror serves the bytes at verification time.

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
to the per-entry attestation record in §3.2 (`attestation`, `signed_by`,
`rekor`, `bundle` — the `EntryAttestation` tagged record): Layer 1's gate
covers document integrity only and has no dependency on §3.2's per-entry
fields. Layer 2 — the per-entry attribution gate (`entry-trust`) that
verifies and enforces the `EntryAttestation` record that §3.2 types — is
specified separately in `rfc-per-entry-attestation.md` and is not part of
this document as of this amendment. §3.2 specifies parsing (the fields are
now typed, not ignored); it does not specify a verifier or a policy gate.
Nothing in this spec should be read as implying an `entry-trust` gate
exists yet.

#### 3.4.0  Generic policy-axis model

This spec defines multiple independent trust/integrity axes over the
registry read path — `index-trust` (this section, whole-index Sigstore
verification), `entry-trust` (per-entry author attribution,
`rfc-per-entry-attestation.md` §4), and `index-history` (§3.5, the
append-only consumer ratchet) — and the count is expected to grow. Each
axis fails independently, is remediated independently, and is deliberately
NOT merged into any other axis: `rfc-per-entry-attestation.md` §4 makes the
axis-separation argument for `entry-trust`, and `rfc-registry-append-only.md`
§2 makes it for `index-history` (a validly-signed, maximally-fresh index can
still be an invalid successor — a distinct failure with a distinct fix). All
axes nonetheless share one authority/effective-policy pattern; this section
states that pattern **once**, parametrized by (axis name, default policy,
environment variable, member-declaration error slug), and each axis's own
subsection instantiates it rather than restating it. The code-level SSOT
already exists — `trust.py`'s `effective_trust_policy` serves every axis —
this section applies the same single-source-of-truth discipline to the spec
prose.

> NORMATIVE (generic effective-policy formula): for an axis with manifest
> node `<axis>`, environment variable `MILPA_<AXIS>`, and default policy
> value `<default>` (values drawn from `{off, warn, strict}` unless the
> axis's own subsection narrows the set):
>
> 1. If the manifest declares `<axis> "off"`, the effective policy is `off`
>    **unconditionally**. No environment variable or CLI flag can override
>    a manifest `off`. `off` is an auditable opt-out that MUST ONLY be
>    declared in `milpa.kdl` (committed to version control) —
>    `MILPA_<AXIS>=off` in the environment is a no-op floor that CANNOT
>    weaken a manifest `warn` or `strict` policy.
> 2. Otherwise: `effective = max(manifest_policy or <default>, env_policy)`
>    over `{warn, strict}`. `MILPA_<AXIS>=off` in the environment is ignored
>    in this step (same no-op-floor rule as step 1).
> 3. An axis MAY define additional CLI-flag escalation rules layered on top
>    of step 2 (e.g. `index-trust`'s `--require-attested-index`, §3.4.5
>    rule 3). Such flags MAY ONLY strengthen the policy and MUST NOT set or
>    clear `off`.

> NORMATIVE (root-only declaration): every axis governed by this model is
> declared ONLY on the **resolution root** — for a standalone package, the
> package manifest; for a workspace, the workspace ROOT manifest (the one
> carrying the `workspace { member … }` block). The resource each axis
> gates (the registry index; for `entry-trust`, the per-entry attestation
> record within it) is process-global and workspace-shared — the axis is
> therefore a property of the resolution root, not of each member, and
> there is no merge across members.

> NORMATIVE (member-declaration error): a workspace MEMBER manifest
> declaring the axis's manifest node (or any sibling configuration node the
> axis defines, e.g. `index-trust`'s `-signer`/`-bundle`) MUST raise that
> axis's dedicated member-declaration error BEFORE any index fetch. This
> check fires at workspace-load time and fires even when the declared value
> is textually identical to the default — the rule is about WHERE the field
> is declared, not what value it holds.

> NORMATIVE (instantiation rows): every axis's member-declaration error is a
> distinct slug following the `WS-<AXIS>-ON-MEMBER` naming pattern
> established by `index-trust`:
>
> | Axis | Manifest node(s) | Env var | Default | Member-error slug | Normative home |
> |---|---|---|---|---|---|
> | `index-trust` | `index-trust`, `index-trust-signer`, `index-trust-bundle` | `MILPA_INDEX_TRUST` | `warn` | `WS-INDEX-TRUST-ON-MEMBER` | §3.4.5 / §3.4.7 (this document) |
> | `entry-trust` | `entry-trust` | `MILPA_ENTRY_TRUST` | `warn` | `WS-ENTRY-TRUST-ON-MEMBER` | `rfc-per-entry-attestation.md` §4 |
> | `index-history` | `index-history` | `MILPA_INDEX_HISTORY` | `warn` | `WS-INDEX-HISTORY-ON-MEMBER` | §3.5.2 (this document) |
>
> This table is the SSOT for which axes exist and their identifying
> parameters. Each row's "Normative home" is where the axis's
> policy-specific behavior (what a verification failure means, what
> remediation looks like) is actually specified; this section specifies
> only the shared authority mechanics.

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
MUST be verified against the certificate's public key. The in-toto statement's
subject digest (`statement.subject[0].digest.sha256`) MUST equal
`sha256(index_bytes)`; a digest mismatch MUST raise `TNG-INDEX-DIGEST-MISMATCH`.
The subject-digest comparison takes precedence over the cryptographic steps and MAY
be performed before them (see the subject-digest-binding-precedence NORMATIVE clause
below); the `Trusted` verdict nonetheless requires the envelope signature and all
other steps to pass.

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

> NOTE: Subject-digest comparison is a deterministic byte check —
> `statement.subject[0].digest.sha256` vs `sha256(index_bytes)` — NOT an inspection
> of exception message text. A conformant implementation MUST NOT infer
> `TNG-INDEX-DIGEST-MISMATCH` from error-string patterns. The payload bytes read for
> the comparison MUST be the same bytes whose DSSE signature is verified on the
> `Trusted` path (so a pre-crypto digest check is not a distinct read); this holds
> whether the comparison is performed before the cryptographic steps (fail-fast) or
> after them.

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
> evaluation order. In particular: a bundle that is both stale (step 3) and has an
> invalid signature (steps 4+) MUST report `TNG-INDEX-BUNDLE-STALE`, not
> `TNG-INDEX-SIGNATURE-INVALID`.
>
> NORMATIVE (subject-digest binding precedence): The subject-digest binding of
> step 6 is evaluated BEFORE the cryptographic verification of steps 4–5 and 7.
> A bundle whose `statement.subject[0].digest.sha256` ≠ `sha256(index_bytes)`
> (or whose subject digest is absent/unextractable) MUST report
> `TNG-INDEX-DIGEST-MISMATCH`, taking precedence over any concurrent signature,
> certificate, signer-identity, or inclusion-proof failure. Rationale: a subject
> mismatch means the bundle attests a DIFFERENT artifact than the index being
> loaded — it is not "about" this index at all, which is the most fundamental
> mismatch and cheapest to detect (a hash comparison, no cryptography). Checking
> it first also yields identical slugs across implementations whose underlying
> verification libraries interleave the cryptographic sub-steps differently.
>
> This precedence is SAFE despite the digest being read from a not-yet-verified
> payload: the pre-check can only REJECT (it never accepts), the `Trusted` verdict
> still requires the full cryptographic verification of steps 4–7 to pass, and the
> exact payload bytes read for the digest pre-check are the same bytes whose DSSE
> signature is verified on the `Trusted` path (single-read invariant below — no
> TOCTOU). Implementations MUST NOT accept a bundle on the strength of the digest
> pre-check alone.

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

> NORMATIVE (effective policy — instantiates §3.4.0): `index-trust` is an
> instantiation of the generic policy-axis model (§3.4.0) with manifest node
> `index-trust`, environment variable `MILPA_INDEX_TRUST`, and default
> `warn`. §3.4.0's rules 1–2 (manifest `off` is unconditional and
> manifest-only; otherwise `max(manifest_policy or "warn", env_policy)`)
> apply verbatim. Rule 3 is this axis's CLI-flag escalation: if
> `--require-attested-index` is given, the effective policy is `strict`
> (unless §3.4.0 rule 1 applies; the flag MUST NOT set or clear `off`).

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

#### 3.4.7  Workspace requirements — root authority

`index-trust` (together with its sibling override nodes `index-trust-signer`
and `index-trust-bundle`) instantiates the generic policy-axis model's
root-only-declaration and member-declaration-error rules (§3.4.0) with
member-error slug `WS-INDEX-TRUST-ON-MEMBER`. The registry index is a
process-global, workspace-shared resource (one index URL per invocation, no
per-member index URL), which is exactly the structural condition §3.4.0's
root-only rule generalizes.

> NORMATIVE (root authority — instantiates §3.4.0): The resolution root is:
>
> - For a standalone package: the package manifest itself (unchanged).
> - For a workspace: the workspace ROOT manifest — the one carrying the
>   `workspace { member … }` block. The workspace-root manifest grammar
>   permits `index-trust` / `index-trust-signer` / `index-trust-bundle` as
>   top-level nodes alongside `workspace { }` (they are neither `deps` nor
>   `kind`, so declaring them does not trigger the deps/kind rejection).
>
> The effective policy for a workspace invocation is simply the root's own
> `index-trust` value (default `warn` if the node is absent) — per §3.4.0
> there is no merge, and no other manifest contributes to it. Consequently a
> workspace HAS a manifest-level path to an effective `off`: declare
> `index-trust "off"` on the workspace root.

> NORMATIVE (member-declaration error — instantiates §3.4.0): A workspace
> MEMBER manifest declaring ANY of `index-trust`, `index-trust-signer`, or
> `index-trust-bundle` MUST raise `WS-INDEX-TRUST-ON-MEMBER` BEFORE any
> index fetch. This check fires at workspace-load time, per §3.4.0's rule
> (fires even when the member's declared value is identical to the default
> — e.g. an explicit `index-trust "warn"` on a member is still an error).
> `WS-INDEX-TRUST-ON-MEMBER` is distinct from the six `TNG-INDEX-*` error
> slugs; it is a manifest-structure error that does not involve
> cryptographic verification.

### 3.5  Append-only invariant & refresh ratchet

§3.4's whole-index attestation gate verifies that a served `index.kdl` was
signed by the expected identity, recently. It does **not** verify that the
signed index is a valid **successor** of the index a consumer previously
trusted — a compromised or buggy vendor-bot re-signs the entirety of history
on every publish, so a mutated historical entry (a swapped `content_hash`, a
stripped attestation, a rolled-back version) can ship inside a perfectly
fresh, perfectly valid signed index. This section specifies a
consumer-side check — the **append-only invariant** over what may change
between two successive index states, and the **refresh ratchet** that
enforces it — that closes this gap. It is the normative content of
`rfc-registry-append-only.md`; that RFC is this section's design record and
carries the threat model, the residuals this section does not close (TOFU
at trust-anchor re-establishment, split-view attacks), and the slice
sequencing that stages enforcement.

This section is orthogonal to §3.4: §3.4 verifies "this document was
signed by the expected identity, recently"; this section verifies "this
document is a legal continuation of the last one this consumer trusted".
Both must pass — the ratchet does not replace the whole-index gate, and
disabling one axis has no effect on the other (§3.4.0).

#### 3.5.1  The monotone-entry invariant (dominance over a product order)

> NORMATIVE (entry key): For the purpose of this section, an index entry is
> keyed by `(namespace, name, raw version string exactly as it appears in
> the document)`. Keying on the raw version string means a cosmetic
> re-spelling (e.g. `"1.4.2"` → `"01.4.2"`) is a package disappearance plus
> a package appearance under this key — caught as rollback (below), not
> silently matched. A `namespace` change is likewise a disappearance under
> the old key; `namespace` needs no field class of its own because it is
> *inside* the key.

> NORMATIVE (the invariant): For every entry key present in a consumer's
> **baseline** index state (§3.5.2), the corresponding entry in a
> **candidate** index state MUST **dominate** the baseline entry in the
> product partial order over the field classes below. Entry *presence*
> is itself a component of that product (`absent < present`; a
> `present → absent` transition is never legal) — so a version or package
> disappearing between baseline and candidate is the same dominance failure
> as a frozen-field mutation, not a separate rule.

Each field is tagged with exactly one of five **disjoint** order kinds. The
tag names are deliberately distinct even where two orders both read as
"monotone" in English — a conformant fold implementation MUST NOT share one
tag between them:

| Class (order kind) | Fields | Legal transitions |
|---|---|---|
| **Frozen** (`set-once`: `absent < v`; distinct values incomparable) | `content_hash`; `dep_decl` **together with** `dep_decl_schema_version` (they move in lockstep — mutating the schema version alone re-interprets the pin and is a violation); `published_at` (§3.2); the attestation record's `rekor` block; presence of the version node; presence of the package node | `absent/empty → value` is legal **exactly once per observed history** (§3.5.2's re-anchoring note). `value → value′` and `value → absent` are violations. Legacy backfill (an entry with an empty `content_hash` is unresolvable anyway, `TNG-NO-IDENTITY`, so backfilling it is semantically a first publication) is the sanctioned shape of the one legal transition; same shape for `dep_decl`. |
| **Attestation-monotone** (the bespoke lattice over attestation kinds — a *distinct* order-kind tag from `ordinal-non-decreasing` below, even though both read as "monotone") | the attestation record (`rfc-per-entry-attestation.md`'s `EntryAttestation` incl. its `bundle` pin). Part 2 owns the *type*; this section owns the *order* over its values. | `None → MilpaVendored`, `None → AuthorSigned(s)`, `MilpaVendored → AuthorSigned(s)` (backfill/upgrade) are legal. `→ None` (stripping), `AuthorSigned(s₁) → AuthorSigned(s₂)` (re-attribution), and `AuthorSigned → MilpaVendored` (downgrade) are violations. `MilpaVendored → MilpaVendored` with a changed `signed_by` (bot workflow identity rotation) is **unconstrained** — vendored attestation is a bug ratchet, not a security boundary. Within an otherwise-unchanged `(kind, signer)`, the record's `bundle` pin MUST be structurally equal; a same-kind `bundle_pin` swap is a violation (`monotone-repinned`) — the pin may change only as part of a legal kind/signer upgrade. This row checks the pin's history *across snapshots* (ratchet-time); it is distinct from and cannot collide with `TNG-ENTRY-BUNDLE-PIN-MISMATCH` (`rfc-per-entry-attestation.md`'s stage 1b), which checks served bytes against the *current* snapshot's pin (acquisition-time transport integrity). |
| **Append-only** (multiset inclusion, compared by full-field value equality — never by list position) | the `provenance` **multiset** (§3.3) | records may be added (mirrors); removal is a violation. In-place mutation of one record's fields (e.g. `commit_sha`) manifests under multiset comparison as removal + addition — caught as removal. Preference **order** among provenance records is advisory-mutable (reordering is legal — the identity gate makes every provenance of an entry byte-equivalent, §3.3, so order affects availability, not identity). |
| **Advisory-mutable** (trivial order — everything comparable, both directions legal) | `yanked` / `yanked_at` / `yanked_reason` (mutable both directions, but every transition MUST be surfaced as a ratchet notice, §3.5.3 — never silent); package-level descriptive fields (`upstream`) (mutable and silent) | both directions legal |

**Root-level fields (outside the entry map).** Root fields ride the **same
generic fold** as entries, not a parallel one: a conformant implementation
synthesizes one reserved entry under the empty key (`namespace = ""`,
`name = ""`, `version = ""` — exactly the key the §3.5.3 composite ordering
already assigns root violations) whose "fields" are the document-root
fields, each tagged with its own order kind:

| Root field | Order kind | Legal transitions |
|---|---|---|
| `schema_version` (§2) | **ordinal-non-decreasing** (plain integer `≤` — its own tag, NOT `attestation-monotone`) | increase is legal (schema evolution); decrease is a violation. `absent` ≡ the spec default (`1`, §2) within this order — removing an explicit `schema_version 2` node is a decrease, not an unclassified state. A candidate declaring a schema *newer than this consumer understands* never reaches the ratchet at all: `TNG-SCHEMA-UNKNOWN` aborts at parse time, unconditionally (§2); the increase-legal row is live only within the consumer's parseable range. |
| `attestation-epoch` (`rfc-per-entry-attestation.md` open question 2) | **set-once** (the same tag as the entry table's `Frozen` row) | `absent → E` is legal exactly once; any change thereafter is a violation. Set-once, not merely non-decreasing: *raising* the epoch reclassifies every published entry as pre-epoch/legacy and nullifies the attestation mandate while staying technically non-decreasing. |

Violations attributed to the reserved root key raise `TNG-INDEX-ROOT-MUTATED`
(§3.5.3; lands with implementation slice). Ownership follows the
attestation-order rule above: this section owns root-field orders; the
document that introduces a field owns its type.

> NORMATIVE (dominance fold): A conformant implementation MUST implement
> **one** generic `dominates(baseline_entry, candidate_entry) → violations`
> fold over field/order-kind tags — root-vs-entry comparison is thereby a
> *data* difference (which entry key is being compared), not a second code
> path. Adding a field later means tagging it with an order kind, not
> writing a new prose carve-out or a new comparison branch.

> NORMATIVE (set-once is per-observed-history): the ratchet (§3.5.2)
> compares exactly two states, so "exactly once" in the Frozen and
> attestation-epoch rows above is enforced relative to the *current
> baseline*, not globally across all of history. Every trust-anchor
> re-establishment — first-contact TOFU, `milpa index accept`, or
> corrupt-baseline recovery (§3.5.2) — re-anchors it: a
> `V₁ → absent → V₂` rewrite whose steps all fell before the new anchor is
> indistinguishable, at that anchor, from a legal first backfill. This is
> not a gap unique to this row — it is the same TOFU/re-anchoring bound
> that applies to the whole ratchet, restated here because the Frozen and
> set-once rows are where it is most visible. A continuously observing
> consumer (one that never re-anchors) still catches the rewrite as a
> `frozen-changed` violation. `index-history "off"` does **not** create a
> re-anchoring gap: `off` freezes the baseline in place but never deletes
> it (§3.5.2).

Two derived rules, stated explicitly because they follow non-obviously from
the invariant above:

> NORMATIVE (no in-band correction path): There is no sanctioned way to
> "fix" a mis-published entry in place. The sanctioned remedy for a
> mis-published entry is: yank it (§3.2) and publish a corrected *new*
> version. An index-generator bug that produced a wrong `dep_decl`, for
> instance, is a mutation of resolution-relevant history like any other —
> a "trusted correction" path would be indistinguishable, consumer-side,
> from the attack this section exists to detect.

> NORMATIVE (registry migration is out-of-band): a catastrophic
> operator-side history rewrite (e.g. a registry migration) is not
> absorbed silently by any policy value. Consumers under `warn` or `strict`
> alarm (§3.5.2); each must explicitly accept the new history via
> `milpa index accept` (`spec/cli-contract.md`). That friction is
> deliberate — history rewrites must never be silently absorbable.

> NORMATIVE (semantic, not byte-level): the invariant constrains the
> **parsed** entry map, never the document's serialization. Re-serializing,
> re-ordering, or re-formatting the `index.kdl` document is always legal
> and produces no violation.

> NORMATIVE (staged enforcement): the lattice above is complete in this
> spec as of this amendment, but two rows constrain fields the parse
> boundary does not yet type: the attestation record and the `rekor` block
> (§3.2 still specifies these as parsed-and-ignored pending
> `rfc-per-entry-attestation.md`'s P2 slice, and a pinned regression test
> asserts `IndexVersion` carries no `rekor` attribute today). Enforcement
> of a given row lands with the slice that makes its fields parse-to-typed:
> `content_hash` / `dep_decl` / `dep_decl_schema_version` / presence /
> provenances are parseable today; `published_at` and the yank triple gain
> parse-to-typed handling, and this section's checks over them gain
> enforcement, at `rfc-registry-append-only.md`'s A2 slice; the attestation
> record and `rekor` rows (including the `attestation-epoch` root field)
> enforce at that RFC's A6 slice, after Part 2's P2 parser change lands.
> Until the corresponding slice lands, this section specifies the target
> behavior; it does not itself change what any implementation currently
> enforces.

#### 3.5.2  The consumer ratchet

**Where the check runs.** The ratchet runs on **every code path that
persists a network-fetched index** — both the ordinary stale-refetch path
(§6 State 2) and any bounded crash-recovery re-fetch (§3.4.2). A candidate
arriving via crash recovery is exactly as untrusted as an ordinary State-2
fetch; leaving it unratcheted would make forced cache corruption a
smuggling channel. The check runs **after** the §3.4 whole-index gate
succeeds and **before any cache mutation begins**, including the bundle
sidecar write — gating only the final index write would leave a
strict-rejected fetch having already overwritten the bundle sidecar, a torn
state the next read would misdiagnose as crash corruption.

> NORMATIVE: Pure cache reads and offline fallback (§6 States 1 and 3) MUST
> NOT run the ratchet — there is no new state to compare. `milpa verify`'s
> offline re-verification of the cached index is likewise out of scope
> (single-state, nothing to diff).

**Baseline sidecars.** A conformant implementation maintains a sidecar pair
per index cache key (§6), distinct from the bundle sidecars of §3.4.2:

- `<cache-key>.index.kdl.baseline` — a full copy of the last index that
  passed the ratchet cleanly. Written atomically (temp file + rename).
- `<cache-key>.index.kdl.baseline.meta` — one small KDL document carrying
  the metadata that must move in lockstep with the baseline:
  `established_at` (the TOFU/advance timestamp — when this consumer first
  trusted this URL, or last re-anchored it), `reported_digest` and
  `reported_at` (the canonical digest, §3.5.3, of the last-warned violation
  set, and when it was *first* reported — the values the *warn* recurrence
  text below reads). This is deliberately **one** sidecar with one atomic
  write, not two independently-torn files: a crash between two separate
  writes could leave a stale digest that silently mispaints a *new*
  mutation as recurring.

> NORMATIVE: `.baseline.meta` is advisory (observability and the
> habituation defense of §3.5.3, never a trust boundary): if it is missing
> or stale relative to `.baseline` (a crash in the window between their
> writes), an implementation MUST treat the reported-violation-set as unset
> — the next warning counts as new. This is self-healing and has no
> security impact.

Both sidecars are part of the same `<cache-key>.index.kdl*` sidecar family
as the bundle sidecars (§6); `milpa clean` MUST NOT remove them, for the
same reason it MUST NOT remove the index cache (§6).

> NORMATIVE (sticky-advance baseline): the baseline advances **only on a
> clean diff** (no violations). It is deliberately NOT the served cache
> file: under `warn`, the served cache advances to the new index (matching
> §3.4's existing warn semantics — warn is observability), but the
> **comparison base** does not advance on a dirty diff. If it did, a single
> warning would be the attack's entire cost and the mutated history would
> become the new baseline (ratchet poisoning: alarm once, then self-heal
> into the attacker's history). With a sticky baseline, every subsequent
> refresh re-alarms until the mutation is reverted upstream or the operator
> explicitly accepts it (`milpa index accept`, below).

> NORMATIVE (write ordering): a conformant implementation MUST write, in
> order: (1) the ratchet check itself (no mutation); (2) the bundle
> sidecar; (3) the index file (rename into place); (4) the freshness stamp;
> (5) the baseline (only on a clean diff); (6) `.baseline.meta` (last). The
> baseline MUST be written strictly **after** a successful index write, so
> it only ever reflects content actually served — a crash between them
> costs one redundant re-diff on the next refresh (safe), whereas writing
> the baseline first could advance trust past content that was never
> served. A crash between the baseline and `.meta` writes is covered by
> `.meta`'s advisory/self-healing rule above.

> NORMATIVE (concurrency): two invocations racing a refresh of the same URL
> MUST NOT be able to poison the baseline. This follows from sticky-advance
> by construction: the baseline only ever advances to a candidate that
> passed a clean diff against a valid baseline, so the worst interleaving
> is a duplicate warning or a diff computed against a one-step-older
> baseline — both self-heal on the next refresh. No lock file is required
> or specified. All index-cache sidecar writes (bundle, index, baseline,
> `.meta`) MUST use a per-write-unique temporary sibling file name (e.g.
> PID + random suffix) before the atomic rename — a fixed temporary name
> allows two concurrent writers to interleave partial writes before either
> renames, a hazard this section's additional sidecars would otherwise
> multiply.

> NORMATIVE (baseline corruption is not TOFU): an *absent* baseline file
> means legitimate first contact (TOFU, below). A *present but
> unparseable or truncated* baseline — including a baseline whose
> `schema_version` exceeds this consumer's supported version
> (`TNG-SCHEMA-UNKNOWN`-shaped skew, but on **local trust state**, not
> served content) — MUST hard-fail with `TNG-INDEX-BASELINE-CORRUPT`
> (lands with implementation slice) under **`warn` and `strict` alike**,
> mirroring §3.4.2's second-mismatch crash-recovery discipline. This check
> does not fire under `index-history "off"` (the file is never read under
> that policy — see the policy table below). The error message SHOULD name
> version skew as a likely cause when applicable, but MUST NOT reuse the
> generic `TNG-SCHEMA-UNKNOWN` slug, which is reserved for served content.
> Any parse or decode error on the baseline read maps to
> `TNG-INDEX-BASELINE-CORRUPT`; raw parser error slugs MUST NOT leak
> through this path. Silently degrading a corrupt baseline to TOFU would
> make "corrupt the baseline file" a free ratchet reset. Recovery from this
> state is `milpa index accept` (below).

> NORMATIVE (the check): a conformant implementation parses the baseline
> and the candidate with the shared index parser (extended per §3.5.1's
> staged-enforcement note), diffs the two entry maps, and evaluates the
> §3.5.1 dominance relation per entry (including the reserved root-field
> entry). All violations are collected into a structured list (§3.5.3); on
> any violation the baseline does not advance. Parsing the candidate at
> this gate — **before** any cache mutation, not after, as an ordinary
> fetch-then-parse sequence would do — is itself a normative behavior
> change from a naive implementation: an unparseable candidate MUST NOT
> clobber a good cache. Fixture-level conformance pins this: fetch OK,
> candidate fails to parse → the index file, bundle sidecar, and freshness
> stamp are byte-identical to their pre-fetch state.

**Policy axis: `index-history`.** This section's checks are gated by their
own policy axis, `index-history` (manifest node) / `MILPA_INDEX_HISTORY`
(env var), values `off | warn | strict`, default `warn` — an instantiation
of the generic policy-axis model (§3.4.0) with member-error slug
`WS-INDEX-HISTORY-ON-MEMBER` (lands with implementation slice). It does
**not** ride `index-trust`: a validly-signed, maximally-fresh index can
still be an invalid successor (an independent failure mode), and the
remediations differ entirely (re-fetch a bundle vs revert upstream / accept
a migration) — the axis-separation criterion §3.4.0 states. Two concrete
configurations the single-knob alternative cannot express: an unsigned
private registry (`index-trust "off"`) still wants history-integrity
detection (the ratchet is a pure content diff, no Sigstore dependency); a
known migration window wants `index-trust "strict"` (signatures stay hard)
together with `index-history "warn"` (acknowledged churn).

> NORMATIVE: when `index-trust` is `off`, the ratchet still runs under its
> own `index-history` policy — it then compares Layer-1-unverified
> documents. This is weaker than the signed case, but still detects CDN
> tampering and index-generator bugs; the residual is stated so it is not
> mistaken for a guarantee.

> NORMATIVE (per-policy behavior):
>
> | `index-history` value | Behavior |
> |---|---|
> | `off` | No ratchet runs. The baseline sidecar pair is neither read nor written. An existing baseline is **preserved**, never deleted — re-enabling the axis resumes the comparison from the frozen baseline, so mutations that occurred during the `off` window alarm on the first post-re-enable refresh. This is intended behavior: the churn either gets reverted upstream or is explicitly accepted (`milpa index accept`). |
> | `warn` (default) | On a violation: warn to stderr; serve the new index (matching §3.4's warn semantics); the baseline does NOT advance. To resist habituation, the warning distinguishes **new** from **recurring** violations: the violation set's canonical digest (§3.5.3) is compared against `.meta`'s `reported_digest`; an unchanged digest is reported as recurring (naming the `reported_at` timestamp), a changed digest is reported as new and `reported_digest`/`reported_at` are rewritten. A chronic unresolved alarm MUST NOT be able to mask a second, later mutation. |
> | `strict` | On a violation: hard fail; **no cache mutation at all** (no bundle write, no index write, no freshness-stamp advance). The cached previous index remains in place; the resolve that triggered the refresh fails with the violation's slug. Because the freshness stamp never advances, every subsequent invocation re-enters the network-fetch path and re-alarms until the index is reverted upstream or the operator explicitly accepts it. |

**TOFU.** Baselines are per-URL, keyed the same way as every other index
cache artifact, and persistent: returning to a previously-used
`MILPA_INDEX_URL` reuses that URL's existing baseline. TOFU applies only to
a URL with **no baseline file** — first contact ever, not "the URL's
content changed this invocation."

**The inspection and reset surface.** Two verbs, `milpa index status` and
`milpa index accept`, are the dedicated, loud, explicit interface for
inspecting ratchet state and accepting a history change; `milpa clean`
remains exactly as specified in §6 — it never touches the index cache or
any baseline sidecar. Full verb-spec blocks (Purpose / NORMATIVE behavior /
exit codes / stdout-stderr split) are specified in `spec/cli-contract.md`.
The baseline-sidecar interactions of both verbs are summarized in §6.

**Ephemeral environments (CI).** A fresh cache directory on every run means
permanent TOFU — the sticky baseline never sticks. Three points, in order
of how much of the CI population they cover:

1. The dominant CI shape (a committed lockfile driving the frozen path) is
   already immune: the frozen path never consults the index at all, and
   the lockfile's per-dep `content_hash` pins are the repo-committed trust
   anchor for everything the project actually depends on (the `go.sum`
   analog).
2. CI jobs that *resolve* (`lock`, `update`, first `add`) get ratchet
   protection only if the runner persists `$XDG_CACHE_HOME/milpa/index/`
   across runs (a standard cache-action shape, keyed per index URL).
   `milpa index status`'s exit code (nonzero on pending violations) gives
   such pipelines a cheap gate.
3. A structurally stronger design — a project-local, **committable**
   baseline anchor, so a fresh runner inherits the repo's trusted history
   instead of TOFU — is deliberately deferred: filed as **#188**. It is
   real design work with real interactions (a compact baseline
   representation and its drift hazard, the `accept` flow, workspace
   roots) and is out of scope for this amendment.

#### 3.5.3  Error taxonomy & diagnostics

Four checks are specified by §3.5.1; each maps to a distinct slug. All four
slugs land with their raise sites (bijection discipline) at
`rfc-registry-append-only.md`'s implementation slices — they are not yet
part of `spec/errors.md` as of this spec-only amendment:

| Slug (lands with implementation slice) | Condition | Policy |
|---|---|---|
| `TNG-INDEX-ROOT-MUTATED` | A document-root field violates its §3.5.1 root-field order (`schema_version` decrease; `attestation-epoch` change once set). | gated by `index-history` |
| `TNG-INDEX-ROLLBACK` | A package or version present in the baseline is absent from the candidate (the presence-component dominance failure). | gated by `index-history` |
| `TNG-ENTRY-MUTATED` | An entry present in both baseline and candidate violates a §3.5.1 field-class order (frozen-field change, monotone downgrade/strip/re-attribution/re-pin, provenance removal). | gated by `index-history` |
| `TNG-INDEX-BASELINE-CORRUPT` | The baseline sidecar exists but is unparseable or truncated. | hard fail **regardless of `index-history` policy** (§3.5.2) |

> NORMATIVE (ordering and precedence — one rule): all violations found in a
> single diff MUST be sorted by the composite key
> `(class_rank, namespace, name, version, field)`, where
> `TNG-INDEX-ROOT-MUTATED` has rank 0 (document-level violations beat
> entry-level — the bluntest signal), `TNG-INDEX-ROLLBACK` has rank 1, and
> `TNG-ENTRY-MUTATED` has rank 2 (root-field violations sort with an empty
> entry key: `namespace = name = version = ""`). The trailing `field`
> component breaks ties between two violations on the same entry key — in
> particular, two simultaneous root-field violations (both rank 0, both
> empty entry key) sort by field name (`attestation-epoch` before
> `schema_version`). The raised or warned diagnostic carries the *first*
> element of the sorted list as its slug and the full sorted list as its
> payload. Both impls MUST produce identical output for the same input:
> given package `aaa` with a frozen-field mutation and package `zzz` with a
> version disappearance in the same diff, the reported slug is
> `TNG-INDEX-ROLLBACK` (rank wins over alphabetical position), the
> primary-named entry is `zzz`'s, and `aaa`'s mutation appears in the
> payload list.

> NORMATIVE (structured payload): the raised or warned diagnostic MUST
> carry `violations=[…]`, where each element is a
> `(class, entry_key, field, kind, baseline_value, candidate_value)` tuple
> and `kind` is one of: `frozen-changed | frozen-unset | monotone-stripped
> | monotone-reattributed | monotone-downgraded | monotone-repinned |
> provenance-removed | root-field-changed`. The sub-class lives in the
> payload, not in additional slugs — these sub-classes are deterministic
> products of the §3.5.1 lattice, so one raise site with a
> machine-readable discriminator preserves both the bijection discipline
> and the incident-response distinction between them (a rollback suggests
> takedown; a `content_hash` swap suggests live substitution; an
> attestation downgrade may be a backfill-tool bug).
>
> Whole-entry *presence* violations (a baseline version or package node
> absent from the candidate — the presence component of §3.5.1's product
> order) are reported with `field` = the empty string and
> `kind = frozen-unset`: presence is a Frozen-class member with no field
> of its own, so the reserved empty field name mirrors the reserved
> empty entry key used for root fields. This rendering is normative —
> the canonical violation digest below hashes these components, so both
> implementations MUST emit identical bytes for the same rollback.

> NORMATIVE (canonical violation digest): the habituation defense of
> §3.5.2's *warn* row depends on both implementations computing the *same*
> digest of a violation set. Definition: sha256 over the UTF-8
> concatenation of one line per violation, the lines in the composite-key
> order above, each line the tab-joined 7-tuple
> `(class, namespace, name, version, field, kind, candidate_value)` with
> absent components rendered as empty strings, each line `\n`-terminated.
> `candidate_value` is the raw document string exactly as served — never
> re-formatted, since value re-formatting is the likeliest cross-impl
> divergence surface — and is included precisely so that a *second*
> mutation of the same field (e.g. `V₂ → V₃` while the first alarm is
> still unresolved) changes the digest and is reported as new, not masked
> as recurring. `baseline_value` is deliberately excluded from the digest
> (the baseline is frozen while violations persist, so it adds no
> discriminating information).

> NORMATIVE (remediation hints required): both the `warn` diagnostic text
> and the `strict` error text MUST name the two sanctioned exits: revert
> the mutation upstream, or run `milpa index accept` after out-of-band
> confirmation that the rewrite is legitimate.

> NORMATIVE (yank-transition notices are not errors): a yank-state change
> observed between the baseline and the candidate (either direction) MUST
> be reported on stderr, using the codebase's single non-fatal stderr
> convention, with the stable prefix `[milpa] warning:` — the line reads
> `[milpa] warning: yank-state changed: <namespace>/<name>@<version>`
> naming the direction and, when present, `yanked_reason`. Un-yank of an
> entry that carries a `yanked_reason` (restoring a CVE-yanked version) is
> the primary case this exists for. Notices fire under `warn` and `strict`
> alike, MUST NOT affect the exit code, and MUST NOT block the baseline
> from advancing — the transition is legal under §3.5.1's advisory-mutable
> class. Because a legal transition advances the baseline, the notice
> naturally fires once per transition, not on every subsequent refresh.
> The "legal, not an error, exit code unaffected" semantics live in this
> spec and in the diagnostic wording, not in the stderr prefix — a
> `[milpa] warning:` line is not, by itself, evidence of a policy failure.

#### 3.5.4  Publication watermark

> NORMATIVE (definition): for a given baseline, define
> `T(baseline) := max(published_at)` over the entries present in that
> baseline (entries without `published_at` contribute nothing to the max).
> The anchor is verified index content, never the consumer's wall clock —
> a consumer-clock anchor would add a trust dependency on exactly the
> party (the local environment) this design otherwise avoids.

A clean baseline is therefore a **watermark**: any entry not present in it
was necessarily published after the baseline was established.

> NORMATIVE: a **new** entry (one absent from the baseline) claiming
> `published_at < T(baseline) − skew` is backdated and consumer-detectable
> without trusting the registry operator. `skew` is an explicit tolerance
> (reference default: 24 hours) absorbing indexing-pipeline jitter; the
> check assumes the registry's indexer appends entries in non-decreasing
> `published_at` order — an operational guarantee that must hold on the
> registry side, not merely an implementation detail of this check.

Two scope caveats: the watermark is **per-consumer** — a TOFU/first-contact
consumer has no baseline and gets no backdate protection from this
mechanism — and an entry that simply **omits** `published_at` dodges the
check entirely. Closing the omission dodge requires `published_at` to be
mandatory on post-epoch entries, which is Part 2's epoch mandate
(`rfc-per-entry-attestation.md` open question 2); that dependency is
recorded here so this section's baseline semantics are not later weakened
in a way that breaks it. The backdating check itself
(a `TNG-ENTRY-BACKDATED`-class check) is out of scope for this section —
it lands with Part 2's P3 slice, where entry-level policy machinery exists;
this section guarantees only the baseline semantics (the watermark
definition above) that make that check possible.

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

> NORMATIVE (staged — enforcement lands at `rfc-registry-append-only.md`'s
> A5 slice): once a version's `yanked` field (§3.2) is `#true`, it MUST be
> excluded from constraint-filtered candidate enumeration, before ordering
> and constraint matching, in **both** named-lookup entry points —
> `resolve_named_all` (§5.5) and its S5b qualified counterpart
> `resolve_named_all_qualified` (§5.1a). Named explicitly because the
> qualified path is exactly where a parallel-logic miss has happened
> before. The frozen path (lockfile-backed reconstruction, which never
> consults the index) MUST NOT apply this exclusion — an already-locked
> yanked version continues to reproduce unaffected; yank steers new
> selection, it never breaks reproduction. If every constraint-satisfying
> version is excluded because all are yanked, the existing
> `TNG-NO-SATISFYING-VERSION` error (§5.4) fires and its message MUST
> additionally name the yanked-but-excluded candidates. There is no
> `--allow-yanked` escape hatch (§3.2). This clause specifies the selection
> semantics as of this spec-only amendment (A1); it is not yet enforced —
> enforcement, fixtures, and the `TNG-NO-SATISFYING-VERSION` message change
> land at A5.

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

> NORMATIVE (append-only ratchet baseline sidecars): in addition to the
> `<cache-key>.index.kdl` index file and its `.bundle` / `.no-bundle`
> sidecars (§3.4.2), a conformant implementation maintains a second sidecar
> pair per cache key once the `index-history` axis (§3.5.2) is not `off`:
> `<cache-key>.index.kdl.baseline` (the last index that passed the
> append-only ratchet cleanly, a full copy) and
> `<cache-key>.index.kdl.baseline.meta` (a small KDL document carrying
> `established_at`, `reported_digest`, and `reported_at`). Both sidecars
> are part of the same `<cache-key>.index.kdl*` glob family as the bundle
> sidecars — `milpa clean` MUST NOT remove them, for the same reason it
> MUST NOT remove the index cache (above). The full lifecycle (sticky
> advance, write ordering, TOFU, corruption handling, per-policy behavior)
> is normatively defined in §3.5.2; this clause states only that the
> baseline pair is part of the index cache's on-disk footprint.

> NORMATIVE: `milpa index status` and `milpa index accept`
> (`spec/cli-contract.md`, `§3.5.2` of this document) are the only commands
> that read or write the baseline sidecar pair outside the ordinary
> ratchet-gated fetch path. `status` never writes it under any invocation,
> including `--refresh`. `accept`'s only mutation beyond an ordinary forced
> refresh is the atomic baseline swap.

> NOTE: Per-URL baseline sidecars accumulate for registries no longer in
> use, the same way index and bundle sidecars already do. This is an
> accepted non-goal for v1: `milpa clean` deliberately does not
> garbage-collect them (above) — absolute sizes are trivial and URL churn
> is rare. A future store-gc mini-RFC (Tier 3 roadmap) is the right home
> for an index-cache GC clause, not this section or `clean`.

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
