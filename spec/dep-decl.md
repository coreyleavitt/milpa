# milpa dependency declaration (DepDecl) — joint milpa↔tianguis contract (S0)

Normative spec of the **DepDecl** (Dependency Declaration) artifact — the
canonical, content-addressed, Rekor-attested serialization of a package
version's edge set. This file is the **single normative contract** shared
between milpa (consumer) and tianguis (producer). Both sides MUST implement
the rules marked `> NORMATIVE:`. Items marked `> NOTE:` are informative.

**Scope:** this document owns the `EdgeSet` type, the `canonical_serialize`
byte-level rules, the `dep_decl_hash` algorithm, `dep_decl_schema_version`
discipline, schema consistency validation, the five `TNG-DEPDECL-*` error
codes, and the normative `.nimble`→`EdgeSet` heuristic. The resolver
consumption model (`DepDeclEdgeSource`, `DepDeclStore`) is specified in
`spec/resolver-semantics.md` (S6). Index pointer fields are specified in
`spec/registry-protocol.md` (S14). Lockfile pin is specified in
`spec/lockfile-schema.md` (S5 §3.7).

Related specs:

- `spec/errors.md` — cross-reference for `TNG-DEPDECL-*` codes (owned here)
- `spec/identity.md` (S12) — `dep_decl_hash` encoding mirrors `content_hash`
- `spec/manifest-grammar.md` (S4) §5 — cross-references §7 of this doc
- `spec/registry-protocol.md` (S14) — `dep_decl` + `dep_decl_schema_version`
  pointer fields in the index version-node
- `spec/lockfile-schema.md` (S5) §2.4 — byte-canonicalization precedent;
  §3.7 for `dep_decl` lockfile pin + `VERIFY-EDGE-MISMATCH`

---

## Normative surface

A conformant implementation of this spec MUST:

1. Represent the in-memory edge set as a single `EdgeSet` value with the
   three fields defined in §1: `requires`, `src_dir`, and the in-memory-only
   `source` fidelity tag. No parallel type duplicates this.
2. Compute `dep_decl_hash` as `"sha256:" + hex(sha256(dep_decl_bytes))`
   (§3), using the same encoding as `content_hash` in `spec/identity.md`.
3. As a **producer**, emit DepDecl artifact bytes by following all seven
   character-level rules of §2 exactly. Any degree of freedom KDL 2.0 leaves
   open that is not pinned by §2 is invalid in a DepDecl artifact.
4. As a **consumer**, verify `sha256(received_bytes) == dep_decl` against
   the index pointer before parsing, and raise `TNG-DEPDECL-HASH-MISMATCH`
   on mismatch (§3).
5. Reject a DepDecl artifact whose embedded `dep_decl_schema_version` exceeds
   the implementation's maximum understood version with
   `TNG-DEPDECL-SCHEMA-UNSUPPORTED` (§4).
6. Verify that the artifact's embedded `dep_decl_schema_version` matches the
   index version-node pointer's `dep_decl_schema_version` field, and raise
   `TNG-DEPDECL-SCHEMA-MISMATCH` on disagreement (§5).
7. Parse `.nimble` transitive-dep files using the normative heuristic in §7;
   this is the **single authoritative spec** for the algorithm shared across
   all impls (milpa Python/Rust resolvers and tianguis ingest).

---

## 1  EdgeSet type definition

**EdgeSet** is the language-neutral in-memory type representing one package
version's declared dependency edges. It is the single shared type consumed by
the resolver, regardless of which source supplied the edges.

```
EdgeSet = {
    requires:  [ NamedRequire | UrlRequire ]  # declarations, authored order
    src_dir:   string                          # "" when unset
    source:    "dep_decl" | "milpa_kdl" | "nimble_fallback"
                                               # fidelity tag — NOT serialized
}

NamedRequire = {
    name:            string
    constraint_str:  string
    predicates:      tuple[Predicate, ...]     # optional; defaults empty
                                               # in-memory only — NOT serialized
                                               # in v0 DepDecl artifacts (#134)
}
UrlRequire = {
    url:        string
    ref:        string
    predicates: tuple[Predicate, ...]          # optional; defaults empty
                                               # in-memory only — NOT serialized
                                               # in v0 DepDecl artifacts (#134)
}
```

The `Predicate` type is the same type defined in `spec/manifest-grammar.md §6` — there is one predicate model shared across manifest conditionals and nimble-fallback annotations.

> NORMATIVE: `EdgeSet` is the **single** edge type in each implementation.
> There MUST NOT be a separate "DepDecl type" duplicating it. The `.nimble`
> heuristic (§7), `milpa.kdl` parsing, and DepDecl artifact parsing all
> return an `EdgeSet`. (Cross-reference: `rfc-content-addressed-metadata.md`
> §3.2 SSOT rationale.)

> NORMATIVE: The `predicates` field on `NamedRequire` and `UrlRequire` is
> **in-memory only**. It MUST NOT appear in any serialized v0 DepDecl artifact.
> For edges derived from the `.nimble` heuristic (§7), the field carries the
> translated `Predicate` tuple from recognized `when` conditions (§7.5). For
> edges from a DepDecl artifact or `milpa.kdl`, the field is empty. The field
> flows through the edge-source bridge into the resolver and is recorded in the
> lockfile as an additive `cond-require` annotation (see `spec/lockfile-schema.md`
> §3.5). Carrying predicates inside DepDecl artifact bytes is a schema-v1
> change deferred to #134.

> NORMATIVE: The `source` field is **in-memory only**. It MUST NOT appear in
> any serialized artifact (lockfile, DepDecl, index). Its sole purpose is to
> allow the resolver and diagnostics layer to distinguish the fidelity of the
> edge source at runtime. Serializing `source` would change `dep_decl_bytes`
> and therefore corrupt the `dep_decl_hash` invariant — an implementation that
> includes `source` in serialized output is non-conformant.

> NORMATIVE: `requires` entries MUST be maintained in **authored order** — the
> order in which they appear in the source (`milpa.kdl`, `.nimble`, or the
> DepDecl artifact). The BFS frontier ordering invariant in
> `spec/resolver-semantics.md` §4.2.1 depends on authored order being preserved
> end-to-end.

### 1.1  Forward-axis extension model

`EdgeSet` is versioned via `dep_decl_schema_version` (§4). Future fields
attach to later schema versions:

- `dep_decl_schema_version 0` — v0 fields: `requires`, `src_dir`.
- **Any additive field serialized in the artifact** (e.g., `capabilities` from
  `rfc-beyond-pubgrub.md` D2, or per-condition branches from issue #134 — the
  DepDecl artifact carrying predicates) is a **schema-version bump**, not a
  retroactive extension of v0. NOTE: issue #26 adds `predicates` to the
  in-memory `RequireEntry` type (§1) but does NOT serialize them in v0 DepDecl
  artifacts; that is deferred to #134. The `RequireEntry.predicates` field is
  therefore not a schema bump.

A v0 DepDecl artifact is **never** re-read as if it had a later schema's
fields. Old `dep_decl_hash` pins remain valid for v0 artifacts indefinitely.

---

## 2  `canonical_serialize` — character-level producer contract

> NORMATIVE: `canonical_serialize(EdgeSet) → bytes` MUST produce
> **byte-identical output** for the same logical `EdgeSet` across all producers,
> at all times. The same `EdgeSet` MUST always yield the same `dep_decl_bytes`
> and therefore the same `dep_decl_hash`. A producer that allows any
> non-determinism (e.g., set-order fields, non-deterministic dictionary
> iteration, locale-dependent string encoding) is non-conformant.

The following seven rules govern every character of the output. **All
degrees of freedom that KDL 2.0 leaves open are resolved here** — there is
no room for "reasonable alternatives."

### Rule 1 — Document shape

> NORMATIVE: The artifact MUST be a single top-level KDL 2.0 `dep_decl { … }`
> node with the following exact structure:
>
> ```
> dep_decl {
>     <children>
> }
> ```
>
> Where `<children>` are the fields defined in rules 2–6, each on its own
> line, indented with exactly **4 spaces** (not tabs). The closing `}` is on
> its own line with no indentation. No other top-level nodes are permitted.

> NORMATIVE: The document MUST end with exactly one trailing newline character
> (`0x0A`). The last byte of the file is `0x0A` (the newline after the closing
> `}`). No blank line follows the `}`.

> NORMATIVE: No KDL comments are emitted in a DepDecl artifact.

### Rule 2 — Field order

> NORMATIVE: The child fields MUST appear in this exact order:
>
> 1. `dep_decl_schema_version`
> 2. `src_dir`
> 3. `require` nodes (one per entry, in authored order — see rule 3)
> 4. *(future v1+ fields appended here, in schema-version-table order)*
>
> No other field order is conformant.

> NORMATIVE: `dep_decl_schema_version` MUST be emitted as an **unquoted
> integer** (KDL 2.0 integer literal), not as a string. Example:
> `    dep_decl_schema_version 0`

### Rule 3 — `requires` authored order

> NORMATIVE: The `require` child nodes MUST appear in the same order as the
> entries in `EdgeSet.requires` — the order in which they were declared in
> the authoritative source. Producers MUST NOT sort, deduplicate, or otherwise
> reorder entries. Authored order is the normative order.

> NORMATIVE: There are **zero or more** `require` nodes. An `EdgeSet` with an
> empty `requires` list produces a document with no `require` children (only
> `dep_decl_schema_version` and `src_dir`).

### Rule 4 — Entry encoding forms

> NORMATIVE: Each `EdgeSet.requires` entry is encoded as a `require` child
> node. The exact KDL form depends on the entry kind:
>
> **Named require** (`NamedRequire { name, constraint_str }`):
>
> ```kdl
>     require "<name>" "<constraint_str>"
> ```
>
> - Node identifier: `require`
> - First positional argument: the package name, double-quoted string
> - Second positional argument: the constraint string, double-quoted string
> - No properties
>
> **URL require** (`UrlRequire { url, ref }`):
>
> ```kdl
>     require (url)"<url>" ref="<ref>"
> ```
>
> - Node identifier: `require`
> - First positional argument: the URL, `(url)`-annotated double-quoted string
> - One property: `ref` with a double-quoted string value
> - No other arguments or properties
>
> These are the **only two forms**. No other node identifier, argument order,
> or property form is conformant.

> NORMATIVE: The KDL node identifier is always `require` (lowercase, singular).
> Not `requires`, not `dep`, not the package name itself.

### Rule 5 — Constraint string verbatim preservation

> NORMATIVE: The `constraint_str` of a `NamedRequire` MUST be serialized
> **verbatim** — exactly as the producer received it from the source.
> Whitespace within the constraint string is preserved as-written.
>
> `">= 1.0"` and `">=1.0"` are **different byte sequences** and therefore
> different `dep_decl_hash` values. This is **intentional**: the DepDecl
> attests what the source declared, not a normalized re-interpretation. A
> package that trims constraint whitespace between versions produces a new
> `dep_decl_hash` — a correct signal that the declaration changed.
>
> Producers MUST NOT normalize, canonicalize, or rewrite constraint strings
> before serializing.

### Rule 6 — Optional-field presence: explicit empty `src_dir`

> NORMATIVE: `src_dir` MUST **always be emitted**, even when the value is the
> empty string. The canonical form for an unset source directory is:
>
> ```kdl
>     src_dir ""
> ```
>
> Omitting `src_dir` entirely is non-conformant. A stable document shape
> (every v0 DepDecl artifact has exactly three top-level child types) is
> required for hash-stable evolution — a future `src_dir` field whose presence
> depends on the value would break hash comparisons.

### Rule 7 — String escaping and KDL 2.0 value forms

> NORMATIVE: All string values — names, constraint strings, URLs, refs, and
> `src_dir` — MUST be encoded as **KDL 2.0 double-quoted strings** with
> standard backslash escaping. The following forms are **non-conformant** and
> MUST NOT appear in a DepDecl artifact:
>
> - Single-quoted strings (`'…'`)
> - Raw strings (`#"…"#` / `##"…"##`)
> - Unquoted identifier values
> - The KDL 1.0 `true`/`false` bare identifiers (use `#true`/`#false` in
>   KDL 2.0; note: v0 DepDecl has no boolean fields, but this is a standing rule)
>
> The escaping rules are standard KDL 2.0: `\"` for a literal double-quote,
> `\\` for a literal backslash, and the standard C-like escapes for control
> characters (`\n`, `\r`, `\t`, `\u{…}`). Only characters that KDL 2.0
> requires to be escaped MUST be escaped; additional unnecessary escaping
> (e.g., escaping ASCII printable characters) is non-conformant.

> NOTE: This is the same defect class documented in
> `spec/lockfile-schema.md §2.4`. The `spec/lockfile-schema.md` canonical
> serialization precedent (`format_lockfile` / `_kdl_str`) applies the same
> discipline: every string passes through a single KDL escaper; no raw
> interpolation is used.

### Annotated v0 example

The following is the **hand-authored v0 golden vector** from
`conformance/spec-v1/dep-decl-golden/v0/example.kdl`. It represents an
`EdgeSet` with `src_dir = "src"`, two named requires (constraint whitespace
preserved as-written), and one URL require:

```kdl
dep_decl {
    dep_decl_schema_version 0
    src_dir "src"
    require "results" ">= 0.5.0"
    require "stew" ">= 0.1 & < 1.0"
    require (url)"https://github.com/status-im/nim-chronos.git" ref="v3.2.0"
}
```

Trailing newline (`0x0A`) after the closing `}`.

`dep_decl_hash` of this exact file:
`sha256:34a91f93fc03cadbd69379b97cdbac82110070ead8595038f0cc203e72d346bd`

---

## 3  `dep_decl_hash` algorithm

> NORMATIVE: The `dep_decl_hash` is computed as:
>
> ```
> dep_decl_hash = "sha256:" + hex(sha256(dep_decl_bytes))
> ```
>
> where:
> - `dep_decl_bytes` is the **exact UTF-8 byte sequence** produced by
>   `canonical_serialize` (§2).
> - `sha256(…)` is the standard SHA-256 digest function.
> - `hex(…)` encodes the 32-byte digest as **64 lowercase hexadecimal
>   characters** (`0`–`9`, `a`–`f`).
> - The prefix `"sha256:"` is a **literal 7-character ASCII string**.

> NORMATIVE: This encoding is **identical** to `content_hash` in
> `spec/identity.md §2.1`. The two are distinct hash axes over different
> artifacts (source tree vs declaration bytes), but the encoding format is
> the same: `<algorithm>:<64-lowercase-hex>`. A conformant implementation
> MUST validate `dep_decl_hash` strings with the same `parse_identity`
> semantics as `content_hash` (same algorithm set, same length, same
> lowercase-hex requirement).

> NORMATIVE: A **consumer** verifies by computing `sha256(received_bytes)` and
> comparing to the `dep_decl` pointer field from the index version-node. If
> they differ, the implementation MUST raise `TNG-DEPDECL-HASH-MISMATCH`
> and MUST NOT parse the bytes or use any data from them. This is the passive
> integrity check that rejects garbled artifacts in transit or in storage.

> NOTE: A producer computes `dep_decl_hash` **after** `canonical_serialize`,
> not before or in parallel. The hash is over the fully-serialized bytes, not
> over any in-memory representation.

### 3.3  DepDecl artifact URL derivation — `index_base_url`

The DepDecl artifact URL is derived from `MILPA_INDEX_URL` by the consumer
(see `docs/rfc-content-addressed-metadata.md §3.3` for the full rationale).
This section pins the normative case-sensitivity rule.

> NORMATIVE: The `<index_base_url>` is derived from `MILPA_INDEX_URL` by
> removing the last path segment of the URL iff that segment matches `*.kdl`
> or `index*` using an **ASCII-case-insensitive** comparison; otherwise the
> index URL with a `/` appended is used as-is.
>
> Examples:
> - `…/tianguis/main/index.kdl`  →  `…/tianguis/main/`
> - `…/tianguis/main/Index.KDL`  →  `…/tianguis/main/` (case-insensitive)
> - `https://example.com/registry/v2`  →  `https://example.com/registry/v2/`
> - `file:///home/user/conformance/index.kdl`  →  `file:///home/user/conformance/`
>
> The comparison MUST be **ASCII-case-insensitive** (`to_ascii_lowercase`
> before comparing). A URL segment `Index.KDL`, `INDEX.kdl`, or `Registry.KDL`
> MUST be stripped exactly as `index.kdl` or `registry.kdl` would be.

> NOTE: This rule applies to URL path segments only. Query strings and
> fragments are excluded from the segment match (strip them before computing
> the last segment). The `oci://` scheme has no path-directory segment and
> does NOT support URL-template derivation (see RFC §3.3).

### 3.3.1  DepDecl artifact transport size cap

> NORMATIVE: A consumer MUST impose a maximum on the number of bytes read from
> the network (or from a `file://` URL) when fetching a DepDecl artifact. The
> RECOMMENDED cap is **1 MiB** (1,048,576 bytes). A DepDecl artifact is KDL
> text with O(dozens) of `require` nodes; 1 MiB admits any plausible growth
> while bounding the resource-exhaustion surface (a compromised or misconfigured
> index can point `dep_decl` at an arbitrary URL).
>
> Enforcement MUST be two-layered:
> 1. **Content-Length early-reject**: if the HTTP response carries a
>    `Content-Length` header whose value exceeds the cap, the consumer MUST
>    raise `TNG-DEPDECL-FETCH-FAILED` without reading the body. (Content-Length
>    can lie; this is a fast path, not the sole defence.)
> 2. **Read cap**: the consumer MUST read at most `cap + 1` bytes; if the read
>    returns `cap + 1` bytes the body is oversized and the consumer MUST raise
>    `TNG-DEPDECL-FETCH-FAILED` with a message identifying the size limit.
>
> `TNG-DEPDECL-FETCH-FAILED` is the correct error class for this condition: in
> the non-strict path it enables the `.nimble` fallback; in strict mode it is
> always a hard failure — the same policy as any other unreachable artifact.
>
> A body of exactly `cap` bytes MUST NOT be rejected (equal-to-cap is within
> bounds).

---

## 4  `dep_decl_schema_version` discipline

### 4.1  Version semantics

> NORMATIVE: Every DepDecl artifact MUST carry exactly one
> `dep_decl_schema_version` child node inside the `dep_decl { }` block (see
> §2 rule 2). This integer self-describes the artifact's schema for offline
> parsing and for schema consistency validation (§5).

> NORMATIVE: A **schema version bump** is required whenever any field is added,
> renamed, removed, or has its encoding changed. Adding a new `require` entry
> kind, adding a new top-level field like `capabilities`, or changing the node
> identifier from `require` to any other name — all require a version bump.
> Editorial changes (spec clarifications, example updates) do NOT require a
> version bump. **The spec maintainer (Corey Leavitt, PRs to this repo)
> decides**; the bump table below (§4.2) is the normative registry.

> NORMATIVE: Schema versions are **non-negotiable epochs**: a v0 artifact is
> never a v1 artifact. A consumer MUST process a v0 artifact as v0 — it MUST
> NOT extrapolate or synthesize fields that do not appear in the artifact.

### 4.2  Schema-version registry

| `dep_decl_schema_version` | Fields included | Status |
|---|---|---|
| `0` | `requires` (named + URL entries), `src_dir` | Current; this spec |
| *(future)* | `capabilities`, per-condition branches, etc. | Requires RFC amendment |

### 4.3  Consumer version enforcement

> NORMATIVE: When a consumer parses a DepDecl artifact and finds
> `dep_decl_schema_version` > the implementation's `MAX_DEP_DECL_SCHEMA_VERSION`
> (the highest schema version the implementation was built to understand), it
> MUST raise `TNG-DEPDECL-SCHEMA-UNSUPPORTED` and MUST NOT attempt a
> best-effort parse of the artifact. Implementations that guess at unknown
> schema fields produce unverifiable results.

> NOTE: For implementations that understand only v0, `MAX_DEP_DECL_SCHEMA_VERSION = 0`.
> A v0 implementation reading a v1 artifact raises
> `TNG-DEPDECL-SCHEMA-UNSUPPORTED` immediately. The user must upgrade their
> milpa installation.

---

## 5  Schema consistency validation

> NORMATIVE: The index version-node carries **two** `dep_decl_schema_version`
> values: one embedded inside the DepDecl artifact bytes, and one in the
> `dep_decl_schema_version` field of the index version-node pointer
> (`spec/registry-protocol.md` S14 §3). A consumer MUST verify that these two
> integers agree **after** hash-verification (§3) and **before** consuming the
> parsed `EdgeSet`.

> NORMATIVE: If the artifact's embedded `dep_decl_schema_version` differs from
> the index pointer's `dep_decl_schema_version`, the consumer MUST raise
> `TNG-DEPDECL-SCHEMA-MISMATCH`. This condition indicates a partially-applied
> index update — the pointer claims one schema version but the artifact on disk
> is a different version. Both directions of mismatch (artifact newer than
> pointer, or artifact older than pointer) are errors.

> NORMATIVE: The schema consistency check is performed **in addition to** (not
> instead of) the version-enforcement check in §4.3. The order is:
> 1. Hash-verify: `sha256(bytes) == dep_decl` pointer → else `HASH-MISMATCH`.
> 2. Parse `dep_decl_schema_version` from the artifact bytes.
> 3. Version enforcement: artifact version ≤ `MAX_DEP_DECL_SCHEMA_VERSION` →
>    else `SCHEMA-UNSUPPORTED`.
> 4. Consistency: artifact version == index pointer version →
>    else `SCHEMA-MISMATCH`.
> 5. Parse the rest of the artifact as the declared schema version.

> NOTE: The `dep_decl_schema_version` field in the index pointer exists
> precisely to enable step 4 without requiring the consumer to parse the
> artifact to discover a disagreement. A consumer can see the mismatch from
> the index alone (before fetching the artifact) only by checking the pointer's
> version, but the authoritative check is on the fetched and hash-verified bytes.

---

## 6  Error codes

All five `TNG-DEPDECL-*` codes are **owned by this document** and
cross-referenced in `spec/errors.md` under the `TNG` prefix. Full raise-site
wiring is in S3b (resolver consumption) and S7 (tianguis ingest); the codes
are registered here so the catalog is aware from S0 onward.

| Code | Condition | Raised by |
|---|---|---|
| `TNG-DEPDECL-HASH-MISMATCH` | `sha256(received_bytes)` ≠ `dep_decl` index pointer | Consumer: `DepDeclStore.get` (§3) |
| `TNG-DEPDECL-FETCH-FAILED` | DepDecl artifact unreachable (network or file-not-found) | Consumer: `DepDeclStore.get` (S3b) |
| `TNG-DEPDECL-PARSE-ERROR` | Artifact bytes are not valid KDL 2.0, or the KDL structure does not conform to §2 | Consumer: DepDecl parser (S1) |
| `TNG-DEPDECL-SCHEMA-UNSUPPORTED` | Artifact `dep_decl_schema_version` > `MAX_DEP_DECL_SCHEMA_VERSION` | Consumer: version check (§4.3) |
| `TNG-DEPDECL-SCHEMA-MISMATCH` | Artifact `dep_decl_schema_version` ≠ index pointer's `dep_decl_schema_version` | Consumer: consistency check (§5) |

> NOTE: `TNG-DEPDECL-FETCH-FAILED` in the non-strict path (during the
> `--require-attested-metadata` transition; see §6 of
> `rfc-content-addressed-metadata.md`) results in an `RES-UNATTESTED-METADATA`
> warning and a fall-through to the `.nimble` fallback (§7), not a hard exit.
> In strict mode (`--require-attested-metadata`), every `TNG-DEPDECL-*` code
> is a hard failure.

---

## 7  Normative `.nimble`→`EdgeSet` heuristic

This section specifies the **single authoritative algorithm** for extracting
an `EdgeSet` from a `.nimble` file. All three independent implementations
(milpa Python resolver, milpa Rust resolver, tianguis ingest in Nim) MUST
produce **byte-identical `requires` order** for the `§3.6`
differential obligation to hold.

The heuristic is relocated here from `spec/manifest-grammar.md §5` (which
cross-references this section). The content is identical to what
`manifest-grammar.md §5` previously specified, sharpened to pin ordering
edge cases.

> NORMATIVE: The `.nimble` parser MUST extract `requires` and `srcDir` values
> using a **line-by-line scan**. It MUST NOT execute NimScript.

### 7.1  Scan order and multi-line continuation

> NORMATIVE: The scan processes the `.nimble` file **sequentially from the
> first line to the last**. Each `requires` statement is processed in the order
> it appears in the file. The scan collects entries into a sequence; it does
> NOT sort, deduplicate, or reorder them. **Authored file order is the output
> order.**

> NORMATIVE: The four recognized `requires` forms are:
>
> 1. **Single-line, single entry**: `requires "foo >= 1.0.0"`
> 2. **Single-line, comma-separated**: `requires "foo >= 1.0.0", "bar"`
>    — the entire comma-separated list is part of one `requires` statement.
> 3. **Multi-line continuation** (statement ends with a trailing comma):
>    the parser MUST join subsequent lines into the current statement until
>    a line is encountered that does **not** end with a trailing comma (after
>    stripping whitespace). Continuation lines are appended to the same
>    ordered sequence (left-to-right, top-to-bottom across all continuation
>    lines). A blank line or a comment line during a continuation MUST be
>    skipped and continuation MUST resume on the next non-blank, non-comment
>    line.
> 4. **Multiple independent `requires` statements**: each is processed as a
>    separate statement in file order. Entries from a later statement MUST
>    appear after entries from an earlier statement in `EdgeSet.requires`.

> NORMATIVE: When a name appears more than once across all scanned `requires`
> positions (including across multiple `requires` statements and across
> `when`-block branches), **it is included at every occurrence in authored
> file order** — no deduplication is performed. Over-inclusion is safe;
> under-inclusion would silently drop a dep.

### 7.2  Entry classification

> NORMATIVE: Each extracted quoted string from a `requires` statement is
> classified exactly as follows (in order):
>
> 1. **URL requirement** — if the string starts with any of:
>    `http://`, `https://`, `ssh://`, `git://`, `file://`
>    (case-sensitive prefix match on the scheme).
>    A `#ref` suffix (if present) is split off as the `ref` component;
>    the remainder (before `#`) is the `url` component. This produces a
>    `UrlRequire`. If no `#` is present, `ref` is the empty string `""`.
>
> 2. **Named requirement** — all other strings. The first whitespace-delimited
>    token (splitting on space, tab) is the `name` component; the remainder
>    of the string (after trimming any leading whitespace following the name)
>    is the `constraint_str` component. If no whitespace follows the name, the
>    `constraint_str` is the empty string `""`. This produces a `NamedRequire`.
>
> This two-branch classification is the **single authoritative rule** for
> URL-vs-named disambiguation in `.nimble` files.

### 7.3  `srcDir` extraction

> NORMATIVE: The scanner MUST extract the `srcDir` declaration using the
> pattern `srcDir\s*=\s*"([^"]*)"` (or equivalently a bare unquoted path
> form `srcDir\s*=\s*([^\s"#]+)`). The extracted path value populates
> `EdgeSet.src_dir`. If no `srcDir` declaration is found, `EdgeSet.src_dir`
> is the empty string `""`.
>
> Only the **last** `srcDir` assignment is used (NimScript assignment
> semantics: a later assignment overwrites an earlier one).

### 7.4  Comment-line handling

> NORMATIVE: A line MUST be treated as a **comment line** if, after stripping
> leading whitespace, it begins with `#`. Comment lines MUST be skipped
> entirely — they contribute no `requires` entries and do not interrupt
> multi-line continuation (see §7.1 rule 3).

> NORMATIVE: Inline `#`-prefixed content following a `requires` entry string
> is NOT stripped by the parser. The strings are delimited by their outer
> quotes; content after the closing quote of the last quoted string on a
> `requires` line is either a trailing comma (continuation signal) or ignored
> trailing content. Implementations MUST NOT attempt to strip inline `#`
> comments from within a requires-line string argument.

### 7.5  `when`-block policy

The `.nimble` scanner recognizes a bounded, well-defined subset of NimScript
`when` conditions and translates them into milpa `Predicate` tuples (per
`spec/manifest-grammar.md §6`). Everything outside that surface degrades to
the pre-#26 over-include + warn behavior. NimScript is never evaluated.

**The dep set is unchanged:** every `requires` from every branch is still
included unconditionally in `EdgeSet.requires`. Predicates are recorded as
metadata on the `RequireEntry.predicates` field (§1) and flow to the lockfile
as an additive `cond-require` annotation (`spec/lockfile-schema.md §3.5`).
Build-time activation (filtering the active dep set by the resolving profile)
is deferred to #110; #26 never under-includes relative to the pre-#26 behavior.

#### 7.5.1  Recognized condition → Predicate translation table

> NORMATIVE: Implementations MUST attempt to translate each `when` / `elif`
> condition string using the following table. A condition that does not match
> any row is **UNRECOGNIZED**. A recognized condition ALWAYS yields a
> **non-empty** tuple of `Predicate` instances; the function MUST NOT return an
> empty tuple for any recognized condition.
>
> | NimScript condition | Predicate(s) | Notes |
> |---|---|---|
> | `defined(windows)` or `defined(win)` | `platform="windows"` | `win` is a standard Nim alias |
> | `defined(macosx)` or `defined(macos)` | `platform="macosx"` | `macos` is a Nim ≥1.4 alias |
> | `defined(linux)` | `platform="linux"` | |
> | `defined(freebsd)` | `platform="freebsd"` | |
> | `defined(openbsd)` | `platform="openbsd"` | |
> | `defined(netbsd)` | `platform="netbsd"` | |
> | `defined(amd64)` | `arch="amd64"` | Nim `hostCPU` vocabulary |
> | `defined(arm64)` | `arch="arm64"` | |
> | `defined(i386)` | `arch="i386"` | |
> | `not <recognized-single>` | the predicate with `negated=true` | single negation only; flips the `negated` flag, does NOT invert the operator |
> | `NimMajor OP X` | `nim="OPX.0.0"` | OP ∈ `{>=, >, <, <=, ==}` |
> | `(NimMajor, NimMinor) OP (X, Y)` | `nim="OPX.Y.0"` | same OP set |
> | `(NimMajor, NimMinor, NimPatch) OP (X, Y, Z)` | `nim="OPX.Y.Z"` | three-tuple form; all five operators accepted |
> | `<nim-tuple> OP1 <v1> and <nim-tuple> OP2 <v2>` | `(nim="OP1v1", nim="OP2v2")` | two-sided range — tuple of two Predicates; AND semantics |
> | anything else | **UNRECOGNIZED** | `defined(posix)`, `defined(release)`, `defined(js)`, `defined(<custom>)`, general `or`, nested calls, etc. |
>
> **`nim` value spelling:** the canonical form is **space-free** — the operator
> is concatenated directly with the version string, e.g. `">=1.4.0"` not
> `">= 1.4.0"`. This is the single serialization form; both impls MUST produce
> this spacing. The lockfile `cond-require` annotation (§7.5.4) reproduces the
> same string verbatim.
>
> **`defined(posix)` is deliberately NOT recognized** (→ UNRECOGNIZED →
> over-include). Nim's `posix` predicate is true on platforms outside milpa's
> closed vocabulary (haiku, solaris, android-on-linux). Mapping it to a fixed
> OR set would under-include on those platforms — violating the invariant that
> this path never under-includes relative to today's behavior. Over-including on
> the few posix-using packages is the safe choice; a precise `posix` mapping
> waits on a formally closed platform vocabulary.

#### 7.5.2  Branch algebra

> NORMATIVE: Implementations MUST track `when` / `elif` / `else` chain structure
> using an indentation-aware state machine that handles both NimScript block
> forms:
>
> - **Indented-block form:** `when <cond>:` followed by body lines at a deeper
>   indent level.
> - **Single-line colon form:** `when <cond>: requires "x"` with the body on
>   the same line as the header.
>
> Branch predicate semantics (canonical, pinned across all impls):
>
> - A branch's predicate(s) attach to **every** `requires` inside that branch
>   (including multiple requires statements per branch).
> - `when A:` branch → predicates from translating condition A.
> - `elif B:` branch (after `when A`) → (predicates of B) AND (negation of
>   every predicate in A's translation). Example: `when defined(linux) … elif
>   defined(macosx)` — the `elif` branch carries `(platform="macosx",
>   platform=(not)"windows")` is incorrect; the correct composition is
>   `(platform="macosx", platform=(not)"linux")`.
> - `else:` branch → AND of the negations of all preceding branch conditions
>   (one negated predicate per preceding `when`/`elif` condition).
> - **Chain poisoning:** if ANY branch in the chain has an UNRECOGNIZED
>   condition, OR if the chain has more than one branch and any recognized
>   condition yields more than one predicate, the ENTIRE chain is poisoned —
>   every branch in that chain is treated as UNRECOGNIZED (over-include, no
>   annotation). Poisoning is necessary because correct `elif`/`else` negation
>   cannot be computed across an opaque condition.
> - **Nested `when`:** an inner `when` chain (at depth ≥ 1 inside an outer
>   branch body) is UNRECOGNIZED — all its branches get `predicates=None` (over-
>   include + warn). The enclosing outer chain is unaffected.

#### 7.5.3  Warning policy

> NORMATIVE: The spec-mandated `UserWarning` MUST fire if and only if at least
> one branch in any chain in the file is UNRECOGNIZED (as defined in §7.5.2 —
> including chains that are wholly poisoned or contain nested `when` blocks).
> A file whose `when` blocks are ALL recognized MUST NOT emit the warning.
>
> The exact warning text when the condition is met:
>
> ```
> .nimble contains `when` block(s); milpa does not evaluate nimscript, so
> all `requires` are included unconditionally. If this over-includes,
> consider expressing the conditionality in milpa.kdl with platform=/nim=
> predicates (#26).
> ```
>
> A recognized `when` translates precisely and emits NO warning. The warning
> announces only the cases where translation failed and over-inclusion applies.

#### 7.5.4  Lockfile annotation and activation

> NORMATIVE: Predicates attached to `RequireEntry.predicates` (§1) are recorded
> in the lockfile as additive `cond-require` nodes (see
> `spec/lockfile-schema.md §3.5`). The `requires` node in the lockfile is
> **unchanged** — it continues to list the full universal require set, including
> entries that carry predicates. Build-time **activation** (filtering `nim.cfg`
> or the active dep set by a resolving profile) is the domain of #110 and is NOT
> part of this spec section. The consumers `frozen`, `milpa verify`, and
> `nimcfg` read `requires` only and MUST NOT be changed to consult
> `cond-require`.

#### 7.5.5  Semantic asymmetry: root `when` vs transitive `when`

> NOTE: The same `platform="linux"` predicate surface means different things
> depending on origin. A `milpa.kdl` root dep declared inside a
> `when platform="linux" { }` block is **filtered at resolve time** — the dep is
> absent from the lockfile on a non-linux host (existing, intentional behavior).
> A `.nimble` transitive dep inside `when defined(linux): requires "extra"` is
> **recorded** under this policy — `extra` stays in the universal lockfile,
> annotated with the predicate, and #110 activates it at build time. The
> distinction reflects the trust gradient: declarative authored intent
> (`milpa.kdl`) is honored immediately; a predicate reverse-engineered from
> un-evaluated NimScript is recorded for deliberate, universal-lockfile-
> preserving activation later.

### 7.6  `nim` requirement filtering

> NORMATIVE: After scanning, any `NamedRequire` whose `name` is the literal
> string `"nim"` (case-sensitive) MUST be silently dropped from
> `EdgeSet.requires`. The Nim compiler version is the v2 toolchain RFC's
> territory, not source-dep resolution.

### 7.7  Setting the fidelity tag

> NORMATIVE: An `EdgeSet` produced by this heuristic MUST have its `source`
> field set to `"nimble_fallback"`.

---

## Appendix A — Golden vector durability

The file `conformance/spec-v1/dep-decl-golden/v0/example.kdl` is the
hand-authored v0 golden byte-vector. It was written character-by-character
directly from the §2 rules; no implementation serializer produced it.

`dep_decl_hash`:
`sha256:34a91f93fc03cadbd69379b97cdbac82110070ead8595038f0cc203e72d346bd`

**Durability guarantee:** the §2 rules are the permanent oracle. If a future
producer's serializer generates bytes that hash differently from the recorded
`dep_decl_hash` for the same logical `EdgeSet`, the **producer is wrong**, not
the golden vector. The test in `harness/test_dep_decl.py` asserts this
relationship directly: `sha256(example.kdl bytes) == recorded dep_decl_hash`.

**Versioning:** the golden vector is versioned per `dep_decl_schema_version`.
When a v1 schema lands, a new directory
`conformance/spec-v1/dep-decl-golden/v1/` will hold its own hand-authored
vector and recorded hash. A v1 producer MUST NOT produce a byte-identical
artifact to the v0 golden vector for any `EdgeSet` that exercises v1 fields.

---

## Appendix B — Producer/consumer asymmetry

> NOTE: Only the **producer** (tianguis ingest; any future milpa `publish`
> path) ever calls `canonical_serialize`. The **consumer** (the resolver) only
> ever parses received bytes and verifies `sha256(received_bytes) == dep_decl`.
> The consumer never re-serializes.
>
> This means:
>
> - The resolver implementations (Python, Rust, future Nim) do **NOT** ship a
>   `canonical_serialize` function. Consumer-side serializers would be exercised
>   only by self-tests (the resolve path never serializes) and would rot.
> - The conformance oracle for consumers is **parse-only**: parse the §A golden
>   corpus artifact, assert `EdgeSet` equality to a hand-constructed expected
>   value, assert `sha256(bytes)` equals the corpus `dep_decl_hash`.
> - `canonical_serialize` lives only in tianguis (Nim) and the harness helper
>   `harness/dep_decl.py:make_dep_decl_fixture`, which exists to generate
>   fixture artifacts for S3b–S6 — not as a resolver component.
