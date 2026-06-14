# RFC: Content-Addressed, Attested Dependency Metadata

- **Status:** Draft (Stage 1 — sliced; architecture review rounds 1 + 2 applied)
- **Scope:** milpa spec (new `spec/dep-decl.md` joint contract; S14 registry-protocol, S6 resolver-semantics, S5 lockfile-schema, errors) + tianguis ingest/attest pipeline (sibling repo)
- **Milestone:** v2 structural (Tier 3 differentiation). Additive + transition-gated; no day-one breakage.
- **Supersedes in spirit:** `rfc-resolver-tianguis-swap.md` line 39–41 ("the index supplies node identity+provenance, not edges").
- **Realizes:** `rfc-content-addressed-identity.md` Phase E *partially* — the attestation **infrastructure + Rekor binding** applied to **metadata edges** (source-identity attestation remains future work); feeds `rfc-beyond-pubgrub.md` D1 (proof certificates), D2 (capability typing), D7 (cryptographic provenance).

> **Terminology (locked, §8):** the new artifact is a **DepDecl** (Dependency
> Declaration) — content hash `dep_decl_hash`, index/lockfile field `dep_decl`. The name
> mirrors a `go.mod` `require` block and is deliberately distinct from `content_hash`
> (source-tree identity). Vocabulary family: `dep_decl` / `dep_decl_hash` /
> `dep_decl_schema_version` / `DepDeclStore` / `DepDeclEdgeSource` / `TNG-DEPDECL-*`.

## 1  Summary

Today milpa discovers a transitive dependency's own requirements by **fetching that
dependency and re-parsing its `.nimble` at resolve time** (`resolver-semantics.md`
§4.2.1, normative). `.nimble` is NimScript — Turing-complete — so milpa cannot
evaluate it; it applies a line-scan heuristic. This is the one place milpa's
"the resolver only ever sees pure declarative data" principle leaks: every resolve
silently re-interprets NimScript-shaped data, per transitive dep, over the network.

This RFC moves the `.nimble` → declarative translation **out of the resolver and
into tianguis ingest**, where it happens **once per `(package, version)`**, is
**content-addressed** (a Dependency Declaration hash, orthogonal to source-tree
identity), and is **Rekor-attested** on the same Sigstore substrate that already
attests artifact identity. The resolver consumes the attested metadata node instead
of parsing `.nimble`, and becomes **purely declarative**: it only ever reads
`milpa.kdl` (root) + index-served, hash-verified metadata nodes.

Raw git-URL deps not yet in the registry remain on the resolve-time `.nimble`
fallback — the transitional escape hatch, exactly analogous to uv building an sdist
with dynamic metadata. The heuristic parser does not disappear; it relocates to the
attested ingest step, run once, where its error surface (`MAN-NIMBLE-*`) is a
publish-time concern rather than a per-resolve one.

**Producer/consumer asymmetry (load-bearing — see §3.2).** Only the *producer*
(tianguis, and any future milpa `publish` path) ever **serializes** a DepDecl. The
*resolver* only ever **parses** a received DepDecl and verifies `sha256(received bytes)`
against the index pointer; it never re-serializes. Therefore byte-identical
`canonical_serialize` is a **producer + spec** obligation, not a both-impls
resolve-path burden. This sharply narrows the cross-impl coordination surface.

## 2  Motivation

### 2.1  The nimble mess, named precisely

The discomfort is **not** "milpa reads transitive deps' metadata" — that is the
normal, correct architecture (uv reads each direct URL/git dep's `pyproject.toml`;
PyPI serves per-package metadata; nobody precomputes a global graph). The discomfort
is that **Nim's per-package metadata format is executable** (`.nimble` = NimScript),
so reading it is heuristic and lossy, and milpa does it **at resolve time, every time,
unverified**.

### 2.2  Why not just copy PEP 658

PEP 658 (PyPI serving the `METADATA` file standalone so resolvers needn't download
the wheel) is the **best retrofit onto a legacy registry**, not the first-principles
ideal. It fixes metadata *delivery* but leaves the *model* legacy:

- metadata keyed by mutable `(name, version)` coordinates, not content;
- self-asserted, unattested — the index serves whatever was uploaded;
- untyped edges (name + version-range strings only);
- resolution is still an online, node-by-node network crawl.

milpa has a clean slate and already owns the three primitives PyPI lacks:
**content-hash identity** (`rfc-content-addressed-identity.md`), a **Sigstore/Rekor
transparency log** at publish (durable `rekor{}` block in every index entry), and a
frozen **result certificate** (`resolver-semantics.md` §5). The best-in-class design
*unifies* these rather than bolting on a delivery optimization.

### 2.3  Rejected alternative — sign the source, parse at resolve

A tempting cheaper design: **cosign-sign the raw `.nimble` bytes** and let each
resolver parse the *verified* bytes at resolve time. No translation step, no
`canonical_serialize`, no DepDecl schema to evolve.

**Rejected**, for a structural reason. Signing the source attests the *NimScript
bytes*, not their *meaning under milpa's heuristic*. Two versions of the line-scan
parser can extract different edge lists from the **same** attested `.nimble` — so the
attested object is not what the solver actually consumes. The DepDecl instead attests the
**translation** (the edge set), making the attested artifact *exactly* the resolver's
input. It also keeps the heuristic out of the resolve hot path (the §2.1 problem),
which sign-the-source does not. Sign-the-source also still leaves first-fetch
`.nimble` unverified before consumer-side attestation (#103) lands — the same gap the
DepDecl's hash-pinned pointer closes for indexed deps.

### 2.4  The best-in-class reference points

- **Go modules** — `go.mod` is *deliberately declarative and non-executable* (the
  exact stance `milpa.kdl` takes against `.nimble`); `go.sum` + the checksum-database
  is a Merkle **transparency log**. Go converged on declarative metadata + content
  hashes + transparency log. milpa already has all three.
- **Nix CA-derivations / Guix** — content-addressed build inputs; the *resolved*
  graph is a Merkle DAG. (We borrow this for the resolved closure — the lockfile —
  not for declarations; see §3.1.)
- **Sigstore / in-toto / SLSA / TUF** — attested supply-chain metadata; the substrate
  tianguis publish already uses.

## 3  Design

### 3.1  Three orthogonal addressing axes (keep them separate)

| Axis | Hashes | Mutability | Status |
|---|---|---|---|
| **Source-tree identity** (`content_hash`) | the extracted source bytes alone | immutable per tree; **trust-independent, recomputable from bytes** | exists (S12) — **NON-NEGOTIABLE, unchanged** |
| **Dependency Declaration (DepDecl)** — *NEW* | the canonical serialization of the package version's `EdgeSet` (requires-as-declarations, `src_dir`, later capabilities) | immutable per `(package, version, dep_decl_schema_version)` | **this RFC** |
| **Resolved closure** (`milpa.lock`) | each resolved dep's source identity + provenance | per-resolution | exists (S5) |

The DepDecl axis is **orthogonal to source-tree identity** — the same discipline that
keeps identity and provenance separate today. A package's source-tree identity MUST
NOT depend on its declared or resolved dependencies (that is the Nix/unison move, and
it would break the "recomputable from bytes alone" invariant). The DepDecl is a *second*
content hash over a *different* artifact (the declaration), not a redefinition of
identity.

### 3.2  The `EdgeSet`, the DepDecl, and the producer/consumer split

**Name the in-memory type first.** Both impls already compute a package version's
declared edges as an *anonymous* value (today: the return tuple of the transitive
`.nimble` parse, embedded in the resolver candidate). Promote it to a first-class,
language-neutral type:

```
EdgeSet = {
    requires:  [ (name, constraint_str) | (url, ref) ]   # declarations, ordered as authored
    src_dir:   string                                     # "" when unset
    source:    "dep_decl" | "milpa_kdl" | "nimble_fallback"   # fidelity tag — NOT serialized (in-memory only)
    # forward axes — additive, gated by dep_decl_schema_version (§3.2.1):
    # capabilities: [...]    # rfc-beyond-pubgrub D2
}
```

**Fidelity tag.** The `source` field is **in-memory only** — it is NOT part of `canonical_serialize` and MUST NOT appear in the DepDecl artifact. Its sole purpose is to allow the resolver and diagnostics layer to distinguish "this EdgeSet may over-declare (nimble_fallback)" from "this EdgeSet is authoritative (dep_decl)." The tag enables the S5 summary warning ("N deps resolved from un-attested metadata") to enumerate *which* deps without re-examining the FallbackEdgeSource composition. Serializing the tag would corrupt the hash invariant; it is an in-memory annotation only.

The **DepDecl** is the canonical serialization of an `EdgeSet`:

```
dep_decl_bytes = canonical_serialize(EdgeSet)              # producer-only (§3.2.2)
dep_decl_hash  = "sha256:" + hex(sha256(dep_decl_bytes))        # SAME encoding as content_hash (identity.md)
```

`EdgeSet` is the **single shared edge type** in each impl: the `.nimble` heuristic
returns one, `milpa.kdl` parsing returns one, and DepDecl parsing returns one. There is
no parallel "DepDecl type" duplicating it (SSOT).

**Producer/consumer asymmetry.**
- **Producer (tianguis ingest; any future milpa `publish`):** builds an `EdgeSet`,
  calls `canonical_serialize` → `dep_decl_bytes`, computes `dep_decl_hash`, signs, publishes the
  bytes. *Serialization is here.*
- **Consumer (the resolver, both impls):** fetches `dep_decl_bytes`, verifies
  `sha256(dep_decl_bytes) == dep_decl`, then **parses** the bytes into an `EdgeSet`.
  *No serialization on the resolve path.* A consumer never needs a byte-identical
  emitter; it needs a parser and a byte hash (both already present — it parses KDL and
  hashes elsewhere).

**The resolver impls do NOT ship a `canonical_serialize`.** A consumer-side serializer
would be exercised only by self-tests (the resolve path never serializes), so it would
rot — and in python-ng it cannot reuse the kdl-py printer (nondeterministic key order;
the same reason `format_lockfile`/`format_manifest` are hand-rolled), so it is real
hand-rolled code for zero production value. The conformance oracle is instead
**parse-only**: both impls parse the S0 golden corpus artifact, assert the resulting
`EdgeSet` equals a hand-constructed expected value, and assert `sha256(bytes)` equals
the corpus `dep_decl_hash`. `canonical_serialize` lives only on the **producer** side
(tianguis; or a future milpa `publish`/`adopt` command, tested at that command's
boundary), never in `fetch`/`lock`.

**`requires` entries are declarations over ranges** (`name >= 1.2`, `url#ref`),
**not** concrete child hashes — exactly like a `go.mod` `require` line. The DepDecl is a
**flat, hashed, per-version declaration** (go.mod-shaped), **not** a recursive Merkle
DAG over concrete versions. Recursive content-addressing of concretes belongs to the
*resolved closure* (the lockfile), which milpa already hashes per dep. Declarations
are over ranges; only resolutions are over concretes.

#### 3.2.1  DepDecl schema versioning (hash agility)

`dep_decl_hash` is the hash of the *full* canonical bytes, so **any additive field changes
the hash** even when the resolver-visible edges are unchanged. To make forward
evolution honest rather than silently hash-breaking:

- The DepDecl carries an explicit `dep_decl_schema_version` integer. **v0 = `{ requires,
  src_dir }`.**
- Adding a field (e.g. `capabilities`, F5) is a **schema-version bump**, not a
  retroactive reinterpretation: a v0 DepDecl is never re-read as if it had the new field,
  and old `dep_decl_hash` pins (§3.7) stay valid for v0 artifacts.
- `dep_decl_schema_version` is a field **inside** the canonical bytes (§3.2.2 rule 2), so it
  is part of the hash *and* self-describes the artifact for offline parsing. The index
  version-node **also** records it alongside `dep_decl`; a consumer MUST verify the
  two agree after hash-verification and raise `TNG-DEPDECL-SCHEMA-MISMATCH` on disagreement
  (the partially-applied-index case — §5 item 1 §5). The golden vector (§9 S0) is
  **versioned per schema** — one oracle per `dep_decl_schema_version`.

This **resolves F5**: capabilities are a future schema version with its own vector,
not a reserved empty slot pretending to be hash-stable.

#### 3.2.2  `canonical_serialize` — a character-level, producer-side contract

`canonical_serialize` MUST be deterministic and byte-stable so that `dep_decl_hash` is a
content address (same `EdgeSet` → same bytes → same hash → global dedup). Because only
producers serialize, the contract binds **producers + the spec**; consumers verify by
hashing received bytes.

The full character-level rules live in **`spec/dep-decl.md`** (new — see §5). They MUST pin
*every* degree of freedom KDL 2.0 leaves open, to the same discipline
`lockfile-schema.md §7` uses for `format_lockfile`:

1. **Document shape** — exact node nesting; a single top `dep_decl { … }` node; child
   indentation; trailing-newline policy.
2. **Field order** — fixed: `dep_decl_schema_version`, `src_dir`, `requires` (then future
   fields appended in schema-version order).
3. **`requires` order** — **authored order preserved** (the BFS-ordering input per
   §4.2.1; see §3.6).
4. **`(url, ref)` vs `(name, constraint)` entry encoding** — the exact KDL node form
   for each (node name, arg order, property vs child).
5. **Constraint values** — serialized as the **raw declaration string** from the
   source (`">= 1.0"`), **not** a normalized `VersionSet` form. Normalization is a
   resolve-time concern and would couple the bytes to `VersionSet`'s canonical form.
   **Whitespace within the raw string is preserved as-written** — `">= 1.0"` and
   `">=1.0"` are different bytes and thus different hashes. This is intentional:
   the DepDecl attests what the source declared, not a re-interpretation of it. A
   package that changes its constraint spelling (e.g., trims whitespace) produces
   a new `dep_decl_hash` — a correct signal that the declaration changed. The producer
   (tianguis ingest) is responsible for passing through the raw declaration bytes;
   it MUST NOT canonicalize whitespace before serializing.
6. **Optional-field presence** — `src_dir ""` when unset vs omitted (pin one;
   recommend explicit `src_dir ""` for a stable shape).
7. **String escaping** — all strings escaped by KDL 2.0 rules via the shared escaper;
   **no raw interpolation, no unquoted/single-quoted forms**, booleans `#true`/`#false`
   (the exact defect class `lockfile-schema.md §2.4` records).

The S0 gate is **`spec/dep-decl.md` + a golden byte-vector** (in the conformance corpus),
not a vector alone. See §9 S0 for the bootstrap protocol.

### 3.3  Where the DepDecl lives — separate content-addressed artifact (**F1 resolved**)

The served metadata is a **separate per-version content-addressed artifact**,
referenced from the index version-node by its `dep_decl_hash`, fetched on demand, and
cached by hash — **not** inlined into `index.kdl`.

Rationale: the index is already ~1.5 MB / 2613 packages; inlining every version's
full `requires` + `src_dir` would multiply it and force a full re-download on any
single package's metadata change. A separate artifact is immutable, globally
dedup-able, lazily fetched, and cache-stable — the PEP-658 "separate METADATA" shape,
done content-addressed.

**Artifact address (self-describing from the pointer).** The pointer is a hash, not a
URL; the address is derived, so no second index field is needed:

```
DepDecl artifact URL  =  <index_base_url>/dep-decl/<sha256_hex>.kdl
```

`<index_base_url>` is defined precisely: **remove the last path segment of
`MILPA_INDEX_URL` iff that segment matches `*.kdl` or `index*` (ASCII-case-insensitive);
otherwise append `/`.** See `spec/dep-decl.md §3.3` for the normative case-sensitivity rule.
Examples: `…/tianguis/main/index.kdl` → `…/tianguis/main/`;
`https://example.com/registry/v2` → `https://example.com/registry/v2/`;
`file:///…/conformance/index.kdl` → `file:///…/conformance/`. **OCI index refs**
(`oci://…`) have no path-directory and do **not** support template derivation — they
MUST supply the DepDecl store out of band (an `OciDepDeclStore` resolving DepDecl artifacts as OCI
referrers, or `MILPA_DEP_DECL_DIR`); the URL template is undefined for them. For fixtures,
`MILPA_DEP_DECL_DIR` overrides the template entirely (`FileDepDeclStore`). A content-addressed
store can serve these flat by hash; air-gapped/`file://` bases work unchanged. The
index version-node gains only the pointer + schema discriminant:

```kdl
version "3.2.0" {
    content_hash "sha256:abc…"          // source-tree identity (existing)
    provenance { kind "git"; … }         // existing
    dep_decl "sha256:7f3c…"          // NEW: hash → DepDecl artifact (address per above)
    dep_decl_schema_version 0                  // NEW: which DepDecl schema produced the hash
    rekor { uuid …; log_index …; … }     // existing — now ALSO covers dep_decl (§3.4)
}
```

#### 3.3.1  DepDecl artifact caching semantics and transport size cap

DepDecl artifacts are **immutable by construction** (content-addressed). The cache model
is therefore *simpler* than the index's four-state model (`registry-protocol.md §6`).
Transport fetch is also subject to a size cap — see `spec/dep-decl.md §3.3.1` for the
normative rule (1 MiB recommended cap; two-layered Content-Length + read enforcement;
`TNG-DEPDECL-FETCH-FAILED` on exceed).

- **Cache forever, no TTL, no staleness check.** A hit (keyed by `dep_decl_hash`) always
  serves; the artifact can never change under a fixed hash.
- **Miss requires network.** On a cache miss with the network unavailable and no
  cached artifact, behavior follows the missing-DepDecl policy (**F4**, §5 item 5): the
  non-strict path falls through to the `.nimble` fallback with `RES-UNATTESTED-METADATA`
  warning; strict mode (`--require-attested-metadata`) raises `TNG-DEPDECL-FETCH-FAILED`.
- The DepDecl cache lives alongside the index cache; `milpa clean` MUST NOT remove it
  (same rule as the index cache).
- **Store GC interaction.** When Phase C of `rfc-content-addressed-identity.md`
  ships a `milpa store gc` command, DepDecl artifacts MUST NOT be eligible for GC
  eviction — they are not source trees and should not be managed by the source-tree
  GC policy. The `milpa store gc` implementation MUST exclude the DepDecl cache
  directory from its sweep. This means the DepDecl cache and the source-tree CAS are
  **two distinct cache roots** (both under `~/.cache/milpa/` but in separate
  sub-directories, e.g., `dep-decl/` vs `cas/`). The DepDecl cache has no GC because
  its entries are globally dedup-able, immutable, and small (KDL text, not source
  trees). Manual pruning (if ever needed) is a future `milpa dep-decl gc` concern,
  deferred until the cache growth is observed to be a problem.

### 3.4  Attestation — ride the existing Sigstore/Rekor flow

Today the tianguis publish workflow cosign-signs the OCI artifact digest and records
`rekor{uuid; log_index; integrated_time}` per version (attesting source identity +
provenance). This RFC extends the **signed payload** to also bind `dep_decl`:
the in-toto statement covers `{ content_hash, provenance, dep_decl,
dep_decl_schema_version }` together. No new signing infrastructure — the same keyless
GitHub-OIDC cosign flow, one larger subject set.

Consumer-side enforcement is **issue #103** (verify the index's Rekor attestation at
resolve time), still open and shared with `rfc-registry-trust-federation.md`. This
RFC does **not** require #103 to land first (see the honest threat model, §6), but it
makes #103 strictly more valuable: once the consumer verifies the attestation, the
*entire* declarative input to the solve — identity, provenance, and edges — is
transparency-log-backed.

### 3.5  Resolver consumption — the `EdgeSource` seam

Rather than a three-way `if/elif/else` inside the BFS fetch loop (which already mixes
network I/O, filesystem probing, and solver-term construction), edge sourcing is split
into three deep, independently-testable units plus a resolver-level coordinator:

```
EdgeSource.edges_for(name, version, ctx) -> EdgeSet      # one per source kind
```

- `DepDeclEdgeSource(dmd_store)` — given `ctx.dep_decl`, `dmd_store.get()` the artifact
  (fetch-or-cache + hash-verify) and **parse → EdgeSet**. Uses **no** `dep_path` — the
  DepDecl is addressed by hash, not by a local source tree.
- `MilpaKdlEdgeSource` — read `milpa.kdl` from `ctx.dep_path`, parse → **transitive
  projection** → `EdgeSet`.
- `NimbleEdgeSource` — line-scan `.nimble` at `ctx.dep_path` → `EdgeSet` (the
  transitional heuristic).

`ctx` carries whichever inputs a source needs (`dep_path`, `dep_decl`,
`is_overridden`); the heterogeneous inputs are why the sources are distinct units, not
one signature pretending `dep_path` is universal (it is meaningless for the DepDecl case).

**Identity fetch is orthogonal to edge sourcing.** The BFS fetches `D`'s source tree to
compute its `content_hash` (the identity gate, `spec/identity.md`) **regardless** of
which `EdgeSource` fires. "`DepDeclEdgeSource` needs no source fetch" means *no source fetch
for **edge data*** — the identity fetch still happens (and, for the `.nimble`/`milpa.kdl`
sources, supplies `ctx.dep_path`). The mainline win of the DepDecl path is avoiding a
`.nimble` **parse**, not avoiding the source fetch.

**The priority decision is a resolver function over an `EdgeCache`, not a per-call
combinator.** Clause (a) below is a *graph-level* property ("one `EdgeSet` per
`(package, version)`, attested wins"), which a per-call `FallbackEdgeSource` cannot
enforce — two BFS parents reaching `D@v` could otherwise get different `EdgeSet`s. The
normative mechanism is a resolver-scoped memo:

```
edge_cache: dict[(name, Version), EdgeSet]        # resolver-scoped

def resolve_edges(name, ver, ctx):
    if (name, ver) in edge_cache: return edge_cache[(name, ver)]   # clause (a): sealed once
    if ctx.is_overridden:           es = nimble_or_milpakdl(ctx)   # clause (b)
    elif ctx.dep_decl:          es = dmd_source.edges_for(...)  # mainline
    elif ctx.has_milpa_kdl:         es = milpakdl_source.edges_for(...)
    else:                           es = nimble_source.edges_for(...)
    edge_cache[(name, ver)] = es; return es
```

`resolve_edges` is decided **once, at first BFS encounter** for `(package, version)`,
and probes `ctx.dep_decl` directly (from the index entry) rather than the BFS path
that discovered the package — so the attested source is chosen whenever the index has a
pointer, independent of parent. Amend `resolver-semantics.md` §4.2.1 step 2 to specify
`resolve_edges` + the `edge_cache` as the normative structure, with priority order:

1. **`D` indexed with `dep_decl`** → `DepDeclEdgeSource` (mainline).
2. **`D@v` ships `milpa.kdl`** (adopted but not indexed) → `MilpaKdlEdgeSource`.
3. **otherwise** (raw git-URL dep, not indexed, no `milpa.kdl`) → `NimbleEdgeSource`
   (transitional; emits the §5 warning).

`FallbackEdgeSource(primary, …, last)` MAY still exist as an injectable **test seam**
for exercising the individual sources, but it is NOT the priority logic — that is
`resolve_edges`.

**The `Manifest → EdgeSet` transitive projection (normative).** `MilpaKdlEdgeSource`
parses a `milpa.kdl` to a full `Manifest` (deps, dev-deps, overrides, flags, src_dir, …)
then projects it to an `EdgeSet`. That projection is normative and MUST: read
`manifest.deps` only (**never** `dev_deps` — `resolver-semantics.md §9`), **drop**
`manifest.overrides` entirely (`§10.2`: a transitive dep's overrides are ignored), and
map `manifest.src_dir → EdgeSet.src_dir`. Specifying the projection at the seam keeps
both impls from re-deriving the dev-deps/override exclusion independently (the exact
per-impl divergence the spec exists to prevent); a conformance fixture asserts a
`milpa.kdl` with dev-deps + overrides yields an `EdgeSet` carrying neither.

**Workspace members (issue #25).** A workspace member is a local package resolved by
name within the workspace; it is not indexed and carries its own `milpa.kdl`. It
does NOT follow the 3-branch priority above — it is handled by
`resolver-semantics.md §11` (workspace resolution) before `EdgeSource` dispatch.
The workspace BFS feeds each member's own `milpa.kdl` edges directly (via
`MilpaKdlEdgeSource` over the member's local path). Workspace members MUST NOT be
passed to `DepDeclEdgeSource` or `NimbleEdgeSource`. This is an implicit 0th-priority
rule: *workspace member → always use local milpa.kdl; never reach the
3-branch priority list.*

**The `DepDeclStore` seam, not a Fetcher and not a bare callable.** DepDecl retrieval is a
`DepDeclStore` protocol, narrower than the `Fetcher` of `rfc-pluggable-fetchers.md`
(`Fetcher` materializes a *source tree*; a DepDecl is a small KDL blob addressed by hash):

```
class DepDeclStore(Protocol):
    def get(self, dep_decl_hash: str) -> bytes:    # fetch-or-cache; verify sha256==dep_decl_hash
        ...   # raises TNG-DEPDECL-FETCH-FAILED (unreachable) | TNG-DEPDECL-HASH-MISMATCH (bytes≠hash)
    def is_cached(self, dep_decl_hash: str) -> bool:   # local cache hit, no network
        ...
```

A bare `(hash) → bytes` callable is the wrong boundary: it has nowhere to host the
immutable-cache model (§3.3.1) and forces the hash-verify to live ambiguously between
caller and lambda. `DepDeclStore.get` owns fetch+cache+hash-verify as one sealed
responsibility (so `TNG-DEPDECL-HASH-MISMATCH` is raised in exactly one place);
`is_cached` is required by §3.7.2's offline-verify distinction (cached-and-immutable vs
evicted). Implementations: `FileDepDeclStore(dir)` for fixtures (reads `<dir>/<hex>.kdl`;
no network — this is what `MILPA_DEP_DECL_DIR` points at), `HttpDepDeclStore(base_url)` for
production (URL template per §3.3). `DepDeclEdgeSource` holds a `DepDeclStore`, calls `get`,
then parses the already-verified bytes → `EdgeSet`. A future OCI-native index swaps in
an `OciDepDeclStore` without touching `DepDeclEdgeSource`.

Normative clauses that the seam must honor:

- **(a) Attested wins across paths (diamond / mixed-source).** `resolve_edges` decides
  the source **once per `(package, version)`** (the `edge_cache` memo above) by probing
  `ctx.dep_decl` from the **index entry**, not from the BFS parent that discovered
  the package. So whenever the index carries a `dep_decl` for `D@v`, the DepDecl is used
  no matter which parent expands `D@v` first; a mixed-provenance diamond (one parent
  knows `D@v`'s DepDecl, another reaches it as a bare URL) cannot produce two different
  `EdgeSet`s, because the index probe is parent-independent and the result is sealed in
  the cache on first encounter. This is the normative resolution of the former F7 fork.
- **(b) Override suppresses DepDecl lookup.** When the root `overrides {}` block
  (`resolver-semantics.md §10.1`) redirects `D`'s provenance to a different URL, the
  attested DepDecl describes the *original* source tree and is **no longer valid** for the
  overridden tree. DepDecl lookup MUST be suppressed for an overridden dep; it falls
  through to `MilpaKdlEdgeSource`/`NimbleEdgeSource` on the overridden source.
- **(c) dev-deps / context.** `.nimble` has no `dev-deps` (so a DepDecl translated from
  `.nimble` may over-declare; see §3.8). The resolver applies dev-deps exclusion by
  **graph position** (`resolver-semantics.md §9`: a transitive dep's dev-deps are
  ignored), **not** by any DepDecl hint — every DepDecl-sourced `requires` for a transitive
  dep is a regular edge.

This makes the resolver's *mainline* path execute over hash-verified declarative nodes;
the executable-metadata path survives only as the explicitly un-attested fallback.

### 3.6  Preserving the canonical-solution ordering invariant

`resolver-semantics.md` §4.2.1 makes BFS frontier order normative (solver entry order
== BFS package order; deps in **authored order**). The DepDecl MUST preserve `requires` in
authored order (§3.2.2 rule 3) so that expansion from a DepDecl yields **byte-identical
frontier ordering** to expansion from the original declarative source.

**Scope of the differential obligation.** Byte-identical lockfiles between the DepDecl path
and the `.nimble` fallback path are guaranteed **only when the `.nimble` contains no
`when` blocks** (see §3.8: `when`-block requires are flattened to an
unconditional union at ingest, and the line-scan fallback flattens them at resolve in
the same authored order — but any future divergence in how the two flatteners order
interleaved `when` requires would break a naive equality). The conformance gate
therefore has **two** S4 fixtures: a clean `.nimble` (assert identical lockfiles) and a
`when`-block `.nimble` (DepDecl is authoritative; the fallback is explicitly allowed to
differ and is already warned).

### 3.7  Lockfile pin (**F2 resolved — include now**)

`milpa.lock` per-dep record gains an additive `dep_decl "sha256:…"` field, pinning
the DepDecl a resolution was computed against. Emitted only when present; parsed as
forward-compat by older consumers (no schema bump). This lets `milpa verify` detect a
registry that silently changed a version's declared edges — a supply-chain tripwire on
the *graph*, complementing the existing source `identity` tripwire.

**Distinct verify findings.** A graph-edge change and a source-byte change are
different events and MUST surface distinctly:

- `VERIFY-IDENTITY-MISMATCH` (existing intent) — the source bytes changed.
- `VERIFY-EDGE-MISMATCH` (**new**) — the locked `dep_decl` no longer matches the
  index's current pointer for that `(package, version)`.

#### 3.7.1  Prior-lockfile interaction (`resolver-semantics.md §8`)

When a prior lockfile is supplied:

- If it carries `dep_decl` for `D@v` **and** the DepDecl artifact is cached under that
  hash, the resolver MUST use the cached artifact directly — **no index round-trip for
  D@v's edges** (the correct offline/airgapped behavior, mirroring §8 pinned-commit
  reuse).
- If the index's *current* `dep_decl` for `D@v` differs from the prior pin, that is
  **graph drift**. Exact semantics:
  - **Non-strict path:** the resolver emits the drift warning, then **re-fetches the
    index's current DepDecl artifact** (not the prior pin) and uses the new EdgeSet for
    this resolution. The prior pin is stale; advancing means advancing to the *current*
    index state, which may find new or changed edges. The new `dep_decl` will be
    written into the updated lockfile.
  - **Strict mode:** raise `VERIFY-EDGE-MISMATCH` and halt. The edges the lock was
    computed against have changed; the user must explicitly accept the drift.
  (This mirrors how §8 treats a moved pinned commit — the prior pin is evidence of
  drift, not an instruction to freeze on the old artifact.)
- **Pin present, artifact cache-miss, network unavailable.** The pin cannot be honored
  (no cached artifact, no fetch) — analogous to a §8 pinned commit that cannot be
  fetched. The resolver MUST NOT silently fall through to the `.nimble` fallback (that
  would abandon the pin's stability guarantee); it raises `FETCH-ALL-FAILED`
  (or `TNG-DEPDECL-FETCH-FAILED` under strict mode). Falling back here is exactly the
  "ignore the pinned SHA, use ref-tip" anti-behavior §8 forbids.

#### 3.7.2  `milpa verify` behavior under eviction / offline

- DepDecl artifact **evicted** but pin present → re-fetch by hash to re-verify; on success
  compare, on fetch failure surface `TNG-DEPDECL-FETCH-FAILED` (do not silently pass).
- Pin present but the index version-node **lacks** `dep_decl` (rolled back /
  stripped) → `LOCK-DEPDECL-PIN-MISSING`. Disappearance of the pin is itself a red flag,
  not a silent downgrade.
- Registry **offline** with a present pin and present cached artifact → the only check
  possible is `sha256(cached_bytes) == pin`, which is **tautological** (the cache was
  populated *by* that hash) — it confirms storage integrity, **not** that the index
  still serves the same pointer. Edge-**drift** detection (the point of `milpa verify`)
  requires the live index, so offline `milpa verify` MUST report the edge check as
  **skipped (network required)**, not passed — under strict mode it hard-fails. Do not
  present the storage-integrity check as drift assurance.

### 3.8  Ingest (tianguis side) — the heuristic's durable home

tianguis ingest, per `(package, version)`, at adopt or vendor-en-absentia time:

1. Obtain the source tree (existing: OCI artifact or git provenance).
2. Build the `EdgeSet`: from the package's `milpa.kdl` if present, else **translate its
   `.nimble`** via the line-scan heuristic. The heuristic's **canonical home is
   `spec/dep-decl.md`** (the joint contract), with `manifest-grammar.md §5` cross-referencing
   it — so milpa and tianguis run the *same* normative algorithm (SSOT), not two copies.
3. `canonical_serialize` → `dep_decl_bytes`, compute `dep_decl_hash`, publish the artifact.
4. Extend the cosign subject set to bind `dep_decl` + `dep_decl_schema_version`; record
   `rekor{}` (existing).
5. Write `dep_decl` + `dep_decl_schema_version` into the index version-node.

**Conditional (`when`-block) requires.** v0 records the **unconditional union** of all
`requires` clauses (the line-scan's current behavior — include every branch). This is a
documented approximation: an attested DepDecl may over-declare platform-conditional deps.
Per-condition edges are a **forward axis** (a later schema version, tied to the
`milpa.kdl` `when`-block feature, issue #26) — referenced here so the forward design is
connected.

**Features (issue #23) vs `when`-blocks (issue #26) — forward story.** These are
distinct axes and the DepDecl handles them differently:
- **`when`-blocks** are resolver-evaluated conditionals (platform, arch, nim version)
  already present in `.nimble` and `milpa.kdl`. A v0 DepDecl flattens them (unconditional
  union); a future schema version will carry the condition AST alongside each requires
  entry so the resolver evaluates the condition rather than expanding all branches.
  This is the §3.2.1 "forward axis" referenced above.
- **Features (#23)** are user-selectable capability flags declared in `milpa.kdl`
  (e.g., `feature "json"` → additional requires). Features are NOT present in `.nimble`
  at all — so a `.nimble`-sourced DepDecl CANNOT carry feature-gated edges. Features are a
  purely `milpa.kdl`-side concern that can only appear in a DepDecl when the package ships
  a `milpa.kdl` with feature declarations. When the EdgeSet is built from a `milpa.kdl`
  that declares features, the v0 behavior is the same as `when`-blocks: flatten to the
  unconditional union (include all feature-requires). Feature-conditional edges are
  a further forward axis in a later `dep_decl_schema_version`, gated on issue #23 design
  stabilization. The resolver's feature evaluation (#23) is a manifest-side concern
  that pre-filters before EdgeSource dispatch; the DepDecl does not need to encode features
  for the resolver to work correctly in the v0 transition period.

**dev-deps over-inclusion.** `.nimble` has no `dev-deps`; a `.nimble`-sourced DepDecl will
include every `requires` as a regular edge. This is the same over-inclusion the current
resolve-time fallback has, now made explicit and attested. The resolver's
position-based dev-deps exclusion (§3.5(c)) still applies. A corrected DepDecl requires a
new `dep_decl_hash` + re-attest (a normal tianguis re-ingest), since the artifact is
immutable.

**`src_dir` authority.** The DepDecl's `src_dir` is authoritative for `nim.cfg --path:`
emission. A conflict between a DepDecl's `src_dir` and an on-disk `milpa.kdl src_dir` for
the same `(package, version)` is an **ingest-time validation failure** (caught once at
publish), not a silently-resolved resolve-time ambiguity.

At resolve time, when `MilpaKdlEdgeSource` wins (§3.5 branches 2 or override), the
`src_dir` in the returned `EdgeSet` comes from `milpa.kdl` — there is no DepDecl to
conflict with. When `DepDeclEdgeSource` wins (branch 1), the `src_dir` in the returned
`EdgeSet` comes from the DepDecl. The resolver propagates `EdgeSet.src_dir` into the
`ResolvedDep` record; `nim.cfg` emission reads `ResolvedDep.src_dir` directly.
**No new plumbing is needed**: `src_dir` already flows through the resolved graph today
(`lockfile-schema.md §3`). The only change is the source of the value: previously it
was always from the fetched source's `milpa.kdl`; now it may come from the DepDecl. The
`nimcfg.py` / `nim.cfg` emitter is **fully transparent to this change**. This is
scoped to: the `EdgeSet` type carries `src_dir`, and `DepDeclEdgeSource.parse()` populates
it from the DepDecl field. Slice S1 (EdgeSet type) is the right place to confirm this.

The `.nimble` error surface (`MAN-NIMBLE-PARSE`, `MAN-NIMBLE-CONSTRAINT`,
`MAN-NIMBLE-AMBIGUOUS`) becomes an **ingest-time publish failure** for vendored
packages — a malformed constraint blocks vendoring with a clear diagnostic, instead of
leaking into every downstream resolve. This directly resolves the 11b
`MAN-NIMBLE-CONSTRAINT` finding: the durable fix is to validate at ingest, not to
harden the resolver's transitional fallback.

### 3.9  Backfill & transition window (first-DepDecl bootstrap)

The existing 2613-package corpus predates `dep_decl`. Until tianguis backfills:

- Existing index entries carry **no** `dep_decl`; deps resolving against them
  operate under §4 row 4 (un-attested fallback) or row 1/2 if they ship `milpa.kdl`.
- Backfill is an **additive re-ingest + re-sign**: tianguis re-runs ingest (§3.8) for
  each `(package, version)`, producing the DepDecl artifact and a *new* Rekor entry whose
  subject set includes `dep_decl`. Entries not yet backfilled keep their existing
  attestation (which does not cover edges) — so #103, once it lands, can only assert
  the edge binding for backfilled entries. This is acceptable: pre-backfill the edge
  guarantee is simply "not yet available," matching the threat model (§6).
- The **schema-v2 bump (F3) is gated on backfill completion**: `dep_decl` stays
  forward-compat-optional (`TIANGUIS_INDEX_SCHEMA_VERSION` 1) until tianguis reports the
  corpus backfilled, then bumps → 2 to make it required (and the missing-DepDecl policy
  hardens, F4).

## 4  Transition & fallback model

| Dep shape | Edge source after this RFC |
|---|---|
| Named dep, indexed, `dep_decl` present | attested DepDecl (mainline) |
| Direct URL dep that ships `milpa.kdl` | its `milpa.kdl` (declarative) |
| Direct URL dep, indexed via vendor-en-absentia | attested DepDecl |
| Direct URL dep, **not** indexed, `.nimble` only | resolve-time `.nimble` line-scan (transitional, warned) |

The fallback never disappears entirely (a brand-new git URL can always predate
vendoring), but it stops being the mainline. A future **strict mode**
(`--require-attested-metadata`) refuses the fallback for security-sensitive builds
(maps to `rfc-beyond-pubgrub.md` D7).

### 4.1  Migration path for unindexed URL deps (user-facing)

A consumer who sees `RES-UNATTESTED-METADATA` has two routes off the fallback:

1. **Self-service:** the dep ships a `milpa.kdl` → priority rule step 2 applies
   immediately, no tianguis action (recommended; this is the `milpa adopt` story).
2. **Vendoring:** tianguis vendor-en-absentia ingests the package (§3.8), after which
   it resolves via an attested DepDecl. This runs at tianguis's discretion; a consumer can
   request it via tianguis's tracker.

## 5  Normative reconciliation (collision map)

1. **NEW `spec/dep-decl.md`** — the joint milpa↔tianguis contract. This is the one file both
   repos depend on byte-for-byte. `registry-protocol.md` and `manifest-grammar.md`
   cross-reference it; they do not own it. `spec/dep-decl.md` MUST contain all of the
   following sections (this is the normative table of contents):
   - **§1 EdgeSet type definition** — the complete language-neutral struct: `requires`,
     `src_dir`, the in-memory-only `source` fidelity tag (NOT serialized), and the
     forward-axis extension model (how future fields attach to `dep_decl_schema_version`).
   - **§2 `canonical_serialize` rules** — all 7 character-level rules from §3.2.2 of
     this RFC, plus the whitespace-preservation rule for constraint strings.
   - **§3 `dep_decl_hash` algorithm** — `"sha256:" + hex(sha256(dep_decl_bytes))`, same encoding
     as `content_hash` in `spec/identity.md`.
   - **§4 `dep_decl_schema_version` discipline** — what constitutes a version bump (any
     additive field change), who decides (spec maintainer = Corey, PRs to this repo),
     where the schema-version registry lives (a table in this section), and the rule
     that consumers MUST raise `TNG-DEPDECL-SCHEMA-UNSUPPORTED` when the artifact's
     `dep_decl_schema_version` exceeds the impl's maximum understood version.
   - **§5 Schema consistency validation** — a consumer that parses a DepDecl artifact MUST
     verify that the artifact's embedded `dep_decl_schema_version` integer matches the
     `dep_decl_schema_version` field from the index version-node pointer; a mismatch MUST
     raise `TNG-DEPDECL-SCHEMA-MISMATCH`. This closes the gap where an index pointer and
     its artifact disagree on schema version (e.g., due to a partially-applied index
     update).
   - **§6 Error codes** — all `TNG-DEPDECL-*` codes are owned by `spec/dep-decl.md` and
     cross-referenced in `spec/errors.md`: `TNG-DEPDECL-HASH-MISMATCH`,
     `TNG-DEPDECL-FETCH-FAILED`, `TNG-DEPDECL-PARSE-ERROR`, `TNG-DEPDECL-SCHEMA-UNSUPPORTED`,
     `TNG-DEPDECL-SCHEMA-MISMATCH`.
   - **§7 Normative `.nimble`→`EdgeSet` heuristic** — relocated from
     `manifest-grammar.md §5`; cross-referenced from there. This is the algorithm
     both tianguis ingest (Nim) and milpa's resolver fallback (Python/Rust) MUST
     implement identically. Because three independent implementations must produce a
     **byte-identical `requires` order** for the §3.6 differential to hold, this section
     MUST pin the extraction at the **same character-level precision** as
     `canonical_serialize` (§2 above): the exact line-matching predicate, multi-line
     continuation handling, comment-line behavior, and the merge order when a name
     appears in multiple scanned positions (incl. flattened `when`-block branches). "Scan
     for `requires` lines" is not a sufficient spec — the ordering edge cases are where
     three impls silently diverge.
2. **S6 §4.2.1 step 2 (NORMATIVE)** — amend to the `EdgeSource` seam + priority rule
   (§3.5), including clauses (a) attested-wins, (b) override-suppresses, (c) dev-deps
   context. Preserve authored order (§3.6).
3. **S14 §3 version-node** — additive `dep_decl` pointer + `dep_decl_schema_version`
   (forward-compat today; required only behind the `TIANGUIS_INDEX_SCHEMA_VERSION` 1→2
   bump, gated on backfill — §3.9 / F3).
4. **S14 §6 caching** — add the immutable DepDecl-artifact cache (§3.3.1) alongside the
   four-state index cache; specify the artifact URL template (§3.3).
5. **S5 §3.4 `requires`** — unchanged (stays a name list); additive `dep_decl` pin
   per §3.7; new `VERIFY-EDGE-MISMATCH`, `LOCK-DEPDECL-PIN-MISSING`.
6. **S14 §3.2 `TNG-NO-IDENTITY` precedent** — define missing-`dep_decl` behavior.
   **F4 (open):** soft-fallback (warn, `.nimble`) during transition vs hard
   `TNG-NO-METADATA`. The same axis governs the unreachable-artifact sub-case (§3.3.1).
7. **`rfc-content-addressed-identity.md` Phase E** — position this RFC as Phase E
   *partially* realized: the attestation infrastructure + Rekor binding, with **metadata
   edges** as the subject; source-identity attestation remains a later Phase E/F item.
   Update that RFC's phase list to point here and note the partial scope.
8. **`rfc-resolver-tianguis-swap.md` L39–41** — explicitly superseded ("the index now
   *can* supply edges, as attested DepDecl pointers").

## 6  Threat model (honest pre-/post-#103)

**What the `dep_decl_hash` pointer alone buys (pre-#103):** integrity against **passive**
corruption — a DepDecl artifact garbled in transit or storage fails `sha256(bytes) ==
dep_decl` and is rejected. It does **not** stop an **active** adversary who
controls index delivery: such an attacker rewrites both the `dep_decl` pointer *and*
the artifact consistently (`dep_decl = sha256(tampered_dmd)`), and the hash check
passes. The pointer is a field, not a signature, until #103.

**What #103 adds (post-#103):** the Rekor attestation over `{content_hash, provenance,
dep_decl, dep_decl_schema_version}` is transparency-log-backed, so consistent active
substitution is caught — the attacker cannot forge a log entry under the publisher's
OIDC identity. This is the property PEP 658 structurally cannot offer.

Compared to **today**, even pre-#103 is a strict improvement: edges are currently
re-derived from an unverified `.nimble` fetched over plain HTTPS — no integrity binding
at all, passive or active. The DepDecl pointer closes the passive gap immediately and makes
the active gap a single, well-scoped #103 deliverable.

**Other properties:**

- **Silent metadata drift:** the lockfile pin (§3.7) makes `milpa verify` detect a
  version whose declared edges changed under a fixed identity (`VERIFY-EDGE-MISMATCH`).
- **Reproducibility / audit:** the entire declarative input to a solve becomes
  content-addressed and (with #103) transparency-log-backed — the substrate
  `rfc-beyond-pubgrub.md` D1's independent verifier needs.

**Non-goals:** (1) faithful-translation proofs — this RFC attests *that tianguis
translated this source to this DepDecl at this time*, not that the translation is a correct
reading of the NimScript (D1 research territory); (2) closing the active-MITM gap before
#103 (explicitly deferred above).

## 7  Cross-repo split

- **milpa (this repo):** `spec/dep-decl.md`; S14 `dep_decl`/`dep_decl_schema_version` fields +
  artifact URL + cache; S6 §4.2.1 `EdgeSource` amendment + fallback; S5 pin + verify
  codes; new error codes; conformance fixtures; resolver implementation (both impls)
  consuming a DepDecl via the injected `DepDeclStore` seam (fixtures need no network —
  `FileDepDeclStore` over a fixture dir).
- **tianguis (sibling repo):** ingest-time `.nimble`→`EdgeSet` translation (per
  `spec/dep-decl.md`), `canonical_serialize` + DepDecl artifact publication, cosign subject
  extension, `dep_decl` index emission, corpus backfill (§3.9). Filed as a
  tianguis-side issue referencing this RFC (**not** a milpa `/tdd` slice — see §9 S8).

The milpa↔tianguis contract is **`spec/dep-decl.md`** — the one thing both sides agree on
byte-for-byte (producers serialize to it; milpa hashes received bytes against it).

## 8  Open forks (for architecture review / Corey)

**Resolved this round (recorded, not awaiting Corey):**

- **F1 — DepDecl storage:** separate content-addressed artifact, addressed by the URL
  template `<index_base>/dep-decl/<hex>.kdl` (§3.3). *Resolved.*
- **F2 — lockfile pin:** include now, with `VERIFY-EDGE-MISMATCH` distinct from the
  identity finding (§3.7). *Resolved.*
- **F3 — schema-v2 bump timing:** keep `dep_decl` forward-compat-optional; bump
  `TIANGUIS_INDEX_SCHEMA_VERSION` 1→2 only once tianguis backfills the corpus (§3.9).
  *Resolved (defer bump).*
- **F5 — capability axis:** **do not** reserve an empty slot (it is hash-unstable);
  capabilities are a future `dep_decl_schema_version` with its own golden vector (§3.2.1).
  *Resolved.*
- **F7 — diamond / mixed-source coordination:** made normative in §3.5 as the
  resolver-scoped `edge_cache` + parent-independent index probe in `resolve_edges`.
  `FallbackEdgeSource` is demoted to a test seam. *Resolved (spec-wording; no fork).*
- **F6 — `milpa show` edge-source introspection:** deferred to a post-S5 follow-up
  issue rather than expanding slice scope. The in-memory `source` fidelity tag (§3.2)
  preserves the option at zero cost — adding `[dep_decl …]`/`[milpa.kdl]`/`[.nimble fallback]`
  to `milpa show --verbose` later is a localized `cli-contract.md` change needing no data
  it doesn't already have. *Resolved (file follow-up issue; out of this RFC's slices).*

**Resolved by Corey (2026-06-13) — no open forks remain:**

- **F4 — missing-/unreachable-DepDecl behavior.** **Soft now + strict flag.** Default:
  warn and fall back during transition; `--require-attested-metadata` / manifest
  `attestation-policy "strict"` opt into hard-fail; harden the default to hard-fail
  (`TNG-NO-METADATA`) at the schema-v2 bump once tianguis backfills. Hardening tracked
  in **issue #127**.
- **Naming — DepDecl (locked).** The vocabulary family is `dep_decl` (index/lockfile
  field) / `dep_decl_hash` / `dep_decl_schema_version` / `DepDeclStore` /
  `DepDeclEdgeSource` / `TNG-DEPDECL-*`. Applied throughout this RFC + handoff;
  `spec/dep-decl.md` (S0) writes it into the spec.
- **`.nimble` fallback in python-ng.** **Keep the resolver fallback** through the
  transition (this RFC retires its *mainline status*, not its existence); `milpa adopt`
  is a separate future convenience, not a precondition. S4's differential gate stands as
  specified.

## 9  Slices (Stage-1 breakdown → `/tdd`-sized)

Spec-first (milpa owns the contract), then resolver, then conformance. The
tianguis-side companion is **not** a milpa slice (S8). Each slice independently
testable.

**Recommended ordering** (dependency-correct, lowest-risk first): **S2** is a true
forward-compat no-op (both index parsers already ignore unknown version-node children —
verified) and can land first as a confidence wedge. Then **S0** (spec) → **S1**
(`EdgeSet` + parse/verify) → **S3a** (fixture plumbing) → **the `EdgeSource` seam +
resolver refactor + `Nimble`/`MilpaKdl` sources (S4's first half)** → **S3b**
(`DepDeclEdgeSource` + `DepDeclStore`, which needs the seam to plug into) → **S4's differential
gate** → **S5** → **S6** → **S7**. Note the seam (currently in S4) is a prerequisite of
the DepDecl loader (currently S3b); build the abstraction before the third implementation
of it.

- **S0 — `spec/dep-decl.md` + canonicalization + golden vector.** Write `spec/dep-decl.md` per the
  complete table of contents in §5 item 1. Write the character-level
  `canonical_serialize` rules (§3.2.2), `dep_decl_schema_version` discipline, the `EdgeSet`
  shape (including the in-memory-only fidelity tag), the schema-consistency validation
  rule (§5 item 1, §5 `dep_decl_schema_version` match check), and all 5 new
  `TNG-DEPDECL-*` error codes. Relocate the `.nimble` heuristic here (cross-ref from
  `manifest-grammar.md §5`). **Bootstrap protocol (serializer-free):** the v0 golden
  byte-vector is **hand-authored** — written character-by-character directly from the
  `spec/dep-decl.md §2` rules as a `.kdl` file and committed to the corpus; its `dep_decl_hash` is
  `sha256` of that file computed with any external tool. **No impl needs to run a
  serializer to produce it**, which is why round 1's "Corey picks a reference serializer"
  decision is dropped: there is no reference *impl*, only the spec text. **Golden-vector
  durability:** `spec/dep-decl.md §2` (the 7 canonical rules) is the permanent oracle for all
  future impls — including the v3+ Nim impl; the vector is a CONFORMANCE FIXTURE that
  catches a new producer's serializer bugs before it ships production DMDs. The vector is
  versioned per `dep_decl_schema_version`. **Fixture generator:** S0 ships a minimal
  `make_dep_decl_fixture(EdgeSet) → bytes` test helper (harness/producer-side tooling, **not**
  in the resolver impl) that S3b–S6 call to emit DepDecl artifact files. It need **not** be
  byte-canonical — those slices test parsing/verification, and each fixture's
  `dep_decl` is simply `sha256` of whatever bytes the helper emits; only the S0
  golden vector tests canonicalization. *(spec + one hand-authored fixture + one
  test-only generator; ~⅓ of the effort is pinning the byte-level rules.)*
- **S1 — `EdgeSet` type + DepDecl parse/verify (both impls, SSOT).** Promote the anonymous
  edge tuple to a first-class `EdgeSet` (incl. the in-memory-only `source` tag). Consumer
  path: **parse a DepDecl artifact → EdgeSet + verify `sha256(bytes)`**. **No serializer in
  the resolver impls** (§3.2): the conformance oracle is parse-only — parse the S0 golden
  fixture, assert the resulting `EdgeSet` equals a hand-constructed expected value, assert
  `sha256(bytes)` equals the corpus `dep_decl_hash`. mypy/clippy clean.
- **S2 — index version-node `dep_decl` + `dep_decl_schema_version`.** Parse +
  ignore-if-absent (forward-compat) in both index parsers; surface on the index Version
  type. **Lowest-risk wedge — recommended FIRST slice:** verified that both index parsers
  (`python-ng registry._parse_version_node`, `rust registry::parse_version_node`)
  whitelist known child names and silently ignore unknown children, so existing fixtures
  cannot break. S2 only *adds* extraction of the two new fields. Gate: index fixture
  with/without the pointer.
- **S3a — fixture-format plumbing.** Amend `conformance-fixtures.md`: a `dep-decl/` fixture
  slot (a fixture **artifact dir**, not a control file — it is copied verbatim into the
  scratch dir like `mocked-fetches/`), and a `MILPA_DEP_DECL_DIR` env var the harness runner
  injects as `MILPA_DEP_DECL_DIR=<scratch>/dep-decl/` when that dir is present (mirroring how
  `MILPA_INDEX_URL` is injected; the runner already strips inherited `MILPA_*`). **Add
  `MILPA_DEP_DECL_DIR` to `spec/cli-contract.md §8` (env-var table):** when set, the
  production `HttpDepDeclStore` is replaced by a `FileDepDeclStore` reading
  `$MILPA_DEP_DECL_DIR/<sha256_hex>.kdl` instead of the network URL derived from
  `MILPA_INDEX_URL`. Conformance-only env var (like `MILPA_MOCKED_FETCHES`), honored by
  all impls. *(No new resolver behavior — pure harness/spec plumbing that S3b–S6 depend
  on.)*
- **S3b — `DepDeclEdgeSource` + `DepDeclStore` (needs the S4 seam first — see ordering note).**
  Given a `dep_decl`, `DepDeclStore.get` (fetch-or-cache + hash-verify), parse → `EdgeSet`.
  Also validate `dep_decl_schema_version` match
  between index pointer and artifact (raise `TNG-DEPDECL-SCHEMA-MISMATCH` on disagreement)
  and check consumer's maximum understood version (raise `TNG-DEPDECL-SCHEMA-UNSUPPORTED`
  when artifact version exceeds impl's cap). Five new codes total:
  `TNG-DEPDECL-HASH-MISMATCH`, `TNG-DEPDECL-FETCH-FAILED`, `TNG-DEPDECL-PARSE-ERROR`,
  `TNG-DEPDECL-SCHEMA-MISMATCH`, `TNG-DEPDECL-SCHEMA-UNSUPPORTED`. **Fixtures** — one per error
  code, generated via S0's `make_dep_decl_fixture` utility: (i) valid DepDecl → parses to correct
  EdgeSet; (ii) corrupted bytes → HASH-MISMATCH; (iii) unreachable file → FETCH-FAILED;
  (iv) malformed KDL → PARSE-ERROR; (v) index pointer `dep_decl_schema_version=1` but
  artifact contains `dep_decl_schema_version 0` → SCHEMA-MISMATCH; (vi) artifact
  `dep_decl_schema_version` exceeds impl's cap → SCHEMA-UNSUPPORTED.
- **S4 — `EdgeSource` seam + resolver refactor + §4.2.1 amendment.** This is two
  movements (see ordering note): **(i)** introduce the `EdgeSource` units + the
  resolver-scoped `resolve_edges`/`edge_cache` priority function (§3.5) +
  `Nimble`/`MilpaKdl` sources (wrappers over existing parse code) + the normative
  `Manifest→EdgeSet` transitive projection + clauses (a)/(b)/(c); **(ii)** the
  differential gate. `FallbackEdgeSource` is a test seam only — the priority logic is
  `resolve_edges`. **Differential gate — twin fixtures:** clean `.nimble` (assert
  identical lockfiles) and a `when`-block `.nimble` (DepDecl authoritative, divergence
  allowed). The cross-fixture lockfile-equality assertion is a **new, genuinely-novel
  harness capability** — the per-fixture runner cannot diff two fixtures' outputs. Build
  it as an imperative test in **`harness/test_dep_decl.py`** (run under `pytest harness/`) that
  loads the fixture pair, runs both impls, and asserts lockfile equality — *not* a
  declarative corpus directive (simpler, no new fixture-metadata format). *Constraint:*
  the `.nimble`-fallback arm MUST NOT contain a malformed transitive constraint until the
  python-ng `MAN-NIMBLE-CONSTRAINT` gap is closed (else cross-impl equality fails on that
  gap, not on this RFC). Gated on the python-ng-fallback fork (§8).
- **S5 — fallback warning UX + strict mode.** A **single summary warning** at resolve
  end ("N deps resolved from un-attested `.nimble` metadata: …; see §4.1"), *not*
  per-dep noise (per-dep only under verbose); enumerated via the `EdgeSet.source` tag.
  **Strict policy composition (normative):** the effective policy is the logical **OR**
  of the manifest `attestation-policy "strict"` (committed, project-default — for
  review-enforced reproducible builds) and the `--require-attested-metadata` flag (CI,
  where the manifest can't be edited); **the flag MUST NOT weaken** a manifest-declared
  strict policy. Under strict policy, two distinct error codes: **(a)** a dep with no
  `dep_decl` in the index → `RES-UNATTESTED-METADATA`; **(b)** a dep whose
  `dep_decl` artifact is unreachable → `TNG-DEPDECL-FETCH-FAILED`. Gate: summary-warn
  fixture + both strict-fail fixtures.
- **S6 — lockfile pin + verify graph-drift.** Additive `dep_decl` pin (§3.7);
  `milpa verify` drift detection with `VERIFY-EDGE-MISMATCH` / `LOCK-DEPDECL-PIN-MISSING`;
  prior-lockfile + offline behavior (§3.7.1/§3.7.2). **Harness:** add the `verify` cmd
  token to the runner (both-impls gate). Gate: verify fixture with a tampered DepDecl + a
  pin-missing fixture.
- **S7 — error catalog + conformance saturation.** All new codes into `errors.md` /
  `errors.py` / Rust catalog with raise sites + fixtures; reconcile
  `conformance-fixtures.md §4`. Cross-impl: Rust passes every new fixture.
- **S8 — tianguis companion (sibling repo) — NOT a milpa slice.** File a tianguis issue
  referencing this RFC: ingest `.nimble`→`EdgeSet` per `spec/dep-decl.md`,
  `canonical_serialize`, DepDecl publication, cosign subject extension, `dep_decl` index
  emission, corpus backfill (§3.9). End-to-end gate (byte-identical `dep_decl_hash` on a real
  package vs milpa's S1) lives in that issue. **No milpa slice blocks on S8 at runtime**
  — the fallback covers the transition until real `dep_decl` entries exist.

## 10  Relationship to the in-flight clean-room rewrite

This RFC **resolves the 11b nimble fork**: resolver-side `.nimble` parsing is
transitional, so the durable fix for `MAN-NIMBLE-CONSTRAINT` is ingest-time validation
(§3.8), not hardening the resolver fallback. 11b's recommendation stands — park the
resolver-side `MAN-NIMBLE-CONSTRAINT` hardening, finish the swap (11c) on the existing
behavior, and let this RFC retire the fallback's mainline status afterward.

**Sequencing.** S0–S2 require python-ng to be **committed** (it is the active impl), but
**not** swapped (11c) — they touch the spec, the index parser, and a new type. S3b+ and
S4+ exercise the resolver and so land after the swap, *or* in parallel on a committed
python-ng baseline. The python-ng `.nimble`-fallback fork is **resolved** (keep the
fallback — §8), so S4's differential gate stands. The clean-room rewrite and this RFC
are otherwise independent.
