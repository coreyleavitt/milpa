# milpa fetcher protocol (S10)

Normative spec of the **Fetcher protocol** — the language-agnostic contract
a transport plugin must satisfy. Any implementation that claims milpa conformance
MUST implement the rules marked `> NORMATIVE:`. Items marked `> NOTE:` describe
the reference Python implementation; conformant alternatives MAY differ in those
details.

This document covers **Layer 2 backend-binding obligations** only.

- **Layer 1 — Provenance-descriptor grammar** (closed meta-grammar, kind
  registry, parse-always / verify-always / fetch-fails-precisely): see
  `docs/spec/manifest-grammar.md` §4 (S4). Do not duplicate the provenance
  shape enumeration here.
- **Layer 3 — Discovery** (`milpa.fetchers` entry-point convention, factory
  signature): Python-specific mechanism implemented in the reference
  implementation's `milpa/fetchers/__init__.py` (`_build_default_registry`,
  `importlib.metadata` entry-point scan). Not normative for non-Python porters;
  non-Python implementations define their own equivalent discovery mechanism.

Related specs:

- `docs/spec/errors.md` — `FETCH-*` error codes
- `docs/spec/identity.md` (S12) — identity algorithm; CAS admission;
  `cas_admissible` CAS-level contract
- `docs/spec/manifest-grammar.md` (S4) — provenance shapes (Layer 1); closed
  meta-grammar; kind registry

---

## Normative surface

A conformant fetcher implementation MUST:

1. Implement the three obligations — Claim, Materialize, Receipt — as defined
   in §1.
2. Signal materialization failure by raising `FetchError` (Python) / returning
   `Err(FetchError)` (Rust); leave `dest` cleanup to the registry (§2).
3. NOT compute or assert identity in any receipt field; the registry computes
   identity post-fetch (§3).
4. Declare `cas_admissible` on every `Provenance` subclass; editable sources
   MUST declare `False` (§4).
5. Return `True` from `can_handle` for exactly the provenance kind(s) the
   fetcher declares; MUST NOT return `True` for any other kind (§5).

A conformant registry implementation MUST:

6. Enforce unique-match dispatch: raise an ambiguity error if two or more
   registered fetchers claim `can_handle` for one descriptor; raise a no-handler
   error if none do (§5).
7. Compute identity from the materialized tree after every successful fetch,
   never delegating identity computation to the fetcher (§3).
8. Read `cas_admissible` before calling `admit()` and skip CAS admission for
   non-admissible provenances (§4).

---

## 1  Three obligations

Every fetcher satisfies exactly three obligations.

### 1.1  Claim

> NORMATIVE: A fetcher MUST implement `can_handle(provenance) -> bool`. The
> method MUST return `True` for every provenance kind the fetcher declares
> support for and MUST return `False` for every other kind. A fetcher MUST NOT
> return `True` for a provenance kind it cannot fully materialize.

The return value is the fetcher's sole dispatch signal. The registry calls
`can_handle` on every registered fetcher and enforces unique-match (§5).

### 1.2  Materialize

> NORMATIVE: A fetcher MUST implement `fetch(name, provenance, *, dest) ->
> ProvenanceReceipt`. On success, the materialized source tree MUST be present
> under `dest/` when the method returns.

> NORMATIVE: The fetcher MUST NOT compute, hash, or assert identity — it must
> not call the milpa identity algorithm (`compute_content_hash` or equivalent)
> anywhere in its `fetch` implementation. Identity is computed by the registry
> post-fetch (§3).

> NORMATIVE: `dest` is provided by the registry. The fetcher MUST write the
> tree under `dest/`; it MUST NOT create a parallel path or rename `dest` to a
> different location.

### 1.3  Receipt

> NORMATIVE: `fetch` MUST return a `ProvenanceReceipt` subclass instance that
> records transport-pinning fields (§3.2). The receipt MUST NOT contain any
> field whose value is a function of the materialized tree bytes (§3.1).

---

## 2  Failure

> NORMATIVE: When materialization cannot complete, the fetcher MUST signal
> failure by raising `FetchError` (Python) / returning `Err(FetchError)` (Rust)
> with an appropriate `FETCH-*` code from `docs/spec/errors.md`.

> NORMATIVE: The contents of `dest` after a failure are **undefined**. The
> fetcher MUST NOT attempt to clean up `dest` itself; cleanup is the
> **registry's responsibility**. The registry calls `clear_dest(dest)` before
> retrying or propagating the error.

> NOTE: In the reference Python implementation, `FetcherRegistry.fetch` wraps
> the fetcher call in a `try/except BaseException` block and removes the scratch
> directory on failure (see `types.py`, the CAS path branch). Callers of
> `fetch_any` similarly call `clear_dest(dest)` between candidates. The fetcher
> is not involved.

The `FETCH-ALL-FAILED` code is raised by `fetch_any` when every candidate
provenance fails; individual fetcher failures use transport-specific codes
(`FETCH-GIT-FAILED`, `FETCH-DOWNLOAD-FAILED`, `FETCH-OCI-PULL-FAILED`, etc.).
See `docs/spec/errors.md` §FETCH for the full list.

> NORMATIVE: A tarball fetcher MUST wrap all archive extraction operations with
> the sandboxed extractor. Extraction failures (zip-slip, symlink-escape, size
> limits, file-count limits) MUST be surfaced as `FETCH-*` errors; `EXTRACT-*`
> codes are defined in `docs/spec/errors.md` §EXTRACT. The tarball fetcher
> signals extraction failure by raising `FetchError` with the appropriate
> `EXTRACT-*` code as the cause; the cleanup obligation above applies.

---

## 2.1  Tarball extraction limits

> NORMATIVE: A conformant tarball fetcher MUST apply the following extraction
> limits **before or during** extraction, before any bytes are written to
> `dest/`. Limits are enforced by the sandboxed extractor
> (`safe_extract.extract_tar` in the reference implementation). The defaults
> are normative; a conformant implementation MAY allow callers to tighten them
> but MUST NOT exceed them without explicit user configuration.
>
> | Limit | Default | Error code |
> |---|---|---|
> | Total uncompressed size across all entries | 1 GiB (2³⁰ bytes) | `EXTRACT-SIZE-LIMIT` |
> | Per-file uncompressed size | 256 MiB (2²⁸ bytes) | `EXTRACT-SIZE-LIMIT` |
> | Total file count (regular files + symlinks) | 100 000 | `EXTRACT-SIZE-LIMIT` |
>
> Additionally, the extractor MUST reject:
>
> | Attack class | Error code |
> |---|---|
> | Zip-slip (entry resolves outside `dest/`) | `EXTRACT-ZIP-SLIP` |
> | Symlink-escape (symlink target resolves outside `dest/`) | `EXTRACT-SYMLINK-ESCAPE` |
>
> All five checks MUST be applied to every extraction. The size checks run
> during extraction (streaming); the path-escape checks run per-entry before
> any write. A failure MUST abort the extraction immediately and raise
> `FetchError` with the matching code.

> NOTE: The reference implementation's defaults are declared as keyword
> arguments on `extract_tar` in `milpa/fetchers/safe_extract.py`:
> `max_total_size=1<<30`, `max_file_size=1<<28`, `max_file_count=100_000`.
> Device nodes, FIFOs, and other non-regular, non-symlink, non-directory entry
> types are silently skipped (never legitimate in a source archive).

---

## 3  Identity contract

### 3.1  Identity is forbidden in the receipt — field-level line

> NORMATIVE: A `ProvenanceReceipt` subclass MUST NOT define any field whose
> value is computed from, or is a function of, the materialized source tree bytes.
> Specifically, fields named or equivalent to `content_hash`, `identity`,
> `tree_sha256`, or any other tree-level digest are **forbidden** in receipt
> types.

**Why:** identity (`sha256` of the source tree) is milpa's trust anchor,
computed by the **registry** in every conformant implementation after the
fetcher returns. If a fetcher populated an `expected_hash` or `tree_sha256`
field in the receipt, a buggy or hostile fetcher could supply a wrong value
that a careless registry accepted instead of recomputing — a trust bypass.
The forbidden-field rule enforces the invariant **structurally**, not by
procedure: there is no "identity field the registry should ignore" because
such a field cannot exist.

> NORMATIVE: Fields recording the **transport artifact's own identifier** are
> **permitted and expected** in receipt types. Examples:
>
> - `GitReceipt.commit_sha` — identifies the git object, not the source tree
> - `OciReceipt.layer_digest` — identifies the compressed OCI blob
> - `TarballReceipt.archive_sha256` — identifies the downloaded archive before
>   extraction
> - `LocalReceipt.resolved_path` — records the filesystem path used
>
> None of these is the source-tree hash milpa keys on. A porter writing a
> receipt field for "what the transport delivered" is explicitly permitted.

**The precise permitted/forbidden boundary:** a receipt field is permitted iff
its value can be computed without access to the materialized tree at `dest/`.
A receipt field is forbidden iff producing its value requires hashing or reading
the materialized tree bytes.

### 3.2  Receipt must be non-empty — structural enforcement

> NORMATIVE: Every concrete `ProvenanceReceipt` subclass MUST declare at least
> one transport-pinning field. A receipt that records no transport-specific
> information provides no provenance evidence and MUST be rejected at admission
> time.

> NOTE: The reference Python implementation (`milpa/fetchers/types.py`) defines
> `ProvenanceReceipt` as an abstract base class with an `@abstractmethod
> transport_fields() -> dict[str, str]` that every concrete subclass must
> implement. The reference registry enforces the non-empty obligation at
> admission time via `FETCH-RECEIPT-EMPTY`. Built-in receipts (`GitReceipt`,
> `TarballReceipt`, `OciReceipt`, `LocalReceipt`) each declare ≥1
> transport-pinning field and implement `transport_fields()`. Third-party
> fetchers MUST satisfy the same obligation; the registry enforces it at
> admission time.

### 3.3  Registry computes identity

> NORMATIVE: The registry MUST call the milpa identity algorithm
> (`compute_content_hash` or its equivalent per `docs/spec/identity.md` §1) on
> the materialized tree at `dest/` after every successful `fetch` call, before
> returning a `FetchResult`. The `identity` field of `FetchResult` MUST be set
> by the registry, never by the fetcher.

> NORMATIVE: No fetcher — built-in or third-party — may influence the
> `FetchResult.identity` value. The registry walks the tree itself.

> NOTE: This is sharpened from the RFC's sketched signature (which had
> `FetchResult` returned by the fetcher). The tightened types enforce the
> invariant structurally — `fetch` returns only `ProvenanceReceipt`; `FetchResult`
> is assembled by the registry.

---

## 4  `cas_admissible` declaration

> NORMATIVE: Every `Provenance` subclass MUST declare a `cas_admissible` class
> attribute (not an instance field) of type `bool`. The registry reads this
> attribute before calling `admit()` on the CAS.

> NORMATIVE: Editable sources — local-path provenances and workspace-member
> provenances — MUST declare `cas_admissible = False`. Admitting an editable
> source would silently freeze user edits: the CAS entry would be immutable while
> the user's source tree continues to change, and subsequent resolution would
> serve the frozen content.

> NORMATIVE: Immutable sources — **all git provenances** (regardless of whether
> `commit_sha` is set or the ref is a branch/tag/HEAD) and tarball provenances
> — MUST declare `cas_admissible = True`. The registry admits these into the
> CAS after the first fetch and serves subsequent resolution from the store.

**Why all git provenances are admissible:** CAS-admission safety does not come
from the provenance kind but from the post-fetch identity gate. After any git
fetch, the registry computes `content_hash` over the materialized tree and
checks it against the expected value in the lockfile. If the fetched content
differs from what was locked (including a moving-ref that advanced), the
identity mismatch is detected at that gate — the CAS entry is never stored with
the wrong hash. A mutable-ref git provenance on a first fetch (before any lock)
produces a correct CAS entry because the CAS is keyed on the content hash; on a
subsequent `--frozen` run the CAS entry is served unconditionally. The safety
invariant is the identity gate, not a restriction on which git provenances may
be admitted.

> NOTE: In the reference Python implementation, `Provenance` (the base dataclass
> in `types.py`) declares `cas_admissible: ClassVar[bool] = True`, making
> immutability the default. `LocalProvenance` overrides with `cas_admissible =
> False`. Subclasses MUST override the default explicitly if they represent an
> editable source.

**Why this is part of the protocol:** `cas_admissible` is a contract
declaration, not an implementation detail. The registry in any conformant
implementation must read it before deciding whether to admit. A third-party
fetcher for a new mutable source (e.g. an SSH-backed live checkout) must
declare `False`; if it did not, the registry would silently freeze content the
user expects to be live. The fetcher is the only party with the knowledge to
make this declaration correctly.

See `docs/spec/identity.md` (S12) §3 for the CAS-level `admit()` contract.

---

## 5  Exclusive dispatch

> NORMATIVE: The registry MUST enforce **unique-match dispatch**. For a given
> provenance descriptor, exactly one registered fetcher MUST claim it via
> `can_handle`. If two or more registered fetchers return `True` for the same
> descriptor, the registry MUST raise an ambiguity error and MUST NOT proceed
> with materialization. If no registered fetcher returns `True`, the registry
> MUST raise a no-handler error.

> NORMATIVE: The dispatch rule is stated without reference to any
> language-specific mechanism. A plugin's `can_handle` MUST return `True` for
> exactly the provenance kinds it declares; the registry enforces unique-match at
> dispatch and raises an ambiguity error if two registered fetchers both claim one
> descriptor.

**Registration order is for readability, not priority.** The exclusive-dispatch
rule means a plugin cannot shadow a built-in fetcher by registration order —
claiming the same kind as a built-in triggers the ambiguity error, not a silent
override. This is a stronger safety property than "built-ins win": it fails
loudly rather than permitting any silent substitution.

> NOTE: In the reference Python implementation, `FetcherRegistry._select`
> (`types.py`) collects all fetchers whose `can_handle` returns `True` in a list
> comprehension, then inspects `len(matches)`. If `> 1`, it raises `FetchError`
> naming the conflicting fetchers. If `== 0`, it raises `FetchError` naming the
> unhandled provenance kind. Only `matches[0]` is used — but the single result is
> the output of a uniqueness check, not a priority tie-break. The `default_registry`
> pre-registers four built-in fetchers: Git, Local, Tarball, OCI.

The built-in kind set (git, local, tarball, oci) is defined by the spec and
owned by the spec version. A third-party fetcher claiming one of these kinds
will trigger the ambiguity error. A fetcher for a **new kind** (not in the
built-in set) is possible only with a spec amendment that adds the kind to the
kind registry; see `docs/spec/manifest-grammar.md` §4 (Layer 1 / P3).

---

## 6  Layer-2 backend binding and content-addressing override safety

**A key property of the Layer-2 backend contract:** two different backends for
the same provenance kind (e.g. a libgit2-based git fetcher vs. the reference
subprocess-git fetcher) produce byte-identical source trees for the same pinned
source — and therefore byte-identical identity hashes. This means backend
substitution is **safe by construction** for immutable references, not a footgun
that must be forbidden.

> NORMATIVE: **Byte-equivalence across backends holds for pinned identities
> only** — commit SHAs, tags that resolve to a fixed commit, tarball
> content-hashes. For a mutable reference (`ref=main`, a branch, a moving tag),
> two backends (or one backend at two times) may clone different commits, produce
> different trees, and therefore produce different identity hashes. This is not a
> hole in the safety argument.

> NORMATIVE: For a **locked** dep (identity pinned in the lockfile), a backend
> that delivers content with a different identity hash MUST be detected by the
> registry's identity check and treated as a failure — the mismatch is raised as
> an identity error, not silently accepted. `fetch_any` enforces this: a candidate
> whose materialized bytes produce a hash different from `expected_identity` is
> dropped and the next candidate is tried (with a warning). The trust boundary is
> the content hash, not the transport.

**Implication for the frozen fast-path:** mutable-ref resolution is not part of
the frozen fast-path because the identity is not yet pinned. Once a resolution
cycle pins the identity into the lockfile, subsequent `--frozen` runs bypass the
fetcher entirely (serving from CAS) and the identity check is structural.

> NOTE: The Layer-2 backend-override configuration surface (declaring "use
> backend B for kind K") is not implemented in spec v1.0. Filing it as a
> follow-up is an explicit design decision ([[feedback_defer_file_now]]); it is
> non-breaking because the exclusive-dispatch + content-hash model already makes
> override semantically safe.

---

## 7  `FetcherConfig` — normative definition

Every plugin factory receives a `FetcherConfig` instance. The factory signature
is:

```
(config: FetcherConfig) -> Fetcher
```

> NORMATIVE: The factory MUST accept exactly one positional argument of type
> `FetcherConfig`. A zero-argument factory is not conformant; a two-or-more-
> argument factory is not conformant. The reserved-slot discipline (§7.1) is why.

### 7.1  v1 shape

> NORMATIVE: `FetcherConfig` in spec v1.0 is a struct with **no required
> fields**. It reserves exactly one optional forward hook:
>
> ```
> FetcherConfig {
>   mirror_urls: list[str]  # optional; default []; not required to be honored in v1
> }
> ```
>
> No other fields exist in v1. An implementation MUST NOT define additional
> fields on `FetcherConfig` without a spec amendment.

> NORMATIVE: A v1 fetcher MAY ignore `mirror_urls`. The field is reserved so
> that a future spec version can pass mirror candidates without a breaking
> signature change. A fetcher that reads and uses `mirror_urls` in v1 is doing
> so as a forward-compatible optimization, not a conformance obligation.

> NOTE: In the reference Python implementation, `FetcherConfig` is a frozen
> dataclass in `milpa/fetchers/types.py`. A Rust porter MUST define the
> equivalent struct before writing the discovery harness; the v1 shape (one
> optional `mirror_urls` field, no required fields) is normative here.

**Why a slot at all:** a zero-argument factory forecloses ever passing a plugin a
mirror URL, a timeout, or a credential token without a breaking signature change.
Reserving the one-argument slot now (with an empty struct) costs nothing and
satisfies [[feedback_minimal_over_completeness]] — the slot is built, the config
system is not. This is the exact failure the gate exists to prevent: if the
factory signature is undefined, the Rust impl invents a different shape and the
two impls diverge at the discovery boundary.

---

## 8  Cancellation and credentials — stated non-contracts

### 8.1  Cancellation

> NORMATIVE: Cancellation and timeout propagation into the fetcher are **not
> guaranteed in spec v1.0**. A fetcher is not required to handle cancellation
> signals. A registry is not required to propagate timeouts to the fetcher's
> `fetch` call.

This is stated explicitly so no conformant implementation invents propagation
semantics that become a de facto cross-impl expectation. A future spec amendment
may add cancellation obligations; until then, implementations that handle
cancellation do so as an incidental quality-of-implementation choice.

### 8.2  Credentials and authentication

> NORMATIVE: Credential passing to fetchers is **explicitly deferred** and is a
> known spec hole in v1.0. No conformant implementation SHOULD define a
> credential-passing convention through `FetcherConfig` or any other mechanism
> without a spec amendment, as doing so risks cross-impl divergence in the
> credential model.

> NOTE: The reference Python implementation handles credentials informally
> (git credential helpers via the subprocess environment; no explicit credential
> API). This is incidental and not normative. Per `docs/rfc-pluggable-fetchers.md`,
> credential federation is deferred work; the `FetcherConfig` slot is designed to
> carry it when the spec amendment lands.
