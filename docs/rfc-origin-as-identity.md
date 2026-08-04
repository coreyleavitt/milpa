# RFC: Origin-as-identity — the solver variable is a source-id, not a name

- **Status:** Draft (architect Step 6 output; pending 2 architect review rounds → `/tdd`)
- **Supersedes:** the "provenance lattice / validate-against-registry" model
  (`1ff17bd`, `f889621`, the resolver part of `31454de`) and the uncommitted
  corrected-§10 stopgap.
- **Fixes:** #193 (named-vs-url provenance divergence — root-caused), #192
  (re-resolution drift — adjacent). **Composes with (does not fix):** #191 (real
  versions — already shipped as `rfc-resolution-semantics.md` Axis A; see §14).
  **Investigates (claim tightened, see §12):** the
  `BUG-root-authority-kdl-transitive.md` regression cases A–D.
- **Touches:** both impls (Python reference + Rust), the shared conformance
  corpus, and normative spec (`spec/resolver-semantics.md` §6a/§6b/§10/§4.2.1,
  `spec/errors.md`, `spec/identity.md`).

---

## 1. Summary

Today milpa keys the PubGrub solver variable by the **consumer's name/label** —
a bare `str` (`Term.package: str` in Python `solver.py:104`; `Dep.package: String`
in Rust `milpa-solver/src/lib.rs:905`). For a `git=`/`local=`/`tarball=` dep that
string is the label the author wrote (or a URL-tail guess); for a `named` dep it
is the registry coordinate (`name` / `ns::name`).

Keying by label is the root defect behind a family of bugs. This RFC makes the
solver variable a **source-id**: the package's *origin*, version-independent. A
`git=` dep is keyed by its normalized URL; a `named` dep by its registry
coordinate; a workspace member by its member name. Source selection stops being a
fragile side-table (`provenance_gate`) bolted onto name-keying and becomes a
first-class **binding phase** that produces the solver's variables.

The design is Cargo's proven `(name, source)` identity model, refined by milpa's
`content_hash` (which lets genuinely-identical bytes dedup across distinct
source-ids — something Cargo cannot do). It is settled industrial practice, not
research.

---

## 2. Motivation

### 2.1 The three namespaces, fused into one string

Milpa (and nimble) collapse three genuinely distinct concepts into "the name":

1. **Import symbol** (`import z3`) — a Nim *compile-time, build-local* resource.
   The flat import namespace means at most one package may occupy `z3` in a
   build. This is a property of a *build closure*, not of a package.
2. **Package origin** — "this is `coreyleavitt/nim-z3`, a specific project,"
   true independent of what any consumer calls it. Global, version-independent.
   (Named "origin," not "identity": per §3.1 the bare word *identity* is reserved
   for `content_hash` everywhere, and this concept is deliberately *not* that.)
3. **Version-solving variable** — the unit PubGrub intersects constraints over.

Keying all three by one author-chosen string produces both failure directions:

- **False collision** — two *different* packages that share an import name
  (`coreyleavitt/nim-z3` vs `zevv/nimz3`) are forced to fight over the string
  `z3`, even when only one is in the graph. This is the amoxtli / proptest `z3`
  scare and the `#193` mess.
- **Missed unification** — the *same* package referred to by two labels (a
  consumer writes `z3`, another writes `nim_z3` for one repo) becomes two solver
  variables that can pick two versions and then collide at `import` time. The
  `edge_cache` keyed by `(name, Version)` (`edge_sources.py:653`) even seals two
  separate EdgeSet entries for one tree — a latent correctness bug.

### 2.2 Source selection is a fragile side-table

Because the solver variable is a name, source selection is bolted on as a
side-table: `provenance_gate: dict[name, (pkey, tier)]` with a hand-rolled
authority lattice (`TIER_ROOT > TIER_REGISTRY > TIER_SELF_URL`) checked *during*
BFS (`resolver.py:3790-3880`; Rust `gate()` mirror). `BUG-root-authority-kdl-transitive.md`
is a direct symptom: when the gate suppresses a claim that came from a fetched
dep's `milpa.kdl`, the solver is left holding a requirement edge whose candidate
universe is never populated → PubGrub unwinds to "no satisfying version" for
*every* root term. The side-table can mutate the solver's inputs into an
inconsistent state; a first-class binding phase that *produces* the variables
cannot.

### 2.3 What exploration confirmed (both impls)

- The solver variable is already an opaque `str` — the solver does not care what
  it denotes. The defect is entirely upstream (what string is built) and
  downstream (how the string maps back to a `_deps/<name>/`).
- **Every origin is knowable before solve, without fetching the package:**
  git/local/tarball from the manifest declaration; `named` from the pre-loaded
  registry index (`IndexVersion.provenances[0]`). Fetching only ever selects a
  *version*. → The binding phase can be **pure and pre-fetch**.
- The git-URL normalizer already exists (`_normalize_git_source_url`,
  `resolver.py:3601`, mirrored in Rust) — but only as a *side-channel* agreement
  check inside `_validate_transitive_url_against_registry`. This RFC promotes it
  to *the* equality definition.

---

## 3. The model

> **AMENDMENT (2026-08-03, DE2-ref) — reverses "ref/digest EXCLUDED".** The
> original model below made a git/oci/tarball source-id *URL-only*, excluding the
> ref/tag/digest on the theory that "they are VERSIONS, not the origin." That is
> wrong for a **direct** dep: a git commit (or a branch, or a non-semver tag)
> does not live in a version lattice, so it cannot be selected as a version — it
> is a **source pin**. Excluding it left the `BindingResolver` blind to
> ref-disagreement: two claims for the same URL at different commits looked
> *identical* to the binding, so it never arbitrated, and the downstream fetch
> silently picked one — differently in each impl (the amoxtli / #194 divergence:
> a root `nkdl ref=62bacf7` pin was silently ignored in favour of a transitive's
> `f42588456`).
>
> **Correction: the ref/digest is part of the source-id of a DIRECT dep.** Not a
> version, not a separate identity axis — the *pin*. A registry dep's source-id
> stays version-independent (the coordinate spans all versions; the registry does
> version-selection); a **direct** dep's source-id is a specific pinned source
> (`origin + ref/digest`), because a `git=`/`oci=`/`tarball=` declaration *is* one
> exact source, not a version range. This asymmetry is honest — a registry is a
> version *source*, a git pin is a version.
>
> Everything then falls out of machinery that already exists, with **no new
> arbitration mechanism**: unification stays **name-based** (`BindingResolver`
> maps `DepKey → source-id`), so a bare `requires "nkdl"` still unifies with a
> root pin via the *name*. A transitive claim on the same origin at a *different*
> ref is now a **disagreeing** claim → `LOST_TO_ROOT` (the root/override pin wins,
> Cargo `[patch]`); two *transitive* pins disagreeing with no root arbiter →
> `RES-BINDING-CONFLICT` ("declare it at the root to resolve"). Rejected: (b1) ref
> as its own identity axis — makes two commits of one repo two graph nodes sharing
> one name (collision) you then special-case away; (b2) Go-style pseudo-versions —
> elegant and maximally uniform, but machinery for *commit-range / branch-tracking*
> semantics milpa's exact-pin ecosystem does not use (and it drags in commit-
> timestamp fetching + semver-vs-pseudo ordering edge cases). milpa is Cargo-shaped
> (hybrid registry + direct); Cargo's git `SourceId` carries the `GitReference` and
> conflicting revs on one source error — that is the model. **Breaking change** to
> the canonical form and the lockfile (pre-v1 — fine). Supersedes the "ref/digest
> EXCLUDED" line below and reframes #194 from "arbitrate a winner" to "implement
> this." See §4.1.

Separate the three namespaces; give each its own layer:

```
solver variable   = source-id = the pinned source
                    origin ∈ { git url | oci coord | tarball url | local path | registry coord | member }
                    DIRECT deps (git/oci/tarball): source-id INCLUDES the ref/digest — it is the PIN
                    REGISTRY/member deps: version-independent coordinate (version-selected separately)
                    (see the DE2-ref amendment above; "origin" names the source-id, per §3.1 — never "identity")

overrides {}      = explicit source replacement            ← the bridge (= Cargo [patch] / Go replace)

content_hash      = per-version verification (UNCHANGED)    ← also CAS-dedups identical bytes
                                                              across DISTINCT source-ids (milpa's edge)

import-slot check = post-solve build-closure constraint     ← where Nim's flat-namespace rule lives
```

### 3.1 Identity vs. the non-negotiable

The CLAUDE.md non-negotiable "identity = `content_hash`" is **not** violated. We
introduce two concepts and name them distinctly:

- **source-id** = *version-independent origin* = the solver variable. (Cargo calls
  this a `SourceId`; Go calls it the module path.)
- **content_hash** = *identity* — the per-version verification identity, unchanged,
  still `dag-sha256:…`, still the CAS key, still orthogonal to source selection.

We rename the *solver variable* from name to source-id; we do not touch what
`content_hash` means or does.

> **Vocabulary discipline (normative for §7 spec prose).** The bare word
> "identity" is reserved for `content_hash`, everywhere — including this section.
> A `SourceId` is an **origin**, never an "identity." This section's own job is to
> prevent that conflation; the spec text it produces (`spec/identity.md`) must hold
> the line, since imprecision compounds across a normative doc read by two impls.

### 3.2 Registry deps: coordinate-is-origin (Cargo's model)

milpa is a **hybrid** resolver (registry *and* direct source deps), so it sits in
the Cargo/npm/pip family, not Go's. Best-in-class for that family is Cargo's:

> A `named` dep's source-id **is** its registry coordinate (`pkg://<registry>/<ns>/<name>`).
> A `git=` dep's source-id is its normalized URL. Same name + different source =
> **different packages.** milpa never auto-unifies a `git=` dep with a `named` dep
> by inspecting/normalizing URLs — no mainstream resolver does, because
> URL-equivalence is undecidable and silently merging a registry identity with a
> lookalike repo is a correctness/security hazard.

The **bridge** is `overrides {}` (milpa's `[patch]`): to make a transitive
`named "chronos"` resolve to a git fork, declare it at the root; the override
rebinds the name's source. Explicit, safe, user-controlled.

**Consequence:** the OCI-`source` field (`2770d3d`/`79be709`) stops being a
*resolution* input. It is re-homed to provenance/audit metadata — still useful
("which repo was this artifact built from," for attestation/traceability), just
not consulted during source selection.

### 3.3 milpa's edge over Cargo

Two distinct source-ids (a registry coordinate and a git URL) that fetch to the
same `content_hash` are provably identical bytes and **dedup at the CAS /
materialization layer** — so we keep Cargo's safe identity semantics (no URL
guessing in the solver) *and* avoid wasted disk when they genuinely are one tree.
Dedup is a storage optimization, strictly downstream of solving; it never merges
solver variables.

**Merge-on-proof vs. merge-on-heuristic — the precise invariant (round-2
correction — D1/B4).** The prohibition above is specifically against merging
*distinct origins by heuristic* (URL normalization *guessing* two remotes are one
package — §3.2's rejected "resolve-through"). It does **not** forbid unifying two
origins that are *provably* one tree. milpa already ships exactly that provable
unification: `resolver.py`'s "Step 6b" `_dedup_candidates` (**Phase B**,
`rfc-content-addressed-identity.md`) runs **post-fetch**, groups eager candidates
by `content_hash`, collapses each identical-byte group to a single canonical solver
variable + one `_deps/` view, and guards the merge with an invariant (*identical
content ⇒ identical `requires`, else `MILPA-INTERNAL`*). That is merge-on-proof,
and it is the deepest, best place to realize milpa's edge.

Under source-id keying this pass becomes **cross-origin**: a registry coordinate
and a git URL that fetch byte-identical trees collapse to one solver variable — the
headline §3.3 win, realized at the solver layer, not merely on disk. It is safe by
construction: it fires only on identical bytes (a dependency-confusion attack
requires *different* bytes → different `content_hash` → never merged), and it runs
*after* the pre-fetch S3c tripwire, so it cannot blind it. This RFC therefore
**keeps and extends** Phase B (S4b reconciles it with source-id keying and records
both collapsed origins' provenance), rather than removing it. What genuinely
remains open in #32–#34 is the *global cross-project* CAS store and multihash — not
this within-resolve unification, which is landed.

---

## 4. Design

The chosen design is a hybrid of four architect proposals: an ergonomic value
type, a single kind-dispatched normalizer, a deterministic binding stage, a
phased import-slot check, and an untouched solver.

### 4.1 `SourceId` — the value type

A **closed union of frozen per-kind dataclasses** (matching the existing
`IndexProvenance = GitIndexProvenance | OciIndexProvenance` idiom in
`registry.py:231` — type-safe dispatch, structural eq/hash for free, no
hand-maintained `kind: str` discriminator):

```python
# milpa/source_id.py  (new module — the single source of truth for origin identity)

# DE2-ref amendment (§3): a DIRECT dep's source-id includes its PIN
# (ref/digest). Two claims for one origin at different pins are DISAGREEING
# claims, arbitrated by BindingResolver (root/override wins; two transitive
# pins with no root arbiter → RES-BINDING-CONFLICT). Unification stays
# name-based, so a bare `requires "x"` still binds to a root pin via the name.

@dataclass(frozen=True)
class GitSourceId:
    url: str                      # ALWAYS normalized (see 4.2)
    ref: str | None = None        # the PINNED ref (branch/tag/sha) AS DECLARED;
                                  #   None = default branch. Part of the source pin
                                  #   (DE2-ref). Compared as-declared pre-fetch — the
                                  #   binding is pure; the lockfile records the
                                  #   RESOLVED commit as provenance. (Normalizing
                                  #   equivalent refs — a tag vs the sha it points to —
                                  #   via `git ls-remote` is a possible future
                                  #   precision refinement, out of scope here.)
    subpath: str | None = None    # normalized posix; None = repo root

@dataclass(frozen=True)
class OciSourceId:
    registry: str
    repository: str
    digest: str | None = None     # the PINNED digest (DE2-ref); part of the pin
    subpath: str | None = None

@dataclass(frozen=True)
class TarballSourceId:
    url: str                      # each distinct URL is a distinct source (the URL
                                  #   IS the pin — a specific archive)
    subpath: str | None = None

@dataclass(frozen=True)
class LocalSourceId:
    path: str                     # canonicalized; workspace-relative when under root, else absolute

@dataclass(frozen=True)
class RegistrySourceId:
    registry: str                 # WHICH index (base URL / configured alias)
    namespace: str | None
    name: str

@dataclass(frozen=True)
class MemberSourceId:
    member_name: str              # workspace-internal; conflict-free by construction

FetchableOrigin = (                        # origins that are fetched, hashed, materialized
    GitSourceId | OciSourceId | TarballSourceId
    | LocalSourceId | RegistrySourceId
)
SourceId = FetchableOrigin | MemberSourceId
```

**`MemberSourceId` is split out of `FetchableOrigin` deliberately (round-2 fix —
G4).** A workspace member is never fetched, never CAS-hashed, and never carries an
attestation subject; it is conflict-free by construction (W1–W5 name uniqueness).
The binding phase (§4.3) genuinely needs all six kinds, so it types over
`SourceId`. But `edge_cache` (§4.5), the import-slot check (§4.6), and the
attestation subject binder (§4.7) apply *only* to fetched origins — they type over
`FetchableOrigin`, so "members do not participate in fetch / CAS / attestation" is
an exhaustiveness fact the type checker enforces at each of those sites, not a
convention an implementer (or the Rust mirror) has to remember from prose.

> **`subpath` stays a per-kind field, not a `Subpathed[T]` wrapper (round-2 —
> considered, declined, G5).** Three kinds (`Git`/`Oci`/`Tarball`) repeat
> `subpath: str | None`. A generic `Subpathed[T]` wrapper was proposed to dedup
> the *field declaration*. Declined: the injectivity/escaping logic is already
> centralized once in `canonical`/`parse` (not duplicated), so only a one-line
> field decl repeats; against that, a wrapper forces a *heterogeneous* union
> (`Subpathed[GitSourceId] | … | LocalSourceId | …`) that breaks the clean
> "closed union of per-kind frozen dataclasses" symmetry and complicates every
> `match` arm. The duplication cost is one field in a hypothetical 7th
> subpath-bearing kind; the wrapper cost is paid at every call site today. Bar
> ([[feedback_minimal_over_completeness]]): keep the flat union.

**Canonical string form** — doubles as the `Term.package` value *and* the
lockfile key. Borrows pip's recognizable `#subdirectory=` fragment:

```
git+https://github.com/coreyleavitt/nim-z3
git+https://github.com/facebook/react#subdirectory=packages/react-dom
oci+ghcr.io/coreyleavitt/softlink
tar+https://example.com/dist/pkg-1.4.0.tar.gz
pkg+tianguis/softlink                         # registry alias + name (no namespace)
pkg+tianguis/acme/utils                       # registry alias + namespace + name
file+relative/path/from/workspace/root
file+/abs/path/outside/workspace              # cross-repo dev link (#42)
member+intonaco
```

```python
def canonical(sid: SourceId) -> str: ...      # ONE-WAY: solver key + display only
def format_source_id(sid: SourceId) -> str: ...  # human diagnostic form (B6)
```

**No `parse()` — the authoritative representation is the native struct, not a
string (round-2.5 correction, [[provenance_source_selection]]).** Research across
cargo/uv/go confirmed none serialize a `(registry, namespace, name)` coordinate
into a flat delimited string that is parsed back into typed fields: cargo holds a
native `SourceId` struct (field-wise eq/hash), formats a string only at write, and
never parses one back; uv stores a *structured* `source = {…}` table; go treats
the whole `/`-laden module path as one never-decomposed atom. milpa follows
cargo/uv: `SourceId` is the frozen struct (its `frozen=True` gives field-wise
eq/hash for free — this **is** the identity), it is serialized **structured on
disk** (§7 — a KDL `source { … }` node, not a flat key), and
`ResolvedDep.source_id` (§4.4) carries the typed struct wherever a consumer needs
it. Nothing reconstructs a `SourceId` by parsing a flat string, so `parse()` is
deleted along with the `#subdirectory=`/percent-escaping machinery an earlier draft
needed only to make a flat string round-trippable.

**The injectivity law** (property-tested with Hypothesis) — `canonical` need only
be a *one-way* injective key, no longer a round-trippable wire format:

```
canonical(a) == canonical(b)  iff  a == b        # injective; NOT parsed back
```

Injectivity is satisfiable without any escaping because each kind's key ends in a
`/`-free discriminating segment. In particular the registry form is
**variable-arity with the name last**: `pkg+<alias>/<ns…>/<name>` where `<ns…>`
may itself contain `/` (host-qualified namespaces — 884/886 real tianguis
namespaces do, e.g. `codeberg.org/eris`). It is injective because `<alias>` is the
first `/`-free segment and `<name>` is the last `/`-free segment (both fenced to
the package-name alphabet), so the middle is unambiguously the namespace. The
grammar below is normative:

**Registry component is an alias, never a base URL (§11 resolved).** A base URL
legitimately contains `/` and `:` (`https://tianguis.example.com/v2`), so it never
appears in a `SourceId`. The `pkg+` form's first segment is a **configured registry
alias** — a slug from `[A-Za-z0-9_-]+` (no `/`), resolved to a base URL via local
config. The lockfile stores the alias; a machine whose config lacks it fails closed
with `FROZEN-REGISTRY-ALIAS-UNRESOLVED`.

**`pkg+` canonical-key rule (normative — variable-arity, name-last).** Because
`canonical` is now a *one-way* key (§above, not parsed back), the form is
`pkg+<alias>/<namespace>/<name>` where **`<namespace>` may contain `/`** (it is a
`/`-joined path of host-qualified segments, as 884/886 real tianguis namespaces
are). Injectivity holds because `<alias>` is the first `/`-free segment and
`<name>` is the last `/`-free segment; the middle is the namespace. A registry dep
with no namespace is `pkg+<alias>/<name>`. No fixed-arity split is ever performed,
and the on-disk form (§7) carries `registry`/`namespace`/`name` as separate
structured fields anyway, so nothing splits this string on read.

**Namespace validation (normative — round-2.5 correction).** `namespace` is a
`/`-separated path; **each segment** is fenced to the manifest package-name alphabet
and MUST reject `..`, empty segments, and control chars — but `/` is the segment
*separator* and is allowed between segments. (An earlier draft folded in "apply
`_validate_safe_name` to the whole `namespace`," which rejects `/` and would thus
reject 884/886 of the real registry — that whole-string fix is NOT applied; the
per-segment rule is. `name` and `alias` remain `/`-free.)

> NOTE on the manifest `::` vs. canonical `/` separators. The manifest/solver
> qualified-name separator is `::` (`spec/resolver-semantics.md §6b`); the
> `SourceId` canonical form uses `/`. These are two *distinct* surfaces (one is
> author-facing manifest syntax, the other is the on-disk source-id wire form)
> and the round-trip law lives entirely on the canonical `/` form. §7 reconciles
> this against §6b's existing "`::` MUST NOT appear in the lockfile" rule
> explicitly (that rule is amended, not silently violated — see §7).

**Subpath in the one-way key (normative — simplified by round-2.5).** Because the
key is one-way (never parsed back) and the authoritative on-disk form carries
`subpath` as its own structured field (§7), the elaborate percent-escaping
round-trip machinery an earlier draft required is **deleted**. `subpath`-bearing
kinds (`Git`/`Tarball`/`Oci`) append `#subdirectory=<subpath>` to the one-way key
when a subpath is present; injectivity only requires that a normalized base URL not
itself carry a literal `#subdirectory=` fragment — such a URL is pathological and
rejected at `normalize_source` as `SRC-ID-MALFORMED`.

**Subpath escape guard (normative).** `subpath` is a location *inside* a fetched
tree; it MUST reject `..` traversal and absolute paths, mirroring the existing
`EXTRACT-ZIP-SLIP`/`EXTRACT-SYMLINK-ESCAPE` discipline in
`fetchers/safe_extract.py`. A malformed subpath is `SRC-ID-MALFORMED`.

**`oci+` segment boundary (normative — parity of rigor with `pkg+`, round-2 D7).**
`oci+<registry>/<repository>` is injective for the same reason `pkg+`'s alias is:
per the OCI distribution spec a registry is `host[:port]` only (no internal `/`),
so the *first* `/`-segment is unambiguously the registry and everything after
(which may itself contain `/` for nested repos) is the repository — reuse
`split_oci_target` (`source_spec.py`) here, which splits on the first `/` only.
This is the *opposite* arity from `pkg+` (fixed 1-or-2 segments, §above); the two
MUST NOT share a splitter. An OCI `subpath` (rare) uses the same
`#subdirectory=` escaping as git/tarball.

**`LocalSourceId` path canonicalization is case-sensitive (normative — round-2
D6).** `path` is canonicalized (workspace-relative under root, else absolute) but
comparison is **case-preserving and case-sensitive by definition**. On a
case-insensitive filesystem (APFS/Windows) `local="Deps/Foo"` and
`local="deps/foo"` denote one directory yet form two distinct `LocalSourceId`s — a
known missed-unification limitation, not remedied here (local deps are rarely
shared cross-author; `overrides {}` is the escape hatch if it ever bites).

**Canonical form is a wire format once shipped.** Post-stabilization, changing a
normalization rule (e.g. "also strip `www.`") is a lockfile-migration event, not
a silent fix — the same commitment Cargo makes for `Cargo.lock`'s `source =`
field. Pre-v1 we regen freely (§8); §7 records the stabilization commitment.

### 4.2 `normalize_source` — one function, kind-dispatched

A single pure function normalizes a raw origin to a `SourceId`, dispatched by a
`match`/`case` on origin kind inside `source_id.py`:

```python
def normalize_source(raw: RawOrigin) -> SourceId: ...   # match on kind
```

Only the **git** case carries non-trivial logic. It promotes the existing
`_normalize_git_source_url` (`resolver.py:3601`) from a side-channel check to *the*
equality definition — **but that function today does less than an earlier draft of
this section claimed** (round-2 fix — D4). Its own docstring disclaims
userinfo/port handling and ssh-vs-https unification. The normative git-normalize
rule for this RFC is therefore stated explicitly, in three tiers:

- **Kept (already implemented):** lowercase scheme+host, strip trailing `/` and
  `.git`; **path case preserved**.
- **Added by this RFC (decidable, cheap, closes a real missed-unification):**
  strip userinfo/credentials (`ssh://git@host` → `ssh://host` — credentials are
  never part of a repo's identity), and strip the scheme's *default* port
  (https:443, http:80, ssh:22, git:9418). Without this, `ssh://user@host:22/org/repo`
  and `ssh://host/org/repo` — very plausibly one repo — become two source-ids,
  the exact §2.1 "missed unification" this RFC exists to kill. Specified
  normatively so S1's round-trip strategy and the Rust mirror both cover it.
- **NOT attempted (undecidable / unreachable):** cross-transport ssh↔https
  desugaring is left undecidable per §3.2's philosophy (`overrides {}` is the
  escape hatch). SCP-style `git@host:org/repo` desugaring is dropped as
  *unreachable*: `_validate_git_url` (`manifest.py:1900`) rejects any `git=`/
  override value without a recognized scheme, so SCP form never flows through
  `SourceId` construction (it appears only in internal `.gitmodules` submodule
  resolution, which never builds a `SourceId`).
- **Added by code-review D1 (query/fragment, cross-impl convergence):** a
  `?query` suffix on a git URL is silently stripped (transport/auth noise,
  not identity-bearing — e.g. `git=(url)".../repo?ref=main"` normalizes to
  `.../repo`). A raw `#fragment`, in contrast, is **rejected outright**
  (`SRC-ID-MALFORMED`), never silently stripped — it collides with milpa's
  own reserved `#subdirectory=` one-way-key delimiter (above), so a
  user-supplied fragment is an error, not noise to discard. Before this fix
  the two reference impls diverged: Python's `urlsplit`/`urlunsplit`-based
  normalizer silently dropped both query AND fragment, while Rust's
  hand-parser preserved both verbatim — meaning the same declared URL
  produced two different source-ids across impls, and
  `.../repo#subdirectory=evil` was silently accepted by Python but rejected
  by Rust. Both impls now converge on "strip query, reject fragment."
- **Added by code-review S2 (control-char injection):** every free-text
  origin field — `GitSourceId.url` (post-normalize), `TarballSourceId.url`,
  `OciSourceId.registry`/`.repository`, `LocalSourceId.path`, and each
  `RegistrySourceId.namespace` segment — is rejected if it contains a
  character `contains_unsafe_char` (`manifest.py`/`milpa_manifest` — the
  existing single source of truth for this predicate, also used by
  `registry.py`'s `TNG-UNSAFE-CONTROL-CHAR` guard) flags: ASCII C0/C1
  controls or the Unicode line separators U+2028/U+2029. Without this guard a
  crafted, network-fetched `milpa.kdl` could smuggle a terminal-escape
  sequence through a declared origin into a diagnostic sink (e.g. `milpa
  show`'s provenance formatter, which now also `repr()`-escapes these same
  fields as defense-in-depth). This also broadens the pre-existing
  `RegistrySourceId.namespace` segment guard, which previously checked ASCII
  controls only and missed the two Unicode line separators.

The other five kinds are identity or trivial path/coordinate canonicalization.
Normalization stays a heuristic, deliberately incomplete: two genuinely different
remotes serving identical bytes are **not** unified here (undecidable; the
`content_hash` layer dedups those post-fetch). The escape hatch for an
under-unified case a human knows is one package is `overrides {}`.

> **No normalizer `Protocol`/registry (YAGNI).** A round-1 review flagged that a
> `SourceIdNormalizer` Protocol + dispatch registry (justified by future F4–F7
> Hg/Fossil/IPFS transports) is speculative generality: five of six kinds have no
> behavior to hide, and the `fetchers/` registry it mirrors earns its genericity
> from *five real transports today*. This RFC applies its own bar
> ([[feedback_minimal_over_completeness]] — grow the core on ≥2 proven needs):
> promote `normalize_source` to a registered-`Protocol` design only when F4 lands
> a second real normalizer. Same ruling as the dropped `BindingConflictPolicy`
> (§11).

### 4.3 The binding phase — deterministic, in-memory, root arbitrates

Replaces `provenance_gate` + `TIER_*` + `_check_provenance_gate` +
`_validate_transitive_url_against_registry` entirely.

```python
@dataclass(frozen=True)
class Claim:
    name: str                 # the label THIS declaration used (for diagnostics + slot projection)
    source_id: SourceId       # normalized origin
    is_root: bool             # root manifest deps + overrides + workspace members
    claimant: str             # "root" | "override:<name>" | "<parent>@<version>" (message text only)

class BindOutcome(Enum):
    NEW          = auto()     # first claim for this key — caller enqueues/fetches
    DUPLICATE    = auto()     # matched the existing binding — harmless no-op
    LOST_TO_ROOT = auto()     # disagreed with a root binding — discarded (Cargo-[patch])

@dataclass(frozen=True)
class BindingDecision:
    accepted: SourceId
    outcome: BindOutcome      # caller enqueues iff outcome is NEW

class BindingResolver:
    """One instance per resolve(). Deterministic, in-memory-only: it never
    fetches a package tree. Root/override claims are bound at construction; only
    transitive claims arrive via submit()."""
    def __init__(self, root_claims: Sequence[Claim]): ...    # asserts every claim.is_root
    def submit(self, claim: Claim) -> BindingDecision: ...    # non-root only; raises RES-BINDING-CONFLICT
    def source_id_for(self, key: DepKey) -> SourceId | None: ...
```

**Authority is a two-valued fact, not a lattice (round-1 fix).** The earlier
sketch used `ClaimAuthority(IntEnum){ROOT=1, TRANSITIVE=2}` — that is the deleted
`TIER_*` priority-integer lattice smuggled back in, and an `IntEnum` invites a
future contributor to slot `REGISTRY=2` between them and rebuild it. `is_root:
bool` makes "there are exactly two authority levels, forever" a type-level fact.
Arbitration never compares magnitudes; it only asks *is this root?*

**Root-first is structural, not a convention (round-1 fix).** Root/override
claims are all bound in `__init__`; `submit()` is reachable only afterward and
accepts only non-root claims (it raises if handed `is_root`). The "root submitted
first" ordering is thus enforced by the API shape, not by caller discipline that
the Rust mirror could independently get wrong.

Arbitration in full:
- **Root vs. root, same name, different source** (a root dep decl *and* a root
  override on the same name — a common placeholder+override authoring pattern):
  the **override pre-empts the root dep declaration before binding**, mirroring
  today's `_apply_git_override_to_url_dep` transform. `__init__` receives the
  already-reconciled root claim set, so two disagreeing root claims for one name
  are unreachable by construction. If one ever arrives, it is an internal
  invariant violation (assert), not `RES-BINDING-CONFLICT`.
- **Transitive matches the existing binding** → no-op dedup (`suppressed=True`).
- **Transitive disagrees with the root binding** → suppressed, loses to root
  silently (this is the Cargo-`[patch]` semantics; the root wins).
- **Transitive disagrees with another *transitive*** binding (no root claim for
  the name) → `RES-BINDING-CONFLICT`. Remedy in the message: "declare it at the
  root via `overrides {}`."

No tiers, no priority integers.

**On "pure/pre-fetch" (round-1 precision).** `BindingResolver` itself does no
I/O. But constructing a `Claim` for a *named* dep requires reading the (already
network-cached) registry index — package-fetch-free, not I/O-free — and a
transitively-discovered named dep's claim can only be built after its parent
tree is fetched and parsed mid-BFS. So arbitration is a clean in-memory stage;
*claim construction* for named deps stays interleaved with the BFS waves exactly
as today. The win is a typed `Claim`/`BindingDecision` arbitration seam replacing
the `(pkey, tier)` side-table, not a new up-front pass. §2.3's "pure, pre-fetch"
is scoped accordingly.

**Grouping/query key is `DepKey`, not a bare `name` (round-2 fix — B1/G1).** An
earlier sketch typed `source_id_for(name: str)`, contradicting the very next
sentence ("grouping key stays `(namespace, name)`"). A bare-`name` store/lookup is
the *literal* #193 root cause: `resolver.py:635` documents that the old
`root_authority: set[str]` is bare-name-scoped precisely *because* its namespace
behavior is the #193 bug. Since this RFC's header claims to root-cause #193,
`BindingResolver` MUST key by `DepKey` (`(name, namespace)`) internally and in
`source_id_for`, so `ns1::foo` and `ns2::foo` never cross-bind. S2's tests assert
this namespace-sensitivity as a first-class RED case, not an implicit consequence.
`RegistrySourceId.namespace` is always the *real resolved index namespace*
(`_Candidate.registry_namespace`, `resolver.py:554`), **never** the manifest
qualifier — the two can differ (a bare `requires "foo"` resolving into a
namespaced index entry), and §4.4/B2 defines which is authoritative on
`ResolvedDep`.

**Suppression is a 3-way outcome, not a bool (round-2 fix — G2).** Flattening
"dedup" and "lost-to-root" into one `suppressed: bool` reproduces exactly the
opacity §2.2 condemns in the side-table — a user asking "why didn't my transitive
git fork get picked up?" gets a log grep, not a typed answer. `BindOutcome`
distinguishes `DUPLICATE` (harmless) from `LOST_TO_ROOT` (a candidate was
deliberately discarded because root pinned the name); the caller's rule is
unchanged (`enqueue iff outcome is NEW`), but `LOST_TO_ROOT` is now a first-class
fact `milpa show`/diagnostics surface ("root pinned X; transitive claim for the
same name was overridden"). The dead-override diagnostic (B10, S5b) reuses it.

The value the grouping key maps to is now a `SourceId` instead of a bare label;
the namespace machinery (H2 qualified deps) is otherwise untouched.

### 4.4 The solver — genericized key (DE1, reverses the original "untouched")

> **DE1 (2026-08-03, code-review reversal).** The original design below kept the
> solver variable a bare `str` and reconstructed the display `DepKey` at every
> emission site through a `canonical → DepKey` reverse map
> (`BindingResolver._canonical_index` / `depkey_for_canonical`). The stage-4
> review found this pushed the two-phase complexity out to ~58 (Python) / ~17
> (Rust) scattered projection call sites, each threading `binding_resolver`, and
> was the root of a latent bug class (P6: a projection site recording a bare name
> instead of the canonical key). The decision was **reversed**: the solver
> variable is now a rich **`SolverKey`** — its string value is
> `canonical(source_id)` (so it hashes, compares, and renders byte-identically to
> the old bare string; the solver, its diagnostics, and every fixture are
> unchanged), carrying its **BFS-first display `DepKey` inline** (`.display`).
> Emission reads `.display` directly; the reverse map is deleted. In Python
> `SolverKey` subclasses `str` (zero blast radius — the trick that made the
> reversal cheap). In Rust it is a newtype with `Deref<str>` + `Borrow<str>`
> (identity-only `Eq`/`Hash`/`Ord`), threaded as the `pubgrub` package type
> `type P = SolverKey`; the resolver keeps its identity-`String` bookkeeping and
> reads display through a single intern-table boundary
> (`BindingResolver::display_for`) since Rust has no `str`-subclass affordance.
> The cost calculus that flipped: the 58-site projection scatter + reverse-map +
> P6 bug-class cost more than carrying display on the key. Interning at the mint
> point (`BindingResolver`) makes `.display` deterministic (first label wins).

`Term.package` is fed `canonical(source_id)` instead of `solver_var`. The
provider's candidate/stub dicts are re-keyed from `name` to
`canonical(source_id)` — **uniformly, for every dep kind. There is no
kind-conditional keying** (no "git/tarball/local stays name-keyed"); the solver
variable of *every* resolved node is `canonical(source_id)` (now carried as a
`SolverKey`, per DE1 above).

#### 4.4.1 Two phases: name-resolution vs. identity-canonicalization (round-3, normative)

The uniform rule above is only coherent if a prior conflation is broken. Keying a
dep for the solver answers **two distinct questions**, and they must be separate
phases:

1. **Name-resolution** — *what source does this reference point to?*
   (`reference → source_id`). This is where all ecosystem/kind logic lives.
2. **Identity-canonicalization** — *what is the stable string for this source?*
   (`source_id → canonical`). This is uniform and total; kind never enters here.

Phase 2 is the thesis (§3) and is already fully specified. Phase 1 is a
**binding-aware resolution seam**, evaluated against the current `BindingResolver`
state:

```
resolve_name_to_source_id(reference, binding_state) -> SourceId
  1. reference pinned by a root/override binding?   → that source
  2. already bound by an earlier accepted claim?    → that source
       (a disagreeing later claim = RES-BINDING-CONFLICT — §4.3)
  3. else, fall back to the reference's own declaration kind:
       git= / local= / tarball= / oci=  → that URL/path/registry source
       bare name (a `named` require)     → registry coordinate (via the index)
```

The solver variable is then `canonical(resolve_name_to_source_id(reference,
binding_state))`, computed the same way for a root dep, a transitive `requires`,
a stub, and a candidate. **Kind affects only step 3 of phase 1 — the *default*
when a name is otherwise unbound — never the keying.**

**The unifying reframe: a direct `git=`/`local=`/`tarball=`/`oci=` declaration
*is* a name→source binding — semantically an implicit `override` of that name**
(Cargo `[patch]` and nimble's URL-federation, unified into one mechanism). This is
why a transitive bare `requires "bearssl >= 0.2.8"` unifies with a root
`bearssl git=<url>` pin: phase 1 resolves the bare reference *through* that binding
(step 1) to the same `GitSourceId`, so phase 2 yields the same canonical string and
the two are **one** solver variable — collapsed **pre-fetch**, delivering the §2.1
efficiency win for direct deps and not only for registry deps. It also honors
coordinate-is-origin exactly: same name + *genuinely* different source (no pin, no
prior binding) still splits into distinct variables (or conflicts per §4.3), and a
registry-coordinate vs. git-URL that merely happen to be byte-identical remain
distinct origins, collapsed only post-fetch by Phase B `content_hash` (§3.3).

> **Rejected — kind-conditional keying (git/tarball/local keyed by bare `name`
> instead of `canonical(url)`).** A first implementation took this shortcut because
> a bare `requires` was (wrongly) canonicalized straight to a registry coordinate
> without consulting bindings first — the "fictional registry canonical" failure.
> That is phase 1 done wrong, not evidence that direct deps can't be canonical-keyed.
> Kind-conditional keying weakens the thesis (the solver variable is no longer the
> source-id for direct deps), forgoes the pre-fetch collapse of same-URL-different-
> label git deps, and splits the model into two regimes. The two-phase factoring
> above supersedes it: uniform canonical keying, all kind/ecosystem logic isolated
> in the binding-aware name-resolution step.

> **Sequencing (implementation, both impls): the solver re-key lands in S5, not
> S3a (round-2.5 refinement).** S3a wires `BindingResolver` for *admission*
> (which claims are enqueued/fetched — where the source-id dedup, conflict, and
> tripwire live) and records `source_id` on `ResolvedDep` as metadata, but leaves
> `Term.package` name-keyed. Feeding `canonical(source_id)` to the solver changes
> the resolved-graph node keys, which the on-disk lockfile writer serializes — so
> it *cannot* land before S5 without breaking the lockfile format S3a must
> preserve. It therefore lands **with** the lockfile re-key in S5, where the two
> compose. Correctness in between is intact: admission-dedup collapses same-`DepKey`
> claims, and Phase B `_dedup_candidates` (§3.3) collapses same-`content_hash`
> trees post-fetch, so the §2.1 missed-unification case is already handled (the
> solver re-key makes it *pre-fetch* and removes the double-fetch, an efficiency +
> cleanliness win, not a new correctness property).

**No separate reverse-map side-table (round-1 fix; strengthened round-2.5).** The
earlier sketch carried a maintained `source_id_of(package: str) -> SourceId` map
threaded through diagnostics, the lockfile writer, and the import-slot check. That
is redundant: the *resolved graph's* own node type — `ResolvedDep`
(`lockfile.py:386`), which already carries a `name` display field — gains a
`source_id: SourceId` field populated once at graph construction from the binding
decision. Downstream consumers (diagnostics, lockfile writer, import-slot check,
`nim.cfg`) read that one typed node. **Round-2.5 makes this the *only* string→struct
path:** with `parse()` deleted, nothing reconstructs a `SourceId` from the one-way
solver-key string at all — the struct travels on `ResolvedDep.source_id` and is
(de)serialized structured on disk (§7). The canonical string stops at the solver's
edge and never becomes the shape of the resolved graph or the lockfile.

This is a deliberate scope boundary: genericizing PubGrub over a key type is a
large, risky diff for zero behavioral gain, since the solver was already agnostic
to what the string means. All four design explorations reached this independently.

**Field-duplication audit — `source_id` vs. existing `ResolvedDep` fields
(round-2 fix — B2/G10).** `ResolvedDep`/`LockedDep` (`lockfile.py:386`) already
carry `namespace`, `registry_namespace`, `aliases`, and `provenances`. Adding
`source_id: SourceId` makes several of these parallel encodings of one fact — a
`RegistrySourceId.namespace` vs. `registry_namespace`; a `GitSourceId.url` vs. a
`GitIndexProvenance.url` in `provenances`. CLAUDE.md's single-source-of-truth
non-negotiable is directly on point (it is the same defect class the `edge_cache`
re-key fixes in §4.5). Normative resolution: `source_id` is authoritative for the
*origin*; `registry_namespace` is deleted in favor of reading
`source_id.namespace` when `source_id` is a `RegistrySourceId` (they are the same
real index namespace); `provenances` is **retained** but re-homed to its distinct
job — per-version transport/attestation *provenance* (git commit SHA, OCI digest,
Rekor pointer), which `source_id` deliberately excludes (ref/digest are versions,
§3). `aliases`/`namespace` (the manifest qualifier) are orthogonal and kept. S5
performs and records this audit the same way §6 audits `provenance_gate`.

### 4.5 `edge_cache` re-key — the latent-bug fix

Re-key `edge_cache` from `(name, Version)` to `(source_id, Version)`. This is not
a rename: it makes the diamond-dedup guarantee (`edge_sources.py:667`) actually
true. Today two BFS parents that reach one repo under two labels seal two
separate EdgeSet entries; keyed by source-id they correctly coalesce.

### 4.6 Import-slot check — post-solve, symbol-level, phased

The second, genuinely-new check: two **distinct** source-ids that occupy the same
Nim import symbol cannot coexist in one build. This is where the flat-namespace
constraint lives — not at binding time (that's `RES-BINDING-CONFLICT`, same name /
different source) but post-solve (different origins, same symbol).

**v1 floor (S6) — a plain function, no port (round-1 fix).** The floor is the
**directory-slot** check: two distinct source-ids that project to the same
`_deps/<slot>/` name collide → `RES-IMPORT-COLLISION`. This is a pure function of
the resolved graph's projected slot names — it needs no bytes-reading, no port, no
`ImportSlot`, no fidelity tag:

```python
def check_directory_slot_collisions(resolved) -> None: ...
    # two distinct source-ids projecting to one _deps/<slot>/ → RES-IMPORT-COLLISION
```

Shipping the `SymbolProviderPort`/`ImportSlot` apparatus "from day one" for a check
that doesn't use it repeats exactly the over-build this RFC rejects for the
normalizer registry and `BindingConflictPolicy`. The port lands in S7, when there
are two real adapters to justify a `Protocol`.

**content_hash short-circuit (round-1 fix — protects milpa's own edge).** The floor
runs post-fetch, so `content_hash` is already available. Two source-ids that
project to the same slot **but hash identically** are the exact same-bytes /
different-origin case §3.3 celebrates as milpa's edge over Cargo — they cannot
produce a symbol conflict and MUST NOT raise. The floor raises only when the slot
*and* the `content_hash` differ. Without this, milpa's headline differentiator
would false-positive in the case it exists to handle gracefully.

**symbol-level (S7) — the complete check.** Directory-slot is a *partial* proxy
(two packages in *different* dirs can still export the same module, and a hijacking
transitive can evade the floor by choosing a distinct label). The complete check
compares the actual exported Nim module symbols, behind a port because the symbol a
tree exports is irreducibly a post-fetch fact (bytes) or a manifest-declared fact:

```python
@dataclass(frozen=True)
class ImportSlot:
    module: str                 # a Nim-importable module path
    fidelity: Literal["manifest_declared", "tree_scanned"]

class SymbolProviderPort(Protocol):
    def import_slots_for(self, sid: SourceId, materialized_path: Path) -> frozenset[ImportSlot]: ...
```

Adapters, composed declared-beats-inferred (mirroring the `EdgeSource` fidelity
tags in `dep_decl.py:58`): `ManifestDeclaredSymbolProvider` (a new optional
`provides { module "x" }` manifest block) falls back to `FetchedTreeSymbolProvider`
(scan `srcDir` for `*.nim`). The same `content_hash` short-circuit applies.

**S6 survives S7 as a fast-path, not scaffolding (round-2 fix — G9).** A
directory-slot collision *implies* a symbol collision (same slot ⇒ same import
path), but not vice versa — so the S6 floor is a sound, cheap pre-filter that
short-circuits before S7's per-tree symbol scan. It is **retained**, not deleted,
when S7 lands. Because the floor is a *partial* check (§6.1: evadable by choosing a
distinct label), the `RES-IMPORT-COLLISION` entry in `spec/errors.md` — and the
CLI diagnostic text — MUST carry a durable caveat: pre-S7, a non-firing check
means "no *directory-slot* collision," **not** "no import collision" (symbol
collisions across differently-named slots are unchecked until S7). This matters
because §10 asks the floor to carry security weight (narrowing the Fork-1 gap); a
slug that over-promises would let CI gates built on it read a false all-clear.

### 4.7 Slot projection → `_deps/`, `nim.cfg`, lockfile

Users still name deps by label and Nim still imports by module name, so `_deps/`
must stay name-addressed. A post-solve `SourceId → display slot` projection
produces the on-disk slot, carried on `ResolvedDep.name` (§4.4). The lockfile keys
each record by `canonical(source_id)` and carries the slot name as an annotation;
`content_hash` verification at materialize is untouched.

**Slot tie-break is fully specified — no silent label drop (round-2 fix — G3).**
"Declared name wins, else URL-tail derivation (`_name_from_url`, now in one
place)" disambiguates *declared vs. derived* but not *two different declared
labels* reaching one source-id (root writes `nimz3`; a transitive `milpa.kdl`
declares the same URL as `z3lib`). The normative tie-break, reusing the RFC's own
root-first + first-occurrence primitives (no new comparator): (1) a **root**
declared label beats any transitive's; (2) among transitive declared labels with
no root claim, **first-BFS-occurrence** wins (§4.2.1's ordering); (3) derived
URL-tail is last resort. When projection drops a declared label, it MUST emit a
low-severity note in `milpa show` / the resolve trace ("`z3lib` and `nimz3` both
name `git+https://…nim-z3`; used `nimz3`") — the collapse is *visible*, never a
silent disappearance from `_deps/`/`nim.cfg`.

**`requires` edges re-derived to the chosen slot (round-1 fix — B3).**
`LockedDep.requires`/`ResolvedDep.requires` are label tuples that `nim.cfg`'s
`_member_dep_closure` and `milpa show` walk through a `{name: dep}` index. When two
parents reach one source-id under two different labels, the slot projection picks
*one* display name — so every `requires` edge pointing at that source-id must be
re-derived to the chosen slot, or the closure lookup silently drops the dep from
`nim.cfg`'s search path. Edges are resolved through `source_id` (unambiguous), then
projected to the chosen slot for display — not carried as raw labels.

**Attestation subject binding uses the coordinate, never the display name (round-1
fix — B7).** Offline attestation re-verification (`frozen.py`) reconstructs the
in-toto subject `pkg:<registry>/<namespace>/<name>@<version>` from a
`RegistrySourceId`'s **coordinate fields** — never from the §4.7 display/slot name
(which may be an author-chosen alias). This is normative; using the display name
where the coordinate is required silently corrupts the attestation subject and
breaks `verify`. See §7.

---

## 5. Handling the specific cases

| Case | Handling |
|---|---|
| **URL normalization** | `normalize_source` git case (promoted `_normalize_git_source_url`). Heuristic; under-unification remedied by `overrides {}`; same-bytes-different-URL deduped by `content_hash`, never by URL guessing. |
| **Monorepo subpath** | `SourceId.subpath`, escape-guarded (§4.1: no `..`/absolute; uniform `#subdirectory=` escaping). **New manifest grammar** (`git=(url)"…" subpath="pkg/foo"`) — confirmed net-new. The value type reserves it now; the grammar slice (S8) can land separately. Same repo + different subpath = different source-ids, correctly. |
| **Bare `requires "x"` unresolvable** | Named path unchanged: resolves to `RegistrySourceId` via the pre-loaded index; if absent → existing `TNG-NOT-FOUND`, now surfaced one phase earlier (cheaper). No more synthetic-version guessing. |
| **Overrides** | `override → RawOrigin → normalize_source → Claim(is_root=True)`, bound at `BindingResolver.__init__`. Deletes the duplicated override-coercion branches in `_enqueue_dep` and the root-seeding loop. This is the Cargo-`[patch]` bridge. |
| **Override to a *different* coordinate** | When an override's target is itself a `RegistrySourceId` in a different `(namespace, name)` than the overridden coordinate (e.g. `chronos` → `acme::chronos-fork`), the binder's grouping key stays the *overridden* `(namespace, name)` while the accepted `SourceId` describes the *new* coordinate. The lockfile record, attestation subject, and diagnostics all read the accepted `SourceId`'s own coordinate fields (§4.7), never the overridden grouping key. |
| **Namespaces (`ns::name`)** | Orthogonal. `RegistrySourceId.namespace` from the resolved index namespace; binder groups by `(namespace, name)` (existing `DepKey`). `ns1::foo` and `ns2::foo` are distinct source-ids by construction. |
| **Workspace members** | `MemberSourceId(member_name)`; pre-registered root claims (`is_root=True`) at workspace load. Conflict-free by construction (W1–W5 name uniqueness). Generalizes `RES_WS_OVERRIDE_MEMBER_COLLISION` into the same arbitration path. |
| **Registry-mediated repo move** | A registry entry has one coordinate identity; per-version provenance is transport detail. A genuine upstream repo move is a new identity (Go `/v2`-style) — not a silent same-coordinate drift. No cross-version drift because the coordinate, not a per-version URL, is the identity. |

---

## 6. What gets deleted / re-homed

- **Deleted:** `provenance_gate`, `TIER_ROOT/REGISTRY/SELF_URL`,
  `_check_provenance_gate`, `_validate_transitive_url_against_registry`,
  `_registry_git_provenances`/`_registry_oci_source_urls` reconciliation, the
  `_ROOT_SELF_PKEY`/`_NAMED_PKEY` sentinels, the duplicated override branches.
  Their tests (`test_provenance_gate.py`, `test_provenance_lattice.py`) are
  replaced by `BindingResolver` tests, not left running in parallel
  (audit-for-duplication) — but see the security callout below: every *threat-model*
  behavior those tests encode must be re-homed to a new check, not merely dropped.
- **Kept & reconciled — Phase B `_dedup_candidates` (round-2 correction — D1):**
  `resolver.py`'s "Step 6b" content-hash unification (`resolver.py:3417`/`4373`) is
  *not* removed. It is merge-on-proof (identical `content_hash` + an identical-
  `requires` invariant guard), post-fetch, and identical-bytes-only — so it does not
  violate §3.3 (which forbids merge-on-*heuristic*), does not blind the pre-fetch
  S3c tripwire, and is milpa's differentiator realized at the solver layer. S4b
  reconciles it with source-id keying (re-key `aliases_map` from labels to
  source-ids; **record both collapsed origins' provenance** so a cross-origin
  collapse keeps its audit trail; keep the invariant guard). This is the shipped
  beachhead of roadmap Phase B; #32–34 extends it (global CAS store, multihash), it
  is not re-implemented here.
- **Re-homed:** the OCI-`source` field (`2770d3d`) → provenance/audit metadata,
  not a resolution input. Its `OciIndexProvenance.source_url` docstring
  (`registry.py:208`), which today describes the deleted reconciliation purpose, is
  rewritten to "audit-only" in the same slice (S3b) — no stale doc left behind
  (the CR8–14 spec/doc-integrity discipline). The parallel audit-only
  `source_url` on the new `publishing.py` (`PublishPlan`/`PublishReceipt`, already
  documented "nothing consumes it yet") already matches this model — S3b's sweep
  notes it so a future audit needn't rediscover it. `_normalize_git_source_url` →
  promoted to the `SourceId` equality definition. `_name_from_url` → the slot
  projection only.
- **Kept:** root-satisfies-own-name (`31454de` §14), alias-name fix (`8238e2d`),
  `content_hash`/CAS (now also deduping across source-ids). **`root_authority`
  survives (round-2 B3):** it is deleted only as an *input to the provenance gate*;
  the same `set[str]` is independently consumed by `_version_unknown_constrained_err`
  (`resolver.py:303`, the "is this declaration site user-owned?" check for
  `VERSION-UNKNOWN-CONSTRAINED`). S3b retains it, single-purpose and bare-name-scoped
  by design, with a comment saying so — a mechanical mass-delete of the gate
  machinery must not take it. (Its bare-name scoping is the open #192/R6 namespace
  door — §14.)

### 6.1 Security-relevant change — the dependency-confusion defense, re-homed ⚠️

`_validate_transitive_url_against_registry` was not only a source-selector; it
carried milpa's **pre-fetch dependency-confusion tripwire**. Coordinate-is-origin
deletes the source-selection role (a `git=` claim and a `RegistrySourceId` are
simply *different packages*), so the tripwire is re-homed as an explicit, separate
check rather than silently dropped. **Resolved design (best-in-class, Corey sign-off
2026-08-02) — a NAME-TRIGGERED, URL-REFINED registry-shadow tripwire** on the
`attestation-policy` seam (not the deleted tier lattice, not a source-selector):

- **Trigger** on the coordinate-ownership signal — the actual confusion signature,
  and what npm scopes / PEP-708 external-index-ownership / Go path-identity all
  encode: a transitive `git=`/`tarball=`/`oci=` claim whose **bare name matches a
  name the registry owns** (any namespace). This signal exists for OCI-only entries
  too — a coordinate is owned whether or not it recorded a `source_url`.
- **Refine** to suppress the legitimate case: if the registry entry has a comparable
  upstream URL that **matches** the claim's normalized URL → silent accept (a genuine
  pin of the same repo the registry points at).
- **Otherwise** — URL disagrees, **or the entry is OCI-only / has no comparable URL**
  → `RES-REGISTRY-SHADOW`: **warn by default, hard-fail under `attestation-policy
  strict`.**

Pre-fetch, single-mechanism, and it covers the OCI-only case **with no gap and no
post-fetch content-hash comparator** (the old fallback fetched the possibly-hostile
tree *before* deciding — deleted entirely). Honest consequence (signed off): an
OCI-only entry pinned via `git=` can no longer be *auto-accepted* by pre-fetch
content comparison — under strict it warns/fails; `content_hash` still verifies bytes
at materialization independently.

**Defense-in-depth layering**, each on a seam this RFC already owns: identity
(source-id — no silent merge) → this tripwire (name-shadow, `attestation-policy`) →
post-solve import-slot check (§4.6 — symbol collision) → `content_hash` verification
at materialize. The threat-model fixtures are **re-homed across the right
mechanisms** (see §10 S3a/S3c), never deleted: multi-claim disagreements (two
competing claims for one name) are `RES-BINDING-CONFLICT` (BindingResolver's job);
lone-name-shadow-of-a-registry-coordinate is `RES-REGISTRY-SHADOW`.

---

## 7. Spec changes (normative)

- **`spec/resolver-semantics.md` §6a/§6b** — the solver variable is a source-id,
  not `DepKey.solver_var()`. `DepKey` remains the *binding grouping key*
  `(name, namespace)`; the in-memory *solved value* is a source-id, keyed for the
  solver by the one-way `canonical(source_id)` string. **On disk the source-id is
  serialized STRUCTURED, not as a flat key (round-2.5 correction):** each locked
  dep carries a `source { … }` node with typed children (uv's model) —
  `RegistrySourceId` → `kind "registry"; registry "<alias>"; namespace "<ns>";
  name "<name>"`; `GitSourceId` → `kind "git"; url (url)"…"; subpath "…"?`; etc. A
  `/`-bearing namespace stores losslessly as an ordinary KDL string value; no
  flat-string parsing, no escaping, and both impls read it as plain KDL (removing
  the largest cross-impl-divergence risk). **Amend §6b's existing "`::` MUST NOT
  appear in the lockfile / `_deps/` / `nim.cfg` / `requires`" rule (round-1 fix —
  D3):** that rule forbade leaking the solver-internal `::` string; it is trivially
  satisfied since the on-disk form is structured typed fields, never the solver key.
  Explicit repeal-and-replace, not a silent violation.
- **§10** — rewritten from "provenance precedence / source selection" to the
  binding model: name→source-id, root arbitration, `RES-BINDING-CONFLICT`. The
  §10.0 factual error ("unification keyed by name, as in … Go") is fixed — Go is
  URL-keyed; milpa now adopts the origin model. **The uncommitted working-tree §10
  stopgap encodes a *different, superseded* "name-keyed unification" model and must
  be resolved first (Fork 2, §11) — S9 writes §10 from the resolved base, never as
  a diff against the stopgap.**
- **§4.2.1** — BFS package order keyed by source-id first-occurrence, not name.
- **§7.1 (frozen / verify) — new source-id precondition (round-1 fix — B1;
  round-2 correction — D2/D3).**
  `frozen.py`'s `resolve_frozen`/`resolve_workspace_frozen` and `milpa verify`
  today never compare the manifest's declared `git=`/`local=`/`tarball=` origin
  against the lockfile — so editing a `git=` URL without re-fetching passes
  silently. Under "different origin = different package" that is a hole. Add a
  `FROZEN-SOURCE-ID-MISMATCH` precondition: `normalize_source(declared)` must equal
  the lockfile record's `source_id`, or frozen/verify fails closed.
  **"declared" means declared-*after-override* (D2):** `frozen.py` today has **zero**
  references to `manifest.overrides`, and an overridden dep's locked `source_id` is
  the override target, not the raw declaration — so a naive check false-positives on
  *every* project using `overrides {}` (the very bridge §5 promotes). The frozen
  path MUST apply overrides before computing `normalize_source`, reusing the same
  pure override-application helper that `BindingResolver.__init__` uses to reconcile
  root claims (§4.3) — not a second copy. S5 is scoped to include this, with a
  differential fixture covering an overridden root dep under `verify`.
  **Error precedence (D3):** for a `pkg+<alias>/…` record whose alias is absent from
  this machine's config, `FROZEN-REGISTRY-ALIAS-UNRESOLVED` is checked **first** and
  short-circuits — an unresolved alias MUST NOT be misreported as a
  `FROZEN-SOURCE-ID-MISMATCH` (the coordinate comparison is not even attempted). A
  slice test enumerates this ordering.
- **`spec/errors.md`** — add `RES-BINDING-CONFLICT`, `RES-IMPORT-COLLISION`,
  `SRC-ID-MALFORMED` (also covers a malformed/traversing `subpath` and a
  bad `pkg+` segment count), `FROZEN-SOURCE-ID-MISMATCH`,
  `FROZEN-REGISTRY-ALIAS-UNRESOLVED` (lockfile references a registry alias not
  configured on this machine); remove `RES-PROVENANCE-CONFLICT` (superseded —
  *unless* Fork 1 retains it as the registry-shadow tripwire slug). Bijection lint
  updated.
- **`spec/identity.md`** — a NOTE distinguishing *source-id* (version-independent
  origin, the solver variable) from *content_hash* (the *identity*, per-version
  verification). Uses the §3.1 vocabulary discipline: "identity" = `content_hash`
  only. Also records that `canonical(source_id)` is a **stable wire format** at
  stabilization (a later normalization-rule change is a lockfile-migration event,
  not a silent fix). No change to the content-hash algorithm.
- **`spec/manifest.md`** — reserve `subpath=` on url/tarball deps (with the
  escape-guard from §4.1) and the optional `provides { module … }` block (grammar
  slices may land after the core). **Overrides parity (round-1 fix — B5):**
  `overrides {}` is claimed as *the* rebind bridge but `OverrideTarget` today is
  only `Git|Local|Member`. Add `OciTarget` and `TarballTarget` (needed for the
  "sole bridge" claim to hold across transports); a `RegistryTarget` (redirect a
  direct-source dep *to* a registry coordinate) and version-scoped overrides.
  **No deferral (Corey 2026-08-02, [[feedback_no_deferring_in_loop]]):** all four
  override targets — `Oci`/`Tarball`/`Registry` — AND version-scoped overrides are
  implemented in **S8b**, not filed as gaps. The overrides bridge must be complete
  for the "sole bridge" claim to hold. Breaking manifest-grammar changes are fine
  pre-v1.

---

## 8. Migration

Clean pre-v1 break ([[feedback_no_legacy_support_prev1]]): lockfile keys move from
name to `canonical(source_id)`; `milpa show`/`verify` output shape changes;
`_deps/` layout is unchanged (still slot-named via the §4.7 slot projection).
One-shot regen, no dual-emit/compat shim. No external consumers to migrate.

---

## 9. Cross-impl discipline

Python is the oracle, Rust mirrors function-for-function (both already key the
solver by an opaque `str`; both already have `normalize_git_source_url`). Each
slice: Python RED→GREEN, then Rust mirror, then a shared `conformance/spec-v1/`
fixture proving zero cross-impl divergence. `RES-BINDING-CONFLICT` /
`RES-IMPORT-COLLISION` / `SRC-ID-MALFORMED` get differential fixtures.

**Mirror per-slice, not batched to the end (round-1 fix — F4).** The earlier plan
deferred *all* Rust to a single S10, letting the two impls diverge for nine slices
— during which the shared corpus cannot gain a `RES-BINDING-CONFLICT` fixture
without breaking Rust's `milpa-conformance` run, violating §9's own zero-divergence
principle. Instead Rust mirrors within each slice's window for the pure/wiring
slices (S1–S4, S6); only the grammar-dependent pieces (S5 lockfile shape, S7/S8
manifest grammar) batch a short Rust catch-up. **Rust's live resolver path is
`resolver.rs::edgeset_to_extracted` — `edge_sources.rs::edgeset_to_terms` is dead
code; mirror into the former.** Rust's tier machinery
(`provenance_gate`/`TIER_*`/`check_provenance_gate`/`validate_transitive_url_against_registry`)
is deleted in the Rust mirror of S3b, and Rust already has its own
`normalize_git_source_url` (`resolver.rs:1211`).

**Rust carries the identical security-window and site-count facts (round-2 —
F6/F7/F12).** (1) Rust's `validate_transitive_url_against_registry` is likewise an
inline, `continue`-gated BFS admission check (`resolver.rs:2596`), so the
S3a-not-S3b gap opening (§10 S3a/S3c note) applies to Rust too — the Rust mirror
of S3a MUST land the tripwire feed atomically, same as Python. (2) The Rust
mutation-verb audit (S5b's Python-only "~34 sites") is a *separate* Rust count
(`solver_var`/`from_solver_var` ~35 sites) that §10's "S10 = grammar slices only"
catch-up list does **not** cover — S5b's Rust half is called out explicitly there.
(3) The Rust S3b deletion surface is larger than the "~34" figure (a
`provenance_gate|TIER_*|check_provenance_gate|validate_transitive_url_against_registry`
grep returns ~55 hits incl. tests); re-count before sizing the in-window mirror.

---

## 10. Slicing (for `/tdd`)

Vertical slices, each independently testable, each green end-to-end before the
next. **The list is in strict build order** (round-2 fix — F1: item order *is*
landing order; the earlier list numbered the tripwire last while its text said it
lands early — that contradiction is removed). Rust mirrors per-slice for the
pure/wiring slices (§9); conformance fixtures land with the behavior.

1. **S0 — base off last-committed §10 (decided, D-Fork2 §11).** The working tree's
   §10 rewrite encodes a *superseded, factually-wrong* "name-keyed unification (as
   in Go)" model; S9 writes §10 from the last-committed base and does not build on
   the stopgap hunk. No code. The only residue is Corey's git action on his own
   tree (revert the hunk or leave it dormant — the RFC bases off last-committed
   either way).
2. **S1 — `SourceId` value type + `normalize_source` + one-way `canonical` +
   `format_source_id`** (B6: the single diagnostic formatter every later slug —
   `RES-BINDING-CONFLICT` in S2, `RES-IMPORT-COLLISION` in S6,
   `FROZEN-SOURCE-ID-MISMATCH` in S5 — reuses). **Landed, then revised for the
   round-2.5 representation decision ([[provenance_source_selection]]):** `canonical`
   is a *one-way* injective solver-key/display string — **there is NO `parse()`**
   and no `#subdirectory=`/percent-escaping machinery (the on-disk form is
   structured, §7). The registry key is variable-arity name-last
   (`pkg+<alias>/<ns…>/<name>`, `<ns>` may contain `/`). Namespace validation is
   **per-`/`-segment** safe-name (NOT a whole-string `_validate_safe_name`, which
   would reject 884/886 real tianguis namespaces). Hypothesis generators (F9): (a)
   git/tarball/oci base+subpath, (b) `pkg+` alias/namespace(with `/`)/name
   generation, (c) the **injectivity** law (`canonical(a)==canonical(b) iff a==b`)
   across all six kinds — over URL-shaped alphabets. Fold in userinfo/default-port
   normalization (§4.2 D4). **Reuse `split_oci_target` for `OciSourceId` only
   (F8).** File organization (G7): "formal half" (value type + one-way `canonical`)
   vs "heuristic half" (`normalize_source`). Pure, no wiring. **(S1 code exists; the
   revision pass deletes `parse`/escaping + fixes the registry key to variable-arity
   name-last + per-segment ns validation — a net simplification.)**
3. **S2 — `BindingResolver`** deterministic stage: `__init__(root_claims)` binds
   root/override, `submit()` for non-root, `DUPLICATE`/`LOST_TO_ROOT` outcomes
   (G2), `RES-BINDING-CONFLICT` (transitive-vs-transitive only). Key by `DepKey`,
   with a first-class RED test that `ns1::foo`/`ns2::foo` never cross-bind (B1/G1).
   Unit + property tests, in-memory only.
4. **S3a — wire `BindingResolver` in + land the tripwire atomically (F2/F3 —
   security-critical ordering).** The deleted checks
   (`_check_provenance_gate`/`_validate_transitive_url_against_registry`) are
   **`continue`-gated BFS-admission conditionals** (`resolver.py:1990`, `2118`,
   `2150`; Rust `resolver.rs:2596`), not passive side-tables — so the instant
   `BindingResolver` becomes authoritative, the pre-fetch dependency-confusion
   tripwire's protective effect is gone. Therefore **S3c lands in this same slice**,
   feeding the registry-shadow accept/reject directly into `submit()`'s pre-check,
   so `main` is never exposed (the §6.1 property is preserved *by construction*, not
   by a scheduling promise). Wire both entry points — `resolve()` (`resolver.py:2948`)
   *and* `resolve_workspace()` (`:4978`), each with its own `provenance_gate = {}`
   and root/override seed — feed the solver `canonical(source_id)`, populate
   `ResolvedDep.source_id`, add the failure-path pretty-printer (reusing
   `format_source_id`). Old `TIER_*` machinery left present-but-unreferenced.
   **Same-URL / different-ref completeness (round-2.5, from the S3a investigation):**
   two claims for one URL at different refs are one source-id with *two versions* — a
   `DUPLICATE` binding decision MUST still register the claim's pinned ref as a
   candidate version for the bound source-id, or a pinned version is silently dropped
   (`TestTwoAgreeingUrlPinsOfSameRegistryNameCoexist`). If this ripples into #191's
   version machinery beyond S3a's reasonable scope, file an issue and assert the
   corrected multi-version behavior rather than regress it silently.
5. **S3a-req — `requires`-edge re-derivation (split out of S3a, F3).** Re-derive
   `LockedDep.requires`/`ResolvedDep.requires` through `source_id` then project to
   the chosen slot (§4.7/B3). Load-bearing and silent-on-failure: `nimcfg.py:236`
   builds `dep_by_name` and `_member_dep_closure` walks `requires` through it, so a
   wrong re-derivation drops a dep from `nim.cfg`'s search path with no error.
   Explicit `nim.cfg` + `milpa show` regression coverage. Green end-to-end (incl.
   workspace) here.
6. **S3c — registry-shadow tripwire (decided, D-Fork1 §11; final design §6.1) —
   lands *inside* S3a's commit.** Pre-fetch, **name-triggered + URL-refined**
   diagnostic: a transitive `git=`/`tarball=`/`oci=` claim whose bare name matches a
   registry-owned coordinate → silent-accept iff the entry has a comparable upstream
   URL matching the claim, else (URL disagrees, or OCI-only/no comparable URL)
   `RES-REGISTRY-SHADOW` — warn-default, hard-fail under `attestation-policy` strict.
   **Corrected fixture re-home map (round-2.5, from the S3a investigation):** the
   `test_provenance_lattice.py` classes split across TWO mechanisms — *multi-claim
   disagreements* (two competing claims for one name: `TestDisagreeingUrl*`,
   `TestMidSolveResidualClosedByImmediateValidation`,
   `TestTwoDisagreeingUrlsForRegistryNameBothConflict`,
   `TestUrlVsUrlStillConflictsWithNoRegistry`) → `RES-BINDING-CONFLICT`; *lone
   name-shadow of a registry coordinate* (`TestLoneUrlPinOfRegistryNameDisagreesConflicts`,
   `TestOciSourceUrlMismatchConflicts`, `TestOciOnlyRegistryEntry*Conflicts`) →
   `RES-REGISTRY-SHADOW` (OCI-only → warn/strict, **no** post-fetch content compare).
   `TestOciOnlyRegistryEntryContentHashMatchAccepted` re-homes from "accept" to
   warn/strict (honest pre-fetch posture, signed off §6.1). Listed separately for
   review clarity; **not** a separately-shippable commit (see S3a).
7. **S3b — pure deletion.** Remove `provenance_gate`, `TIER_*`,
   `_check_provenance_gate`, `_validate_transitive_url_against_registry`,
   `_registry_git_provenances`/`_registry_oci_source_urls`, the
   `_ROOT_SELF_PKEY`/`_NAMED_PKEY` sentinels; rewrite the `OciIndexProvenance.source_url`
   docstring to audit-only; note the `publishing.py` audit-only `source_url`.
   **Retain `root_authority`** single-purpose for `_version_unknown_constrained_err`
   with a comment (B3) — do not mass-delete it. Reviewable as a diff-reduction.
   **Add the hermetic conformance fixture reproducing
   `BUG-root-authority-kdl-transitive.md` cases B/D.** **Exit condition (D5, updated
   — no deferral, Corey 2026-08-02):** if the fixture shows B/D *still* fail
   post-wiring, **FIX the underlying BFS wave-orchestration defect in this same loop**
   (breaking changes are fine pre-v1) — do NOT xfail/file-and-move-on, and do **not**
   pin the fixture at broken behavior (that would canonize a bug). The fixture asserts
   B/D *resolve correctly*.
8. **S4 — `edge_cache` re-key** to `(source_id, Version)` (single call site,
   `resolver.py:776`) with a diamond-under-two-labels regression test.
9. **S4b — reconcile Phase B `_dedup_candidates` with source-id keying (round-2
   correction — D1).** Keep the merge-on-proof pass (`:3417`/`:4373`); re-key
   `aliases_map` from labels to source-ids so it becomes *cross-origin* unification
   (a registry coordinate and a git URL fetching identical bytes collapse to one
   solver variable + one `_deps/` view — the §3.3 win). Keep the identical-
   `requires` invariant guard. **Record both collapsed origins' provenance** in the
   lockfile so a cross-origin collapse preserves its audit trail (today
   `aliases_map` carries only labels). Regression tests: (a) two distinct source-ids
   with identical `content_hash` collapse to one solver variable *and* both
   provenances survive; (b) two distinct source-ids with *different* `content_hash`
   are never merged. (Provenance-recording scope confirm — §11.)
10. **S6 — import-slot floor.** `check_directory_slot_collisions(resolved)` →
    `RES-IMPORT-COLLISION`, with the `content_hash` short-circuit (§4.6). Plain
    function, **no port.** Kept as a fast-path pre-filter under S7 (§4.6/G9); its
    slug carries the "directory-slot only, not full import" caveat. **Frozen-path
    reachability (F4):** the floor only sees `source_id` on a *fresh* resolve until
    S5 adds it to the lockfile schema — so either scope S6 explicitly as
    "fresh-resolve only; `verify`/frozen protected from S5" *or* fold the one
    `frozen.py:193` `ResolvedDep` construction site's `source_id` population into S6.
    Pulled ahead of S5 so no committed state has two source-ids sharing a slot with
    zero diagnostic (B4).
11. **S5 — feed solver `canonical(source_id)` + lockfile source serialization
    (STRUCTURED) + one-shot regen.** **Solver re-key (moved here from S3a, round-2.5
    §4.4):** `Term.package` fed `canonical(source_id)`; provider candidate/stub dicts
    re-keyed name→`canonical`. This lands WITH the lockfile change because it changes
    the resolved-graph node keys the lockfile serializes. Each locked dep gains a
    `source { … }` node with typed children (§7, uv model), NOT a flat
    `canonical(source_id)` key; deserialize field-by-field into the frozen `SourceId`
    struct (no `parse()`). Slot projection → `nim.cfg`/`_deps`;
    `milpa show`/`verify` output; the §4.4/B2 field-duplication audit (delete
    `registry_namespace`, re-home `provenances`). Add the `FROZEN-SOURCE-ID-MISMATCH`
    precondition — **declared-after-override**, reusing `BindingResolver`'s override
    helper (D2) — plus `FROZEN-REGISTRY-ALIAS-UNRESOLVED` checked-first (D3), each
    with a fixture. **Pull the mutation-verb lockfile call sites into S5 (F5):**
    `add`/`remove`/`update` read/write the locked source (`cli.py:4131`) and break
    the instant the on-disk shape changes — they cannot wait for S5b.
12. **S5b — CLI-wide `solver_var` audit + dead-override diagnostic.** Audit all ~34
    Python `solver_var`/`from_solver_var` sites (and the ~35 Rust sites — F7, not in
    S10's grammar-only catch-up); each either carries a `SourceId`/canonical string
    or stays a bare label, explicitly. Dead-override diagnostic (B10) via
    `BindOutcome`/unmatched root claims.
13. **S7 — import-slot check (symbol-level):** the `SymbolProviderPort`/`ImportSlot`
    seam (introduced *here*, not S6), `provides { module … }` grammar,
    `ManifestDeclaredSymbolProvider` / `FetchedTreeSymbolProvider`, fidelity-tagged.
14. **S8 — subpath grammar:** `subpath=` on url/tarball deps threaded into
    `SourceId`, escape-guarded. **S8b — COMPLETE overrides grammar (F11 + B5, no
    deferral):** extend `OverrideTarget` with `Oci`, `Tarball`, AND `Registry`
    targets, plus version-scoped overrides — the full rebind bridge (§7 B5). Parser/
    grammar work (not S9 spec prose); lands here with S8. Breaking manifest-grammar
    changes are fine pre-v1.
15. **S9 — spec rewrite:** §6a/§6b (incl. the leak-rule repeal-and-replace), §10
    (from the S0 base, not the stopgap), §4.2.1, §7.1, `errors.md`, `identity.md`,
    `manifest.md`; bijection lint. Spec prose only (parser work is in S1/S8/S8b).
16. **S10 — Rust catch-up** for the grammar-dependent slices only (S5/S7/S8); the
    pure/wiring slices were mirrored in-window (§9), and the Rust mutation-verb audit
    rides with S5b (F7). Conformance corpus parity.
17. **S11 — amoxtli proof (manual/gated runbook, NOT an automated slice — F10).**
    Re-resolve amoxtli; softlink resolves via its own URL with **no tianguis
    republish**; commit only amoxtli's `milpa.lock`. This talks to live git remotes
    and cannot be a hermetic RED→GREEN slice — it is an on-demand smoke test in the
    "Real fresco verification" tradition (CLAUDE.md), *not* gated in CI. The
    hermetic B/D fixture (S3b) is the automated regression guard; S11 is
    confirmation.

---

## 11. Decided (by the bar) vs. open

**Decided:**
- Registry identity = **coordinate-is-origin** (Cargo's model); `overrides {}` is
  the bridge; no URL-inspection auto-unification. (Corey sign-off 2026-08-01.)
- Import-slot check = **symbol-level target, directory-slot floor, phased** —
  floor is a plain function with a `content_hash` short-circuit (§4.6); the port
  lands in S7, not S6.
- **Drop** the pluggable `BindingConflictPolicy` *and* the `SourceIdNormalizer`
  Protocol/registry (both YAGNI); a single `normalize_source` function, add the
  seam when a second real case exists.
- Value type = **closed union of frozen per-kind dataclasses** (not `kind:str`).
- **Authority is `is_root: bool`, not an `IntEnum`** (round 1 — the tier lattice
  must not sneak back); root-first is structural (`__init__` binds root claims).
- **No reverse-map side-table** — `parse()` is the inverse; `ResolvedDep.source_id`
  carries the origin (round 1).
- **Don't touch the solver.**
- **Registry canonical form = `pkg+<alias>/[<ns>/]<name>` with the registry
  component a *configured alias slug*, never a base URL** (round 1 — resolved: a
  base URL contains `/`, making the flat-join non-injective and the round-trip law
  undecidable; alias makes it satisfiable and lockfiles portable via
  `FROZEN-REGISTRY-ALIAS-UNRESOLVED`). Prefix is `pkg+` (matches `git+`/`oci+`/
  `tar+`/`file+`/`member+`).
- **Failure-path pretty-printer is in scope (S3a)** — resolved yes (round 1).

**Decided (round 2 — all clear-best fixes, no genuine forks; Corey may veto):**
- **Grouping/query key is `DepKey`, not bare `name`** (§4.3, B1/G1) — a bare-name
  store is the literal #193 root cause; namespace-sensitivity is an S2 RED test.
- **Suppression is a 3-way `BindOutcome`** (`NEW`/`DUPLICATE`/`LOST_TO_ROOT`), not a
  bool (§4.3, G2) — restores the typed "why was my claim dropped?" answer.
- **`MemberSourceId` split out of `FetchableOrigin`** (§4.1, G4) — members' exemption
  from fetch/CAS/attestation becomes type-enforced, not prose-remembered.
- **`subpath` stays per-kind; no `Subpathed[T]` wrapper** (§4.1, G5) — flat closed
  union beats a heterogeneous generic union for one repeated field decl.
- **Slot tie-break fully specified** (root > first-BFS > URL-tail) with a visible
  drop note (§4.7, G3) — no silent label disappearance.
- **Keep & extend Phase B `_dedup_candidates`** (§6/S4b, D1 — *corrected after Corey
  pushed on honoring the roadmap*) — it is merge-on-*proof* (identical content_hash
  + invariant guard), post-fetch, identical-bytes-only, so it does not violate §3.3
  (which forbids merge-on-*heuristic*) and cannot blind the pre-fetch tripwire.
  Source-id keying makes it cross-origin = milpa's differentiator at the solver
  layer. S4b reconciles + records both origins' provenance; #32–34 (global CAS
  store, multihash) extends it, not re-implements it.
- **`FROZEN-SOURCE-ID-MISMATCH` compares declared-*after-override*** (§7.1, D2) and
  is preceded by `FROZEN-REGISTRY-ALIAS-UNRESOLVED` (D3) — else it false-positives on
  every `overrides {}` project.
- **git-normalize is stated in three explicit tiers** (§4.2, D4): kept (host/scheme/
  `.git`), *added* (userinfo + default-port stripping — a real decidable
  missed-unification), *not attempted* (ssh↔https / SCP — undecidable or unreachable).
- **`source_id` is authoritative; `registry_namespace` deleted, `provenances`
  re-homed** to per-version provenance (§4.4, B2/G10) — single source of truth.
- **Security-critical slice ordering** (§10, F1/F2): the registry-shadow tripwire
  (S3c) lands *inside* S3a's commit, because the deleted checks are `continue`-gated
  BFS admission — deferring it opens the dependency-confusion gap on `main`. S3a is
  split (wiring vs. `requires`-edge re-derivation, F3); S11 is a manual runbook, not
  an automated slice (F10); Rust mirror carries the same window/counts (F6/F7).
- **`root_authority` survives** single-purpose for `VERSION-UNKNOWN-CONSTRAINED`
  (§6, B3); its bare-name scoping is the open #192/R6 door (§14), out of scope here.

**Decided (round 2.5 — the representation correction; Corey "go" 2026-08-02):**
- **coordinate-is-origin KEPT** after considering and rejecting URL-as-origin (Go's
  model). URL-as-identity would demote tianguis to a name→URL phonebook and discard
  the registry's whole value (content-addressed attestation keyed to a coordinate,
  curation/yank, signer ratchet, repo-move stability, namespacing). Nim **with
  tianguis** is a hybrid registry+direct ecosystem = cargo/uv's shape, not Go's.
  (See §13.)
- **The flat parse-back canonical string is dropped in favor of native-struct
  identity + structured-on-disk source (cargo/uv model):** `SourceId` is the frozen
  struct (field-wise eq/hash = identity); on disk it serializes structured (§7);
  `canonical` survives only as a *one-way* injective solver-key/display string;
  **`parse()` and the escaping machinery are deleted.** This dissolves the
  host-qualified-namespace snag (`codeberg.org/eris`; 884/886 real) — a `/`-namespace
  is an ordinary structured field, and the one-way key is injective via name-last.
  Kills the escaping bug class and the biggest cross-impl-divergence risk. Reworks
  §4.1 (loses `parse`), §7/§6b (structured lockfile), S1 (net simplification), S5
  (structured ser/de). S2 unaffected (already assumed coordinate-is-origin).

**Resolved under the bar (round 1 — no genuine forks remain).** Each item below
had a goal-determined answer; presenting them as open forks was a polling error
([[feedback_resolve_dont_poll]]). Corey may veto the reasoning; absent that, these
are decided.

**D-Fork1 — the dependency-confusion defense = a pre-fetch registry-shadow
tripwire (§6.1).** Deleting `_validate_transitive_url_against_registry` removes
milpa's *pre-fetch* tripwire: a lone transitive `git=` pinning a registry-owned
name at a *different* repo would otherwise raise nothing and the tree gets fetched;
the only downstream catch is the post-fetch import-slot check, and only once S7
lands. **Resolved: retain the tripwire.** Rationale under the bar: milpa's entire
positioning is supply-chain integrity, and dependency-confusion is *the* canonical
supply-chain attack (Birsan 2021) — the ecosystems option (b) imitates (Cargo/npm)
are the ones it hit. Shipping a defense weaker than milpa's own current behavior
fails the mandate. The coordinate-is-origin sign-off is Cargo's *identity model*
(keying); Cargo's *absence of a confusion defense* is a **separable** property we
are not obligated to inherit. The tripwire changes no keying — it is a trust check
layered on the existing `attestation-policy` seam (not the deleted tier lattice):
when a transitive `git=`/`tarball=`/`oci=` claim uses a bare name that is *also* a
registry-owned coordinate, emit a diagnostic *before* fetch — **name-triggered,
URL-refined** (§6.1, final design 2026-08-02): silent-accept only when the registry
entry has a comparable upstream URL matching the claim; otherwise (URL disagrees, or
OCI-only/no comparable URL) `RES-REGISTRY-SHADOW`, **warn by default** (a git fork of
a registry package is legitimate and common), **hard-fail under `attestation-policy`
strict**. Re-homes (not deletes) the threat-model fixtures across the right
mechanisms (multi-claim → `RES-BINDING-CONFLICT`; lone-name-shadow →
`RES-REGISTRY-SHADOW`); lands *inside* S3a's commit so `main` is never exposed.
*Rejected (b) full-Cargo-no-tripwire: a strict security step-down for milpa's differentiator.*

**D-Fork2 — discard the uncommitted §10 stopgap text (S0).** The end state is
identical either way (S9 rewrites §10 from a clean base regardless). The stopgap
text is not just superseded but *factually wrong* ("name-keyed unification, as in
Go" — Go is URL-keyed); committing known-wrong normative text as a "checkpoint"
purely to have a diff base is history pollution. **Resolved: write §10 in S9 from
the last-committed base; do not build on the stopgap hunk.** *The only residue that
is genuinely Corey's is the git action on his own working tree* — the RFC will
treat last-committed §10 as the base whether or not the hunk is reverted; the other
uncommitted edits (`publishing.py` etc.) are unrelated and untouched. *Rejected
(b) commit-as-checkpoint: history noise, no functional difference.*

**D-Fork3 — subpath grammar stays in-RFC as S8.** No design content distinguishes
in-RFC from spin-out; the value type reserves the field identically, and the
escape-guard + injectivity rules are already specified here. Splitting helps only
if a consumer waits for the core — there are none. **Resolved: in-RFC.** *Rejected
spin-out: pure coordination overhead, zero benefit.*

---

## 12. Proof

The end-to-end validation: re-resolve amoxtli. `softlink` resolves via its own
`git=` URL as an ordinary source-id, with **no tianguis republish** — the entire
publish-softlink / backfill thread was chasing a false conflict created by the
old validate-against-registry model. This is the headline win and is directly
caused by the keying change.

**On `BUG-root-authority-kdl-transitive.md` cases B/D — claim tightened (round 1).**
The earlier draft asserted the re-key *fixes* cases B and D. Depth review showed
that is not established: case B is annotated in the bug report as already
`pkey`-string-identical (root + proptest declare the same URL+ref), which stays a
same-source-id dedup post-RFC (ref is excluded from `SourceId`); and case D loses
candidates for an *unrelated* package (`nim-z3`), a collateral-damage symptom that
looks like a BFS wave-orchestration defect (suppressing one claim starves a
sibling's candidate registration), **not** a name-vs-source-id collision. Re-keying
the solver variable does not, by itself, touch that control-flow path. Therefore:
- The RFC does **not** claim credit for B/D until the actual mechanism is traced.
- S3a/S3b must confirm whether the new `BindingResolver`+wave wiring changes that
  control path; the hermetic B/D fixture (S3b) locks the traced behavior.
- **Committed exit condition (round-2 — D5; updated round-2.5, no deferral):** "lock
  whatever the real behavior is" is *not* license to pin a still-broken case. If the
  S3b fixture shows B/D still fail, **S3b FIXES the underlying BFS wave-orchestration
  defect within this loop** (breaking changes fine pre-v1) so B/D resolve correctly —
  never an xfail/file-and-defer, never a green pin that canonizes the bug
  ([[feedback_no_invariant_dismissal]], [[feedback_no_deferring_in_loop]]).
- S11 re-runs **cases A–D** as differential regression fixtures, not just the
  amoxtli end-to-end case.

---

## 13. Alternatives considered

- **Content-hash-as-solver-key (Nix / Go-zero-install style).** Key the solver by
  `content_hash` directly. Rejected: `content_hash` is a *per-version, post-fetch*
  fact, but the solver variable must be *version-independent and pre-fetch* (you
  cannot intersect version constraints over a key that only exists after you've
  picked and fetched a version). This is precisely why the model separates
  source-id (pre-fetch origin) from content_hash (post-fetch identity); collapsing
  them re-fuses two of the three namespaces §2.1 exists to separate.
- **URL-auto-unification (resolve-through).** Inspect/normalize URLs to merge a
  `git=` dep with a registry entry pointing at the same repo. Rejected in §3.2:
  URL-equivalence is undecidable, and silently merging a registry identity with a
  lookalike repo is a correctness/security hazard no mainstream resolver takes.
  `overrides {}` is the explicit, safe bridge instead.
- **URL-as-origin (Go's module-path model).** Make every dep's identity its
  normalized upstream URL (a `named` dep resolving to its recorded upstream URL),
  treated as one opaque atom — which fits Nim's URL-federated nimble heritage and
  dissolves the coordinate-representation question entirely. **Considered and
  rejected (round 2.5):** it demotes tianguis to a name→URL phonebook and discards
  the registry's first-class value (attestation keyed to a coordinate, curation,
  signer ratchet, repo-move stability, namespacing). milpa keeps coordinate-is-origin
  (§3.2) — a hybrid registry+direct model (cargo/uv) — and borrows only Go/uv's
  *representation* discipline (native struct + structured on-disk; no flat
  parse-back string). See §11 "Decided (round 2.5)".
- **Genericize PubGrub over a key type.** Initially rejected as a large, risky
  diff for zero behavioral gain — then **adopted** (DE1, code-review reversal;
  see §4.4). The key became a rich `SolverKey` that still IS its canonical string
  (so the solver stays agnostic and every fixture is byte-identical) but carries
  its display `DepKey` inline, deleting the reverse map + the 58-site projection
  scatter that the bare-`str` key forced. What made the reversal cheap was
  realizing the key can carry display without changing the solver's behavior
  (Python: subclass `str`; Rust: newtype with `Deref<str>`).

## 14. Relationship to adjacent in-flight work

- **#191 (real versions).** Already shipped as `docs/rfc-resolution-semantics.md`
  Axis A — *not* fixed by this RFC. Listed in the header only because that model's
  real per-source version labels must compose cleanly with source-id keying (they
  do: version is orthogonal to the origin key). This RFC contains no
  version-reading mechanism; do not look for one in its `/tdd` plan.
- **#192 / R6 (re-resolution drift via the namespace door) — traced, still open
  (round-2 B5).** `rfc-resolution-semantics.handoff.md` R6 (listed *open*) notes
  that `root_authority` is a bare-name `set[str]`, so under `lowest-direct` a
  transitive `ns2::foo` can be misclassified root-direct when root declares
  `ns1::foo`, reintroducing #192. Verdict against this design: `BindingResolver`
  replaces only the *provenance-gate* consumer of `root_authority`; the
  `lowest-direct` preference mechanism (`root_direct_keys`/`is_root_direct`) is a
  *separate, untouched* path (§4.4 "solver untouched"). So this RFC does **not**
  close R6/#192 — the bare-name scoping survives there (§6 "Kept"). It is left open,
  tracked by #192, and is the natural next RFC once origin-keying lands (the
  `DepKey`-scoping discipline this RFC establishes for `BindingResolver` is the
  template for fixing it). Stated here so the header's "adjacent" claim is traced,
  not asserted.
- **Per-entry attestation / distribution-publishing RFCs** (both with modified
  handoffs in the working tree). This RFC shares the lockfile/registry/attestation
  surface but does not conflict: the new `publishing.py` touches only the
  publishing package's *own* name, not dependency-graph keying. The one live
  coupling is attestation subject-binding, handled normatively in §4.7/§7 (subject
  derives from the `RegistrySourceId` coordinate, never the display slot).
