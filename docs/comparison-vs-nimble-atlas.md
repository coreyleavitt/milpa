# milpa vs nimble vs atlas — full feature comparison

**Last updated**: 2026-05-22

This document compares milpa against the two existing Nim dependency
resolvers (nimble v0.22.3, atlas v0.14.2). The milpa column reflects
**milpa with all currently-filed RFCs and issues completed**, not the
current shipped state — the question this doc answers is "what does
the field look like when milpa realizes its design intent?"

Scope of "all RFCs":
- `rfc-content-addressed-identity.md` — Phases A-E
- `rfc-pluggable-fetchers.md` — F1-F8 + SafeExtractor
- `rfc-beyond-pubgrub.md` — research roadmap (proof certificates,
  capability-aware resolution, refinement-typed versions)
- `rfc-compile-time-dep-graphs.md` — compile-time-first dep extraction
- `rfc-effect-typed-deps.md` — capability/effect typing on deps

Plus the filed feature-parity gap issues (#23-#27, #49-#53).
Out-of-scope items (#54-#56: nim version management, tasks,
companion binaries) are deliberately ceded to nimble.

## Feature matrix

Legend: ✓ = supported; ✗ = absent; **bold** = structural exclusive
(would require ground-up rebuild for competitor to match); *italic* =
deliberate scope-out.

### Manifest + format

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| Manifest format | nimscript .nimble | nimscript .nimble + atlas.config | **declarative KDL** + .nimble compat for the requires line |
| Manifest is Turing-complete | yes (nimscript) | yes (nimscript) | **no — pure data; supply-chain attack surface minimized** |
| Lockfile | yes | yes (atlas.lock) | yes (milpa.lock v2 — identity + provenance) |
| Library/application distinction | no | no | **yes — `kind` field decides if lockfile is committed** |
| Schema versioning | no | no | yes (lockfile v1 → v2 → ...; explicit migration) |

### Identity + integrity

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| Dep identity | commit SHA | commit SHA | **sha256 of source tree (content-addressed)** |
| Multi-provenance per identity | no | no | **yes — one identity, N delivery paths** |
| Cross-fork dedup | no | no | **yes — same content → same package, regardless of URL** |
| Mirror substitution | no | no | **yes — adding a mirror is a provenance append, not a new dep** |
| Offline lockfile verification | requires git | requires git | **yes — bytes + lockfile suffice** |
| Global content-addressed store | no | no | **yes — `~/.cache/milpa/store/sha256/...`, cross-project dedup** |
| Hash algorithm agility | no | no | **yes — multihash encoding (`sha256:...`); future-proof** |
| Sigstore / SLSA attestation | no | no | **yes (research direction)** |

### Resolution

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| Algorithm | SAT (vnext) | 3 heuristics (MaxVer/SemVer/MinVer) | PubGrub (paper-spec) |
| Resolution strategies | one | 3 (Max/Sem/Min) | 3+ (Max/Sem/Min + extensible) |
| Conflict narration | "Unsatisfiable" basic | manual override | **derivation chain; proof-certificate verification (research)** |
| Backtracking | yes (SAT) | no | yes (paper-spec) |
| Cycle detection | yes | yes | yes |
| Compile-time dep graphs | no | no | **yes (research — compile-time-first extraction)** |
| Capability-aware resolution | no | no | **yes (research — effect-typed deps)** |
| Refinement-typed versions | no | no | **yes (research — beyond semver)** |

### Transports / fetching

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| Git URL (https / ssh / git / file) | yes | yes | yes |
| Transitive URL deps | unclear (was broken) | yes | yes |
| Tarball | no | no | **yes — verify-before-extract is stricter than git** |
| Mercurial | no | no | yes |
| Fossil | no | no | yes |
| Local path / workspace | basic | yes | yes (with in-place drift detection) |
| OCI registry | no | no | **yes (research) — registry-verified digest** |
| IPFS | no | no | **yes (research) — CID-as-identity alignment** |
| Pluggable fetcher protocol (third-party) | no | no | **yes — entry-point registration** |
| Parallel fetch | no | yes | yes |
| Pre-fetch integrity verification | no | no | **yes (tarball / OCI / IPFS)** |
| Archive sandbox (zip-slip / symlink-escape protection) | n/a | n/a | yes (SafeExtractor utility) |

### Dep declaration semantics

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| Direct deps | yes | yes | yes |
| Features / optional deps | no | yes | yes |
| Conditional deps (`when`) | yes (nimscript) | yes (nimscript) | yes (declarative `when` syntax) |
| Dev / test deps | basic | yes (feature blocks) | yes |
| Patch / override section | no | yes | yes |
| Fork management | no | yes (auto remote) | yes (subsumed by overrides) |
| Workspace linking | basic | yes | yes |

### Registry + ecosystem

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| nim-lang/packages.json | yes | yes | yes |
| Version constraints (`>=`, `==`, ranges) | yes | yes | yes |
| Caret / tilde (`^`, `~`) constraints | no | no | yes |
| Prerelease opt-in | no | no | yes |
| Build metadata (`+build`) | no | no | yes |

### Tooling + ergonomics

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| `fetch` / `install` | yes | yes | yes |
| `lock` (write lockfile without fetch) | yes | yes (`pin`) | yes |
| `show` / dep tree | yes | yes | yes |
| `verify` (integrity check) | partial | no | yes |
| `clean` | no | manual | yes |
| `add` / `remove` / `update` | partial | yes | yes |
| `outdated` / `why` | no | no | yes (filed) |
| `doctor` (environment check) | no | no | yes (filed) |
| Binary distribution | yes | yes | yes |

### Out of scope by design (ceded to nimble)

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (post-RFC) |
|---|---|---|---|
| Nim compiler installation / version selection | yes | yes | *no (intentional)* |
| Task scripts / build hooks | yes (nimscript) | yes (NimScript plugins) | *no (intentional)* |
| Companion binary symlinking (nimsuggest, nimgrep, ...) | yes | no | *no (intentional)* |

milpa stays a **narrow excellent dep resolver**. The single-tool model
is nimble's territory; consumers compose milpa with nimble (or any
build tool) for the broader story.

## What this comparison reveals

### milpa's structural exclusives (15 features, no patch closes them)

Identity-and-trust layer:
1. Declarative KDL manifest (no nimscript evaluation)
2. Content-hash-as-identity
3. Multi-provenance per identity
4. Cross-fork dedup
5. Mirror substitution
6. Offline lockfile verification
7. Global content-addressed store
8. Hash algorithm agility
9. Sigstore/SLSA attestation
10. Library/application lockfile policy

Resolution-and-narration layer:
11. Proof-certificate failure narration
12. Compile-time dep graphs
13. Capability-aware resolution
14. Refinement-typed versions

Transport layer:
15. Pluggable fetchers (tarball / hg / fossil / OCI / IPFS / third-party)

Each of these would require ground-up redesign for nimble or atlas to
match. They aren't features to add; they're commitments embedded in
the data model.

### Where milpa matches

Every feature atlas has that nimble lacks, milpa has too: workspaces,
features, parallel fetch, overrides, resolution strategies. milpa
doesn't cede ground on capability.

### Where milpa intentionally cedes

The three nim-toolchain features (compiler management, task scripts,
companion binaries) belong to nimble. milpa doesn't pretend to be a
one-tool-does-everything system — it's the dep layer.

## Implication for the field

If milpa realizes the full RFC roadmap, the comparison flips from
"milpa is a Python prototype with structural intent" to **"milpa is
the only Nim resolver with a 21st-century identity model, transport
extensibility, and verifiable failure narration."** nimble and atlas
each have years of head start on adoption, ecosystem, and polish; they
do not have a path to closing the structural gap without a major
redesign.

The strategic position milpa occupies after the RFCs:

- **Adoption parity** with atlas on every capability that matters for
  daily use (workspaces, features, overrides, parallel fetch,
  strategies, .nimble compat).
- **Differentiated exclusively** on the identity / provenance / trust
  layer — where the actual interesting research and engineering lives.
- **Narrow** — doesn't try to subsume nimble's compiler/task/toolchain
  role.
- **Composable** — works alongside nimble, doesn't replace it.

The line for "milpa is the obvious choice" is the moment Tier 1
(adoption blockers) and Tier 2 (atlas parity) of the implementation
roadmap (see `docs/roadmap-prioritization.md` companion doc, or the
filed issues directly) land. Tier 3 (structural differentiation)
flips it from "the obvious choice" to "the only choice for anyone who
cares about supply-chain integrity, reproducibility, or multi-
transport dep delivery."

## Caveats and honest disclaimers

- **All currently shipped milpa is a research prototype.** Today
  ≠ post-RFC. The 124 unit tests + 3 gated integration tests cover
  v0; everything in this matrix labeled differentiating-exclusive is
  in RFC form, not in code.
- **nimble and atlas don't stand still.** They could add features
  during milpa's roadmap window. The structural exclusives in §"milpa's
  structural exclusives" are the slowest-to-close gaps; the
  capability-parity items (features, workspaces, strategies) are the
  fastest. Race to differentiation, not to parity.
- **"Research direction" items in milpa's column** (proof
  certificates, compile-time graphs, effect-typed deps, refinement
  types, OCI/IPFS, sigstore) are catalog entries in RFCs, not staffed
  implementations. They are positioned as multi-year directions, each
  worth a publishable artifact.
