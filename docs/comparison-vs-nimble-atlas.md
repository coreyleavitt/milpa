# milpa vs nimble vs atlas — full feature comparison + roadmap

**Last updated**: 2026-05-22

This document tracks how milpa compares to the two existing Nim
dep resolvers (nimble v0.22.3, atlas v0.14.2) across feature axes that
matter for adoption and differentiation. It includes a "what if"
column projecting milpa after the filed RFCs + gap issues land, to
guide where energy goes.

## Today: shipped capabilities

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa today |
|---|---|---|---|
| Manifest format | nimscript .nimble | nimscript .nimble + atlas.config | KDL milpa.kdl |
| Lockfile | yes | atlas.lock | KDL milpa.lock |
| Resolution algorithm | SAT (vnext) | 3 strategies (MaxVer/SemVer/MinVer) | PubGrub |
| Conflict narration | "Unsatisfiable" basic | manual override | derivation chain |
| Direct URL deps | yes | yes | yes |
| Transitive URL deps | unclear (was broken; [#543](https://github.com/nim-lang/nimble/issues/543)) | yes | yes |
| Registry resolution | yes | yes | yes |
| **Identity model** | commit SHA | commit SHA | **sha256 content hash** |
| Multi-provenance | no | no | no |
| Workspace / link | basic | yes | no |
| Features / optional deps | no | yes | no |
| Conditional deps (`when`) | nimscript-native | nimscript-native | no |
| Overrides | no | yes | no |
| Fork management | no | yes | no |
| Parallel fetch | no | yes | no |
| Multiple SCMs (hg/fossil) | no | no | no |
| Tarball deps | no | no | no |
| OCI / IPFS deps | no | no | no |
| Virtual env / nim version | yes | yes | no (out of scope) |
| Task scripts | yes (nimscript) | NimScript plugins | no (out of scope) |
| Companion binaries | yes | no | no (out of scope) |
| Binary distribution | yes | yes | no |
| Production-ready | yes (official) | yes | research prototype |

**Score (today, ignoring out-of-scope):** nimble ≈ 12 yes, atlas ≈ 14
yes, milpa ≈ 6 yes. Atlas is the capability leader; nimble is the
incumbent.

## What if: milpa after all filed RFCs + gap issues land

If every currently-open milpa issue lands, the column flips:

| Feature | nimble v0.22.3 | atlas v0.14.2 | milpa (today) | milpa (post-all-filed) |
|---|---|---|---|---|
| Manifest format | nimscript | nimscript + atlas.config | KDL | KDL + .nimble compat ([#51](https://github.com/coreyleavitt/milpa/issues/51)) |
| Lockfile | yes | yes | yes | yes (+ v2 schema with identity/provenance split [#33](https://github.com/coreyleavitt/milpa/issues/33)) |
| Resolution algorithm | SAT | 3 strategies | PubGrub | PubGrub + strategy modes ([#49](https://github.com/coreyleavitt/milpa/issues/49)) + full paper parity ([#28](https://github.com/coreyleavitt/milpa/issues/28)) |
| Conflict narration | basic | manual | derivation chain | proof-certificates (research direction; rfc-beyond-pubgrub) |
| Direct URL deps | yes | yes | yes | yes |
| Transitive URL deps | unclear | yes | yes | yes |
| Registry resolution | yes | yes | yes | yes |
| **Identity model** | commit SHA | commit SHA | sha256 (used but underclaimed) | **content-hash-as-identity, full model** ([#29-#39](https://github.com/coreyleavitt/milpa/milestone/5)) |
| Multi-provenance | no | no | no | yes ([#37](https://github.com/coreyleavitt/milpa/issues/37)) |
| Global content store | no | no | no | yes ([#35](https://github.com/coreyleavitt/milpa/issues/35), [#36](https://github.com/coreyleavitt/milpa/issues/36)) |
| Workspace / link | basic | yes | partial ([#25](https://github.com/coreyleavitt/milpa/issues/25)) | yes ([#25](https://github.com/coreyleavitt/milpa/issues/25), [#42](https://github.com/coreyleavitt/milpa/issues/42)) |
| Features / optional deps | no | yes | no | yes ([#23](https://github.com/coreyleavitt/milpa/issues/23)) |
| Conditional deps (`when`) | nimscript | nimscript | no | yes ([#26](https://github.com/coreyleavitt/milpa/issues/26)) |
| Overrides | no | yes | no | yes ([#50](https://github.com/coreyleavitt/milpa/issues/50)) |
| Fork management | no | yes | no | yes (subsumed by [#50](https://github.com/coreyleavitt/milpa/issues/50)) |
| Parallel fetch | no | yes | no | yes ([#52](https://github.com/coreyleavitt/milpa/issues/52)) |
| Multiple SCMs (hg/fossil) | no | no | no | yes ([#43](https://github.com/coreyleavitt/milpa/issues/43), [#44](https://github.com/coreyleavitt/milpa/issues/44)) |
| Tarball deps | no | no | no | yes ([#41](https://github.com/coreyleavitt/milpa/issues/41)) |
| OCI / IPFS deps | no | no | no | yes ([#45](https://github.com/coreyleavitt/milpa/issues/45), [#46](https://github.com/coreyleavitt/milpa/issues/46)) |
| Pluggable third-party fetchers | no | no | no | yes ([#47](https://github.com/coreyleavitt/milpa/issues/47)) |
| Sigstore / SLSA attestation | no | no | no | yes (research, [#38](https://github.com/coreyleavitt/milpa/issues/38)) |
| Virtual env / nim version | yes | yes | no | no (deliberate, [#54](https://github.com/coreyleavitt/milpa/issues/54)) |
| Task scripts | yes | yes | no | no (deliberate, [#55](https://github.com/coreyleavitt/milpa/issues/55)) |
| Companion binaries | yes | no | no | no (deliberate, [#56](https://github.com/coreyleavitt/milpa/issues/56)) |
| Binary distribution | yes | yes | no | yes ([#53](https://github.com/coreyleavitt/milpa/issues/53)) |
| Production-ready | yes | yes | research prototype | yes (post-#53) |

**Projected score (post-all-filed, excluding deliberate-OUT):** milpa
parity on every adoption feature, exclusive on content-hash identity,
multi-provenance, pluggable transports, sigstore attestation,
proof-certificate failure narration.

## Where milpa pulls ahead vs the field (after roadmap)

These are the structural differentiators no patch to nimble or atlas
closes easily:

1. **Content-hash-as-identity.** Both competitors pin commit SHA;
   neither has a path to content addressing without rebuild. Unlocks
   cross-fork dedup, mirror substitution, cross-SCM identity,
   trust-independent verification.

2. **KDL declarative manifest.** Both competitors evaluate nimscript
   to resolve deps. Supply-chain attack surface is fundamentally
   smaller in milpa (parsing KDL ≠ executing arbitrary Nim).

3. **Multi-provenance.** Same dep, multiple delivery paths, identity
   unchanged. Neither competitor has this; both bake URL into identity.

4. **Pluggable transports.** Tarball / OCI / IPFS via a uniform
   fetcher protocol. Atlas is git-only; nimble is git-only.

5. **Proof-certificate failure narration.** PubGrub baseline today;
   the rfc-beyond-pubgrub direction extends to verifiable proof objects
   that third parties can check without re-running resolution.

6. **Library/application lockfile policy** based on manifest `kind`.
   Cargo-derived; neither competitor implements this.

## Where milpa stays narrow by design

These are deliberately out-of-scope. Resist scope creep here.

- **nim compiler version management** ([#54](https://github.com/coreyleavitt/milpa/issues/54)) — nimble/atlas already do this well.
- **Task scripts / build hooks** ([#55](https://github.com/coreyleavitt/milpa/issues/55)) — nimble's task blocks, atlas's plugins.
- **Companion binary symlinking** ([#56](https://github.com/coreyleavitt/milpa/issues/56)) — nim toolchain concern.

The single-tool-does-everything model is nimble's territory. milpa is
the *narrow excellent* dep resolver; consumers compose it with nimble
(or whatever) for the broader build/toolchain story.

## Priority recommendation: where to focus next

Ordered by adoption-friction-removal first, then by structural
differentiation:

### Tier 1 — adoption blockers (do these next)

These are table stakes; no real Nim consumer adopts milpa without them.

1. **.nimble compatibility ([#51](https://github.com/coreyleavitt/milpa/issues/51))**. Today consumers must author a parallel milpa.kdl. Reading existing .nimble's requires removes the biggest adoption barrier. ~2-3 days.
2. **Binary distribution ([#53](https://github.com/coreyleavitt/milpa/issues/53))**. uv-based Python isn't on most Nim user machines. PyInstaller / zipapp + GH Actions release pipeline. ~3-4 days.
3. **Parallel fetch ([#52](https://github.com/coreyleavitt/milpa/issues/52))**. 4x speedup on fresco's tree. UX-visible; easy win. ~1-2 days.
4. **Phase A of content-addressing RFC ([#29](https://github.com/coreyleavitt/milpa/issues/29), [#30](https://github.com/coreyleavitt/milpa/issues/30), [#31](https://github.com/coreyleavitt/milpa/issues/31))**. Documentation cleanup, executable-bit in hash, `milpa verify` CLI. ~2-3 days for all three. Cleans up the identity story before bigger phases.

**Total Tier 1: ~10-12 days for a milpa that's adoption-ready and
correctly positions its identity model.**

### Tier 2 — feature parity with atlas (close the cap gap)

These remove "atlas has this; why doesn't milpa?" objections during
evaluation.

5. **Resolution strategy modes ([#49](https://github.com/coreyleavitt/milpa/issues/49))** — MaxVer/SemVer/MinVer.
6. **Dependency overrides ([#50](https://github.com/coreyleavitt/milpa/issues/50))** — name/URL/pkg substitution + forks.
7. **Workspace `link` ([#25](https://github.com/coreyleavitt/milpa/issues/25))** — local-project linking for monorepos.
8. **Features / optional deps ([#23](https://github.com/coreyleavitt/milpa/issues/23))** — `feature "test"` blocks.
9. **Conditional deps / when blocks ([#26](https://github.com/coreyleavitt/milpa/issues/26))** — match nimble's nimscript-when semantics.

**Total Tier 2: ~10-15 days. After this, milpa is at-or-ahead of atlas
on every feature axis except scope-OUT items.**

### Tier 3 — structural differentiation (start publishing on these)

These are what makes milpa interesting research-and-engineering wise.
Each is a meaningful contribution to the field.

10. **Content-addressing Phase B-C ([#32](https://github.com/coreyleavitt/milpa/issues/32), [#33](https://github.com/coreyleavitt/milpa/issues/33), [#35](https://github.com/coreyleavitt/milpa/issues/35), [#36](https://github.com/coreyleavitt/milpa/issues/36))** — dedup by content_hash, global store, schema v2.
11. **Pluggable fetchers Phase F1-F3 ([#40](https://github.com/coreyleavitt/milpa/issues/40), [#41](https://github.com/coreyleavitt/milpa/issues/41), [#42](https://github.com/coreyleavitt/milpa/issues/42))** — protocol refactor, tarball, local.
12. **Multi-provenance ([#37](https://github.com/coreyleavitt/milpa/issues/37))** — completes the identity/provenance split.

**Total Tier 3: ~25-30 days. After this, milpa has a real claim to
"the modern Nim dep resolver" — every existing tool would need
ground-up rebuild to match.**

### Tier 4 — research direction (start an artifact)

13. **Hg / fossil fetchers ([#43](https://github.com/coreyleavitt/milpa/issues/43), [#44](https://github.com/coreyleavitt/milpa/issues/44))**.
14. **PubGrub full paper parity ([#28](https://github.com/coreyleavitt/milpa/issues/28))** — backjumping, conflict-driven learning.
15. **OCI / IPFS fetchers ([#45](https://github.com/coreyleavitt/milpa/issues/45), [#46](https://github.com/coreyleavitt/milpa/issues/46))**.
16. **Sigstore / SLSA attestation ([#38](https://github.com/coreyleavitt/milpa/issues/38))**.
17. **Beyond-PubGrub** — proof certificates, capability-aware resolution, refinement-typed versions (rfc-beyond-pubgrub catalog).

Each Tier 4 item is research-paper-or-blog-post material. Pick one
when an engineering focus block is needed; don't try to do them all.

## Total effort estimate to "milpa is the obvious choice"

Tier 1 + Tier 2 + Tier 3 = roughly 45-60 working days, or ~3 calendar
months of focused work. After that, the question isn't "milpa or
atlas?" — it's "is there a reason *not* to milpa?"

The narrow excellent dep resolver, fully realized.

## Anti-priorities

Do **not** spend time on:

- nim version management ([#54](https://github.com/coreyleavitt/milpa/issues/54))
- Task / script system ([#55](https://github.com/coreyleavitt/milpa/issues/55))
- Companion binary symlinking ([#56](https://github.com/coreyleavitt/milpa/issues/56))

These are nimble's territory. Resist scope creep; close-as-wontfix if
proposals arrive.
