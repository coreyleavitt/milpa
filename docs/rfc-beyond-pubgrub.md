# RFC: beyond PubGrub — research directions in dependency resolution

**Status**: Stub / research roadmap
**Author**: Corey Leavitt

## Why this RFC exists

milpa v0 picks PubGrub as its resolution algorithm (good error messages, well-understood, ~400 lines of Python). This is the right v0 choice: it's the current-best-practice baseline. But the dep-resolution field is *not* solved. Several research directions are alive and could give milpa real contributions past v0.

This RFC catalogs them, prioritizes by tractability + relevance, and serves as a roadmap for milpa v1+.

## Direction 1: proof-certificate failure explanations

**The current state.** PubGrub produces a derivation tree: a sequence of "incompatibility" facts that together prove no solution exists. The tree is human-readable but not *minimal* — it shows *a* path to the failure, not the *smallest*.

**The research frontier.** Treat the derivation as a *proof object* that a third party can verify in polynomial time without re-running resolution. Recent papers (2022–2023, e.g. on CDCL proof minimization) extend Boolean satisfiability proof techniques to package management. The output: not just "here's why I failed" but "here's a certificate. If you don't trust me, you can verify it."

**Why milpa cares.** Supply-chain provenance. Reproducibility audits. Lockfile verification across teams without sharing the resolver state.

**Tractability for milpa.** Medium. Requires extending PubGrub's incompatibility tracking with proof-minimization, but the algorithms exist in the SAT literature.

## Direction 2: capability-aware resolution

**The current state.** No production resolver tracks dep *capabilities* — what authorities a dep requires (network, filesystem, process spawn, etc.). All deps are treated as having full capability of the host process.

**The research frontier.** Mark each dep with the capabilities it imports; propagate transitively; verify consumer's grant set covers the union. Compositional algebraic effect systems (Eckert et al.) provide the theoretical foundation. No mainstream resolver has shipped this.

**Why milpa cares.** This is *literally* fresco/intonaco's compile-time-first thesis applied to dep management. It also turns supply-chain attacks into compile-time diff events (a dep that gained `Process` capability between v1.2.3 and v1.2.4 cannot be silently upgraded).

**Tractability for milpa.** Medium-high. Requires (a) a capability taxonomy, (b) per-dep capability declarations or inference, (c) propagation algorithm, (d) compile-time enforcement story. See `rfc-effect-typed-deps.md` for the milpa-specific design.

**This is the most likely place milpa contributes a publishable result.**

## Direction 3: refinement-typed versions

**The current state.** Semver. "A version is `major.minor.patch`." Constraints are tuples of comparisons.

**The research frontier.** Express versions as *refinement types*: "this version provides function `foo` with signature `(int, int) -> int` and capability `Pure`." Resolution becomes SMT solving over typed constraints. Liquid types (Liquid Haskell, F*) provide the substrate.

**Why milpa cares.** When a dep advertises "provides `foo`" the consumer can require "needs `foo` with capability `Pure`" and the resolver becomes type-driven, not version-driven. Beats semver semantically.

**Tractability for milpa.** Low. Requires every dep to publish refinement types, an SMT solver inline with resolution, and an ecosystem migration. Strong research, far from production.

## Direction 4: compositional / workspace resolution

**The current state.** Cargo workspaces, pnpm workspaces, Yarn berry, Bazel modules — different design points for "many packages share resolved deps." None have a clean theoretical model.

**The research frontier.** Treat workspace resolution as a categorical composition: each package has a *local* resolution; workspace-level resolution is the *colimit* of the local resolutions under shared-dep constraints. Recent work on monorepo build systems hints at this; nobody has formalized it.

**Why milpa cares.** When fresco + intonaco + sinopia + amoxtli all live in a workspace, do they share one resolution or four? milpa needs a coherent answer.

**Tractability for milpa.** Medium. Doesn't require new theory but does require careful design — most existing workspace systems have warts (locked-version skew across crates in Cargo, hoisting issues in pnpm).

## Direction 5: probabilistic / risk-aware resolution

**The current state.** All versions are equal in the resolver's eyes. "Latest stable" is the closest heuristic; some tools (cargo, pip) prefer it; others (Nix) prefer "exactly what's locked."

**The research frontier.** Bayesian dep selection. "This release is 2 days old, low prior on quality. This release is 2 years old + downloaded 10M times, high prior. The resolver should pick the one whose posterior expected utility is highest given the consumer's risk tolerance." Cargo author Brian Anderson wrote about this; nobody has shipped it.

**Why milpa cares.** Real-world dep management has risk; modeling it explicitly is honest.

**Tractability for milpa.** Medium-low. Hard part is data — where do priors come from? (Download counts? CVE history? Test pass rate?)

## Direction 6: streaming / incremental resolution

**The current state.** Cargo's resolver is monolithic: given the whole manifest, produces the whole lockfile. Editing the manifest = re-solve from scratch.

**The research frontier.** Incremental algorithms that extend an existing solution under a new constraint. Active area; ties into the "live-update production systems" problem.

**Why milpa cares.** As Nim ecosystem grows, monorepos grow, fresh resolution becomes slow. Incremental is a nice-to-have for large consumers.

**Tractability for milpa.** Medium. PubGrub doesn't naturally extend; would need a different algorithm.

## Direction 7: cryptographic provenance (Sigstore / SLSA)

**The current state.** Sigstore, SLSA framework — emerging standards for "this artifact has a verified attestation that this source produced it."

**The research frontier.** Resolvers that won't pick a version without an attestation. Or: resolvers that prefer attested versions. Or: that surface attestation gaps in their error messages.

**Why milpa cares.** Supply chain. Nontrivial real-world relevance.

**Tractability for milpa.** Mostly engineering, not research. Stand on the shoulders of Sigstore tooling.

## Prioritization for milpa post-v0

If milpa is going to make a *novel* contribution, it should be Direction 2 (capability-aware). The reason: it intersects directly with fresco/intonaco's compile-time-first thesis; nobody has shipped it; it has clear research-publishable shape; and it requires no ecosystem change because milpa can ship capability declarations as a milpa.kdl extension.

Direction 1 (proof certificates) is a nice second — incremental on PubGrub, achievable in a few weeks of focused work, real but smaller theoretical contribution.

Direction 4 (workspace composition) is the most *useful* third — sinopia + intonaco + fresco multi-package workspace handling lives here. Required-when-needed rather than research-led.

Directions 3, 5, 7 are far-future or external-dependency-heavy. Don't prioritize for v0/v1.

## Connections

- `rfc-compile-time-dep-graphs.md` — runtime/compile-time boundary; complementary to capability-aware resolution
- `rfc-effect-typed-deps.md` — the concrete milpa-side design for Direction 2
- `coreyleavitt/fresco/docs/rfc-information-flow.md` — fresco's multi-axis lattice; capabilities are one axis
- `coreyleavitt/fresco/docs/roadmap-compile-time-research.md` — the parallel compile-time-research roadmap for the substrate
