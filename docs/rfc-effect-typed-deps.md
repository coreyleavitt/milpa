# RFC: effect-typed dependencies

**Status**: Stub
**Author**: Corey Leavitt
**Companion to**: `coreyleavitt/fresco/docs/rfc-information-flow.md`, `coreyleavitt/fresco/docs/rfc-effect-classification.md`, `coreyleavitt/fresco/docs/rfc-linear-caps.md`

## Why this RFC exists

Every modern dep manager tracks *which* packages a project depends on. None track *what those packages do*. The result: supply-chain attacks where a benign dep updates to start exfiltrating data, capability creep where a "logging library" silently gains network access, and a complete inability to answer "if I import package X, what powers does X gain?"

The fresco/intonaco compile-time-first thesis advocates `cap T` concept-based capability discharge — code declares what authority it needs; the compiler proves the supervisor granted it. This RFC extends the same ethos *one level up*: the resolver itself tracks effects per dep, propagates them transitively, and consumers either grant the union of required capabilities (with a `provide` at app boot) or face a compile error.

## Sketch

milpa.kdl declares effects per dep:

```kdl
deps {
    chronos git="..." ref="feat/contextvars" {
        effects "Net" "Time" "Files"
    }
    results git="..." ref="v0.5.1" {
        effects // pure, no entry needed
    }
}
```

Effects propagate transitively: if chronos requires `Net` and intonaco depends on chronos, intonaco's effect set ⊇ chronos's. milpa builds an effect graph as part of resolution.

At compile time, the consumer declares its tolerated effect set:

```nim
import milpa/effects
expectedEffects {Net, Time, Files, FS}  # union of what we'll grant
```

If any resolved dep imports an effect outside the expected set, the compile fails with:

```
milpa: capability mismatch
  chronos@feat/contextvars requires `Net`, `Time`, `Files`
  intonaco@main requires       (transitive: same as chronos)
  your `expectedEffects` allows `Files`, `Time`
  
  MISSING: `Net`
  
  Either:
    - add `Net` to expectedEffects (acknowledging chronos may make network calls)
    - replace chronos with a dep that doesn't require Net
    - vendor a sandboxed chronos build
```

## Theoretical contribution

Algebraic effects in dep resolution. Most prior art (Eckert et al. on "effects of effects," Haskell's `extensible-effects`, OCaml 5's effect system) focuses on *intra-program* effect tracking. Applying the same lens *across dep boundaries* — where the effect system constrains not just functions you call but packages you import — is novel.

Practical contribution: a Nim resolver where supply-chain attacks become *compile-time-visible diff events*. If `chronos@4.2.3` declared `effects "Net Time"` and `chronos@4.2.4` (post-compromise) declared `effects "Net Time FS Process"`, every consumer that pinned its expected set sees a compile error on `milpa update`. The attack surface is now type-system-visible.

## Connections

- **fresco's cap concept system** — terminal-side capability tokens (TruecolorCap, SixelCap) are *intra-program* caps; this RFC adds the *cross-package* layer
- **fresco's `rfc-information-flow.md`** — multi-axis lattice for information flow; effect tracking is one axis (control flow → side effects)
- **fresco's `rfc-effect-classification.md`** — the substrate-side stub for effect classification; this RFC extends it to dep resolution
- **fresco's `rfc-linear-caps.md`** — linear caps in substrate; orthogonal to dep-level effect tracking but the lattice machinery overlaps

## Deferred until

- milpa v0 shipping
- fresco's substrate-level effect-classification RFC at least drafted (the lattice needs to exist before we attach it to deps)
- Real second consumer (sinopia or amoxtli) so the multi-package effect-propagation story is tested

## Open questions

1. What's the effect *taxonomy* — exactly which effects do we track? FS / Net / Process / Threading / Allocation / IPC / Time / Random? Cargo's "features" system is one prior art; not directly applicable but rhymes.
2. How do effects get declared? Hand-written by package authors in their `.nimble` / `milpa.kdl`, or *inferred* by static analysis of the package source?
3. What about effects from C FFI? An `importc` for `socket()` is invisible to Nim's effect system; how does milpa know?
4. Effects vs capabilities: capabilities are something *granted* (provide cap); effects are something *required* (uses cap). Are they two sides of the same coin or genuinely distinct?
5. Performance: validating effects across a large graph could be slow. Does this happen at `milpa fetch` time or at `nim c` time?
