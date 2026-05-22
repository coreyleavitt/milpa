# Decision: config.nims coexistence policy

**Status**: Decided 2026-05-22
**Author**: Corey Leavitt

## Question

Nim projects often use both `nim.cfg` (declarative key=value config)
and `config.nims` (NimScript — Turing-complete imperative config).
Does milpa:

- **(A)** Ignore `config.nims` entirely and drive everything through
  `nim.cfg`?
- **(B)** Lean into `config.nims` as the more powerful format and emit
  programmable Nim configuration?

## Decision: (A) — milpa owns `nim.cfg`, coexists with user-owned `config.nims`

milpa generates `nim.cfg` and explicitly does NOT generate
`config.nims`. The two files coexist cleanly because nim's compiler
reads both in a defined order (project-local nim.cfg → project-local
config.nims → parent dirs → global).

## Why

1. **The declarative-manifest commitment forces this.** milpa.kdl is
   pure data because parsing the manifest must not execute code —
   that's the supply-chain safety argument. The same logic applies to
   milpa's *outputs*: if milpa generates NimScript, it's generating
   Nim code that runs at compile time. The audit surface that
   milpa.kdl removed is reintroduced. A user reading milpa's outputs
   should not need to read Nim to know what they say.

2. **Lane separation is clean and useful.**

   | Concern | File | Owner |
   |---|---|---|
   | Dep paths (`--path:_deps/foo/src`) | `nim.cfg` | milpa (auto-generated) |
   | Static compile flags (`-d:release`, `--opt:speed`) | either | user |
   | Conditional logic (`when defined(linux): ...`) | `config.nims` | user (hand-written) |
   | Project-specific defines | `config.nims` | user |
   | Cross-compile target selection | `config.nims` | user |

3. **No migration friction.** Existing nim projects with hand-written
   `config.nims` files work with milpa unchanged. milpa fetches deps
   + writes nim.cfg; the user's existing config.nims continues to
   apply its own logic. nim's compiler reads both.

4. **Cargo precedent.** Cargo writes `.cargo/config.toml` (declarative)
   and coexists with user-written `build.rs` (procedural) without
   trying to own it. The same model.

## User contract

- **milpa owns `nim.cfg` completely.** It is auto-generated on every
  `milpa fetch` and may be regenerated at any time. Don't hand-edit
  it — your changes will be overwritten.
- **The user owns `config.nims` completely.** milpa never reads, writes,
  or generates it. Custom flags, conditionals, and project-specific
  logic live there.
- **Reproducibility scope:** "given identical milpa.kdl and milpa.lock,
  milpa produces identical `_deps/`, `nim.cfg`, and toolchain." Anything
  the user adds in `config.nims` is the user's reproducibility surface,
  not milpa's.

## Future direction (deferred): `milpa.nims` typed-data API

There's a third path worth flagging but not committing to. milpa
could optionally emit a *different* file — `milpa.nims` — that
exposes milpa's resolved state as typed Nim constants. The user's
hand-written `config.nims` could `import milpa` and query:

```nim
# user's config.nims (still hand-written by the user)
import milpa
when defined(release):
  switch("opt", "speed")
  switch("passL", "-L" & milpa.depPath("openssl") & "/lib")
```

`milpa.nims` would be a *thin data module* — only constants and
read-only procs, no logic. It composes with user-owned `config.nims`
without milpa generating NimScript itself.

This is an attractive design space but not v0/v1 work. Filed as a
deferrable RFC stub (`rfc-milpa-nims-api.md`) for future
consideration.
