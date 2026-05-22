# RFC: toolchain in the build closure — content addressing extends to nim itself

**Status**: Proposed (v2 design commitment; phased, not v0.x-near-term)
**Author**: Corey Leavitt
**Date**: 2026-05-22

## Why this RFC exists

The content-addressed-identity RFC (`rfc-content-addressed-identity.md`)
commits milpa to a model where every *source dependency* is identified
by the sha256 of its contents. The pluggable-fetchers RFC
(`rfc-pluggable-fetchers.md`) generalizes the transport layer so any
delivery mechanism (git, tarball, hg, OCI, IPFS) can produce
content-addressed source.

This RFC closes the obvious next question: **why stop at source?**

The nim compiler, its companion binaries, and the runtime environment
that executes `nim c` against your dep tree are all part of the build
closure. If milpa's identity claim is "these are the bytes that
participate in producing my artifact," the toolchain participates as
much as any source dep.

This RFC commits milpa to extending content-addressing to the toolchain
in v2. v0.x and v1 stay narrow (source-deps only) by deliberate
sequencing, not by permanent exclusion.

## The name argument

milpa is the Mesoamerican intercropping system — corn, beans, squash —
grown together. None of the three is complete alone:

- **Corn** provides structural support (the stalk for the beans to
  climb)
- **Beans** fix nitrogen (the ecological substrate corn and squash
  depend on)
- **Squash** shades the ground (preventing weeds and water loss)

The agricultural metaphor maps directly onto a software build:

- **Source dependencies** = the corn — the structural code that other
  packages build on
- **Toolchain** = the beans — fixes the "nitrogen": the runtime
  substrate (compiler, linker, stdlib) that everything else depends on
- **Environment + tasks** = the squash — covers the ground: ensures
  the closure actually executes (test runner, build commands,
  reproducibility wrappers)

A narrow source-only dep resolver is just-corn farming. The polyculture
metaphor demands the full triad. The name we chose is the argument for
the scope this RFC commits to.

## The principle

> milpa's identity model applies to the **complete build closure**,
> not just source dependencies. The compiler is a dep; the companion
> tools are deps; the task runner is a fixture of the closure. All
> are content-addressed; all participate in lockfile identity claims.

Concretely, this means:

1. The nim compiler is fetched and content-hashed like any other
   package.
2. The active nim version is pinned by content_hash in milpa.lock,
   not just by version string.
3. Companion binaries (nimsuggest, nimgrep, nimpretty) are managed in
   the same content-addressed store.
4. A thin declarative task wrapper lets `milpa task <name>` execute
   named commands defined in milpa.kdl, without milpa embedding a
   scripting language.
5. The build closure is reproducible: `milpa fetch && milpa task
   test` produces byte-identical artifacts across machines as long as
   identity hashes match.

## Prior art

**Nix** is the canonical realization of this principle. A Nix
derivation's identity is the hash of its complete input closure
(sources + builder script + every transitive build input). The system
makes no distinction between "source dep" and "tool dep" — both are
just inputs.

**Bazel** has a similar story for its remote action cache: the action's
inputs (source files, command line, env vars) are hashed together.
Toolchain binaries participate in the cache key.

**Cargo + rust-toolchain.toml** is a partial version of this: cargo
itself doesn't manage rustc, but `rust-toolchain.toml` lets a project
pin a rustc version, and rustup honors it. Tight integration via
convention, not via cargo absorbing toolchain management directly.

**asdf / mise / nix-shell** all do version-pinning of dev tools as a
*separate* tool. milpa-as-polyculture argues for one tool, integrated.

The milpa position aligns with Nix. Cargo+rustup is the
already-shipped "Position A" reference. milpa goes to Position B
because the content-addressing commitment makes the toolchain a
natural extension, not an awkward bolt-on.

## What this RFC commits milpa to

### Toolchain components covered

The build closure includes:

1. **Nim compiler binary** — `nim`, downloaded or built from source,
   identified by content_hash.
2. **Companion tools** — `nimsuggest`, `nimgrep`, `nimpretty`, etc.
   Shipped with nim; managed in the same closure.
3. **Standard library** — bundled with nim; participates in the
   nim-package's content_hash.
4. **Source dependencies** — already content-addressed per Phase A-E
   of `rfc-content-addressed-identity.md`.
5. **Task definitions** — declarative shell-command names in
   milpa.kdl. Not executable code from the manifest; just named
   exec lines.

Out of scope (system-level concerns, deferred to OS or user):
- The C compiler (cc/clang/gcc) that nim shells out to
- libc / system libraries
- Build host hardware

These could be content-addressed in a fully reproducible-build system
(Nix does this) but require sandboxing infrastructure milpa doesn't
have and probably shouldn't. We accept that "reproducibility" in
milpa's claim means "reproducibility given the same OS and C toolchain"
— which is the same bound Cargo, Maven, Gradle, etc. live with.

### Manifest extension

```kdl
// milpa.kdl after this RFC lands

toolchain {
    nim ">= 2.0.0 & < 3.0.0"
    // optional: pin to a specific identity for absolute reproducibility
    nim-identity "sha256:abc123..."
}

deps {
    chronos git=(url)"https://github.com/.../chronos.git" ref="main"
}

tasks {
    test    "nim r tests/run_all.nim"
    bench   "nim r --opt:speed bench/main.nim"
    docs    "nim doc --project --outdir:htmldocs src/myproj.nim"
}

kind "application"
```

- `toolchain` block declares the compiler constraint and optional
  identity pin. If `nim-identity` is set, milpa resolves to exactly
  that compiler regardless of available versions. If not, milpa
  picks the highest matching version and *records* its identity in
  the lockfile.
- `tasks` block is a flat map: name → shell command. Pure data; no
  control flow, no variables, no scripting. If you want logic, write
  a script and call it from the task.

### Lockfile extension

```kdl
version 2

toolchain {
    nim {
        identity "sha256:abc123..."
        version "2.2.10"
        provenance {
            kind "github-release"
            url "https://github.com/nim-lang/nim/releases/download/v2.2.10/nim-2.2.10-linux_x64.tar.xz"
            archive_sha256 "..."
        }
    }
}

dep "chronos" {
    identity "sha256:def456..."
    // ... as today
}
```

The toolchain is recorded with the same shape as any other dep:
identity + provenance.

### Storage

The content-addressed store at `~/.cache/milpa/store/sha256/...`
(from `rfc-content-addressed-identity.md` Phase C) gains a new
content type: extracted compiler trees. Same key structure, same GC
semantics, same hardlink-or-symlink-into-project model.

A project's `_deps/` doesn't change shape; `_toolchain/` is a new
sibling directory containing the active compiler's tree (link into
the global store). `nim.cfg` gains a `--nim:_toolchain/bin/nim` line
or equivalent (the actual mechanism depends on how nim is invoked).

### Task execution

`milpa task <name>` executes the named command:
- Reads `tasks.<name>` from milpa.kdl
- Ensures `_deps/` is populated (auto-fetches if not)
- Ensures `_toolchain/` is populated (auto-installs if not)
- Sets PATH to include `_toolchain/bin/`
- Executes the shell command literally

No control flow. No variables. No conditionals. If a project needs
those, the task value is `bash scripts/foo.sh` and the logic lives in
the script. This is the declarative-manifest invariant preserved.

### Companion binaries

When the compiler tree is installed, the companion binaries
(`nimsuggest`, `nimgrep`, `nimpretty`, etc.) come with it — they're
shipped in the nim distribution. milpa exposes them on PATH the same
way it exposes `nim` itself. No separate management needed.

## What this RFC explicitly does NOT do

- **No script language.** `tasks` are flat name → command strings.
  No `if`, no loops, no functions. Imperative logic lives in scripts
  the task calls.
- **No build system.** milpa doesn't replace make, cmake, just,
  shake, etc. It runs declared tasks. Tasks may invoke build systems;
  milpa is agnostic to which.
- **No C/C++ toolchain management.** System-level. Deferred to OS or
  user.
- **No replacement of nimble's package format.** Source deps still
  carry `.nimble` files (because the registry uses them); milpa just
  doesn't *execute* the nimscript. Read-only compatibility.
- **No deep nim-language integration.** milpa runs nim binaries; it
  doesn't extend nim's language or import system.

## Phasing

This RFC is **v2** work. v0.x and v1 deliberately stay narrow
(source-deps-only) for these reasons:

1. **De-risk the identity model first.** Content-addressing for source
   deps must be proven in practice before extending it to the
   toolchain.
2. **Avoid platform sprawl.** Toolchain installation means Linux x64,
   Linux arm64, macOS x64, macOS arm64, Windows x64, possibly more.
   Each is its own download + extraction + verification surface.
3. **Build adoption first.** A working v1 milpa-the-dep-resolver is
   the credibility that buys permission to expand scope. Shipping v2
   from scratch is premature optimization.

### v2 Phase T1 — toolchain manifest + lockfile schema

1. Add `toolchain { ... }` block to milpa.kdl grammar.
2. Add `toolchain { ... }` block to milpa.lock v3 schema.
3. Don't fetch yet — just record the *constraint* and verify against
   whatever nim is on PATH.
4. CLI: `milpa fetch` warns if active nim doesn't satisfy
   `toolchain.nim` constraint.

**Estimated effort:** 3-5 days. Schema work + verification logic.

### v2 Phase T2 — nim compiler fetcher

1. Implement a `GithubReleaseFetcher` (special case of TarballFetcher
   from `rfc-pluggable-fetchers.md`). Pulls compiler binaries from
   `github.com/nim-lang/nim/releases/`.
2. Verify the archive sha256.
3. Extract into the global content-addressed store.
4. milpa.lock records the identity + GitHub release provenance.

**Estimated effort:** 5-8 days. Includes per-platform archive
selection logic (linux_x64 vs linux_arm64 vs mac vs win), source-build
fallback (when no prebuilt is available).

### v2 Phase T3 — toolchain activation

1. `_toolchain/` directory per project, linking into the global store.
2. `nim.cfg` references `_toolchain/bin/nim` (or PATH-prepend it).
3. `milpa task <name>` execution path sets up the toolchain before
   running.

**Estimated effort:** 3-5 days.

### v2 Phase T4 — declarative task system

1. Parse `tasks { name "command" ... }` from milpa.kdl.
2. `milpa task <name>` reads the named command, ensures
   environment, executes via subprocess.
3. List commands: `milpa tasks` (or `milpa task --list`).
4. Pass-through args: `milpa task test -- --verbose` forwards
   `--verbose` to the underlying command.

**Estimated effort:** 2-4 days.

### v2 Phase T5 — build-from-source fallback

1. When no prebuilt binary matches the constraint (e.g. nim on a
   niche platform), fetch nim source, run its bootstrap build,
   content-hash the resulting binary.
2. Treat the built binary as if it were prebuilt for caching
   purposes.

**Estimated effort:** 5-8 days. Build-from-source is brittle;
expect platform-specific edge cases.

### v2 Phase T6 — devshell integration (research direction)

Once the toolchain is content-addressed, the next research direction
is hermetic dev shells: `milpa shell` drops into a subshell where
PATH, environment vars, and nim version are all the lockfile's
identity. This is the Nix-shell / direnv pattern.

**Estimated effort:** open-ended.

## Open design questions

### 1. How to handle Windows

Most of the toolchain RFC assumes Unix-shaped semantics (symlinks,
shell commands, PATH manipulation). Windows works differently:
junctions instead of symlinks, .exe extensions, different shell.

Decision: target Linux + macOS in v2. Windows support is a stretch
goal; the first cut may require WSL.

### 2. What about `~/.choosenim` users?

Many Nim users have nim installed via choosenim or system package
manager. milpa's toolchain management would clash with those.

Decision: detect and warn. If a system-managed nim is on PATH and
matches the manifest's constraint, milpa uses it (records identity
in lockfile) and skips the install. If the system nim doesn't match,
milpa installs into the store and prepends.

This is the "play nice" stance. A future flag `milpa fetch
--strict-toolchain` could force milpa-managed nim always.

### 3. How does identity work for binaries with embedded paths?

Some Nim builds embed the path to the stdlib at compile time
(`nim --stdlib:...`). If we move the install, the path breaks.

Decision: install with a canonical path scheme; use nim.cfg to
override stdlib path at consumer-side; if necessary, patch the binary
on first install (Nix does this with `patchelf`).

This is the gnarly OS-coupling work that makes Phase T2 nontrivial.

### 4. What about cross-compilation?

A project may target a different platform than the build host. The
toolchain identity has to capture the target as well as the host.

Decision: defer. v2 supports same-host-target builds; cross-compile
is a v3 concern.

### 5. Companion-binary-only updates

Sometimes the nim release ships an updated nimsuggest while the nim
compiler is unchanged. Do we treat that as a new toolchain identity?

Decision: yes. Identity is over the *complete tree*, so any companion
binary change is a new identity. This is consistent with how source
deps work.

## What this means for the comparison

The previous comparison doc (`comparison-vs-nimble-atlas.md`)
flagged compiler management, task scripts, and companion binaries as
"deliberate scope-out" / "ceded to nimble." That framing is now
**incorrect**. The correct framing:

- Compiler management: **v2 commitment** (this RFC). Deferred from
  v0.x for sequencing reasons, not permanent.
- Task scripts: **partial commitment** — declarative wrapper in v2,
  but no native scripting language. Imperative logic stays in scripts
  invoked from tasks.
- Companion binaries: **falls out of compiler management** — managed
  in the same closure once the compiler is.

After v2 lands, milpa is positioned as **the integrated polyculture**:
source deps + toolchain + task execution, all unified under the
content-addressing identity model. Not a dep resolver alongside
nimble; a complete reproducible-build tool that replaces nimble's
dep-resolution + toolchain-management roles. nimble would remain
useful only for its package-publishing role and its tie-in with the
nim-lang/packages registry.

## Acceptance: testable invariants

When the v2 RFC is fully realized:

1. `milpa fetch` in a clean project produces both `_deps/` and
   `_toolchain/`; the active nim invocation goes through the
   content-addressed compiler.
2. The same milpa.lock on two different machines (same OS / arch)
   results in byte-identical compiler binaries.
3. `milpa task test` runs without `nim` being on the system PATH at
   all — the toolchain is fully self-contained.
4. Editing the `toolchain.nim` constraint to a different version
   invalidates the lockfile loudly and triggers a re-fetch on next
   `milpa fetch`.
5. Companion tools (nimsuggest, etc.) are available in the
   toolchain bin directory and version-pinned with the compiler.

## Issues this RFC will spawn

Tracked at GitHub milestone "v2 — toolchain in the build closure
(rfc-toolchain-content-addressing)":

- **#54 (retitled)** — toolchain block parsing + lockfile schema (Phase T1)
- **#55 (retitled)** — declarative task system (Phase T4)
- **#56 (retitled)** — companion binary exposure (subsumed under T2/T3)
- **(new)** — GithubReleaseFetcher (Phase T2)
- **(new)** — toolchain activation + nim.cfg integration (Phase T3)
- **(new)** — build-from-source fallback (Phase T5)
- **(new)** — devshell integration (Phase T6, research)
- **(new)** — choosenim coexistence policy
- **(new)** — Windows support
