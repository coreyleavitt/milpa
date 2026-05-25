# RFC: container-first runtime — milpa as the build-system-of-its-manifest

**Status**: Proposed (v2+ direction; v0.x ships only the project-local CAS prerequisite that this RFC depends on)
**Author**: Corey Leavitt
**Date**: 2026-05-25

## Why this RFC exists

milpa has committed to three substrate-level decisions that together
imply a runtime story this RFC makes explicit:

1. **OCI artifacts are the source distribution substrate** (per
   `rfc-distribution-and-publishing.md`). Source deps are pulled by
   OCI digest from any OCI-compliant registry.
2. **The toolchain is content-addressed and lives in the build closure**
   (per `rfc-toolchain-content-addressing.md`). The Nim compiler is
   itself an OCI artifact, identity-pinned in the lockfile alongside
   source deps.
3. **Identity is content hash; provenance is multi-valued metadata**
   (per `rfc-content-addressed-identity.md`). Every dep has a verifiable
   content hash regardless of transport.

If all three are true, the dep cache, the compiler, and the build
environment are *already* OCI-native. Having three separate mechanisms
(CAS at `~/.cache`, compiler via choosenim/nimble, "you run docker
yourself") is the awkward middle. The opinionated end is **one
mechanism for everything**.

This RFC proposes that milpa offer a **container-first runtime mode**
as a first-class option declared in the manifest. In that mode milpa
owns the entire build orchestration: the CAS lives in an isolated
location, the compiler runs inside a container milpa provisioned, the
user invokes `milpa task test` and never types `docker run` themselves.

Container-first is **opt-in**, not the only mode. Native (host-Nim)
development continues to be a first-class path. This RFC defines the
container-first lane so consumers who want it get the full
ergonomics, not a "you're on your own with docker" experience.

## The principle

> When the manifest declares `runtime { kind "container" }`, milpa
> owns the build orchestration end-to-end: container provisioning,
> CAS placement, compiler invocation, output extraction. The user
> experiences the same surface as native development (`milpa build`,
> `milpa test`, `milpa shell`); container details are not exposed.

The reverse is also true: when the manifest declares
`runtime { kind "host" }` (or omits the block), milpa stays out of
runtime orchestration. The user invokes nim directly; milpa just
populates `_deps/` and writes `nim.cfg`. Today's behavior, unchanged.

The two modes are clean: the manifest is the switch, not a runtime
flag, env var, or implicit detection. Reproducibility argument: the
mode is declared in version-controlled manifest, so every consumer of
the project gets the same runtime regardless of their local setup.

## Prior art

**Cargo + `cross`**: cargo itself is native; `cross` (a separate tool)
wraps cargo invocations in docker containers per declared target
triple. Pattern: external tool owns the container; cargo doesn't know.
milpa container-first goes one step further — make it native to the
dep manager.

**Nix Flakes + `nix develop`**: a flake defines a dev shell;
`nix develop` enters it. Containerization is one of several
realization mechanisms. Closest existing reference to milpa's
container-first vision, with the warts of needing to learn Nix to use
it.

**Devcontainer spec (VS Code, Codespaces)**: `.devcontainer/devcontainer.json`
declares a container-based dev environment. IDE-specific surface but
widely adopted. milpa container-first could emit a devcontainer spec
as one of its outputs for IDE integration.

**Bazel + sandbox + remote execution**: every build action runs in an
isolated sandbox; remote execution moves the sandbox onto another
machine. milpa container-first is the same idea at lower scale (per-
project rather than per-action sandboxing).

**uv + `uv tool run`**: uv can install and run tools in isolated
environments without polluting the global namespace. Same ergonomics
shape as `milpa task <name>`: declare what runs, milpa handles the
isolation.

## What changes when `runtime { kind "container" }` is declared

### Manifest extension

```kdl
name "myproject"
kind "application"
src_dir "src"

runtime {
    kind "container"
    base (oci)"ghcr.io/nimlang/nim@sha256:abc..."   // toolchain identity
}

cas {
    dir ".milpa/cas"   // container-first defaults to project-local
}

deps {
    chronos oci="ghcr.io/coreyleavitt/chronos" digest="sha256:def..."
}

tasks {
    test  "nim c -r tests/test_all.nim"
    build "nim c -d:release src/main.nim"
}
```

Three new manifest blocks:

- `runtime { kind "container", base (oci)"..." }` — declares the
  runtime model and toolchain image. `base` MUST be an OCI digest
  reference (content-addressed); tag-only references are rejected at
  parse time. This makes the toolchain identity-pinned in lockstep
  with source deps.
- `cas { dir "..." }` — already shipped in v0.x as the project-local
  CAS prerequisite for this RFC. Container-first projects effectively
  require it; native projects can use it too.
- `tasks { <name> "<command>" ... }` — flat name → shell command map.
  This is the same `tasks` block defined in
  `rfc-toolchain-content-addressing.md` Phase T4. The two RFCs share
  this surface.

### Container provisioning

`milpa task test` (or any `milpa task <name>`) does:

1. Verify `runtime { kind "container" }` is declared; if not, run the
   command directly on the host with `_deps/`-aware nim.cfg.
2. Verify the `runtime.base` OCI digest is locally available (pulled
   via the same FetcherRegistry path source deps use). Cache hit =
   no pull.
3. Spawn a transient container from the base image with:
   - Project tree bind-mounted at a known path (e.g., `/work`)
   - CAS bind-mounted at the corresponding container path (`/work/.milpa/cas`)
     — works because the project-local CAS lives inside the project tree
   - PATH adjusted to include the toolchain's bin directory
   - Environment minimal: only what the manifest declares passed through
4. Execute the task's command inside the container.
5. Stream stdout/stderr back to the user's terminal.
6. Capture exit code; surface it as `milpa`'s exit code.
7. Tear down the container.

The user sees: `milpa task test` runs and exits with the right code.
No docker commands, no mounts, no env var setup.

### `milpa shell`

Drops into an interactive container with the same setup. Useful for
ad-hoc commands, debugging, exploring the dep tree. Equivalent to
`docker run -it --rm <fully-configured-args> bash` but with all the
mounts/env/PATH handled by milpa.

### `milpa nim <args>`

Convenience shim: same as `milpa task __anonymous__` with the command
`nim <args>`. Lets users invoke nim with their own arguments without
declaring them as named tasks first. Optional sugar; not load-bearing.

### Build outputs

The container's view of `/work` is the same tree as the host's view of
the project directory. Build outputs land in the project tree
naturally — `nim c -o:dist/main` produces `dist/main` on both sides
because they're the same bytes via bind mount.

A `.gitignore` convention covers the new artifacts:

```
_deps/
.milpa/
nim.cfg
dist/        # if you use dist/ for outputs
```

### Lockfile

The `runtime.base` digest gets pinned in `milpa.lock` exactly like a
dep:

```kdl
toolchain {
    identity "sha256:abc..."
    provenance {
        kind "oci"
        registry "ghcr.io"
        repository "nimlang/nim"
        digest "sha256:abc..."
    }
}

dep "chronos" {
    identity "sha256:def..."
    ...
}
```

Same shape as the v2 toolchain RFC's `toolchain` block. Both RFCs
agree on this lockfile entry.

### Composition with the v2 toolchain RFC

`rfc-toolchain-content-addressing.md` covers compiler management as a
v2 milpa capability — content-addressed nim, companion binaries,
declarative tasks. This RFC is **the runtime realization** of that
toolchain work in the container-first lane.

When v2 toolchain ships, `runtime.base` can be derived from a
higher-level `toolchain { nim ">= 2.0.0" }` declaration: milpa resolves
the nim constraint, finds the appropriate OCI image, populates
`runtime.base` automatically. The manifest stays declarative; the
container materializes from the constraint.

Native-mode users of the v2 toolchain get the same compiler resolution
without containerization: `_toolchain/bin/nim` symlinked into PATH,
`nim` invoked directly.

## What stays the same

- `_deps/` directory layout, `nim.cfg` emission, milpa.kdl + milpa.lock
  formats are unchanged. The same artifacts power both modes.
- The Fetcher protocol, identity model, resolver, and lockfile schema
  are mode-agnostic.
- Native-mode (`runtime { kind "host" }` or no block) consumers see
  zero change from today's behavior.
- `milpa fetch`, `milpa lock`, `milpa show`, `milpa verify`, `milpa
  clean` all work identically in both modes (they don't invoke the
  compiler).

The only commands that gain container-aware logic are `milpa task`,
`milpa shell`, and `milpa nim` — the runtime orchestration commands.

## Why container-first is the right default for some projects

The fresco / nopal / amoxtli ecosystem already does all Nim work
inside containers (`./dev` wrapper script in fresco, choosenim+docker
for nopal, similar elsewhere). The current pattern is:

1. User has a `./dev` script in each project that wraps docker
   invocations.
2. Each script invents its own mount conventions, env passthrough,
   image selection.
3. CI rebuilds the docker image; local dev maintains another one.
4. Image versions drift across projects.

Container-first mode replaces all of that with one declared image per
project, milpa-orchestrated invocations, automatic identity pinning
in the lockfile, and consistent ergonomics across every project that
opts in. The `./dev` script becomes unnecessary; `milpa task` is the
universal entry.

## Why container-first is NOT the right default for milpa as a whole

- Hosts without docker can't use it at all. Defaulting to it taxes
  every new user with "you must install docker first."
- Native development is materially faster (no container startup, no
  bind-mount IO overhead). Container-first amortizes well over long
  build sessions but is friction for one-shot builds.
- The native + container split means two test surfaces for milpa
  itself; we can't drop native.
- It requires the v2 toolchain machinery to be polished — premature
  to ship before that's stable.

Default stays native; container-first is opt-in via manifest
declaration.

## Phasing

### Phase C0 — prerequisites (v0.x, partially shipped)

- ✅ Project-local CAS via `cas { dir "..." }` manifest block.
- ✅ Relative symlinks in CAS link emission (so `_deps/<name>` survives
  bind-mounting at a different path inside containers).
- ⏳ Distribution-and-publishing RFC Phase 2 (OCI fetcher F6) for
  `runtime.base` to resolve from OCI digests.

The CAS work is done; OCI fetcher is on the existing pluggable-fetchers
roadmap.

### Phase C1 — manifest extension (v2+)

1. `runtime { kind "container" | "host" }` block parsing.
2. `runtime.base` reference parsing (OCI digest required for container
   mode).
3. `tasks { ... }` block parsing (shared with v2 toolchain RFC Phase
   T4).
4. Round-trip + format tests.

**Estimated effort:** 2-3 days, mechanical extension of the manifest
parser.

### Phase C2 — container orchestration

1. Container runtime abstraction (`milpa/runtime/container.py`).
2. docker / podman / containerd backend selection (start with docker,
   easy to add others via the same abstraction).
3. Mount + env + PATH setup logic.
4. Streaming stdout/stderr, exit-code propagation.

**Estimated effort:** 5-7 days, including platform variation handling
(Linux / macOS / Windows-via-WSL).

### Phase C3 — task execution

1. `milpa task <name> [args...]` — parses tasks block, dispatches to
   container backend or native invocation based on `runtime.kind`.
2. `milpa shell` — interactive container session.
3. `milpa nim <args>` — convenience shim.

**Estimated effort:** 2-3 days, layered on Phase C2.

### Phase C4 — toolchain integration with v2 RFC

When the v2 toolchain RFC's `toolchain { nim ">= 2.0.0" }` block lands,
container-first derives `runtime.base` from the resolved compiler's
OCI artifact. Closes the loop between the toolchain RFC and this one.

**Estimated effort:** 1-2 days once both RFCs' prerequisite work is
shipped.

### Phase C5 — devshell + reproducibility tooling

1. `milpa shell` becomes a full hermetic devshell (env vars zeroed,
   only declared passthroughs allowed, deterministic PATH).
2. Output image option: `milpa build --image-out` produces an OCI
   image containing the binary + minimal runtime, signed by the
   author's cosign identity.
3. Per-task resource limits (cpu/memory) for CI scenarios.

**Estimated effort:** open-ended — this is the polyculture endgame.

## Open design questions

### 1. docker vs podman vs containerd as the backend

docker has the broadest install base; podman is rootless-friendly;
containerd is the substrate both use under the hood.

Recommendation: start with docker (broadest user base), add podman
detection (rootless preferred where available), defer containerd
direct integration unless a real consumer needs it.

### 2. Image rebuild semantics

If the `runtime.base` image is updated (digest changes in lockfile),
do we automatically re-pull on next `milpa task <name>`? Or require
an explicit `milpa toolchain update`?

Recommendation: auto-pull on digest change (same model as deps). The
lockfile's identity guarantee makes this safe.

### 3. Bind-mount semantics on macOS/Windows

macOS bind mounts are slow under Docker Desktop (osxfs). Windows
without WSL has similar friction. Container-first may need a "named
volume + sync" mode for these platforms.

Recommendation: document the performance footgun; default to bind
mount with a fallback to named-volume-with-mutagen-sync for
performance-sensitive consumers. Real engineering work; defer until a
macOS consumer hits it.

### 4. Network policy

Should the container have network access? For builds, sometimes yes
(remote stuff via `nim importc` calling out, etc.); for hermetic
reproducibility, no.

Recommendation: default to no-network for `milpa task build` (closest
to hermetic), default to network-allowed for `milpa shell` and
`milpa task test` (humans expect interactivity). Per-task override
in manifest (`tasks { build "..." network=#false }`).

### 5. Container user identity

Running as root inside the container creates root-owned files on the
host (bind mount preserves UIDs). Map to the host user via `--user
$(id -u):$(id -g)`? Use rootless containers?

Recommendation: default `--user` matching invoking user; document the
gotcha. Rootless container support follows when podman backend lands.

### 6. Image pull authentication

Private OCI registries need credentials (docker login, GHCR PAT,
etc.). milpa shouldn't reinvent OCI auth.

Recommendation: rely on the standard `~/.docker/config.json` /
`$DOCKER_CONFIG` mechanism. If the user's docker client can pull, milpa
can pull (because milpa shells out to docker / oras).

### 7. Caching strategy for image layers

Docker has its own layer cache. milpa's CAS is for source deps. Are
they duplicative?

Recommendation: separate concerns. milpa CAS caches source deps;
docker layer cache caches base images. No bridging needed unless we
choose to push milpa source deps as OCI artifacts AND want layer
sharing — that's a v2+ optimization, not a v2 requirement.

### 8. Native escape hatch

If a user declares `runtime { kind "container" }` but wants to run
nim natively this one time (debug a container issue, etc.), how?

Recommendation: `milpa --runtime=host task test` env-var/flag
override. Doesn't change the manifest; just bypasses the runtime
declaration for one invocation. Logs a warning that the user
chose to deviate from the declared mode.

## What this RFC commits milpa to

- A `runtime { kind "container" | "host", base (oci)"..." }` manifest
  block, parsed and validated.
- A `tasks { ... }` manifest block (shared with v2 toolchain RFC), flat
  name → shell command.
- `milpa task <name>`, `milpa shell`, `milpa nim <args>` commands that
  honor the declared runtime mode.
- A container backend abstraction with docker as the first
  implementation; podman / containerd as future plugins.
- Lockfile pinning of the runtime base image identity, identical in
  shape to source-dep pinning.

## What this RFC does NOT commit milpa to

- Container-first as a default. Native remains the unspecified-runtime
  default.
- A specific container runtime beyond docker (podman / containerd come
  later if needed).
- Windows-native (non-WSL) support in the first cut. Linux + macOS
  first; Windows via WSL2.
- A specific image-output format (Phase C5 is a future deliverable).
- Replacement of the v2 toolchain RFC. This RFC is *the runtime
  realization* of toolchain content-addressing in the container lane;
  the v2 RFC retains the toolchain identity / fetcher / version
  resolution work.
- Replacement of `./dev` scripts overnight. Adoption migrates project-
  by-project as consumers see fit.

## Acceptance: testable invariants

When fully realized:

1. A milpa.kdl with `runtime { kind "container", base (oci)"..." }`
   plus `tasks { test "nim c -r tests/test_all.nim" }` enables
   `milpa task test` to run the tests inside the declared container
   with zero docker invocation by the user.
2. Two machines with the same milpa.lock produce byte-identical
   test runs when the runtime base image is content-addressed
   (same OCI digest → same image bytes → same compiler).
3. `runtime { kind "host" }` (or no runtime block) preserves today's
   behavior — `nim c` runs on the host using `_deps/` populated by
   `milpa fetch`.
4. `milpa shell` drops into a container with `nim`, source-deps,
   and the project tree available; exit cleanly tears down the
   container.
5. CAS is project-local (per `cas { dir "..." }` already shipped) and
   bind-mounted into the container at the corresponding path; no
   host-wide cache mount required.
6. `milpa --runtime=host task test` on a container-mode project bypasses
   containerization for one invocation, with a warning logged.

## Issues this RFC will spawn

Filed under a new milestone "container-first runtime
(rfc-container-first-runtime)" when work starts (v2+):

- C1: `runtime { kind, base }` manifest block parsing + validation
- C1: `tasks { ... }` manifest block parsing (shared deliverable with
  v2 toolchain RFC)
- C2: container runtime abstraction + docker backend
- C2: bind-mount + env + PATH setup logic
- C3: `milpa task <name>` command
- C3: `milpa shell` command
- C3: `milpa nim <args>` convenience shim
- C4: `runtime.base` derivation from v2 toolchain `nim ">= 2.0.0"`
  constraint
- C5: hermetic devshell mode
- C5: `milpa build --image-out` OCI image output
- podman backend (post-C2)
- macOS bind-mount performance investigation
- Windows / WSL support

## Connections

- `rfc-toolchain-content-addressing.md` — toolchain identity, fetcher,
  task system. This RFC realizes the toolchain in the container lane;
  the two RFCs share the `tasks` block and the lockfile `toolchain`
  entry.
- `rfc-distribution-and-publishing.md` — OCI as the source substrate.
  `runtime.base` uses the same OCI fetcher path as source deps.
- `rfc-content-addressed-identity.md` — identity model the runtime base
  inherits. Image identity = digest = content hash.
- `rfc-multi-impl-strategy.md` — both Python and Rust milpa
  implementations honor the same `runtime { ... }` manifest grammar.
  The container backend abstraction is per-impl; the spec is shared.
- v0.x `cas { dir "..." }` work — the prerequisite that landed alongside
  the tianguis bootstrap. Container-first depends on project-local CAS
  + relative symlinks.

## Why this RFC exists now (not later)

Two reasons:

1. **Capture the design while context is fresh.** The decision to ship
   project-local CAS + relative symlinks was made specifically to
   enable container-first eventually. Documenting that "eventually"
   makes the v0.x work intentional rather than ad-hoc.
2. **Inform parallel work.** The v2 toolchain RFC needs to know that
   the tasks block is a shared deliverable. The distribution-and-
   publishing RFC needs to know runtime.base will be an OCI digest
   consumer. Without this RFC, those RFCs would each invent their own
   answers and collide.

Implementation does not start until v2+ when the prerequisites mature.
The RFC itself is the v0.x deliverable.
