# RFC: store-level garbage collection (`milpa store gc`)

**Status**: Design note — implementation deferred to issue #141
**Author**: Corey Leavitt
**Date**: 2026-06-15
**Companion**: `rfc-content-addressed-identity.md` Phase C item 7

---

## Why this RFC exists

The content-addressed store (`<cas-root>/sha256/<hex>/`) accumulates entries
indefinitely. Each `milpa fetch` admits new entries; nothing ever removes them.
Over time — especially in a developer environment where many projects share a
single `~/.cache/milpa/` store — the store grows without bound.

`milpa store gc` is the commanded remedy. But safe GC against a shared store
requires settling three questions before any code is written:

1. **Liveness:** which store entries are "in use" and MUST NOT be evicted?
2. **Admit/GC race:** how does GC avoid evicting an entry that a concurrent
   fetch has just admitted and is about to link?
3. **`_scratch/` staleness:** how does GC avoid sweeping the staging area of a
   live, in-progress fetch?

The round-2 architecture review of the Phase C sketch found all three under-
defined. This RFC settles them normatively. No implementation slice may
proceed until this document is ratified.

---

## Scope

This RFC covers only GC design: liveness predicate, sentinel protocol, and
scratch-staleness age. It does NOT cover:

- The `milpa store path`, `milpa store list`, or `milpa store verify` commands
  (those are Phase C items 1–6 in the identity RFC).
- Multi-hash / dedup beyond sha256 (Phase B).
- Lockfile format changes.
- Adding `STORE-GC-ENTRY-IN-USE` to `spec/errors.md` or either impl (deferred
  to the implementation slice to preserve the bijection invariant).

---

## 1. Liveness / watched-project set

### 1.1 The registration problem

A store entry for identity `sha256:<hex>` is "live" if at least one project
currently depends on it. The naive predicate — "live iff symlinked under any
project's `_deps/`" — requires walking all projects on disk, which GC cannot
discover autonomously.

Two candidate mechanisms exist:

**Option A — `~/.cache/milpa/projects.kdl` central registry**
A single file listing absolute paths of all projects that have ever run
`milpa fetch` (or `milpa lock`). GC reads this file, loads each project's
`milpa.lock`, and unions the identity sets.

**Option B — per-project sentinel file**
Each project writes a `<project>/.milpa/gc-root` file containing the project's
absolute path. GC discovers roots by following a configurable search base or by
trusting the `_deps/` symlink tree.

**Normative choice: Option A (`projects.kdl`)**

Rationale: Option B requires either a global search root (which re-introduces
the discovery problem, now at a configurable base path) or a convention that
`_deps/` symlinks always resolve into the store (true post-CAS, but symlinks
are relative, so following them from GC's perspective requires resolving against
the project dir — meaning GC still needs to know the project dir). Option A
places knowledge of the project set in one place that `milpa fetch/lock`
maintains directly. It is simpler, auditable (`cat ~/.cache/milpa/projects.kdl`
shows every tracked project), and survives project directory moves (stale paths
are pruned, not fatal — §1.4 below).

The file path is `<cas-root>/projects.kdl` — that is, a sibling of the
`sha256/`, `_scratch/`, and `_sentinels/` directories inside the store root.
Using the store root (not a separate `~/.cache/milpa/` path) ensures a
non-default `cas.dir` in `milpa.kdl` keeps the registry co-located with its
store.

### 1.2 `projects.kdl` schema

```kdl
// milpa store project registry
// Each entry is the absolute path of a project directory whose milpa.lock
// should be treated as a GC root.
project "/home/alice/projects/fresco"
project "/home/alice/projects/intonaco"
project "/home/alice/work/some-lib"
```

One `project "<absolute-path>"` node per registered project. The file is
written by `milpa fetch` and `milpa lock` (self-registration on every
successful run). No other commands write it. GC reads it (and prunes it).

The file is written atomically: write to `projects.kdl.tmp`, `rename` into
place. Concurrent registrations from parallel `milpa fetch` runs are safe
because each write is a full rewrite of the file (read → add/dedup → write),
and the rename is atomic. The window for a lost concurrent registration is the
same as for any compare-and-swap write; if two `milpa fetch` calls run in
parallel for different projects, one registration may be lost. This is
acceptable: the missing project will re-register on its next `milpa fetch/lock`
run, and the GC is a commanded operation (not automatic), so no immediate data
loss occurs. A future implementation MAY use file locking (`fcntl.flock` or
`LockFile`) to eliminate the window if concurrent registration proves
problematic in practice.

### 1.3 Self-registration

On every successful `milpa fetch` or `milpa lock` run, the implementation
MUST register the project's absolute directory path into `projects.kdl`:

1. Read `<cas-root>/projects.kdl` (empty set if absent).
2. Add the project's absolute path if not already present.
3. Write atomically (tmp-then-rename).

Registration happens AFTER the fetch/lock succeeds — never on partial runs.

### 1.4 Liveness predicate

The **live identity set** is computed as follows:

```
live_identities = {}
for each path P in projects.kdl:
    if P does not exist as a directory:
        mark P for pruning from projects.kdl (§1.5)
        continue
    lockfile = P / "milpa.lock"
    if lockfile does not exist:
        mark P for pruning from projects.kdl (§1.5)
        continue
    for each dep record R in lockfile:
        if R.identity is not None:
            live_identities.add(R.identity)
```

An entry `<cas-root>/sha256/<hex>/` is **evictable** iff ALL of the following
hold:

1. Its identity (`sha256:<hex>`) is NOT in `live_identities`.
2. It is NOT guarded by any in-use sentinel (§2.3).
3. No live-symlink in any registered project's `_deps/` resolves to it.
   (This is a belt-and-suspenders check: if the lockfile predicate is correct,
   symlinks and lockfile agree. Checking both prevents bugs in condition 1 from
   causing silent data loss.)

Condition 3 is operationally: for each project P in the registry, walk
`P/_deps/` for symlinks, resolve each (following one level of indirection),
and add the resolved store path's hex to a `symlinked_entries` set. An entry
is not evictable if its canonical path appears in `symlinked_entries`.

### 1.5 Stale registry pruning

During GC, after computing `live_identities`, the implementation MUST prune
stale entries from `projects.kdl`:

- A project entry is stale if its directory does not exist OR it has no
  `milpa.lock`.
- Stale entries are removed from `projects.kdl` (atomic rewrite after
  computing the evictable set). A stale entry does NOT count as keeping
  entries alive — it is treated as absent.
- A project that has been deleted from disk is simply pruned; the GC does not
  error on absent directories.

---

## 2. Admit/GC race — sentinel-before-admit protocol

### 2.1 The race

Consider this sequence without sentinels:

```
fetch-A:  admit(src) → renames src → sha256/<hex>/  ← admitted
GC:                                                    enumerates store entries
GC:                                                    sha256/<hex>/ not in live set
fetch-A:  link(sha256/<hex>/, _deps/foo)             ← about to link
GC:       evicts sha256/<hex>/                        ← RACES link()
fetch-A:  link() → dangling symlink                  ← BUG
```

The window `admit() rename → [GC enumerates] → link()` allows GC to evict an
entry the caller is about to link. This is a real race when GC runs concurrently
with fetch.

### 2.2 The corrected ordering

The fix is to place the sentinel BEFORE `admit()`, not before `link()`:

```
fetch-A:  place sentinel(<uuid>, identity=sha256:<hex>)
fetch-A:  admit(src) → renames src → sha256/<hex>/
fetch-A:  link(sha256/<hex>/, _deps/foo)
fetch-A:  clear sentinel(<uuid>)
```

This closes the race: GC finds the sentinel during enumeration and refuses to
evict the entry, regardless of whether `admit()` has completed yet.

### 2.3 Sentinel specification

**Location:** `<cas-root>/_sentinels/<uuid>` where `<uuid>` is a random UUID
hex string (e.g. `550e8400e29b41d4a716446655440000`) chosen by the fetch
process. One sentinel file per in-flight fetch operation.

**Content (KDL):**

```kdl
sentinel {
    identity "sha256:<64-hex-chars>"
    pid 12345
    timestamp "2026-06-15T10:23:45Z"
}
```

Fields:
- `identity`: the identity being admitted (normalized `sha256:<hex>` form).
- `pid`: the OS process ID of the writing process. Used for staleness detection
  (§2.4) — if the pid is not running, the sentinel is a candidate for reaping.
- `timestamp`: ISO 8601 UTC timestamp of sentinel creation. Used as fallback
  staleness check if pid-liveness is unavailable or unreliable.

**Eviction rule:** GC MUST NOT evict `sha256/<hex>/` if any sentinel file
contains `identity "sha256:<hex>"`. GC reads all sentinel files before
computing the evictable set. A sentinel-guarded entry that would otherwise be
evictable is skipped with a warning to stderr. Attempting to forcibly evict a
sentinel-guarded entry raises `STORE-GC-ENTRY-IN-USE` (deferred to the
implementation slice).

**Fetch path ordering (NORMATIVE):**

```
1. sentinel_path = <cas-root>/_sentinels/<uuid>
2. write sentinel_path with {identity, pid, timestamp}
3. admit(src) — atomic rename into sha256/<hex>/
4. link(sha256/<hex>/, _deps/<name>) — symlink into project
5. unlink(sentinel_path)
```

Step 5 (clear) happens in a `finally`-equivalent so that crashes after step 3
still clear the sentinel on process-normal exit (KeyboardInterrupt, SystemExit).
Only SIGKILL can leave a stale sentinel.

**`CasAdmittingFetcher` (Python) and the equivalent Rust `CasAdmittingFetcher`
MUST implement this ordering.** The current implementations place no sentinel
before `admit()`. This is the primary behavioral change the implementation slice
introduces.

### 2.4 Sentinel staleness reaping

A SIGKILL'd fetch leaves a stale sentinel. GC may reap sentinel files if:

- The sentinel's `timestamp` is older than age T (same T as §3 — suggested
  1 hour), AND
- Either the `pid` field is absent, OR the pid is no longer running (checked
  via `os.kill(pid, 0)` on POSIX — raises `ProcessLookupError` if absent).

GC MUST NOT reap a sentinel where both conditions are not met (pid still
running OR timestamp young). This is conservative: a long-running fetch that
takes > T will have its sentinel reaped and its entry GC'd. The suggested T=1h
is chosen to be larger than any realistic single-fetch duration (worst case: a
very large dep over a slow connection). The implementation SHOULD warn to stderr
when reaping a sentinel to aid diagnostics.

---

## 3. `_scratch/` staleness age T

### 3.1 Purpose

Orphaned `<cas-root>/_scratch/<uuid>/` directories left by SIGKILL'd fetches
are disk-space waste. GC may sweep them — but MUST NOT sweep a scratch dir
belonging to a live, in-progress fetch that happens to be taking longer than
expected.

### 3.2 Normative definition of T

```
T = 1 hour (3600 seconds)
```

An orphaned scratch entry `<cas-root>/_scratch/<uuid>/` is eligible for sweep
if and only if:

```
now() - mtime(<cas-root>/_scratch/<uuid>/) > T
```

where `mtime` is the filesystem modification time of the scratch directory
itself (updated on creation and on last write to any file within it).

Rationale for T=1h: the largest realistic single-dep fetch (a git clone of a
large repo over a slow connection) completes in under 10 minutes. 1 hour gives
6× headroom. A future spec amendment MAY tighten T once empirical fetch
duration data is available.

### 3.3 Why mtime-gating is correct

A live fetch writes into `_scratch/<uuid>/` during the clone/download phase.
Its mtime is recent (within the last few seconds to minutes). A SIGKILL'd
fetch stops writing; its mtime ages. The mtime gate cleanly separates the two
populations provided T >> max-realistic-fetch-duration.

### 3.4 Interaction with sentinel staleness

Both `_scratch/` sweep and sentinel reaping use the same age T. This is
intentional: if a fetch has been silent for > T, its scratch dir and its
sentinel are both stale by the same reasoning. The implementation SHOULD use a
single configured `--gc-stale-age` duration (default 1h) for both.

---

## 4. The `milpa store gc` command (implementation scope)

This section summarizes what the implementation slice must build. It is not a
spec today — it becomes normative when the implementation lands.

**CLI surface:**

```
milpa store gc [--dry-run] [--gc-stale-age <duration>]
```

- `--dry-run`: print what would be evicted / swept without performing any
  removal. MUST be the default behavior in the first implementation to allow
  validation.
- `--gc-stale-age`: override T (default 1h). Accepts a duration string
  (e.g. `30m`, `2h`).

**Algorithm:**

```
1. Read projects.kdl → project set.
2. Compute live_identities and symlinked_entries (§1.4).
3. Prune stale entries from projects.kdl (§1.5).
4. Read _sentinels/ → sentinel_guarded_identities (§2.3).
5. Enumerate sha256/<hex>/ entries.
6. For each entry:
     if hex not in live_identities AND
        sha256:<hex> not in sentinel_guarded_identities AND
        entry not in symlinked_entries:
       evict (or dry-run: report)
7. Reap sentinel files older than T with dead pids (§2.4).
8. Sweep _scratch/<uuid>/ entries where mtime older than T (§3).
9. Rewrite projects.kdl without stale entries (§1.5).
10. Report: N entries evicted, M bytes reclaimed, K scratch dirs swept.
```

**Error behavior:** if a sentinel-guarded entry is somehow forced for eviction
(e.g. `--force` flag, not in initial implementation), raise
`STORE-GC-ENTRY-IN-USE`. In the normal non-force path, sentinel-guarded entries
are silently skipped (reported in `--dry-run` output as "skipped: in use").

---

## 5. Error codes this RFC will spawn

| Slug | Condition | When added |
|---|---|---|
| `STORE-GC-ENTRY-IN-USE` | GC attempts to evict an entry guarded by an in-use sentinel or a live `_deps/` symlink | Implementation slice (not now) |

The `STORE-GC-ENTRY-IN-USE` slug MUST NOT be added to `spec/errors.md` or
either impl until the implementation slice lands. Adding it prematurely breaks
the bijection invariant (errors.md ↔ impl constants must be 1:1, enforced by
the test suite).

---

## 6. Issues this RFC spawns

- Implementation: see the issue filed at the Status line above.

---

## 7. Open questions (resolved)

**Q: Why not a per-project sentinel file instead of `projects.kdl`?**
Settled in §1.1: per-project sentinels still require GC to discover projects,
and the discovery problem is equivalent to the registration problem. A central
registry is strictly simpler.

**Q: Why not scan `_deps/` symlinks alone (no lockfile)?**
Symlinks are relative paths; resolving them requires knowing the project dir.
Without a registry, GC has no way to find project dirs to start from. The
lockfile check is more reliable (it's a flat file listing all identities) and
catches identities that have been admitted but not yet linked.

**Q: Is the sentinel-before-admit ordering backwards-compatible?**
Yes. Adding a sentinel write before `admit()` is invisible to any observer
except GC. Existing callers of `admit()` / `link()` require no API change; the
sentinel is internal to `CasAdmittingFetcher`.

**Q: What if the CAS store root is on a read-only filesystem during GC?**
GC MUST fail fast with `CAS-STORE-IO-ERROR` (existing slug) rather than
partially evicting.

**Q: Concurrent GC runs?**
Two simultaneous `milpa store gc` invocations are safe: both will compute the
same live set and attempt to remove the same entries. The second removal will
find the entry already gone (a no-op, not an error). A future implementation
MAY use a lockfile (`<cas-root>/_gc.lock`) to serialize GC runs.
