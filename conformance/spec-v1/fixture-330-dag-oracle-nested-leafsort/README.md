# fixture-330 — epoch-2 Merkle-DAG oracle: nested tree, leaf-name sort

**Status: LIVE (epoch-2 DAG builder, RFC slice B2-git).** The `cmd: dag-oracle`
selector now feeds this staged seam input (`dag-oracle.json`) directly to each
impl's production DAG builder, which reproduces the frozen
hand/independently-computed oracle value below (the impls assert against the pin,
never against each other). The cross-transport git counterpart is
`fixture-331-dag-oracle-git-nested`.

## The tree this fixture encodes

A flat materialized `(relpath, mode, content)` sequence (see `dag-oracle.json`),
which describes this source tree (≥2 directory levels):

```
.
├── a.txt            regular     "alpha\n"
├── a/
│   ├── b.txt        regular     "beta\n"
│   └── run.sh       executable  "#!/bin/sh\necho hi\n"
└── link  -> a/b.txt symlink     (content = the target string "a/b.txt")
```

It deliberately exercises every load-bearing epoch-2 axis: a subdirectory (mode
`0x40`), a regular file (`0x00`), an **executable** (`0x01` — exec bit now in
identity, epoch-2 correction), and a **symlink** (`0x80`, content = target
string).

## Why this is the sort-divergence anchor

This is the case where **leaf-name order ≠ full-path order** — the top
cross-impl divergence risk (`spec/identity.md` §1.8).

At the root level the immediate children are the subdirectory `a` and the file
`a.txt`. Epoch-2 sorts children by **leaf name**: `"a"` is a byte-prefix of
`"a.txt"`, so the subdirectory `a` sorts **first**.

A buggy builder that re-uses the materializer's *stream order* (a flat
full-relpath walk / `git ls-tree -r`) would instead see `a.txt` before
`a/b.txt`, because `'.'` (0x2e) < `'/'` (0x2f) — i.e. the **file before the
directory** — and produce a different (wrong) root `H_tree`. The pinned digest
only reproduces when children are independently re-sorted by leaf name at each
level.

## Pinned identity (frozen epoch-2 oracle)

```
dag-sha256:e3213019260649b72bb0295aaec004eb20a625dd55fcd4bac9e35df96bce316f
```

Computed by the standalone reference `conformance/spec-v1/_oracle/dag_sha256_reference.py`
(which does NOT import milpa) and independently re-derived by hand. See the
oracle self-test `impls/python/tests/test_dag_sha256_oracle.py`.
