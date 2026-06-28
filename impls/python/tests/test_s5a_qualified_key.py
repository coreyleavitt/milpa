"""S5a — internal qualified key (#108, rfc-resolver-correctness.md).

RED → GREEN: thread DepKey through seen_named + solver variable so two
namespaced deps with the same bare name are DISTINCT (not silently collapsed).

Because no manifest grammar exists yet to WRITE a second namespace (that's
S5b), these tests exercise the internal dedup key and solver-variable
structures directly rather than driving a full resolve.

Three invariants pinned here:
1. ``DepKey.solver_var()`` exists and returns the correct canonical string
   for the PubGrub solver variable (bare name for namespace=None; "ns::name"
   for non-None namespace).
2. ``seen_named: set[DepKey]`` correctly keeps two same-bare-name/different-
   namespace DepKeys as distinct (the collapse that existed before S5a with
   ``set[str]`` is visible in the OLD-code block).
3. ``_NamedStub.dep_key`` carries the qualified DepKey; ``_NamedStub.name``
   still returns the solver_var string (used as the dict key in _stubs /
   _candidates).
"""

from __future__ import annotations

import pytest

from milpa.version import DepKey


# ---------------------------------------------------------------------------
# 1. solver_var — unit test (RED until S5a lands: method does not exist yet)
# ---------------------------------------------------------------------------


def test_solver_var_bare_name_is_identity():
    """namespace=None → solver_var() == bare name (backward compat)."""
    k = DepKey(name="chronos", namespace=None)
    assert k.solver_var() == "chronos"


def test_solver_var_with_namespace():
    """namespace='core' → solver_var() == 'core::chronos'."""
    k = DepKey(name="chronos", namespace="core")
    assert k.solver_var() == "core::chronos"


def test_solver_var_two_namespaces_are_distinct():
    """(ns1, foo) and (ns2, foo) produce DISTINCT solver vars."""
    k1 = DepKey(name="foo", namespace="ns1")
    k2 = DepKey(name="foo", namespace="ns2")
    assert k1.solver_var() != k2.solver_var()


# ---------------------------------------------------------------------------
# 2. seen_named dedup — collapse demonstration (RED until S5a threading)
# ---------------------------------------------------------------------------


def test_seen_named_set_of_depkey_distinguishes_namespaces():
    """
    After S5a: seen_named is set[DepKey].  Two same-bare-name/different-
    namespace DepKeys are NOT the same key → neither is dropped.

    The old bug (set[str]) is illustrated in the comment block below:
    an old ``seen: set[str]`` would insert both under ``"foo"``, causing the
    second to be silently skipped (only one dep resolved instead of two).
    """
    k_ns1 = DepKey(name="foo", namespace="ns1")
    k_ns2 = DepKey(name="foo", namespace="ns2")
    k_none = DepKey(name="foo", namespace=None)

    # OLD code (set[str]) — collapse:
    # old: set[str] = {"foo"}  → "foo" in old is True → second dropped (BUG)
    old_seen: set[str] = {k_ns1.name}  # bare name "foo"
    assert k_ns2.name in old_seen  # demonstrates the collapse (both are "foo")

    # NEW code (set[DepKey]) — no collapse:
    new_seen: set[DepKey] = {k_ns1}
    assert k_ns2 not in new_seen       # DIFFERENT key → not dropped (FIX)
    assert k_none not in new_seen      # namespace=None also distinct from "ns1"

    # None-namespace still deduplicates correctly (no regression):
    new_seen2: set[DepKey] = {k_none}
    second_none = DepKey(name="foo", namespace=None)
    assert second_none in new_seen2    # same name + same None-namespace → dedup OK


def test_seen_named_solver_var_agreement():
    """
    The solver variable and seen_named key agree on the qualified identity.

    seen_named key for DepKey(name, ns) == dep_key  (set[DepKey] uses __eq__)
    solver var  for DepKey(name, ns) == dep_key.solver_var() (str key in provider)

    These agree because if DepKey("foo", "ns1") is in seen_named, the solver
    variable is "ns1::foo" — uniquely mapping back to the same dep.  Both are
    derived from the same DepKey; no dual-source inconsistency.
    """
    k = DepKey(name="foo", namespace="ns1")
    seen: set[DepKey] = {k}
    assert k in seen                     # identity check passes
    assert k.solver_var() == "ns1::foo"  # solver var is the qualified string


# ---------------------------------------------------------------------------
# 3. _NamedStub carries dep_key (RED until S5a stubs resolver change)
# ---------------------------------------------------------------------------


def test_named_stub_dep_key_field():
    """_NamedStub.dep_key carries the DepKey; .name returns solver_var string."""
    from milpa.resolver import _NamedStub
    from milpa.version import Version

    # Create a minimal IndexVersion-like object (only version + content_hash used here)
    class _FakeIV:
        version = "1.0.0"
        content_hash = "abc"
        dep_decl = None
        dep_decl_schema_version = None

    dep_key = DepKey(name="pkg", namespace=None)
    stub = _NamedStub(dep_key=dep_key, version=Version(1, 0, 0), index_version=_FakeIV())
    assert stub.dep_key == dep_key
    # .name must return solver_var string (bare name for namespace=None)
    assert stub.name == "pkg"


def test_named_stub_dep_key_with_namespace():
    """_NamedStub with namespace → .name returns the qualified solver_var."""
    from milpa.resolver import _NamedStub
    from milpa.version import Version

    class _FakeIV:
        version = "1.0.0"
        content_hash = "abc"
        dep_decl = None
        dep_decl_schema_version = None

    dep_key = DepKey(name="pkg", namespace="core")
    stub = _NamedStub(dep_key=dep_key, version=Version(1, 0, 0), index_version=_FakeIV())
    assert stub.dep_key.namespace == "core"
    assert stub.name == "core::pkg"  # qualified solver_var
