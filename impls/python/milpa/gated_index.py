"""``GatedIndex`` — the trust-boundary witness type (RFC:
``docs/rfc-trusted-index-invariant.md``).

Mirrors ``impls/rust/crates/milpa-core/src/gated_index.rs``.

Possessing a ``GatedIndex`` proves the index-level gates (index-trust
verification + enforcement, and the epoch-commitment fold, §2.2) *ran under
the effective ``index-trust`` policy and their outcome was applied*. It is
**not** a claim that the wrapped content is cryptographically trusted — see
the NORMATIVE per-policy invariant below and
:meth:`GatedIndex.is_cryptographically_trusted`.

# NORMATIVE per-policy invariant (RFC §2.3)

``GatedIndex`` ⇒ acquisition completed under the effective ``index-trust``
policy:

- ``strict`` ⇒ cryptographically verified (``Trusted``), else no
  ``GatedIndex`` exists;
- ``warn`` ⇒ verified, or a non-``Trusted`` result was recorded as a warning;
- ``off`` ⇒ verification was explicitly disabled; no trust claim is asserted.

# Why ``verification`` is ``VerificationResult | None`` (RFC §2.4)

Under ``off`` the verifier is never invoked, so there is no
``VerificationResult`` to store — ``None`` means exactly "policy was
``off``, verification deliberately skipped." This is deliberately NOT an
8th ``VerificationResult`` variant: ``VerificationResult`` is a closed
7-variant enum with a *total* ``result_to_slug`` dispatch, and a slug-less
variant would both break that totality and conflate "not checked" with
"checked and failed."

# Why ``.index`` is a property, not the whole object (RFC §2.5)

Python has no compile-time borrow checker, so — unlike Rust's ``.index()``
vs. ``Deref`` choice — there is no coercion-invisibility risk either way.
The property is still the ONE sanctioned extraction point (grep-able via
``grep -rn '\\.index\\b'``), matching the Rust accessor's name and the
RFC's cross-impl vocabulary.

# ``_mint`` containment (RFC §2.1, §2.6)

``GatedIndex._mint`` is the privileged constructor. It is **private by
convention** to the gate module, ``milpa.index_cache`` — every path from
raw bytes to a resolver-consumable index goes through
``index_cache.load_index_gated`` / ``load_default_index``, which call
``_mint`` after the index-trust gate (and, per §2.2, the epoch-commitment
fold) have already run. No other module under ``milpa/`` may call
``_mint`` or construct a ``GatedIndex`` directly —
``tests/test_gated_index_containment.py`` greps the ``milpa/`` tree and
fails the build if one appears. Test code that needs a ``GatedIndex`` over
an arbitrary fixture ``Index`` (bypassing the real gate) uses
``tests/_gated_index_helpers.py`` — deliberately placed OUTSIDE the
``milpa`` package (Python has no ``#[cfg(test)]``; anything importable from
``milpa/`` is callable by production code).

**What the runtime ``_witness`` guard does and does not buy you.** The
``_witness`` sentinel checked in ``__post_init__`` (below) stops the
*accidental* case, which is also the *common* case: a contributor writes
``GatedIndex(...)`` directly, not realizing minting is gated, and gets an
immediate ``TypeError`` pointing at the real gate instead of a silently
unverified index flowing into the resolver. That is the guard's real and
useful job.

It is **not** structurally unforgeable, and this module previously
overclaimed that it was. Two first-party bypasses exist, both proven by
``tests/test_gated_index_invariant.py``:

1. ``dataclasses.replace(some_valid_gated_index, _index=evil, \
_verification=VerificationResult.TRUSTED)``. ``dataclasses.replace()``
   copies every field not named in ``changes`` from the source object,
   including ``_witness`` — so it carries the source's already-valid
   sentinel into the new instance, ``__post_init__`` sees a valid witness
   and does not raise, and the caller has freely overridden ``_index`` /
   ``_verification`` / ``_bundle_info``. This is not an obscure trick:
   ``dataclasses.replace`` is the idiom this codebase already uses
   throughout (``resolver.py``, ``cli.py``, ``lockfile.py``) to
   non-destructively update frozen dataclasses.
2. ``from milpa.gated_index import _MINT_SENTINEL`` and passing it to
   ``GatedIndex(...)`` directly. Python's leading-underscore convention
   only excludes a name from ``from module import *`` — an explicit
   ``import`` of a single-underscore name always works. There is no
   Python-level access modifier that closes this off.

Neither bypass is reachable by anything outside first-party Python source
with access to the ``milpa`` package — and anyone with that access has
strictly easier ways to defeat the trust gate (e.g. editing
``index_cache.py`` itself, or monkeypatching). The actual backstop against
a first-party contributor routing around the gate is
``tests/test_gated_index_containment.py`` (the static grep) plus ordinary
code review, not runtime unforgeability of this type. Compile-time
unforgeability — no struct-literal or field-update syntax reaching a
non-``pub`` field from outside its module — is a real property of the
Rust sibling type (``impls/rust/crates/milpa-core/src/gated_index.rs``),
and it is a property Python's object model cannot reproduce. State that
plainly rather than dressing up a best-effort runtime check as its
equivalent.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from milpa.index_trust import IndexBundleInfo, VerificationResult
from milpa.registry import Index

#: Module-private mint witness, checked by ``__post_init__`` to reject the
#: COMMON failure mode — a contributor constructing ``GatedIndex(...)``
#: directly, unaware that minting must go through the trust gate. It is
#: single-underscore-private by convention only: Python has no access
#: modifier that would actually prevent ``from milpa.gated_index import
#: _MINT_SENTINEL`` (leading underscore only excludes a name from
#: ``import *``, never from an explicit import), and it is not consulted
#: by ``dataclasses.replace()`` at all — ``replace()`` copies whatever
#: witness the source object already carries. Neither this sentinel nor
#: ``__post_init__`` makes forgery structurally impossible; the actual
#: backstop for first-party callers is the static grep
#: (``tests/test_gated_index_containment.py``) plus code review. See the
#: module docstring's "``_mint`` containment" section for the full account
#: and the two proven bypasses.
_MINT_SENTINEL = object()


@dataclass(frozen=True)
class GatedIndex:
    """The trust-boundary witness type. See the module docstring for the
    NORMATIVE per-policy invariant and the rationale for each field/accessor.

    Fields are named with a leading underscore to signal "do not construct
    or reach into this directly" — use the ``.index`` / ``.verification`` /
    ``.bundle_info`` properties and :meth:`is_cryptographically_trusted`.
    Frozen so a later ``gated._index = other`` reassignment raises at the
    point of misuse rather than silently mutating the witness.

    Construction is additionally gated at runtime by ``_witness``: every
    sanctioned constructor (``_mint``, ``empty``) passes the module-private
    ``_MINT_SENTINEL`` object, and ``__post_init__`` (below) rejects any
    other value. This catches the common failure mode — naive direct
    construction, e.g. a contributor writing ``GatedIndex(...)`` without
    realizing minting is gated — with an immediate, clear error.

    It does NOT make forgery structurally impossible for a determined
    first-party caller: ``dataclasses.replace()`` on an already-held valid
    ``GatedIndex`` carries that instance's already-valid ``_witness`` into
    the replacement, satisfying ``__post_init__`` while letting every other
    field be overridden; and ``_MINT_SENTINEL`` is directly importable
    despite its leading underscore. See the module docstring's "``_mint``
    containment" section for the full account — the repo-local grep
    (``tests/test_gated_index_containment.py``) plus code review, not this
    runtime check, is what actually contains construction to the gate
    module. True unforgeability is a Rust-only property this type cannot
    have in Python.
    """

    _index: Index
    _verification: VerificationResult | None
    _bundle_info: IndexBundleInfo | None
    _witness: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # NOTE: deliberately no `__replace__` override here. `__replace__`
        # (PEP-added in 3.13) is consulted by `copy.replace()`, which this
        # codebase does not use anywhere. It is NOT consulted by
        # `dataclasses.replace()` — verified empirically against this
        # interpreter: `dataclasses.replace()` reads `_replace()`, which
        # rebuilds unspecified fields (including `_witness`) straight from
        # `getattr(self, f.name)` and calls `self.__class__(**changes)`,
        # never looking for `__replace__`. Since `dataclasses.replace()` is
        # the idiom this codebase actually uses (resolver.py, cli.py,
        # lockfile.py), a `__replace__` override would guard an unused
        # entry point while leaving the real one exactly as open as today.
        # Adding it would trade one false sense of security for another
        # instead of closing the gap, so it's skipped — see the module
        # docstring for the honest account of what this guard does and
        # does not cover.
        if self._witness is not _MINT_SENTINEL:
            raise TypeError(
                "GatedIndex must be minted via the production trust gate "
                "(GatedIndex._mint / load_index_gated / acquire) — direct "
                "construction bypasses index-trust verification."
            )

    @property
    def index(self) -> Index:
        """The single sanctioned extraction point for the wrapped ``Index``."""
        return self._index

    @property
    def verification(self) -> VerificationResult | None:
        """The verification outcome recorded at mint time, or ``None`` if
        policy was ``off`` (verifier never invoked)."""
        return self._verification

    @property
    def bundle_info(self) -> IndexBundleInfo | None:
        """The observable bundle claims (Rekor time/log-index, signer SAN,
        etc.) recorded at mint time, if a bundle was fetched and parsed.

        A non-``None`` value here is NOT an endorsement of trust — under
        ``warn``, a ``DigestMismatch`` (tampering) still warns-and-continues
        and still populates ``bundle_info`` from the mismatched sidecar.
        Use :meth:`is_cryptographically_trusted` to ask the trust question.
        """
        return self._bundle_info

    def is_cryptographically_trusted(self) -> bool:
        """The ONLY sanctioned "is this index cryptographically trusted?"
        question (RFC §2.4). ``True`` if and only if verification ran and
        produced ``VerificationResult.TRUSTED``.

        Do NOT read trust off ``bundle_info is not None`` — see
        :attr:`bundle_info`.
        """
        return self._verification is VerificationResult.TRUSTED

    @staticmethod
    def _mint(
        index: Index,
        verification: VerificationResult | None,
        bundle_info: IndexBundleInfo | None,
    ) -> GatedIndex:
        """Mint a ``GatedIndex`` from a parsed ``Index`` and the verification
        outcome already computed for it by the gate.

        PRIVILEGED: by convention, private to ``milpa.index_cache`` (the gate
        module) per RFC §2.1 — "the mint point is the production gate, not a
        leaf ``acquire``." No other production module may call this; see the
        module docstring's containment section. Test code uses
        ``tests/_gated_index_helpers.for_test`` instead.

        ``verification=None`` asserts the ``off``-policy case (verifier
        never called); ``Some``/non-``None`` asserts ``strict``/``warn``
        (verifier ran and produced this result, already enforced by the
        caller per policy before minting).
        """
        return GatedIndex(
            _index=index,
            _verification=verification,
            _bundle_info=bundle_info,
            _witness=_MINT_SENTINEL,
        )

    @staticmethod
    def empty() -> GatedIndex:
        """An empty, trust-neutral ``GatedIndex``. An empty index asserts no
        trust claim, so this is sound under every policy (RFC §2.6) — used
        at the resolver's default/frozen anchors, which never load a real
        index (``resolver.py``'s ``env.index is None`` fallback,
        ``frozen.py``'s ``reconcile_root_claims`` anchor)."""
        return GatedIndex(
            _index=Index(),
            _verification=None,
            _bundle_info=None,
            _witness=_MINT_SENTINEL,
        )
