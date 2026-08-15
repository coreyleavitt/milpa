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
"""

from __future__ import annotations

from dataclasses import dataclass

from milpa.index_trust import IndexBundleInfo, VerificationResult
from milpa.registry import Index


@dataclass(frozen=True)
class GatedIndex:
    """The trust-boundary witness type. See the module docstring for the
    NORMATIVE per-policy invariant and the rationale for each field/accessor.

    Fields are named with a leading underscore to signal "do not construct
    or reach into this directly" — use the ``.index`` / ``.verification`` /
    ``.bundle_info`` properties and :meth:`is_cryptographically_trusted`.
    Frozen so a later ``gated._index = other`` reassignment raises at the
    point of misuse rather than silently mutating the witness.
    """

    _index: Index
    _verification: VerificationResult | None
    _bundle_info: IndexBundleInfo | None

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
        return GatedIndex(_index=index, _verification=verification, _bundle_info=bundle_info)

    @staticmethod
    def empty() -> GatedIndex:
        """An empty, trust-neutral ``GatedIndex``. An empty index asserts no
        trust claim, so this is sound under every policy (RFC §2.6) — used
        at the resolver's default/frozen anchors, which never load a real
        index (``resolver.py``'s ``env.index is None`` fallback,
        ``frozen.py``'s ``reconcile_root_claims`` anchor)."""
        return GatedIndex(_index=Index(), _verification=None, _bundle_info=None)
