"""Package data directory for the embedded Sigstore trust bundle.

The ``trust_bundle.json`` file in this directory is loaded via
``importlib.resources`` by ``TrustBundle.production()`` in
``milpa.index_trust``.

RFC: docs/rfc-registry-trust-federation.md §3.1 (trust bundle embedding).
"""
