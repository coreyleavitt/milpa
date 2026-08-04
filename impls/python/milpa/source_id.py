"""``SourceId`` — the version-independent origin, per
``docs/rfc-origin-as-identity.md`` §4.1/§4.2 (S1; revised round-2.5,
[[provenance_source_selection]]).

This is the SINGLE SOURCE OF TRUTH for origin identity: what makes two
dependency declarations "the same package," independent of which version is
selected. It fixes the #193/#192 root cause (the solver variable was the
consumer's LABEL, a bare ``str``, conflating three distinct namespaces — see
the RFC §2.1); a future slice (S2, ``BindingResolver``) will feed the solver
``canonical(source_id)`` instead.

**Nothing imports this module yet.** S1 is a pure value-type slice — the
binding/resolver wiring lands in S2+.

**Round-2.5 representation correction — there is NO ``parse()``.** The
authoritative representation is the frozen dataclass itself: its
``frozen=True`` field-wise eq/hash IS the identity (cargo/uv model, not a
flat delimited string parsed back into typed fields — research across
cargo/uv/go confirmed neither unifies a coordinate into a round-trippable
string). On disk (a later slice, S5) each kind serializes STRUCTURED (a KDL
``source { … }`` node with typed children), never as a flat key. ``canonical()``
survives ONLY as a **one-way** injective string — the in-memory solver key and
the human/diagnostic display form. Nothing ever reconstructs a ``SourceId`` by
parsing a flat string, so the ``#subdirectory=``/percent-escaping round-trip
machinery an earlier draft needed only to make a flat string round-trippable is
gone along with ``parse()`` itself.

File organization (RFC §10 S1, G7) — two clearly-marked halves:

  - **Formal half**: the closed union of frozen per-kind dataclasses and the
    one-way ``canonical()``/``format_source_id()`` (B6) functions. This is the
    frozen, normative surface.
  - **Heuristic half**: ``normalize_source()`` — a single kind-dispatched
    function, deliberately incomplete for cross-kind unification (RFC §4.2),
    but now ALSO the sole validation boundary (see below) since ``parse()``'s
    validation boundary no longer exists.

**The injectivity law** (property-tested with Hypothesis,
``test_source_id_properties.py``) is the only law left:

    canonical(a) == canonical(b)  iff  a == b        # one-way; NEVER parsed back

Injectivity holds over well-formed ``SourceId`` values without any escaping,
because each kind's canonical form ends in (or is entirely) a ``/``-free
discriminating segment:

  - ``pkg+<alias>/<namespace>/<name>`` is **variable-arity, name-last**:
    ``<namespace>`` MAY itself contain ``/`` (884/886 real tianguis namespaces
    are host-qualified, e.g. ``codeberg.org/eris``) because ``<alias>`` is
    always the FIRST ``/``-free segment and ``<name>`` is always the LAST
    ``/``-free segment — the middle is unambiguously the namespace. This is
    satisfiable only because ``alias``/``name`` are validated (below) to never
    themselves contain ``/``.
  - ``oci+<registry>/<repository>`` is injective the same way: a real OCI
    registry is ``host[:port]`` only (no internal ``/``, per the OCI
    distribution spec), so the FIRST ``/`` segment is unambiguously the
    registry and the rest (which may itself nest ``/``) is the repository.
  - ``git+``/``tar+``/``oci+``'s optional ``#subdirectory=<subpath>`` suffix is
    injective against a base that itself might contain a literal
    ``#subdirectory=`` substring ONLY because ``normalize_source`` rejects such
    a base as ``SRC-ID-MALFORMED`` (pathological input, not reachable through
    normal construction) — see ``test_source_id_properties.py`` for a test that
    both demonstrates the raw collision (bypassing ``normalize_source``,
    ``canonical()`` alone does no validation) AND proves the guard rejects it.

**Validation boundary moved to ``normalize_source`` (round-2.5 correction).**
The six dataclasses still do NOT self-validate on construction (plain frozen
value containers). Previously ``parse()`` was "the only place UNTRUSTED
strings become a ``SourceId``," so it owned validation. With ``parse()``
gone, ``normalize_source`` is now that boundary: it both normalizes AND
enforces the field invariants below, raising ``MilpaError(SRC_ID_MALFORMED)``
on violation. ``canonical()`` itself remains pure formatting — it does not
validate, so calling it directly on a hand-constructed (never-normalized)
instance can produce a non-injective string for pathological input; the
injectivity law is a contract over ``normalize_source``'s output, not over
arbitrary direct construction.

Well-formedness invariants (enforced by ``normalize_source``):

  - Any ``subpath`` field: ``None`` means "no subpath" — when NOT ``None``,
    it MUST be non-empty, MUST NOT start with ``/`` (absolute), and MUST NOT
    contain a ``..`` segment (mirrors ``fetchers/safe_extract.py``'s
    zip-slip discipline). Use ``None``, never ``""``, for "no subpath."
  - ``GitSourceId.url`` / ``TarballSourceId.url`` / the OCI
    ``f"{registry}/{repository}"`` base: MUST NOT contain a literal
    ``#subdirectory=`` substring (the injectivity guard above).
  - ``OciSourceId.registry``: MUST NOT contain ``/`` (the segment-boundary
    guard above).
  - ``RegistrySourceId.registry`` (the configured alias) and ``.name``: each
    matches the manifest package-name alphabet ``[A-Za-z0-9_-]+``
    (``valid_dep_name``) — never ``/``.
  - ``RegistrySourceId.namespace``, when not ``None``: a ``/``-separated path;
    EACH segment (not the whole string) MUST be non-empty, MUST NOT be ``..``,
    and MUST NOT contain an unsafe character (below). Segments are NOT fenced
    to ``valid_dep_name``'s stricter charset — real tianguis namespaces are
    host-qualified domain names (``codeberg.org``, ``bitbucket.org/<user>``)
    which contain ``.`` characters ``valid_dep_name`` rejects; applying that
    charset per-segment would reject the vast majority of the real registry
    (884/886 entries), the exact mistake an earlier draft made at the
    whole-string level. ``/`` is the segment *separator*, always allowed
    between segments (mirrors ``registry.py``'s own resolved position on this
    question).
  - **Control-char / Unicode-line-separator guard (code-review S2).**
    ``GitSourceId.url`` (post-normalize), ``TarballSourceId.url``,
    ``OciSourceId.registry``/``.repository``, ``LocalSourceId.path``, and
    each ``RegistrySourceId.namespace`` segment MUST NOT contain a character
    ``contains_unsafe_char`` (``manifest.py`` — the single source of truth,
    ASCII C0/C1 controls + U+2028/U+2029) flags. Without this guard a
    crafted, network-fetched ``milpa.kdl`` could smuggle a terminal-escape
    sequence through a free-text origin field into a diagnostic sink (e.g.
    ``milpa show``'s provenance formatter).
  - **Git URL fragment guard (code-review D1).** A raw ``#fragment`` in a
    declared ``GitSourceId.url`` is REJECTED, never silently stripped — it
    collides with milpa's own reserved ``#subdirectory=`` one-way-key
    delimiter. A ``?query`` IS silently stripped (transport/auth noise, not
    identity-bearing) — this closes a Python/Rust divergence where Python's
    ``urlsplit``-based normalizer silently dropped both fragment and query
    while Rust's hand-parser preserved both; both impls now converge on
    "strip query, reject fragment."

Property tests generate only well-formed instances (per the above) so the
injectivity law holds over its actual domain — see
``test_source_id_properties.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from milpa.errors import SRC_ID_MALFORMED, MilpaError
from milpa.manifest import contains_unsafe_char, valid_dep_name

# ---------------------------------------------------------------------------
# Formal half — the value type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitSourceId:
    """A ``git=`` dependency's SOURCE PIN: normalized URL + the pinned ref.

    DE2-ref (RFC §3 amendment): a git commit/branch/non-semver-tag is not a
    version (no version lattice), so ``ref`` is not a version — it is part of
    the *pin*. Two claims for the same ``url`` at different ``ref``s are
    DIFFERENT source-ids, so ``BindingResolver`` arbitrates them by the same
    root-authority rule as a URL disagreement (root/override pin wins; two
    transitive pins with no root arbiter → ``RES-BINDING-CONFLICT``). ``ref``
    is the ref AS DECLARED (compared pre-fetch — the binding stays pure); the
    lockfile records the RESOLVED commit separately as provenance. ``None`` =
    the remote's default branch. Unification stays name-based, so a bare
    ``requires "x"`` still binds to a root pin (and inherits its ``ref``).
    """

    url: str
    ref: str | None = None      # the pinned ref (branch/tag/sha) as declared
    subpath: str | None = None  # normalized posix; None = repo root


@dataclass(frozen=True)
class OciSourceId:
    """An ``oci=`` dependency's SOURCE PIN: registry + repository + digest.

    DE2-ref: ``digest`` is the pin (an OCI artifact is addressed by digest),
    arbitrated exactly like ``GitSourceId.ref``. ``None`` only for a bare
    registry/repository reference with no digest declared.
    """

    registry: str
    repository: str
    digest: str | None = None
    subpath: str | None = None


@dataclass(frozen=True)
class TarballSourceId:
    """A ``tarball=`` dependency's origin. Each distinct URL is a distinct source."""

    url: str
    subpath: str | None = None


@dataclass(frozen=True)
class LocalSourceId:
    """A ``local=`` dependency's origin: a filesystem path.

    Canonicalized by the caller (workspace-relative when under root, else
    absolute) — case-SENSITIVE and case-PRESERVING by definition (RFC §4.1
    D6: on a case-insensitive filesystem, ``Deps/Foo`` and ``deps/foo`` are
    two distinct ``LocalSourceId``s, a known missed-unification limitation
    left to ``overrides {}``, not remedied here).
    """

    path: str


@dataclass(frozen=True)
class RegistrySourceId:
    """A ``named``/registry-coordinate dependency's origin.

    ``registry`` is a CONFIGURED ALIAS slug (``[A-Za-z0-9_-]+``), never a
    base URL (RFC §4.1 "Registry component is an alias, never a base URL" —
    a base URL's own ``/``/``:`` would make the ``pkg+`` segment boundary
    undecidable). ``namespace`` is the REAL resolved index namespace, never
    the manifest qualifier (those can differ; see RFC §4.3), and MAY contain
    ``/`` (host-qualified namespaces).
    """

    registry: str
    namespace: str | None
    name: str


@dataclass(frozen=True)
class MemberSourceId:
    """A workspace member's origin — never fetched, hashed, or attested.

    Deliberately split OUT of ``FetchableOrigin`` (RFC §4.1 G4): a member is
    conflict-free by construction (W1-W5 name uniqueness), so callers that
    type over ``FetchableOrigin`` get "members don't participate in
    fetch/CAS/attestation" enforced by the type checker, not left as prose.
    """

    member_name: str


#: Origins that are fetched, hashed, and materialized under ``_deps/``.
FetchableOrigin = (
    GitSourceId | OciSourceId | TarballSourceId | LocalSourceId | RegistrySourceId
)

#: The full closed union — the solver variable's value type (RFC §3/§4.1).
SourceId = FetchableOrigin | MemberSourceId

#: ``normalize_source``'s input type. A structural alias of ``SourceId``
#: (same six dataclasses, same shapes) — kept distinct in name only, so a
#: call site / docstring can say "this hasn't been normalized/validated yet"
#: even though the underlying type is identical. Normalization never changes
#: a value's KIND, only cleans/validates field values WITHIN a kind (RFC
#: §4.2), so reusing the six dataclasses (rather than inventing a parallel
#: "raw" hierarchy) keeps origin identity in exactly one place — the
#: single-source-of-truth discipline CLAUDE.md requires.
RawOrigin = SourceId


_GIT_PREFIX = "git+"
_OCI_PREFIX = "oci+"
_TAR_PREFIX = "tar+"
_PKG_PREFIX = "pkg+"
_FILE_PREFIX = "file+"
_MEMBER_PREFIX = "member+"

#: The uniform subpath delimiter (RFC §4.1) shared by Git/Tarball/Oci.
_SUBDIR_DELIM = "#subdirectory="

#: DE2-ref pin delimiters — one-way, injective (url/repo/ref/digest carry no
#: '#', enforced by normalize_source), placed BEFORE the subpath suffix.
_REF_DELIM = "#ref="
_DIGEST_DELIM = "#digest="

#: Kind labels for ``format_source_id`` (B6).
_KIND_LABELS: dict[type, str] = {
    GitSourceId: "git dependency",
    OciSourceId: "OCI dependency",
    TarballSourceId: "tarball dependency",
    LocalSourceId: "local dependency",
    RegistrySourceId: "registry package",
    MemberSourceId: "workspace member",
}

def _subdir_suffix(subpath: str | None) -> str:
    if subpath is None:
        return ""
    return _SUBDIR_DELIM + subpath


def _ref_suffix(ref: str | None) -> str:
    if ref is None:
        return ""
    return _REF_DELIM + ref


def _digest_suffix(digest: str | None) -> str:
    if digest is None:
        return ""
    return _DIGEST_DELIM + digest


def canonical(sid: SourceId) -> str:
    """Serialize *sid* to its canonical wire-format string (RFC §4.1).

    ONE-WAY: this is the ``Term.package`` solver-variable value and the
    in-memory/display key — it is NEVER parsed back (the on-disk lockfile
    form is structured, a later slice). Injective over well-formed
    ``SourceId`` values (i.e. values that have passed through
    ``normalize_source``) — see the module docstring and
    ``test_source_id_properties.py``'s injectivity law. ``canonical()``
    itself performs no validation.
    """
    if isinstance(sid, GitSourceId):
        return _GIT_PREFIX + sid.url + _ref_suffix(sid.ref) + _subdir_suffix(sid.subpath)
    if isinstance(sid, TarballSourceId):
        return _TAR_PREFIX + sid.url + _subdir_suffix(sid.subpath)
    if isinstance(sid, OciSourceId):
        base = f"{sid.registry}/{sid.repository}"
        return _OCI_PREFIX + base + _digest_suffix(sid.digest) + _subdir_suffix(sid.subpath)
    if isinstance(sid, LocalSourceId):
        return _FILE_PREFIX + sid.path
    if isinstance(sid, RegistrySourceId):
        if sid.namespace is None:
            return f"{_PKG_PREFIX}{sid.registry}/{sid.name}"
        return f"{_PKG_PREFIX}{sid.registry}/{sid.namespace}/{sid.name}"
    if isinstance(sid, MemberSourceId):
        return _MEMBER_PREFIX + sid.member_name
    raise TypeError(f"unrecognized SourceId variant: {type(sid)!r}")  # pragma: no cover


def format_source_id(sid: SourceId) -> str:
    """The single diagnostic formatter for a ``SourceId`` (RFC §10 S1, B6).

    Every later slug that needs to name a source-id in a human message —
    ``RES-BINDING-CONFLICT`` (S2), ``RES-IMPORT-COLLISION`` (S6 directory-slot
    floor + S7 symbol-level check), ``FROZEN-SOURCE-ID-MISMATCH`` (S5) —
    reuses this, defined once here so those slices don't each invent ad-hoc
    formatting a later pretty-printer has to unify.
    """
    label = _KIND_LABELS[type(sid)]
    return f"{label} {canonical(sid)!r}"


# ---------------------------------------------------------------------------
# Heuristic half — normalize_source (also the sole validation boundary)
# ---------------------------------------------------------------------------

#: Default port per git URL scheme (RFC §4.2 "Added by this RFC"): stripping
#: these closes a real missed-unification (``ssh://user@host:22/org/repo``
#: and ``ssh://host/org/repo`` are the same repo).
_GIT_DEFAULT_PORTS: dict[str, int] = {"https": 443, "http": 80, "ssh": 22, "git": 9418}


def _validate_subpath(subpath: str, *, context: str) -> None:
    """Subpath escape guard (RFC §4.1 normative) — mirrors
    ``fetchers/safe_extract.py``'s zip-slip discipline: reject an empty,
    absolute, or ``..``-traversing subpath."""
    if subpath == "":
        raise MilpaError(
            SRC_ID_MALFORMED,
            f"{context} has an empty subdirectory subpath "
            f"(use `subpath=None` to mean the repo root)",
            value=subpath,
        )
    if subpath.startswith("/"):
        raise MilpaError(
            SRC_ID_MALFORMED,
            f"{context} has an absolute subpath {subpath!r} "
            f"(subpath must be relative)",
            value=subpath,
        )
    if any(seg == ".." for seg in subpath.split("/")):
        raise MilpaError(
            SRC_ID_MALFORMED,
            f"{context} has a path-traversal subpath {subpath!r} "
            f"(a `..` segment is not allowed)",
            value=subpath,
        )


def _validate_no_delim_collision(base: str, *, context: str) -> None:
    """Injectivity guard (RFC §4.1 "Subpath in the one-way key"): a base URL
    (or OCI ``registry/repository``) that itself contains a literal
    ``#subdirectory=`` substring would let ``canonical()`` collide between
    ``SourceId(url=f"{b}#subdirectory={s}", subpath=None)`` and
    ``SourceId(url=b, subpath=s)`` — two DIFFERENT structs, one string. Such
    a base is pathological; reject it here rather than escape it."""
    if _SUBDIR_DELIM in base:
        raise MilpaError(
            SRC_ID_MALFORMED,
            f"{context} contains a literal {_SUBDIR_DELIM!r} fragment, which "
            f"would collide with the subpath delimiter in the canonical "
            f"source-id key",
            value=base,
        )


def _validate_no_unsafe_char(value: str, *, context: str) -> None:
    """Reject ASCII control characters (0x00-0x1F, 0x7F) and Unicode line
    separators (U+2028/U+2029) in a free-text origin field (code-review S2 —
    control-char injection). Reuses ``contains_unsafe_char`` (``manifest.py``,
    the single source of truth for this predicate — mirrors ``registry.py``'s
    ``TNG-UNSAFE-CONTROL-CHAR`` precedent) rather than a fourth duplicate
    regex. Without this guard a crafted fetched ``milpa.kdl`` could smuggle a
    terminal-escape sequence through an origin field into a diagnostic sink
    (e.g. ``milpa show``'s ``_format_provenance``)."""
    if contains_unsafe_char(value):
        raise MilpaError(
            SRC_ID_MALFORMED,
            f"{context} contains a control character or Unicode line "
            f"separator (U+2028/U+2029), which is not allowed in a source "
            f"origin field",
            value=value,
        )


def _validate_registry_component(value: str, *, label: str) -> None:
    """``alias``/``name`` fence (RFC §4.1): both MUST be ``/``-free and match
    the manifest package-name alphabet — the injectivity anchors that make
    the ``pkg+`` variable-arity form's boundaries unambiguous."""
    if not valid_dep_name(value):
        raise MilpaError(
            SRC_ID_MALFORMED,
            f"registry {label} {value!r} must match the package-name "
            f"alphabet [A-Za-z0-9_-]+",
            value=value,
        )


def _validate_namespace(namespace: str) -> None:
    """Per-``/``-segment namespace validation (RFC §4.1 round-2.5
    correction; broadened by code-review S2 to the full ``contains_unsafe_char``
    charset — ASCII controls AND Unicode line separators U+2028/U+2029, not
    ASCII controls alone). Each segment must be non-empty, not ``..``, and
    free of unsafe characters. NOT fenced to ``valid_dep_name``'s charset —
    real namespaces are host-qualified (``codeberg.org``) and contain ``.``.
    ``/`` is the segment separator, always allowed between segments."""
    for seg in namespace.split("/"):
        if seg == "":
            raise MilpaError(
                SRC_ID_MALFORMED,
                f"registry namespace {namespace!r} has an empty '/'-segment",
                value=namespace,
            )
        if seg == "..":
            raise MilpaError(
                SRC_ID_MALFORMED,
                f"registry namespace {namespace!r} has a path-traversal "
                f"segment {seg!r}",
                value=namespace,
            )
        _validate_no_unsafe_char(seg, context=f"registry namespace {namespace!r} segment {seg!r}")


def _normalize_git_url(url: str) -> str:
    """The git-source equality definition (RFC §4.2), in three explicit tiers:

    - **Kept** (promoted from ``resolver.py``'s ``_normalize_git_source_url``):
      lowercase scheme+host, strip a trailing ``/`` and a trailing ``.git``
      suffix; path case is PRESERVED (many git hosts are path-case-sensitive).
    - **Added by this RFC**: strip userinfo/credentials (``.hostname`` never
      includes them) and strip the scheme's DEFAULT port only (``.port`` is
      ``None`` when the URL used the default, or the URL had no port at all).
    - **NOT attempted**: ssh<->https unification, SCP-style desugaring — both
      undecidable/unreachable (RFC §4.2); ``overrides {}`` is the escape hatch.

    Total: never raises. A URL with no recognizable ``scheme://authority``
    (or a scheme with a malformed port) falls back to a lowercased whole
    string, exactly like the function this promotes.
    """
    s = url.strip()
    if s.endswith("/"):
        s = s[:-1]
    if s.endswith(".git"):
        s = s[:-4]
    parts = urlsplit(s)
    if not parts.netloc:
        return s.lower()
    scheme = parts.scheme.lower()
    try:
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        # Malformed port etc. — still total: fall back to lowercasing the
        # whole netloc (no userinfo/port stripping attempted).
        return urlunsplit((scheme, parts.netloc.lower(), parts.path, "", ""))
    default_port = _GIT_DEFAULT_PORTS.get(scheme)
    netloc = host if port is None or port == default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path, "", ""))


def normalize_source(raw: RawOrigin) -> SourceId:
    """Normalize *raw* to its equality-defining ``SourceId`` form (RFC §4.2)
    — and, since ``parse()`` no longer exists to own it, the sole VALIDATION
    boundary (module docstring): raises ``MilpaError(SRC_ID_MALFORMED)`` on
    any well-formedness violation.

    Kind-dispatched; only the git case has non-trivial NORMALIZATION (see
    ``_normalize_git_url``) — two genuinely different remotes serving
    identical bytes are NOT unified here (undecidable; that is
    ``content_hash``'s job, post-fetch — RFC §3.3), and ``LocalSourceId``
    path canonicalization (workspace-relative-vs-absolute) needs workspace
    context this pure function does not have, so it is the caller's job to
    hand in an already-canonicalized ``path``.
    """
    if isinstance(raw, GitSourceId):
        # D1 (code-review): a raw '#' fragment in the DECLARED url is
        # rejected outright, never silently stripped. `#subdirectory=` is
        # milpa's OWN reserved one-way-key subpath delimiter (RFC §4.1); a
        # user-supplied fragment collides with it, so it is an error, not
        # noise to discard — checked here (on the untrusted input) rather
        # than inside `_normalize_git_url`, which stays a total, never-raise
        # string transform. This also closes the Python/Rust divergence: Rust
        # hand-parses and PRESERVES a fragment/query, Python's urlsplit-based
        # normalizer silently DROPS them — both now converge on "reject a
        # fragment, silently strip a query" (query is transport/auth noise,
        # not identity-bearing).
        if "#" in raw.url:
            raise MilpaError(
                SRC_ID_MALFORMED,
                f"git source url {raw.url!r} contains a '#' fragment, which "
                f"collides with milpa's reserved subpath delimiter "
                f"({_SUBDIR_DELIM!r}) — use the manifest `subpath=` property "
                f"instead of a URL fragment",
                value=raw.url,
            )
        url = _normalize_git_url(raw.url)
        _validate_no_unsafe_char(url, context=f"git+ source url {url!r}")
        # Vestigial for Git specifically (a normalized url can never contain
        # '#' given the reject-above), kept for structural symmetry with the
        # Tarball/Oci branches below, which still rely on this guard.
        _validate_no_delim_collision(url, context=f"git+ source url {url!r}")
        if raw.subpath is not None:
            _validate_subpath(raw.subpath, context="git dependency")
        # DE2-ref: the pinned ref joins the source-id. Reject '#' (guarantees
        # canonical() injectivity against the #ref=/#subdirectory= delimiters)
        # and any terminal-unsafe char (same sink as the url).
        if raw.ref is not None:
            if "#" in raw.ref:
                raise MilpaError(
                    SRC_ID_MALFORMED,
                    f"git ref {raw.ref!r} contains a '#', which collides with "
                    f"milpa's reserved source-id delimiters",
                    value=raw.ref,
                )
            _validate_no_unsafe_char(raw.ref, context=f"git ref {raw.ref!r}")
        return GitSourceId(url=url, ref=raw.ref, subpath=raw.subpath)
    if isinstance(raw, OciSourceId):
        if "/" in raw.registry:
            raise MilpaError(
                SRC_ID_MALFORMED,
                f"OCI registry {raw.registry!r} must not contain '/' (per the "
                f"OCI distribution spec a registry is host[:port] only)",
                value=raw.registry,
            )
        _validate_no_unsafe_char(raw.registry, context=f"OCI registry {raw.registry!r}")
        _validate_no_unsafe_char(raw.repository, context=f"OCI repository {raw.repository!r}")
        base = f"{raw.registry}/{raw.repository}"
        _validate_no_delim_collision(base, context=f"oci+ source {base!r}")
        if raw.subpath is not None:
            _validate_subpath(raw.subpath, context="OCI dependency")
        # DE2-ref: the pinned digest joins the source-id (reject '#' for
        # canonical() injectivity; digest format itself is validated at the
        # fetch boundary — TNG-BAD-OCI-DIGEST).
        if raw.digest is not None and "#" in raw.digest:
            raise MilpaError(
                SRC_ID_MALFORMED,
                f"OCI digest {raw.digest!r} contains a '#', which collides with "
                f"milpa's reserved source-id delimiters",
                value=raw.digest,
            )
        return OciSourceId(
            registry=raw.registry, repository=raw.repository,
            digest=raw.digest, subpath=raw.subpath,
        )
    if isinstance(raw, TarballSourceId):
        _validate_no_unsafe_char(raw.url, context=f"tar+ source url {raw.url!r}")
        _validate_no_delim_collision(raw.url, context=f"tar+ source url {raw.url!r}")
        if raw.subpath is not None:
            _validate_subpath(raw.subpath, context="tarball dependency")
        return TarballSourceId(url=raw.url, subpath=raw.subpath)
    if isinstance(raw, LocalSourceId):
        _validate_no_unsafe_char(raw.path, context=f"local source path {raw.path!r}")
        return LocalSourceId(path=raw.path)
    if isinstance(raw, RegistrySourceId):
        _validate_registry_component(raw.registry, label="alias")
        if raw.namespace is not None:
            _validate_namespace(raw.namespace)
        _validate_registry_component(raw.name, label="name")
        return RegistrySourceId(registry=raw.registry, namespace=raw.namespace, name=raw.name)
    if isinstance(raw, MemberSourceId):
        return MemberSourceId(member_name=raw.member_name)
    raise TypeError(f"unrecognized RawOrigin variant: {type(raw)!r}")  # pragma: no cover
