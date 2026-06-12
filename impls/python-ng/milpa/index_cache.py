"""tianguis index acquisition — four-state freshness cache (S8b).

Mirrors ``impls/rust/crates/milpa-core/src/index_cache.rs``.

The HTTP transport and clock are injected (``HttpGet`` / ``now_unix``) so all
four cache states are unit-testable without a network or a real wall-clock.
Production callers pass ``urllib_http_get`` and ``time.time`` (cast to ``int``).

Four states (registry-protocol §6 NORMATIVE):
  1. **Fresh cache** (age < TTL) → serve cached bytes, no network.
  2. **Stale cache** (age ≥ TTL) → re-fetch, overwrite, serve fresh bytes.
  3. **Network failure with stale-but-present cache** → serve the stale cache
     as an offline fallback; emit a warning to stderr that MUST NOT contain
     a ``milpa-error:`` line (R3 requirement).
  4. **Network failure with no cache** → raise ``MILPA-INDEX-UNREACHABLE``.

``MILPA_INDEX_URL``, when set to a non-empty string, overrides the default
index URL for every index-fetching operation in that invocation.  Supports
the ``file://`` scheme so air-gapped / harness deployments can substitute a
private or local index (``cli-contract.md`` §8.1 NORMATIVE).

Cache writes are atomic: write to a sibling ``.tmp`` file, then
``os.replace()`` (POSIX ``rename(2)``).  Concurrent readers never observe a
partial write.

The cache lives outside the project directory (under ``$XDG_CACHE_HOME/milpa/
index/`` by default).  ``milpa clean`` MUST NOT remove the index cache — it is
the registry, not project state (registry-protocol §6 NORMATIVE).

Spec authority: ``spec/registry-protocol.md`` §6; ``spec/cli-contract.md`` §8.
"""

from __future__ import annotations

import hashlib
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from milpa.errors import MILPA_INDEX_UNREACHABLE, MilpaError

if TYPE_CHECKING:
    from milpa.registry import Index

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The live tianguis index URL (the federation seam — one URL for now).
#: Conformant implementations MUST use this URL when no override is configured
#: (registry-protocol §1 NORMATIVE).
DEFAULT_INDEX_URL: str = (
    "https://raw.githubusercontent.com/coreyleavitt/tianguis/main/index.kdl"
)

#: Default TTL — 24h: generous enough to avoid hammering tianguis on every
#: invocation, short enough that the vendor-en-absentia daily pass is visible.
DEFAULT_TTL_SECONDS: int = 24 * 60 * 60

# ---------------------------------------------------------------------------
# HttpGet type
# ---------------------------------------------------------------------------

#: A fetch transport: maps a URL string to body text, or raises a ``str`` on
#: failure.  Injected so tests drive cache states without a network.
#:
#: Signature: ``(url: str) -> str``
#: On error: raise ``Exception`` (any subclass); the message is used for
#: the ``MILPA-INDEX-UNREACHABLE`` error message.
HttpGet = Callable[[str], str]

# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def index_url_from_env() -> str:
    """Return ``MILPA_INDEX_URL`` if set to a non-empty string, else ``DEFAULT_INDEX_URL``.

    Registry-protocol §1 NORMATIVE; cli-contract.md §8.1 NORMATIVE.
    Supports the ``file://`` scheme for air-gapped / harness deployments.
    """
    override = os.environ.get("MILPA_INDEX_URL", "").strip()
    return override if override else DEFAULT_INDEX_URL


def _default_cache_dir() -> Path:
    """Return the platform-appropriate index cache directory.

    ``$XDG_CACHE_HOME/milpa/index/`` (default ``~/.cache/milpa/index/``).
    """
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "milpa" / "index"


# ---------------------------------------------------------------------------
# Cache path + stamp helpers
# ---------------------------------------------------------------------------


def cache_path_for(url: str, cache_dir: Path) -> Path:
    """Return the stable per-URL cache file path for *url* under *cache_dir*.

    Cache key: first 16 hex characters of ``sha256(url.encode("utf-8"))``
    (registry-protocol §6 NORMATIVE: deterministic so two concurrent
    invocations share the same entry and ``MILPA_INDEX_URL`` substitution
    caches the substitute correctly).
    """
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return cache_dir / f"{digest[:16]}.index.kdl"


def _stamp_path(cache_file: Path) -> Path:
    """Sidecar fetch-time stamp: ``<cache_file>.at``."""
    return cache_file.with_suffix(".kdl.at")


def _read_stamp(stamp_file: Path) -> int | None:
    """Read a sidecar stamp file and return its unix-second value, or ``None``."""
    try:
        raw = stamp_file.read_text().strip()
        return int(raw)
    except (OSError, ValueError):
        return None


def _write_stamp(stamp_file: Path, now_unix: int) -> None:
    """Write the fetch time (unix seconds) to the sidecar stamp file."""
    import contextlib

    with contextlib.suppress(OSError):
        stamp_file.write_text(str(now_unix))  # non-fatal: worst case the next invocation re-fetches


# ---------------------------------------------------------------------------
# load_index — main entry point
# ---------------------------------------------------------------------------


def load_index(
    url: str,
    cache_dir: Path,
    http_get: HttpGet,
    ttl_seconds: int,
    now_unix: int,
) -> Index:
    """Fetch + cache + parse the ``index.kdl`` at *url*.

    Arguments:
        url:         Index URL to fetch.  Supports ``http://``, ``https://``,
                     and ``file://`` schemes.
        cache_dir:   Directory where the cached ``*.index.kdl`` and sidecar
                     ``*.index.kdl.at`` files are stored.
        http_get:    Injected transport.  Receives the URL, returns the body
                     text.  On failure raises any ``Exception``; the message
                     is used in the ``MILPA-INDEX-UNREACHABLE`` error.
        ttl_seconds: Cache TTL in seconds.  Pass ``DEFAULT_TTL_SECONDS`` for
                     the normative 24h value.
        now_unix:    Current time (unix seconds).  Injected for test
                     determinism; production callers pass ``int(time.time())``.

    Returns:
        Parsed ``Index``.

    Raises:
        ``MilpaError(MILPA_INDEX_UNREACHABLE)`` — network failure with no
        usable cache (state 4).
        Any ``MilpaError(TNG-*)`` raised by ``parse_index`` — these propagate
        unchanged.
    """
    from milpa.registry import parse_index  # local import to avoid circular at module level

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file = cache_path_for(url, cache_dir)
    stamp_file = _stamp_path(cache_file)

    # -------------------------------------------------------------------------
    # State 1: Fresh cache (age < TTL) → serve without network.
    # The fetch time is recorded in a sidecar ``.at`` file (not the fs mtime)
    # so age is controlled by the injected ``now_unix`` clock — deterministic.
    # -------------------------------------------------------------------------
    fetched_at = _read_stamp(stamp_file)
    if fetched_at is not None:
        age = now_unix - fetched_at
        if age < ttl_seconds:
            text = cache_file.read_text()
            return parse_index(text)

    # -------------------------------------------------------------------------
    # State 2 / 3 / 4: Stale or missing → attempt to fetch.
    # -------------------------------------------------------------------------
    fetch_error: str | None = None
    fetched_text: str | None = None

    try:
        fetched_text = http_get(url)
    except Exception as exc:
        fetch_error = str(exc)

    if fetch_error is not None:
        # Network failed.
        if cache_file.is_file():
            # State 3: offline fallback — serve stale cache.
            # Warning MUST NOT contain a ``milpa-error:`` line (R3).
            print(
                f"[milpa] warning: failed to refresh index from {url!r} "
                f"({fetch_error}) — using cached (possibly out-of-date) index",
                file=sys.stderr,
            )
            text = cache_file.read_text()
            return parse_index(text)

        # State 4: no usable cache — hard failure.
        raise MilpaError(
            MILPA_INDEX_UNREACHABLE,
            f"failed to load index from {url!r}: {fetch_error}",
            url=url,
        )

    assert fetched_text is not None  # type narrowing: fetch_error is None implies success

    # -------------------------------------------------------------------------
    # Atomic write: temp sibling + os.replace(), so a concurrent reader never
    # sees a half-written file (registry-protocol §6 NORMATIVE).
    # -------------------------------------------------------------------------
    tmp_file = cache_file.with_suffix(f".kdl.tmp.{now_unix}")
    import contextlib

    try:
        tmp_file.write_text(fetched_text)
        os.replace(tmp_file, cache_file)
    except OSError:
        with contextlib.suppress(OSError):
            tmp_file.unlink(missing_ok=True)
        raise

    # Record fetch time to the sidecar (governs freshness, not fs mtime).
    _write_stamp(stamp_file, now_unix)

    return parse_index(fetched_text)


# ---------------------------------------------------------------------------
# Default production HTTP transport (handles file:// too)
# ---------------------------------------------------------------------------


def urllib_http_get(url: str) -> str:
    """Production ``HttpGet`` transport using ``urllib``.

    Supports ``http://``, ``https://``, and ``file://`` schemes.
    On any error raises an exception whose ``str()`` is used in the
    ``MILPA-INDEX-UNREACHABLE`` message.
    """
    with urllib.request.urlopen(url) as resp:  # noqa: S310 — URL is user-controlled; known risk
        raw: bytes = resp.read()
        encoding: str = resp.headers.get_content_charset("utf-8") or "utf-8"
        return raw.decode(encoding)


# ---------------------------------------------------------------------------
# High-level convenience: load_default_index
# ---------------------------------------------------------------------------


def load_default_index(
    *,
    cache_dir: Path | None = None,
    http_get: HttpGet | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now_unix: int | None = None,
) -> Index:
    """Load the index from ``MILPA_INDEX_URL`` (or the default URL).

    Convenience wrapper over ``load_index`` for production callers:

    - ``cache_dir``:   defaults to the XDG cache dir.
    - ``http_get``:    defaults to ``urllib_http_get``.
    - ``ttl_seconds``: defaults to ``DEFAULT_TTL_SECONDS``.
    - ``now_unix``:    defaults to the real wall clock (``int(time.time())``).
    """
    import time

    return load_index(
        url=index_url_from_env(),
        cache_dir=cache_dir if cache_dir is not None else _default_cache_dir(),
        http_get=http_get if http_get is not None else urllib_http_get,
        ttl_seconds=ttl_seconds,
        now_unix=now_unix if now_unix is not None else int(time.time()),
    )
