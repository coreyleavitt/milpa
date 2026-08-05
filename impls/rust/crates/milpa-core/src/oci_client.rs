//! `OciRegistryClient` — the native OCI Distribution v2 pull client (slice S7,
//! Rust mirror of the Python S5 client at `impls/python/milpa/fetchers/oci_client.py`).
//!
//! RFC: `docs/rfc-native-oci-fetch.md` §3.2 (client design), §3.6 (token
//! cache), §3.7/§4 (canned-transport fixture + unit test matrix).
//!
//! Two deep modules plus a pure policy function, exactly as the RFC specifies:
//!
//!   - [`OciRegistryClient`] — registry-/artifact-agnostic: token acquisition
//!     (RFC-7235 Bearer challenge), manifest fetch + digest verification +
//!     manifest-list rejection, blob fetch + streaming cap + digest
//!     verification. Generic OCI hygiene lives HERE.
//!   - [`select_source_layer`] — milpa's own artifact-shape policy, a PURE
//!     function over a parsed [`Manifest`]. The ONE place the "exactly one
//!     milpa source-tarball layer" predicate lives.
//!   - [`tokenize_www_authenticate`] / [`select_bearer_challenge`] — the
//!     RFC-7235 challenge tokenizer, a pure function tested exhaustively on
//!     its own.
//!   - [`TokenCache`] — per-`(registry, scope)` striped-lock cache with
//!     expiry and explicit invalidation (RFC §3.6).
//!
//! `fetchers.rs::fetch_oci` composes this client directly (slice S8 — the
//! `oras` shell-out is deleted; there is no compatibility fallback).
//!
//! # `phase` convention (M5 — structured, not stringly)
//!
//! Every `FETCH-OCI-PULL-FAILED` / `FETCH-OCI-DIGEST-MISMATCH` raised here
//! carries its phase (`"token"` / `"manifest"` / `"blob"`) as the **named
//! `phase` field** on [`FetchError::OciTransport`] — never baked into the
//! message string. A caller (or a test) asserts via the structured
//! `err.phase() == Some("manifest")` accessor, mirroring Python's
//! `MilpaError.context["phase"]` (RFC docs/rfc-native-oci-fetch.md §3.4:
//! "the codebase asserts on structured fields, not substrings").
//! `select_source_layer`'s `FETCH-OCI-NO-TARBALL` / `FETCH-OCI-AMBIGUOUS-
//! TARBALL` are NOT phase-scoped (they are an artifact-shape policy check,
//! not a token/manifest/blob transport step) and stay plain
//! `FetchError::Transport`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::bounded_http::{HttpResponse, Sink};
use crate::fetch::FetchError;
use crate::fetchers::{sha256_of_file, MAX_COMPRESSED_BYTES};

// ---------------------------------------------------------------------------
// Constants — the fixed milpa OCI artifact shape (RFC §1, §3.2 step 3)
// ---------------------------------------------------------------------------

/// Small fixed cap for token + manifest responses (RFC §3.2 step 1/2) — these
/// are always small JSON documents; never an unbounded stream.
pub const TOKEN_OR_MANIFEST_CAP: u64 = 1 << 20; // 1 MiB

/// The one artifactType milpa publishes (defense-in-depth check in
/// [`select_source_layer`] — milpa fully owns this format).
pub const SOURCE_ARTIFACT_TYPE: &str = "application/vnd.milpa.source.v1";

/// The one config mediaType milpa publishes — an empty descriptor.
pub const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// The one layer mediaType that carries the actual source tarball.
pub const SOURCE_LAYER_MEDIA_TYPE: &str = "application/vnd.milpa.source.v1.tar+gzip";

/// `Accept` header sent on the manifest GET — the OCI + docker manifest set
/// (RFC §3.2 step 2).
pub const MANIFEST_ACCEPT: &str =
    "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

/// A non-phase-scoped OCI transport failure (`select_source_layer`'s
/// `FETCH-OCI-NO-TARBALL` / `FETCH-OCI-AMBIGUOUS-TARBALL` — an artifact-shape
/// policy check, not a token/manifest/blob transport step).
fn transport_err(code: &'static str, msg: impl Into<String>) -> FetchError {
    FetchError::Transport(code, msg.into())
}

/// A phase-scoped OCI transport failure (M5): `phase` is a structured field
/// on [`FetchError::OciTransport`], never baked into `message` — see the
/// module doc comment's "`phase` convention" section.
fn oci_transport_err(code: &'static str, phase: &'static str, msg: impl Into<String>) -> FetchError {
    FetchError::OciTransport {
        code,
        phase,
        message: msg.into(),
    }
}

/// A short description of a `serde_json::Value`'s shape, for an
/// H1 "manifest body was not a JSON object" error message (never a field
/// dump — the whole point is the body ISN'T shaped as expected).
fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Wrap a raw transport-layer failure (`FETCH-DOWNLOAD-FAILED` from
/// `bounded_http::request` — DNS/reset/timeout) with this call's `phase`
/// context (M1 finding), as the structured field (M5). Only the raw
/// connectivity code is rewrapped — `FETCH-DOWNLOAD-SIZE-EXCEEDED` (and any
/// other transport-layer code) passes through unchanged, matching the Python
/// twin's narrow `except MilpaError` scope (`_transport_request`).
fn wrap_transport_phase(phase: &'static str, err: FetchError) -> FetchError {
    if err.code() != "FETCH-DOWNLOAD-FAILED" {
        return err;
    }
    oci_transport_err(
        "FETCH-OCI-PULL-FAILED",
        phase,
        format!("transport request failed: {}", err.message()),
    )
}

// ---------------------------------------------------------------------------
// Transport seam — OciTransport, structurally bounded_http::request's shape
// ---------------------------------------------------------------------------

/// The minimal transport [`OciRegistryClient`] depends on: a per-call
/// `(method, url, headers, cap, sink) -> HttpResponse` request, identical in
/// signature to [`bounded_http::request`] — including that redirects are
/// followed and `Authorization` is stripped on a cross-origin hop internally,
/// so a call through this alias never returns a `3xx` status to its caller.
///
/// M6: a bare closure alias, NOT a reified `trait OciTransport` + a
/// do-nothing forwarding struct — mirrors this crate's own `HttpGet`
/// (`fetchers.rs`) precedent and Python's zero-adapter `Protocol` alias for
/// the same seam (`oci_client.py`). Production code passes
/// `Box::new(bounded_http::request)` directly at the `fetch_oci` call site
/// (`fetchers.rs`) — a bare fn item coerces straight into this alias, no
/// adapter type needed. Tests inject a fixture-replaying closure with the
/// same signature (see `oci_client_tests.rs`).
pub type OciTransport =
    Box<dyn Fn(&str, &str, &[(&str, &str)], u64, Sink<'_>) -> Result<HttpResponse, FetchError> + Send + Sync>;

// ---------------------------------------------------------------------------
// Parsed manifest shape
// ---------------------------------------------------------------------------

/// One layer descriptor from a parsed OCI manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub media_type: String,
    pub digest: String,
    pub size: i64,
}

/// A parsed, generically-validated OCI manifest (single-manifest shape).
///
/// [`OciRegistryClient::manifest`] never returns this for a manifest
/// **list**/index — that shape is rejected before construction (RFC §3.2
/// step 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub media_type: String,
    pub artifact_type: Option<String>,
    pub config_media_type: Option<String>,
    pub layers: Vec<Layer>,
}

// ---------------------------------------------------------------------------
// WWW-Authenticate tokenizer (RFC §3.2 step 1) — pure, fail-closed
// ---------------------------------------------------------------------------

/// One parsed challenge from an RFC-7235 `WWW-Authenticate` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub scheme: String,
    pub params: HashMap<String, String>,
}

/// Split `header` on commas that are NOT inside a quoted string.
///
/// Handles `\"`-escapes inside quotes so a comma embedded in a quoted param
/// value (or an escaped quote) never splits a challenge/param in two.
fn split_top_level_commas(header: &str) -> Vec<String> {
    let chars: Vec<char> = header.chars().collect();
    let n = chars.len();
    let mut segments = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let mut i = 0;
    while i < n {
        let ch = chars[i];
        if in_quotes {
            if ch == '\\' && i + 1 < n {
                buf.push(ch);
                buf.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if ch == '"' {
                in_quotes = false;
            }
            buf.push(ch);
            i += 1;
            continue;
        }
        if ch == '"' {
            in_quotes = true;
            buf.push(ch);
            i += 1;
            continue;
        }
        if ch == ',' {
            segments.push(std::mem::take(&mut buf));
            i += 1;
            continue;
        }
        buf.push(ch);
        i += 1;
    }
    segments.push(buf);
    segments
}

/// Match a bare scheme token at the start of `seg`, optionally followed by
/// whitespace + more text (mirrors `_SCHEME_START_RE` in the Python twin).
/// Returns `(token, rest)`: `rest` is `None` when the token is the whole
/// segment, `Some(text)` for whatever follows the mandatory whitespace.
/// Returns `None` when `seg` does not start with an identifier token, OR
/// there is leftover text with no whitespace separating it from the token
/// (e.g. a bare `key=value` continuation param, which must NOT be mistaken
/// for a new challenge).
fn scheme_start(seg: &str) -> Option<(String, Option<String>)> {
    let bytes = seg.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' {
            i += 1;
        } else {
            break;
        }
    }
    let token = seg[..i].to_string();
    let remainder = &seg[i..];
    if remainder.is_empty() {
        return Some((token, None));
    }
    let trimmed = remainder.trim_start();
    let ws_len = remainder.len() - trimmed.len();
    if ws_len == 0 {
        // Leftover text with no separating whitespace — not a valid new-scheme
        // match (mirrors the anchored regex failing to match at all).
        return None;
    }
    Some((token, Some(trimmed.to_string())))
}

/// Parse one `key=value` param, value either a quoted string (with possible
/// `\"`/`\\` escapes) or an unquoted token with no whitespace/comma.
fn parse_param(text: &str) -> Option<(String, String)> {
    let text = text.trim();
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-' {
            i += 1;
        } else {
            break;
        }
    }
    let key = text[..i].to_string();
    let rest = text[i..].trim_start();
    let rest = rest.strip_prefix('=')?;
    let rest = rest.trim_start();
    if let Some(inner) = rest.strip_prefix('"') {
        let ichars: Vec<char> = inner.chars().collect();
        let mut value = String::new();
        let mut idx = 0;
        let mut closed = false;
        while idx < ichars.len() {
            let c = ichars[idx];
            if c == '\\' && idx + 1 < ichars.len() {
                value.push(ichars[idx + 1]);
                idx += 2;
                continue;
            }
            if c == '"' {
                closed = true;
                break;
            }
            value.push(c);
            idx += 1;
        }
        if !closed || idx + 1 != ichars.len() {
            return None;
        }
        Some((key, value))
    } else {
        if rest.is_empty() || rest.chars().any(|c| c.is_whitespace() || c == ',') {
            return None;
        }
        Some((key, rest.to_string()))
    }
}

/// Parse an RFC-7235 `WWW-Authenticate` header into ordered challenges.
///
/// Handles multiple challenges in one header (`Basic realm="x", Bearer
/// realm="y",service="z"`), unordered/quoted params, `\"`-escapes, and
/// commas embedded inside quoted values. A segment is a NEW challenge iff it
/// starts with a bare scheme token (no `=` immediately after it); anything
/// else is a continuation param of the current challenge. A malformed
/// leading param with no preceding scheme is dropped — the caller
/// ([`select_bearer_challenge`]) fails closed downstream rather than this
/// function guessing.
pub fn tokenize_www_authenticate(header: &str) -> Vec<AuthChallenge> {
    let segments = split_top_level_commas(header);
    let mut challenges = Vec::new();
    let mut current_scheme: Option<String> = None;
    let mut current_params: HashMap<String, String> = HashMap::new();

    for raw_seg in segments {
        let seg = raw_seg.trim();
        if seg.is_empty() {
            continue;
        }
        let parsed = scheme_start(seg);
        let starts_new_scheme = match &parsed {
            Some((_, rest)) => rest.is_none() || rest.as_deref().unwrap().contains('='),
            None => false,
        };
        if starts_new_scheme {
            if let Some(scheme) = current_scheme.take() {
                challenges.push(AuthChallenge {
                    scheme,
                    params: std::mem::take(&mut current_params),
                });
            }
            let (token, rest) = parsed.expect("starts_new_scheme implies parsed.is_some()");
            current_scheme = Some(token);
            if let Some(r) = rest {
                if !r.is_empty() {
                    if let Some((k, v)) = parse_param(&r) {
                        current_params.insert(k, v);
                    }
                }
            }
            continue;
        }
        if current_scheme.is_none() {
            // A param with no preceding scheme token — malformed header.
            // Dropped; downstream "no Bearer challenge" / "missing realm"
            // checks fail closed rather than this function guessing intent.
            continue;
        }
        if let Some((k, v)) = parse_param(seg) {
            current_params.insert(k, v);
        }
    }
    if let Some(scheme) = current_scheme.take() {
        challenges.push(AuthChallenge {
            scheme,
            params: current_params,
        });
    }
    challenges
}

/// Return the `Bearer` challenge, or fail closed with a distinguishable error.
///
/// Never runs Bearer logic against a `Basic` (or other non-Bearer)
/// challenge's params — a self-hosted `Basic`-only registry is out of scope
/// for v1 (RFC §2) and must fail cleanly, not silently misbehave.
pub fn select_bearer_challenge(challenges: &[AuthChallenge]) -> Result<AuthChallenge, FetchError> {
    for challenge in challenges {
        if challenge.scheme.eq_ignore_ascii_case("bearer") {
            return Ok(challenge.clone());
        }
    }
    let schemes: Vec<&str> = challenges.iter().map(|c| c.scheme.as_str()).collect();
    Err(oci_transport_err(
        "FETCH-OCI-PULL-FAILED",
        "token",
        format!(
            "registry advertised no Bearer challenge in WWW-Authenticate \
             (unsupported auth scheme; got {schemes:?})"
        ),
    ))
}

// ---------------------------------------------------------------------------
// select_source_layer — milpa's artifact policy, the ONE tarball gate
// ---------------------------------------------------------------------------

/// Select the single milpa source-tarball layer from a parsed [`Manifest`].
///
/// Requires (RFC §3.2 step 3):
///   - single-manifest shape (already enforced by
///     [`OciRegistryClient::manifest`] rejecting a manifest list before this
///     is ever called);
///   - `artifactType` is either absent or exactly [`SOURCE_ARTIFACT_TYPE`]
///     (defense-in-depth on a format milpa fully owns);
///   - the config descriptor's mediaType is either absent or exactly the
///     empty-config media type (same rationale);
///   - exactly one layer of [`SOURCE_LAYER_MEDIA_TYPE`].
///
/// An artifactType/config mismatch is treated as "no [valid milpa] tarball
/// present" rather than a separate error code — there is no dedicated slug
/// for a shape mismatch, and semantically it IS the no-tarball case.
pub fn select_source_layer(manifest: &Manifest) -> Result<Layer, FetchError> {
    let artifact_type_ok =
        manifest.artifact_type.is_none() || manifest.artifact_type.as_deref() == Some(SOURCE_ARTIFACT_TYPE);
    let config_ok =
        manifest.config_media_type.is_none() || manifest.config_media_type.as_deref() == Some(EMPTY_CONFIG_MEDIA_TYPE);
    let shape_ok = artifact_type_ok && config_ok;
    let tarballs: Vec<&Layer> = if shape_ok {
        manifest
            .layers
            .iter()
            .filter(|l| l.media_type == SOURCE_LAYER_MEDIA_TYPE)
            .collect()
    } else {
        Vec::new()
    };
    match tarballs.len() {
        0 => Err(transport_err(
            "FETCH-OCI-NO-TARBALL",
            format!(
                "OCI artifact contained no milpa source-tarball layer (artifactType={:?}, \
                 configMediaType={:?}, layers={:?})",
                manifest.artifact_type,
                manifest.config_media_type,
                manifest.layers.iter().map(|l| l.media_type.as_str()).collect::<Vec<_>>()
            ),
        )),
        1 => Ok(tarballs[0].clone()),
        n => Err(transport_err(
            "FETCH-OCI-AMBIGUOUS-TARBALL",
            format!("OCI artifact has {n} milpa source-tarball layers; ambiguous"),
        )),
    }
}

// ---------------------------------------------------------------------------
// TokenCache — per-(registry, scope) striped locking, expiry, invalidation
// ---------------------------------------------------------------------------

type CacheKey = (String, String);

struct CachedToken {
    value: String,
    /// A `clock()` timestamp (seconds); `None` = no expiry given.
    expires_at: Option<f64>,
}

/// Monotonic seconds since first use — the default clock, mirroring Python's
/// `time.monotonic`.
fn default_clock() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_secs_f64()
}

/// Per-`(registry, scope)` token cache with striped locking (RFC §3.6).
///
/// Lock granularity is per-key, not one coarse mutex: concurrent misses on
/// DIFFERENT keys proceed in parallel; concurrent misses on the SAME key
/// coalesce into exactly one fetch (double-checked locking under a
/// short-held outer lock that only guards get-or-create of the per-key
/// lock, never the HTTP round-trip itself).
///
/// Expiry is respected (an expired entry reads as a miss); callers that
/// observe a 401 from a live request MUST call [`TokenCache::invalidate`]
/// before retrying — a token can be rejected by the registry before its
/// self-reported `expires_in` elapses, and the cache has no way to know
/// that on its own.
pub struct TokenCache {
    entries: Mutex<HashMap<CacheKey, CachedToken>>,
    key_locks: Mutex<HashMap<CacheKey, Arc<Mutex<()>>>>,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::with_clock(default_clock)
    }

    /// Construct a cache with an injectable clock (test-only escape hatch for
    /// deterministic expiry tests).
    pub fn with_clock<F>(clock: F) -> Self
    where
        F: Fn() -> f64 + Send + Sync + 'static,
    {
        TokenCache {
            entries: Mutex::new(HashMap::new()),
            key_locks: Mutex::new(HashMap::new()),
            clock: Box::new(clock),
        }
    }

    fn lock_for(&self, key: &CacheKey) -> Arc<Mutex<()>> {
        let mut locks = self.key_locks.lock().unwrap();
        locks.entry(key.clone()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }

    fn peek(&self, key: &CacheKey) -> Option<String> {
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(key)?;
        if let Some(exp) = entry.expires_at {
            if (self.clock)() >= exp {
                return None;
            }
        }
        Some(entry.value.clone())
    }

    /// Return the cached token for `key`, fetching on a miss or expiry.
    ///
    /// `fetch()` is called at most once per miss even under concurrent
    /// callers on the same `key` (double-checked locking).
    pub fn get_or_fetch<F>(&self, key: CacheKey, fetch: F) -> Result<String, FetchError>
    where
        F: FnOnce() -> Result<(String, Option<f64>), FetchError>,
    {
        if let Some(v) = self.peek(&key) {
            return Ok(v);
        }
        let lock = self.lock_for(&key);
        let _guard = lock.lock().unwrap();
        if let Some(v) = self.peek(&key) {
            return Ok(v);
        }
        let (token, expires_in) = fetch()?;
        let expires_at = expires_in.map(|e| (self.clock)() + e);
        self.entries.lock().unwrap().insert(
            key,
            CachedToken {
                value: token.clone(),
                expires_at,
            },
        );
        Ok(token)
    }

    /// Drop the cached entry for `key`, forcing the next `get_or_fetch` to
    /// refetch.
    pub fn invalidate(&self, key: &CacheKey) {
        self.entries.lock().unwrap().remove(key);
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// OciRegistryClient — token / manifest / blob
// ---------------------------------------------------------------------------

/// Generic OCI Distribution v2 client: token → manifest → blob.
///
/// Registry-/artifact-agnostic — milpa's own artifact-shape policy lives in
/// [`select_source_layer`], not here (RFC §3.2). The [`TokenCache`] is held
/// behind an `Arc`, not owned outright (RFC §3.6) — the type is
/// `Send + Sync` so the SAME cache instance can be handed to multiple
/// `OciRegistryClient`s (one constructed per fetch) and still coalesce
/// token acquisition across them.
///
/// #203 (closed by this wiring): `DefaultRegistry` (`fetchers.rs`) owns ONE
/// `Arc<TokenCache>` for the life of a resolve and threads it into every
/// `fetch_oci` call, which in turn hands `Arc::clone(&cache)` to the
/// `OciRegistryClient` it constructs for that fetch. N OCI deps sharing a
/// `(registry, scope)` in one resolve therefore share one token acquisition
/// — only the FIRST fetch pays the challenge round trip; the rest hit
/// [`TokenCache::get_or_fetch`]'s cache path. Within a single fetch, the
/// cache still also serves the 401-invalidate-and-refetch retry
/// (`get_with_auth_retry`), unchanged.
pub struct OciRegistryClient {
    http: OciTransport,
    token_cache: Arc<TokenCache>,
}

impl OciRegistryClient {
    pub fn new(http: OciTransport, token_cache: Arc<TokenCache>) -> Self {
        OciRegistryClient { http, token_cache }
    }

    /// The pull scope string for a repository — single source of truth. Used
    /// identically by [`OciRegistryClient::token`] (to request the scope) and
    /// by the 401-invalidate-and-refetch path (to invalidate the right cache
    /// key).
    fn scope_for(repository: &str) -> String {
        format!("repository:{repository}:pull")
    }

    /// Acquire (or reuse a cached) Bearer token for `repository` pulls.
    ///
    /// Anonymous — no credentials are sent on the challenge GET; ghcr and
    /// similar registries still require a token exchange for public pulls.
    /// Cached per `(registry, scope)` for the life of this client.
    ///
    /// `scheme` is NOT hardcoded to `"https"` (RFC §2 registry-diversity
    /// deferral — the caller decides).
    pub fn token(&self, registry: &str, repository: &str, scheme: &str) -> Result<String, FetchError> {
        let scope = Self::scope_for(repository);
        let key = (registry.to_string(), scope.clone());
        let registry_owned = registry.to_string();
        let repository_owned = repository.to_string();
        let scheme_owned = scheme.to_string();
        self.token_cache.get_or_fetch(key, move || {
            self.acquire_token(&registry_owned, &repository_owned, &scope, &scheme_owned)
        })
    }

    fn acquire_token(
        &self,
        registry: &str,
        // Not read here — the scope string already encodes the repository
        // (see `scope_for`); kept as a named parameter for symmetry with the
        // Python twin's `_acquire_token` signature.
        _repository: &str,
        scope: &str,
        scheme: &str,
    ) -> Result<(String, Option<f64>), FetchError> {
        let challenge_url = format!("{scheme}://{registry}/v2/");
        let mut buf = Vec::new();
        let resp = (self.http)("GET", &challenge_url, &[], TOKEN_OR_MANIFEST_CAP, Sink::Bytes(&mut buf))
            .map_err(|e| wrap_transport_phase("token", e))?;
        let www_auth = resp
            .headers
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty());
        let Some(www_auth) = www_auth else {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "token",
                format!(
                    "registry {registry:?} did not present a WWW-Authenticate \
                     challenge (status {})",
                    resp.status
                ),
            ));
        };
        let challenges = tokenize_www_authenticate(www_auth);
        let bearer = select_bearer_challenge(&challenges)?;
        let realm = bearer.params.get("realm").filter(|s| !s.is_empty());
        let service = bearer.params.get("service").filter(|s| !s.is_empty());
        let (Some(realm), Some(service)) = (realm, service) else {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "token",
                format!(
                    "Bearer challenge missing realm or service (params={:?})",
                    bearer.params
                ),
            ));
        };
        // C1 (confirmed critical finding): `realm` is attacker-controlled —
        // it comes straight from the registry's `WWW-Authenticate` header,
        // and a hostile/MITM registry can put anything in it. Without this
        // check, `token_url` below is built directly from `realm` and handed
        // to the transport: a `file://` realm is a local-file-read primitive
        // on the Python transport, an `ftp://`/internal-`http://` realm an
        // SSRF / credential-exfiltration primitive. Validate BEFORE building
        // `token_url` — never forward an unvalidated scheme into the next
        // request (mirrors the Python twin's `_acquire_token`).
        let realm_scheme = url::Url::parse(realm).map(|u| u.scheme().to_string());
        let is_http_scheme = matches!(realm_scheme.as_deref(), Ok("http") | Ok("https"));
        if !is_http_scheme {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "token",
                format!(
                    "Bearer challenge realm has unsupported scheme \
                     (realm={realm:?}); only http/https are permitted"
                ),
            ));
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([("scope", scope), ("service", service.as_str())])
            .finish();
        let token_url = format!("{realm}?{query}");
        let mut token_buf = Vec::new();
        let token_resp = (self.http)(
            "GET",
            &token_url,
            &[],
            TOKEN_OR_MANIFEST_CAP,
            Sink::Bytes(&mut token_buf),
        )
        .map_err(|e| wrap_transport_phase("token", e))?;
        if token_resp.status != 200 {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "token",
                format!("token endpoint returned status {}", token_resp.status),
            ));
        }
        let payload: serde_json::Value = serde_json::from_slice(&token_buf).map_err(|e| {
            oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "token",
                format!("token response was not valid JSON: {e}"),
            )
        })?;
        let token = payload
            .get("token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| payload.get("access_token").and_then(|v| v.as_str()).filter(|s| !s.is_empty()));
        let Some(token) = token else {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "token",
                "token response had neither 'token' nor 'access_token'",
            ));
        };
        let expires_in = payload.get("expires_in").and_then(|v| v.as_f64());
        Ok((token.to_string(), expires_in))
    }

    /// GET (via `attempt`) with a Bearer token, retrying once on a 401.
    ///
    /// A 401 invalidates the cached token for this `(registry, scope)` and
    /// reacquires one before the single retry — this is how an
    /// expired-mid-resolve token self-heals transparently instead of
    /// surfacing an opaque auth failure (RFC §3.6). `attempt` performs one
    /// full request for the given token, building a fresh sink internally so
    /// nothing is double-consumed across the retry.
    ///
    /// `phase` (`"manifest"` or `"blob"`) tags a raw transport failure
    /// (`attempt`'s bare `FETCH-DOWNLOAD-FAILED`) with this call's phase
    /// context before rewrapping as `FETCH-OCI-PULL-FAILED` (M1) — see
    /// [`wrap_transport_phase`]. A status-driven or digest-mismatch error
    /// the caller raises afterward is untouched.
    fn get_with_auth_retry<F>(
        &self,
        registry: &str,
        repository: &str,
        token: &str,
        scheme: &str,
        phase: &'static str,
        mut attempt: F,
    ) -> Result<HttpResponse, FetchError>
    where
        F: FnMut(&str) -> Result<HttpResponse, FetchError>,
    {
        let resp = attempt(token).map_err(|e| wrap_transport_phase(phase, e))?;
        if resp.status != 401 {
            return Ok(resp);
        }
        let scope = Self::scope_for(repository);
        self.token_cache.invalidate(&(registry.to_string(), scope));
        let new_token = self.token(registry, repository, scheme)?;
        attempt(&new_token).map_err(|e| wrap_transport_phase(phase, e))
    }

    /// Fetch + verify + parse the manifest at `digest`.
    ///
    /// Verifies `sha256(bytes) == digest` BEFORE parsing (fetch is
    /// digest-pinned). Rejects a manifest **list**/index outright — never an
    /// uncaught `layers[0]` panic.
    pub fn manifest(
        &self,
        registry: &str,
        repository: &str,
        digest: &str,
        token: &str,
        scheme: &str,
    ) -> Result<Manifest, FetchError> {
        let url = format!("{scheme}://{registry}/v2/{repository}/manifests/{digest}");
        let mut body: Vec<u8> = Vec::new();
        let resp = self.get_with_auth_retry(registry, repository, token, scheme, "manifest", |tok| {
            body.clear();
            let auth = format!("Bearer {tok}");
            let headers = [("Accept", MANIFEST_ACCEPT), ("Authorization", auth.as_str())];
            (self.http)("GET", &url, &headers, TOKEN_OR_MANIFEST_CAP, Sink::Bytes(&mut body))
        })?;
        if resp.status != 200 {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "manifest",
                format!("manifest fetch for {digest:?} returned status {}", resp.status),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let actual_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
        if actual_digest != digest {
            return Err(oci_transport_err(
                "FETCH-OCI-DIGEST-MISMATCH",
                "manifest",
                format!("manifest digest mismatch: expected {digest:?}, got {actual_digest:?}"),
            ));
        }
        let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "manifest",
                format!("manifest body was not valid JSON: {e}"),
            )
        })?;
        if !payload.is_object() {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "manifest",
                format!("manifest body was not a JSON object (got {})", json_kind(&payload)),
            ));
        }
        if payload.get("manifests").is_some() && payload.get("layers").is_none() {
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "manifest",
                "registry returned a manifest list/index, not a single manifest",
            ));
        }
        let layers = payload
            .get("layers")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|entry| Layer {
                        media_type: entry.get("mediaType").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        digest: entry.get("digest").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        size: entry.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let config_media_type = payload
            .get("config")
            .and_then(|c| c.get("mediaType"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        Ok(Manifest {
            media_type: payload.get("mediaType").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            artifact_type: payload.get("artifactType").and_then(|v| v.as_str()).map(|s| s.to_string()),
            config_media_type,
            layers,
        })
    }

    /// Fetch `digest` into `dest`, verifying its sha256 internally.
    ///
    /// `size` (when present AND positive) only tightens the cap via
    /// `min(size, MAX_COMPRESSED_BYTES)` to fail fast on an oversized
    /// declared size; absent/zero/negative falls back to the fixed cap alone
    /// (a publish-side `size: 0` bug must not reject a legitimate pull). The
    /// fixed ceiling always applies regardless — a lying-small `size` cannot
    /// smuggle more bytes past it, and the SOLE way this method returns
    /// successfully is after the digest check below passes; no caller can
    /// forget it.
    ///
    /// `dest` MUST be a scratch path the caller owns exclusively and is
    /// prepared to discard — `bounded_http`'s transport streams the response
    /// body into `Sink::File(dest)` UNCONDITIONALLY, before this method has
    /// seen the HTTP status, so a non-2xx response's error body lands at
    /// `dest` transiently. On a non-200 status this method removes that
    /// partial/error-body file before returning `Err`, so `dest` never holds
    /// unverified content when this call fails; callers still MUST NOT
    /// pass a path they read from independently of this method's `Ok`
    /// return (e.g. via a caller-held handle opened before the call).
    // Mirrors the Python twin's `blob()` — same logical parameter set (RFC
    // §3.2), one over clippy's default arg-count lint.
    #[allow(clippy::too_many_arguments)]
    pub fn blob(
        &self,
        registry: &str,
        repository: &str,
        digest: &str,
        size: Option<i64>,
        token: &str,
        dest: &Path,
        scheme: &str,
    ) -> Result<(), FetchError> {
        let cap = match size {
            Some(s) if s > 0 => (s as u64).min(MAX_COMPRESSED_BYTES),
            _ => MAX_COMPRESSED_BYTES,
        };
        let url = format!("{scheme}://{registry}/v2/{repository}/blobs/{digest}");
        let resp = self.get_with_auth_retry(registry, repository, token, scheme, "blob", |tok| {
            let auth = format!("Bearer {tok}");
            let headers = [("Authorization", auth.as_str())];
            (self.http)("GET", &url, &headers, cap, Sink::File(dest))
        })?;
        if resp.status != 200 {
            // L3: `Sink::File(dest)` already streamed the (error) response
            // body to `dest` above — bounded_http streams unconditionally,
            // before any caller sees the status. Remove it so a non-200
            // never leaves a usable file at `dest`; best-effort (the file may
            // not exist if the transport itself failed before writing).
            let _ = std::fs::remove_file(dest);
            return Err(oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "blob",
                format!("blob fetch for {digest:?} returned status {}", resp.status),
            ));
        }
        // N1: sha256_of_file is hoisted into fetchers.rs (single source of
        // truth shared with the tarball archive-digest path) — mirrors how
        // MAX_COMPRESSED_BYTES already flows from there into this module. It
        // returns a raw io::Result so this call site keeps its own
        // FETCH-OCI-PULL-FAILED/phase="blob" error convention (RFC §3.4
        // NORMATIVE) rather than inheriting the tarball path's bare
        // FETCH-DOWNLOAD-FAILED.
        let actual_digest = format!(
            "sha256:{}",
            sha256_of_file(dest).map_err(|e| oci_transport_err(
                "FETCH-OCI-PULL-FAILED",
                "blob",
                format!("reading blob for digest verification: {e}"),
            ))?
        );
        if actual_digest != digest {
            return Err(oci_transport_err(
                "FETCH-OCI-DIGEST-MISMATCH",
                "blob",
                format!("blob digest mismatch: expected {digest:?}, got {actual_digest:?}"),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "oci_client_tests.rs"]
mod oci_client_tests;
