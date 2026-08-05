//! Unit tests for `oci_client` (RFC `rfc-native-oci-fetch.md` §3.2/§3.6/§4
//! test matrix a-j, Rust half). Drives the SAME shared canned-transport
//! fixtures the Python client (`impls/python/tests/test_oci_client.py`)
//! replays, at `conformance/oci-transport/*.json` — the cross-impl guarantee
//! the RFC commits to (§3.7).
//!
//! [`FixtureTransport`] replays a fixture's ordered exchange list and runs
//! the SAME redirect loop shape `bounded_http::request` runs internally —
//! including calling the real, shared [`bounded_http::same_origin`]
//! predicate to decide whether `Authorization` survives a hop. It is wrapped
//! in a closure at the `OciRegistryClient::new` boundary (M6: `OciTransport`
//! is a bare `Box<dyn Fn(...) + Send + Sync>` alias, not a trait — see
//! `client_over`), so this is what "relies on bounded_http's strip" means
//! here: the security-critical equality check is shared code, not a second,
//! test-only reimplementation of it.

use super::*;

use crate::bounded_http;
use base64::Engine;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

const REGISTRY: &str = "ghcr.io";
const REPOSITORY: &str = "coreyleavitt/test-pkg";
const SCHEME: &str = "https";

// ---------------------------------------------------------------------------
// Fixture loading (conformance/oci-transport/*.json)
// ---------------------------------------------------------------------------

fn fixtures_root() -> std::path::PathBuf {
    std::path::Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../conformance/oci-transport"
    ))
    .to_path_buf()
}

fn load_fixture(name: &str) -> serde_json::Value {
    let path = fixtures_root().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading fixture {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing fixture {path:?}: {e}"))
}

fn decode_body_base64(value: &serde_json::Value) -> Vec<u8> {
    let s = value.as_str().expect("body_base64 is a string");
    base64::engine::general_purpose::STANDARD.decode(s).expect("valid base64")
}

fn digest_from_manifest_url(url: &str) -> String {
    url.rsplit_once("/manifests/").expect("manifest url").1.to_string()
}

fn digest_from_blob_url(url: &str) -> String {
    let after = url.rsplit_once("/blobs/").expect("blob url").1;
    after.split('?').next().unwrap().to_string()
}

#[derive(Clone)]
struct FixtureExchange {
    method: String,
    url: String,
    expect_request_headers: HashMap<String, Option<String>>,
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn exchanges_from_fixture(data: &serde_json::Value) -> Vec<FixtureExchange> {
    data["exchanges"]
        .as_array()
        .expect("exchanges array")
        .iter()
        .map(|exch| {
            let response = &exch["response"];
            let body = if let Some(v) = response.get("body_base64") {
                decode_body_base64(v)
            } else if let Some(file) = response.get("body_file").and_then(|v| v.as_str()) {
                std::fs::read(fixtures_root().join(file)).expect("reading body_file")
            } else if let Some(text) = response.get("body").and_then(|v| v.as_str()) {
                text.as_bytes().to_vec()
            } else {
                Vec::new()
            };
            let headers: HashMap<String, String> = response
                .get("headers")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let expect_request_headers: HashMap<String, Option<String>> = exch
                .get("expect_request_headers")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .map(|(k, v)| (k.clone(), v.as_str().map(|s| s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            FixtureExchange {
                method: exch["method"].as_str().expect("method").to_string(),
                url: exch["url"].as_str().expect("url").to_string(),
                expect_request_headers,
                status: response["status"].as_u64().expect("status") as u16,
                headers,
                body,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// FixtureTransport — replays a fixture through the real redirect/strip shape
// ---------------------------------------------------------------------------

struct FixtureTransport {
    exchanges: Vec<FixtureExchange>,
    index: Mutex<usize>,
}

impl FixtureTransport {
    fn new(fixture_name: &str) -> Self {
        let data = load_fixture(fixture_name);
        FixtureTransport {
            exchanges: exchanges_from_fixture(&data),
            index: Mutex::new(0),
        }
    }

    fn assert_exhausted(&self) {
        let idx = *self.index.lock().unwrap();
        assert_eq!(
            idx,
            self.exchanges.len(),
            "fixture had {} unconsumed exchange(s)",
            self.exchanges.len() - idx
        );
    }

    fn next(&self, method: &str, url: &str, headers: &[(String, String)]) -> FixtureExchange {
        let mut idx_guard = self.index.lock().unwrap();
        let idx = *idx_guard;
        assert!(
            idx < self.exchanges.len(),
            "fixture exhausted after {idx} exchange(s); unexpected request {method} {url}"
        );
        let exch = self.exchanges[idx].clone();
        *idx_guard += 1;
        drop(idx_guard);
        assert_eq!(method, exch.method, "exchange {}: method mismatch", idx + 1);
        assert_eq!(url, exch.url, "exchange {}: url mismatch", idx + 1);
        for (name, expected) in &exch.expect_request_headers {
            let actual = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone());
            match expected {
                Some(exp) => assert_eq!(
                    actual.as_deref(),
                    Some(exp.as_str()),
                    "exchange {}: header {name} mismatch",
                    idx + 1
                ),
                None => assert!(
                    actual.is_none(),
                    "exchange {}: header {name} should be absent, got {actual:?}",
                    idx + 1
                ),
            }
        }
        exch
    }
}

fn write_capped(body: &[u8], cap: u64, sink: Sink<'_>) -> Result<(), FetchError> {
    if body.len() as u64 > cap {
        return Err(FetchError::Transport(
            "FETCH-DOWNLOAD-SIZE-EXCEEDED",
            format!("response body exceeded download cap ({cap} bytes)"),
        ));
    }
    match sink {
        Sink::Bytes(buf) => {
            buf.extend_from_slice(body);
            Ok(())
        }
        Sink::File(path) => std::fs::write(path, body)
            .map_err(|e| FetchError::Transport("FETCH-DOWNLOAD-FAILED", format!("writing {path:?}: {e}"))),
    }
}

fn header_map_from(headers: &HashMap<String, String>) -> ureq::http::HeaderMap {
    let mut hmap = ureq::http::HeaderMap::new();
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (
            ureq::http::HeaderName::from_bytes(k.as_bytes()),
            ureq::http::HeaderValue::from_str(v),
        ) {
            hmap.insert(name, value);
        }
    }
    hmap
}

impl FixtureTransport {
    /// M6: an inherent method, not a `trait OciTransport` impl — `OciTransport`
    /// is now a bare closure alias (mirrors `HttpGet`'s precedent, `fetchers.rs`);
    /// callers wrap `Arc<FixtureTransport>::request` in a closure at the
    /// `OciRegistryClient::new` boundary (see `client_over`) instead of relying
    /// on trait-object dispatch.
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        cap: u64,
        sink: Sink<'_>,
    ) -> Result<HttpResponse, FetchError> {
        let original_url = url.to_string();
        let base_headers: Vec<(String, String)> =
            headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let mut current_url = url.to_string();
        let mut sink_opt = Some(sink);

        loop {
            // Mirrors bounded_http::request's own loop: recompute the strip
            // decision, per hop, against the ORIGINAL request URL — using the
            // SAME `same_origin` predicate production code relies on.
            let same_as_original = bounded_http::same_origin(&original_url, &current_url);
            let effective_headers: Vec<(String, String)> = if same_as_original {
                base_headers.clone()
            } else {
                base_headers
                    .iter()
                    .filter(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
                    .cloned()
                    .collect()
            };

            let exch = self.next(method, &current_url, &effective_headers);
            let status = exch.status;
            if (300..400).contains(&status) {
                if let Some(loc) = exch.headers.get("Location") {
                    current_url = loc.clone();
                    continue;
                }
            }

            let sink = sink_opt.take().expect("sink consumed exactly once, on the terminal response");
            write_capped(&exch.body, cap, sink)?;
            return Ok(HttpResponse {
                status,
                headers: header_map_from(&exch.headers),
            });
        }
    }
}

/// Wrap a `Arc<FixtureTransport>` in a closure satisfying the `OciTransport`
/// alias, keeping the test's own `Arc` handle live so it can assert
/// `assert_exhausted()` after handing a transport to the client (M6: no
/// blanket `Arc<T: OciTransport>` impl needed now that `OciTransport` is a
/// bare closure type, not a trait).
fn client_over(transport: &Arc<FixtureTransport>) -> OciRegistryClient {
    let transport = Arc::clone(transport);
    OciRegistryClient::new(
        Box::new(move |method, url, headers, cap, sink| transport.request(method, url, headers, cap, sink)),
        Arc::new(TokenCache::new()),
    )
}

// ---------------------------------------------------------------------------
// (a) happy pull: token -> manifest -> blob, extracts + verifies
// ---------------------------------------------------------------------------

#[test]
fn happy_pull_extracts_blob_to_dest() {
    let fixture = load_fixture("happy-pull.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());
    let blob_body = decode_body_base64(&fixture["exchanges"][3]["response"]["body_base64"]);

    let transport = Arc::new(FixtureTransport::new("happy-pull.json"));
    let client = client_over(&transport);

    let token = client.token(REGISTRY, REPOSITORY, SCHEME).expect("token");
    assert_eq!(token, "test-token-abc");

    let manifest = client
        .manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME)
        .expect("manifest");
    let layer = select_source_layer(&manifest).expect("layer");

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("source.tar.gz");
    client
        .blob(REGISTRY, REPOSITORY, &layer.digest, Some(layer.size), &token, &dest, SCHEME)
        .expect("blob");

    assert_eq!(std::fs::read(&dest).unwrap(), blob_body);
    transport.assert_exhausted();
}

#[test]
fn token_is_cached_across_repeated_calls() {
    // The happy-pull fixture has exactly one token-challenge + one
    // token-fetch exchange; a cache miss on the second call would exhaust
    // the fixture and panic inside FixtureTransport::next.
    let fixture = load_fixture("happy-pull.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("happy-pull.json"));
    let client = client_over(&transport);

    let token1 = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    let token2 = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    assert_eq!(token1, "test-token-abc");
    assert_eq!(token2, "test-token-abc");

    client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token1, SCHEME).unwrap();
}

// ---------------------------------------------------------------------------
// (b) phase failures carry the right slug + phase= token
// ---------------------------------------------------------------------------

#[test]
fn token_endpoint_error_raises_pull_failed_phase_token() {
    let transport = Arc::new(FixtureTransport::new("token-endpoint-error.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

#[test]
fn manifest_not_found_raises_pull_failed_phase_manifest() {
    let fixture = load_fixture("manifest-not-found.json");
    let digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("manifest-not-found.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();

    let err = client.manifest(REGISTRY, REPOSITORY, &digest, &token, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("manifest"));
}

#[test]
fn blob_fetch_error_raises_pull_failed_phase_blob() {
    let fixture = load_fixture("blob-fetch-error.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());
    let layer_digest = digest_from_blob_url(fixture["exchanges"][3]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("blob-fetch-error.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    let manifest = client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
    let layer = select_source_layer(&manifest).unwrap();
    assert_eq!(layer.digest, layer_digest);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.tar.gz");
    let err = client
        .blob(REGISTRY, REPOSITORY, &layer.digest, Some(layer.size), &token, &dest, SCHEME)
        .unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("blob"));
}

/// L3: `bounded_http`'s transport streams the response body into
/// `Sink::File(dest)` UNCONDITIONALLY (by design — it has no notion of
/// "success" or "failure", just a status to report), before `blob()` has
/// seen the status. A non-200 response therefore lands its (error) body at
/// `dest` transiently; `blob()` must remove it before returning `Err`, so a
/// caller never finds a leftover file at `dest` after a failed pull.
fn error_body_transport(
    _method: &str,
    _url: &str,
    _headers: &[(&str, &str)],
    _cap: u64,
    sink: Sink<'_>,
) -> Result<HttpResponse, FetchError> {
    let body = b"<html>500 Internal Server Error</html>";
    match sink {
        Sink::Bytes(buf) => buf.extend_from_slice(body),
        Sink::File(path) => std::fs::write(path, body).unwrap(),
    }
    Ok(HttpResponse {
        status: 500,
        headers: ureq::http::HeaderMap::new(),
    })
}

#[test]
fn blob_non_200_leaves_no_usable_file_at_dest() {
    let client = OciRegistryClient::new(Box::new(error_body_transport), Arc::new(TokenCache::new()));
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("scratch-blob");

    let err = client
        .blob(
            REGISTRY,
            REPOSITORY,
            "sha256:0136074d159d69d15e33d557d57da884d81644d327ee060bfa6ecb0ffc72431b",
            None,
            "tok",
            &dest,
            SCHEME,
        )
        .unwrap_err();

    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("blob"));
    assert!(
        !dest.exists(),
        "L3: a non-200 blob response must not leave its (error) body at dest"
    );
}

// ---------------------------------------------------------------------------
// (c) manifest / blob digest mismatch -> FETCH-OCI-DIGEST-MISMATCH, fail closed
// ---------------------------------------------------------------------------

#[test]
fn manifest_digest_mismatch_raises_digest_mismatch() {
    let fixture = load_fixture("manifest-digest-mismatch.json");
    let digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("manifest-digest-mismatch.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();

    let err = client.manifest(REGISTRY, REPOSITORY, &digest, &token, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-DIGEST-MISMATCH");
    assert_eq!(err.phase(), Some("manifest"));
}

#[test]
fn blob_digest_mismatch_raises_digest_mismatch() {
    let fixture = load_fixture("blob-digest-mismatch.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());
    let layer_digest = digest_from_blob_url(fixture["exchanges"][3]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("blob-digest-mismatch.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    let manifest = client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
    let layer = select_source_layer(&manifest).unwrap();
    assert_eq!(layer.digest, layer_digest);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.tar.gz");
    let err = client
        .blob(REGISTRY, REPOSITORY, &layer.digest, Some(layer.size), &token, &dest, SCHEME)
        .unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-DIGEST-MISMATCH");
    assert_eq!(err.phase(), Some("blob"));
}

// ---------------------------------------------------------------------------
// (d) blob redirect: cross-host strips Authorization (relies on bounded_http)
// ---------------------------------------------------------------------------

#[test]
fn blob_cross_host_redirect_strips_authorization() {
    let fixture = load_fixture("blob-redirect-cross-host.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());
    let layer_digest = digest_from_blob_url(fixture["exchanges"][3]["url"].as_str().unwrap());
    let final_body = decode_body_base64(&fixture["exchanges"][4]["response"]["body_base64"]);

    let transport = Arc::new(FixtureTransport::new("blob-redirect-cross-host.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    let manifest = client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
    let layer = select_source_layer(&manifest).unwrap();
    assert_eq!(layer.digest, layer_digest);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.tar.gz");
    client
        .blob(REGISTRY, REPOSITORY, &layer.digest, Some(layer.size), &token, &dest, SCHEME)
        .unwrap();

    assert_eq!(std::fs::read(&dest).unwrap(), final_body);
    // The fixture's expect_request_headers on the CDN hop asserts
    // Authorization is absent; FixtureTransport::next panics if that is
    // violated, so reaching here already proves the strip happened — via the
    // same same_origin() predicate bounded_http::request uses for real.
    transport.assert_exhausted();
}

// ---------------------------------------------------------------------------
// (e) blob over declared size -> size-exceeded
// ---------------------------------------------------------------------------

#[test]
fn blob_over_declared_size_cap_raises_size_exceeded() {
    let fixture = load_fixture("happy-pull.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());
    let layer_digest = digest_from_blob_url(fixture["exchanges"][3]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("happy-pull.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    let manifest = client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
    let layer = select_source_layer(&manifest).unwrap();
    assert_eq!(layer.digest, layer_digest);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.tar.gz");
    let err = client
        .blob(REGISTRY, REPOSITORY, &layer.digest, Some(10), &token, &dest, SCHEME)
        .unwrap_err();
    assert_eq!(err.code(), "FETCH-DOWNLOAD-SIZE-EXCEEDED");
}

// ---------------------------------------------------------------------------
// (f) manifest list/index rejected
// ---------------------------------------------------------------------------

#[test]
fn manifest_list_is_rejected_not_a_panic() {
    let fixture = load_fixture("manifest-list-rejected.json");
    let digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("manifest-list-rejected.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();

    let err = client.manifest(REGISTRY, REPOSITORY, &digest, &token, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("manifest"));
}

// ---------------------------------------------------------------------------
// (f2) H1: manifest body is valid JSON but not an object -> never a leaked
// empty-layers Manifest / wrong slug, always a structured phase=manifest error.
// ---------------------------------------------------------------------------

#[test]
fn manifest_not_an_object_raises_pull_failed_not_a_panic() {
    let fixture = load_fixture("manifest-not-an-object.json");
    let digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("manifest-not-an-object.json"));
    let client = client_over(&transport);
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();

    let err = client.manifest(REGISTRY, REPOSITORY, &digest, &token, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("manifest"));
}

// ---------------------------------------------------------------------------
// (g) WWW-Authenticate: multiple challenges, unsupported scheme, missing params
// ---------------------------------------------------------------------------

#[test]
fn www_auth_multiple_challenges_selects_bearer() {
    let fixture = load_fixture("www-auth-multiple-challenges.json");
    let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());

    let transport = Arc::new(FixtureTransport::new("www-auth-multiple-challenges.json"));
    let client = client_over(&transport);

    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    assert_eq!(token, "test-token-abc");
    // Reaching a successful manifest fetch proves the Bearer challenge (not
    // the ignored Basic realm) drove the token endpoint selection.
    client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
}

#[test]
fn www_auth_basic_only_fails_with_unsupported_scheme() {
    let transport = Arc::new(FixtureTransport::new("www-auth-basic-only.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
    assert!(err.message().to_lowercase().contains("bearer"));
}

#[test]
fn www_auth_missing_realm_fails_closed() {
    let transport = Arc::new(FixtureTransport::new("www-auth-missing-realm.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

#[test]
fn www_auth_missing_service_fails_closed() {
    let transport = Arc::new(FixtureTransport::new("www-auth-missing-service.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

/// C1 (confirmed critical finding): the Bearer challenge's `realm` is
/// attacker-controlled (a hostile/MITM registry). Without a realm-scheme
/// check, `realm` flows directly into the second (token) request URL — a
/// `file://` realm is a local-file-read primitive on the Python transport,
/// an `ftp://`/internal-`http://` realm an SSRF primitive. The fixture has
/// exactly ONE exchange (the challenge); `FixtureTransport::next` panics if
/// the client issues a second request, so reaching a clean `Err` here also
/// pins "no second request is ever attempted."
#[test]
fn www_auth_non_http_realm_fails_closed_before_second_request() {
    let transport = Arc::new(FixtureTransport::new("token-realm-non-http.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
    transport.assert_exhausted();
}

// ---------------------------------------------------------------------------
// (g2) M4: access_token accepted; token-phase JSON error paths
// ---------------------------------------------------------------------------

#[test]
fn token_accepts_access_token_only_field() {
    // §7.3 MUST accept EITHER 'token' or 'access_token' — this exercises the
    // access_token-only branch, which no fixture previously covered.
    let transport = Arc::new(FixtureTransport::new("token-access-token-only.json"));
    let client = client_over(&transport);

    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    assert_eq!(token, "test-token-abc");
    transport.assert_exhausted();
}

#[test]
fn token_response_invalid_json_raises_pull_failed_phase_token() {
    let transport = Arc::new(FixtureTransport::new("token-invalid-json.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

#[test]
fn token_response_neither_field_raises_pull_failed_phase_token() {
    let transport = Arc::new(FixtureTransport::new("token-neither-field.json"));
    let client = client_over(&transport);

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

// ---------------------------------------------------------------------------
// (g3) M1: a raw transport failure (FETCH-DOWNLOAD-FAILED from
// bounded_http::request — DNS/reset/timeout) is wrapped with this call's
// phase= context, never propagated bare. Hand-built fake transports (not the
// JSON replay, which only ever answers with a status — it cannot simulate a
// connection-level Err).
// ---------------------------------------------------------------------------

fn token_challenge_fails_transport(
    _method: &str,
    _url: &str,
    _headers: &[(&str, &str)],
    _cap: u64,
    _sink: Sink<'_>,
) -> Result<HttpResponse, FetchError> {
    Err(FetchError::Transport("FETCH-DOWNLOAD-FAILED", "connection refused".to_string()))
}

#[test]
fn token_challenge_transport_failure_wrapped_phase_token() {
    let client = OciRegistryClient::new(Box::new(token_challenge_fails_transport), Arc::new(TokenCache::new()));

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

fn www_authenticate_401() -> HttpResponse {
    let mut hmap = ureq::http::HeaderMap::new();
    hmap.insert(
        ureq::http::HeaderName::from_static("www-authenticate"),
        ureq::http::HeaderValue::from_str(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#).unwrap(),
    );
    HttpResponse { status: 401, headers: hmap }
}

/// M6: a bare fn transport (no `struct` + `impl OciTransport` ceremony — this
/// fake carries no state) — coerces directly into the `OciTransport` closure
/// alias, same as production's `bounded_http::request`.
fn token_endpoint_fails_transport(
    _method: &str,
    url: &str,
    _headers: &[(&str, &str)],
    _cap: u64,
    _sink: Sink<'_>,
) -> Result<HttpResponse, FetchError> {
    if url.ends_with("/v2/") {
        return Ok(www_authenticate_401());
    }
    Err(FetchError::Transport("FETCH-DOWNLOAD-FAILED", "connection reset".to_string()))
}

#[test]
fn token_endpoint_transport_failure_wrapped_phase_token() {
    let client = OciRegistryClient::new(Box::new(token_endpoint_fails_transport), Arc::new(TokenCache::new()));

    let err = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

fn manifest_transport_fails_transport(
    _method: &str,
    url: &str,
    _headers: &[(&str, &str)],
    _cap: u64,
    sink: Sink<'_>,
) -> Result<HttpResponse, FetchError> {
    if url.ends_with("/v2/") {
        return Ok(www_authenticate_401());
    }
    if url.starts_with("https://ghcr.io/token") {
        if let Sink::Bytes(buf) = sink {
            buf.extend_from_slice(br#"{"token": "tok-1"}"#);
        }
        return Ok(HttpResponse { status: 200, headers: ureq::http::HeaderMap::new() });
    }
    if url.contains("/manifests/") {
        return Err(FetchError::Transport("FETCH-DOWNLOAD-FAILED", "timed out".to_string()));
    }
    panic!("unexpected url {url}");
}

#[test]
fn manifest_transport_failure_wrapped_phase_manifest() {
    let client = OciRegistryClient::new(Box::new(manifest_transport_fails_transport), Arc::new(TokenCache::new()));
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();

    let digest = format!("sha256:{}", "0".repeat(64));
    let err = client.manifest(REGISTRY, REPOSITORY, &digest, &token, SCHEME).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("manifest"));
}

struct BlobTransportFailsTransport {
    manifest_body: Vec<u8>,
}

impl BlobTransportFailsTransport {
    /// M6: an inherent method — wrapped in a closure at the call site instead
    /// of implementing the now-retired `trait OciTransport`.
    fn request(
        &self,
        _method: &str,
        url: &str,
        _headers: &[(&str, &str)],
        _cap: u64,
        sink: Sink<'_>,
    ) -> Result<HttpResponse, FetchError> {
        if url.ends_with("/v2/") {
            return Ok(www_authenticate_401());
        }
        if url.starts_with("https://ghcr.io/token") {
            if let Sink::Bytes(buf) = sink {
                buf.extend_from_slice(br#"{"token": "tok-1"}"#);
            }
            return Ok(HttpResponse { status: 200, headers: ureq::http::HeaderMap::new() });
        }
        if url.contains("/manifests/") {
            if let Sink::Bytes(buf) = sink {
                buf.extend_from_slice(&self.manifest_body);
            }
            return Ok(HttpResponse { status: 200, headers: ureq::http::HeaderMap::new() });
        }
        if url.contains("/blobs/") {
            return Err(FetchError::Transport("FETCH-DOWNLOAD-FAILED", "connection reset".to_string()));
        }
        panic!("unexpected url {url}");
    }
}

#[test]
fn blob_transport_failure_wrapped_phase_blob() {
    let manifest_body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": []
    })
    .to_string()
    .into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&manifest_body);
    let manifest_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    let fake = BlobTransportFailsTransport { manifest_body };
    let client = OciRegistryClient::new(
        Box::new(move |m, u, h, c, s| fake.request(m, u, h, c, s)),
        Arc::new(TokenCache::new()),
    );
    let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    let manifest = client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
    assert!(manifest.layers.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.tar.gz");
    let blob_digest = format!("sha256:{}", "1".repeat(64));
    let err = client
        .blob(REGISTRY, REPOSITORY, &blob_digest, None, &token, &dest, SCHEME)
        .unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("blob"));
}

// --- pure tokenizer unit tests (exhaustive) --------------------------------

#[test]
fn tokenizer_single_bearer_challenge() {
    let challenges =
        tokenize_www_authenticate(r#"Bearer realm="https://auth.example/token",service="reg.example""#);
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, "Bearer");
    assert_eq!(challenges[0].params.get("realm").unwrap(), "https://auth.example/token");
    assert_eq!(challenges[0].params.get("service").unwrap(), "reg.example");
}

#[test]
fn tokenizer_multiple_challenges_unordered_params() {
    let challenges = tokenize_www_authenticate(r#"Basic realm="x", Bearer service="z",realm="y""#);
    assert_eq!(challenges.len(), 2);
    assert_eq!(challenges[0].scheme, "Basic");
    assert_eq!(challenges[0].params.get("realm").unwrap(), "x");
    assert_eq!(challenges[1].scheme, "Bearer");
    assert_eq!(challenges[1].params.get("service").unwrap(), "z");
    assert_eq!(challenges[1].params.get("realm").unwrap(), "y");
}

#[test]
fn tokenizer_handles_escaped_quotes_and_embedded_commas() {
    let challenges = tokenize_www_authenticate(
        r#"Bearer realm="https://auth.example/token",error_description="a \"quoted, comma\" value""#,
    );
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].scheme, "Bearer");
    assert_eq!(challenges[0].params.get("realm").unwrap(), "https://auth.example/token");
    assert_eq!(challenges[0].params.get("error_description").unwrap(), "a \"quoted, comma\" value");
}

#[test]
fn tokenizer_bare_scheme_with_no_params() {
    let challenges = tokenize_www_authenticate("Negotiate");
    assert_eq!(
        challenges,
        vec![AuthChallenge {
            scheme: "Negotiate".to_string(),
            params: HashMap::new(),
        }]
    );
}

#[test]
fn tokenizer_bare_scheme_then_challenge_with_params() {
    let challenges = tokenize_www_authenticate(r#"Negotiate, Basic realm="x""#);
    let mut expected_params = HashMap::new();
    expected_params.insert("realm".to_string(), "x".to_string());
    assert_eq!(
        challenges,
        vec![
            AuthChallenge {
                scheme: "Negotiate".to_string(),
                params: HashMap::new(),
            },
            AuthChallenge {
                scheme: "Basic".to_string(),
                params: expected_params,
            },
        ]
    );
}

#[test]
fn select_bearer_challenge_picks_bearer_among_several() {
    let challenges = vec![
        AuthChallenge {
            scheme: "Basic".to_string(),
            params: HashMap::from([("realm".to_string(), "x".to_string())]),
        },
        AuthChallenge {
            scheme: "Bearer".to_string(),
            params: HashMap::from([("realm".to_string(), "y".to_string()), ("service".to_string(), "z".to_string())]),
        },
    ];
    let selected = select_bearer_challenge(&challenges).unwrap();
    assert_eq!(selected.scheme, "Bearer");
    assert_eq!(selected.params.get("realm").unwrap(), "y");
    assert_eq!(selected.params.get("service").unwrap(), "z");
}

#[test]
fn select_bearer_challenge_raises_when_absent() {
    let challenges = vec![AuthChallenge {
        scheme: "Basic".to_string(),
        params: HashMap::from([("realm".to_string(), "x".to_string())]),
    }];
    let err = select_bearer_challenge(&challenges).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-PULL-FAILED");
    assert_eq!(err.phase(), Some("token"));
}

// ---------------------------------------------------------------------------
// (h) size absent/0/negative -> cap alone, no spurious reject
// ---------------------------------------------------------------------------

#[test]
fn blob_size_absent_zero_or_negative_uses_cap_alone() {
    for size in [None, Some(0), Some(-1)] {
        let fixture = load_fixture("happy-pull.json");
        let manifest_digest = digest_from_manifest_url(fixture["exchanges"][2]["url"].as_str().unwrap());
        let layer_digest = digest_from_blob_url(fixture["exchanges"][3]["url"].as_str().unwrap());
        let expected_body = decode_body_base64(&fixture["exchanges"][3]["response"]["body_base64"]);

        let transport = Arc::new(FixtureTransport::new("happy-pull.json"));
        let client = client_over(&transport);
        let token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
        let manifest = client.manifest(REGISTRY, REPOSITORY, &manifest_digest, &token, SCHEME).unwrap();
        let layer = select_source_layer(&manifest).unwrap();
        assert_eq!(layer.digest, layer_digest);

        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.tar.gz");
        client.blob(REGISTRY, REPOSITORY, &layer.digest, size, &token, &dest, SCHEME).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), expected_body);
    }
}

struct SpyTransport {
    captured_caps: Mutex<Vec<u64>>,
}

impl SpyTransport {
    /// M6: an inherent method — the test holds an `Arc<SpyTransport>` handle
    /// to inspect `captured_caps` after the client (which holds its own
    /// `Arc::clone` via a wrapping closure) has run.
    fn request(
        &self,
        _method: &str,
        _url: &str,
        _headers: &[(&str, &str)],
        cap: u64,
        sink: Sink<'_>,
    ) -> Result<HttpResponse, FetchError> {
        self.captured_caps.lock().unwrap().push(cap);
        match sink {
            Sink::Bytes(buf) => buf.extend_from_slice(b"x"),
            Sink::File(path) => std::fs::write(path, b"x").unwrap(),
        }
        Ok(HttpResponse {
            status: 200,
            headers: ureq::http::HeaderMap::new(),
        })
    }
}

#[test]
fn blob_cap_value_falls_back_to_max_when_size_non_positive() {
    // Directly spy on the `cap` passed to the transport for size<=0 vs a
    // positive size — pins the exact cap formula, not just its externally
    // observable effect.
    let spy = Arc::new(SpyTransport {
        captured_caps: Mutex::new(Vec::new()),
    });
    let spy_for_client = Arc::clone(&spy);
    let client = OciRegistryClient::new(
        Box::new(move |m, u, h, c, s| spy_for_client.request(m, u, h, c, s)),
        Arc::new(TokenCache::new()),
    );
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");

    let mut hasher = Sha256::new();
    hasher.update(b"x");
    let digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    client.blob(REGISTRY, REPOSITORY, &digest, Some(0), "tok", &dest, SCHEME).unwrap();
    client.blob(REGISTRY, REPOSITORY, &digest, Some(-5), "tok", &dest, SCHEME).unwrap();
    client.blob(REGISTRY, REPOSITORY, &digest, None, "tok", &dest, SCHEME).unwrap();
    client.blob(REGISTRY, REPOSITORY, &digest, Some(42), "tok", &dest, SCHEME).unwrap();

    let caps = spy.captured_caps.lock().unwrap().clone();
    assert_eq!(caps, vec![MAX_COMPRESSED_BYTES, MAX_COMPRESSED_BYTES, MAX_COMPRESSED_BYTES, 42]);
}

// ---------------------------------------------------------------------------
// (i) token-cache stampede + expiry
// ---------------------------------------------------------------------------

#[test]
fn token_cache_stampede_same_key_one_fetch() {
    // N threads racing on the identical (registry, scope) trigger exactly
    // one fetch. `fetch()` sleeps briefly so all 8 threads are genuinely
    // inside the critical section's window at once (mirrors the Python
    // pinned regression: without the delay, scheduling can accidentally
    // serialize threads enough that a broken, non-double-checked lock still
    // passes by luck).
    let call_count = Arc::new(Mutex::new(0u32));
    let barrier = Arc::new(Barrier::new(8));
    let cache = Arc::new(TokenCache::new());
    let results = Arc::new(Mutex::new(Vec::new()));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let call_count = Arc::clone(&call_count);
            let barrier = Arc::clone(&barrier);
            let cache = Arc::clone(&cache);
            let results = Arc::clone(&results);
            thread::spawn(move || {
                barrier.wait();
                let token = cache
                    .get_or_fetch(("ghcr.io".to_string(), "repository:x:pull".to_string()), || {
                        *call_count.lock().unwrap() += 1;
                        thread::sleep(Duration::from_millis(20));
                        Ok(("stampede-token".to_string(), None))
                    })
                    .unwrap();
                results.lock().unwrap().push(token);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(*call_count.lock().unwrap(), 1);
    assert_eq!(*results.lock().unwrap(), vec!["stampede-token".to_string(); 8]);
}

#[test]
fn token_cache_different_keys_do_not_serialize_incorrectly() {
    let fetched_keys = Arc::new(Mutex::new(Vec::new()));
    let cache = Arc::new(TokenCache::new());

    let handles: Vec<_> = ["a", "b", "c"]
        .into_iter()
        .map(|k| {
            let fetched_keys = Arc::clone(&fetched_keys);
            let cache = Arc::clone(&cache);
            let key = k.to_string();
            thread::spawn(move || {
                let key2 = key.clone();
                cache
                    .get_or_fetch(("ghcr.io".to_string(), key), move || {
                        fetched_keys.lock().unwrap().push(key2.clone());
                        Ok((format!("token-{key2}"), None))
                    })
                    .unwrap();
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    let mut got = fetched_keys.lock().unwrap().clone();
    got.sort();
    assert_eq!(got, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
}

#[test]
fn token_cache_expiry_treated_as_miss() {
    let fake_now = Arc::new(Mutex::new(1000.0f64));
    let clock_source = Arc::clone(&fake_now);
    let cache = TokenCache::with_clock(move || *clock_source.lock().unwrap());
    let calls = Arc::new(Mutex::new(0u32));
    let key = ("ghcr.io".to_string(), "repository:x:pull".to_string());

    let calls_c = Arc::clone(&calls);
    let first = cache
        .get_or_fetch(key.clone(), move || {
            let mut c = calls_c.lock().unwrap();
            *c += 1;
            Ok((format!("token-{}", *c), Some(60.0)))
        })
        .unwrap();
    assert_eq!(first, "token-1");

    *fake_now.lock().unwrap() += 30.0; // still valid
    let calls_c = Arc::clone(&calls);
    let still_valid = cache
        .get_or_fetch(key.clone(), move || {
            let mut c = calls_c.lock().unwrap();
            *c += 1;
            Ok((format!("token-{}", *c), Some(60.0)))
        })
        .unwrap();
    assert_eq!(still_valid, "token-1");

    *fake_now.lock().unwrap() += 60.0; // now expired
    let calls_c = Arc::clone(&calls);
    let second = cache
        .get_or_fetch(key, move || {
            let mut c = calls_c.lock().unwrap();
            *c += 1;
            Ok((format!("token-{}", *c), Some(60.0)))
        })
        .unwrap();
    assert_eq!(second, "token-2");
    assert_eq!(*calls.lock().unwrap(), 2);
}

/// A hand-built fake transport (not the JSON replay) exercising the
/// client's own 401-invalidate-and-refetch integration: the first manifest
/// GET with the stale token returns 401; the client must invalidate,
/// reacquire via a second token exchange, and retry, succeeding without the
/// caller ever seeing a failure.
struct RefreshFakeTransport {
    token_calls: Mutex<u32>,
    manifest_attempts: Mutex<u32>,
    manifest_body: Vec<u8>,
}

impl RefreshFakeTransport {
    /// M6: an inherent method — the test holds an `Arc<RefreshFakeTransport>`
    /// handle to inspect `token_calls`/`manifest_attempts` after the client
    /// (which holds its own `Arc::clone` via a wrapping closure) has run.
    fn request(
        &self,
        _method: &str,
        url: &str,
        headers: &[(&str, &str)],
        _cap: u64,
        sink: Sink<'_>,
    ) -> Result<HttpResponse, FetchError> {
        if url.ends_with("/v2/") {
            let mut hmap = ureq::http::HeaderMap::new();
            hmap.insert(
                ureq::http::HeaderName::from_static("www-authenticate"),
                ureq::http::HeaderValue::from_str(r#"Bearer realm="https://ghcr.io/token",service="ghcr.io""#)
                    .unwrap(),
            );
            return Ok(HttpResponse { status: 401, headers: hmap });
        }
        if url.starts_with("https://ghcr.io/token") {
            let mut n = self.token_calls.lock().unwrap();
            *n += 1;
            let body = format!(r#"{{"token": "tok-{n}"}}"#);
            if let Sink::Bytes(buf) = sink {
                buf.extend_from_slice(body.as_bytes());
            }
            return Ok(HttpResponse {
                status: 200,
                headers: ureq::http::HeaderMap::new(),
            });
        }
        if url.contains("/manifests/") {
            let mut n = self.manifest_attempts.lock().unwrap();
            *n += 1;
            let auth = headers.iter().find(|h| h.0.eq_ignore_ascii_case("authorization")).map(|h| h.1);
            if auth == Some("Bearer tok-1") {
                return Ok(HttpResponse {
                    status: 401,
                    headers: ureq::http::HeaderMap::new(),
                });
            }
            if let Sink::Bytes(buf) = sink {
                buf.extend_from_slice(&self.manifest_body);
            }
            return Ok(HttpResponse {
                status: 200,
                headers: ureq::http::HeaderMap::new(),
            });
        }
        panic!("unexpected url {url}");
    }
}

#[test]
fn manifest_transparent_refresh_on_expired_token() {
    let manifest_body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": []
    })
    .to_string()
    .into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&manifest_body);
    let manifest_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    let transport = Arc::new(RefreshFakeTransport {
        token_calls: Mutex::new(0),
        manifest_attempts: Mutex::new(0),
        manifest_body,
    });
    let transport_for_client = Arc::clone(&transport);
    let client = OciRegistryClient::new(
        Box::new(move |m, u, h, c, s| transport_for_client.request(m, u, h, c, s)),
        Arc::new(TokenCache::new()),
    );

    let stale_token = client.token(REGISTRY, REPOSITORY, SCHEME).unwrap();
    assert_eq!(stale_token, "tok-1");

    let manifest = client
        .manifest(REGISTRY, REPOSITORY, &manifest_digest, &stale_token, SCHEME)
        .unwrap();
    assert!(manifest.layers.is_empty());
    assert_eq!(*transport.manifest_attempts.lock().unwrap(), 2);
    assert_eq!(*transport.token_calls.lock().unwrap(), 2);

    // The cache now holds the refreshed token, not the stale one.
    assert_eq!(client.token(REGISTRY, REPOSITORY, SCHEME).unwrap(), "tok-2");
}

/// Same shape as [`RefreshFakeTransport`] (401-invalidate-and-refetch), but
/// scheme-parameterized to `http://` throughout — including the bearer
/// challenge's `realm` — and hard-fails on ANY `https://` request. Backs
/// [`manifest_401_retry_reacquires_token_over_original_scheme`] below.
struct HttpSchemeOnlyFakeTransport {
    token_calls: Mutex<u32>,
    manifest_attempts: Mutex<u32>,
    manifest_body: Vec<u8>,
}

impl HttpSchemeOnlyFakeTransport {
    fn request(
        &self,
        _method: &str,
        url: &str,
        headers: &[(&str, &str)],
        _cap: u64,
        sink: Sink<'_>,
    ) -> Result<HttpResponse, FetchError> {
        assert!(
            !url.starts_with("https://"),
            "unexpected https:// request on an http-scheme pull: {url}"
        );
        if url.ends_with("/v2/") {
            let mut hmap = ureq::http::HeaderMap::new();
            hmap.insert(
                ureq::http::HeaderName::from_static("www-authenticate"),
                ureq::http::HeaderValue::from_str(r#"Bearer realm="http://ghcr.io/token",service="ghcr.io""#)
                    .unwrap(),
            );
            return Ok(HttpResponse { status: 401, headers: hmap });
        }
        if url.starts_with("http://ghcr.io/token") {
            let mut n = self.token_calls.lock().unwrap();
            *n += 1;
            let body = format!(r#"{{"token": "tok-{n}"}}"#);
            if let Sink::Bytes(buf) = sink {
                buf.extend_from_slice(body.as_bytes());
            }
            return Ok(HttpResponse {
                status: 200,
                headers: ureq::http::HeaderMap::new(),
            });
        }
        if url.contains("/manifests/") {
            let mut n = self.manifest_attempts.lock().unwrap();
            *n += 1;
            let auth = headers.iter().find(|h| h.0.eq_ignore_ascii_case("authorization")).map(|h| h.1);
            if auth == Some("Bearer tok-1") {
                return Ok(HttpResponse {
                    status: 401,
                    headers: ureq::http::HeaderMap::new(),
                });
            }
            if let Sink::Bytes(buf) = sink {
                buf.extend_from_slice(&self.manifest_body);
            }
            return Ok(HttpResponse {
                status: 200,
                headers: ureq::http::HeaderMap::new(),
            });
        }
        panic!("unexpected url {url}");
    }
}

#[test]
fn manifest_401_retry_reacquires_token_over_original_scheme() {
    // Code-review Fix 3 (parity pin with Python's
    // `test_manifest_401_retry_reacquires_token_over_original_scheme`, added
    // for the L2 fix): a 401-retry must reacquire the token over the SAME
    // scheme as the original call (`http` vs. `https`) — not silently
    // upgrade to https. Rust's `get_with_auth_retry` already threads
    // `scheme` correctly through the retry's `self.token(registry,
    // repository, scheme)` call (unlike Python before the L2 fix); this
    // pins that existing-correct behavior with a dedicated regression test,
    // mirroring Python's coverage. The fake transport panics on ANY
    // `https://` request, so every step of this http-scheme pull —
    // challenge, token endpoint, manifest, and the retry's token
    // reacquisition — must stay on `http://` end to end.
    let manifest_body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": []
    })
    .to_string()
    .into_bytes();
    let mut hasher = Sha256::new();
    hasher.update(&manifest_body);
    let manifest_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    let transport = Arc::new(HttpSchemeOnlyFakeTransport {
        token_calls: Mutex::new(0),
        manifest_attempts: Mutex::new(0),
        manifest_body,
    });
    let transport_for_client = Arc::clone(&transport);
    let client = OciRegistryClient::new(
        Box::new(move |m, u, h, c, s| transport_for_client.request(m, u, h, c, s)),
        Arc::new(TokenCache::new()),
    );

    let stale_token = client.token(REGISTRY, REPOSITORY, "http").unwrap();
    assert_eq!(stale_token, "tok-1");

    let manifest = client
        .manifest(REGISTRY, REPOSITORY, &manifest_digest, &stale_token, "http")
        .unwrap();
    assert!(manifest.layers.is_empty());
    assert_eq!(*transport.manifest_attempts.lock().unwrap(), 2);
    assert_eq!(*transport.token_calls.lock().unwrap(), 2);

    // The cache now holds the refreshed token, acquired over http.
    assert_eq!(client.token(REGISTRY, REPOSITORY, "http").unwrap(), "tok-2");
}

// ---------------------------------------------------------------------------
// (j) select_source_layer: NO-TARBALL / AMBIGUOUS-TARBALL
// ---------------------------------------------------------------------------

#[test]
fn select_source_layer_happy_single_tarball() {
    let source_layer = Layer {
        media_type: SOURCE_LAYER_MEDIA_TYPE.to_string(),
        digest: format!("sha256:{}", "0".repeat(64)),
        size: 1,
    };
    let manifest = Manifest {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        artifact_type: Some(SOURCE_ARTIFACT_TYPE.to_string()),
        config_media_type: Some(EMPTY_CONFIG_MEDIA_TYPE.to_string()),
        layers: vec![source_layer],
    };
    let layer = select_source_layer(&manifest).unwrap();
    assert_eq!(layer.digest, format!("sha256:{}", "0".repeat(64)));
}

#[test]
fn select_source_layer_no_tarball_raises() {
    let manifest = Manifest {
        media_type: "x".to_string(),
        artifact_type: None,
        config_media_type: None,
        layers: vec![],
    };
    let err = select_source_layer(&manifest).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-NO-TARBALL");
}

#[test]
fn select_source_layer_wrong_layer_media_type_is_no_tarball() {
    let wrong_layer = Layer {
        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
        digest: format!("sha256:{}", "1".repeat(64)),
        size: 1,
    };
    let manifest = Manifest {
        media_type: "x".to_string(),
        artifact_type: Some(SOURCE_ARTIFACT_TYPE.to_string()),
        config_media_type: None,
        layers: vec![wrong_layer],
    };
    let err = select_source_layer(&manifest).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-NO-TARBALL");
}

#[test]
fn select_source_layer_wrong_artifact_type_is_no_tarball() {
    let source_layer = Layer {
        media_type: SOURCE_LAYER_MEDIA_TYPE.to_string(),
        digest: format!("sha256:{}", "2".repeat(64)),
        size: 1,
    };
    let manifest = Manifest {
        media_type: "x".to_string(),
        artifact_type: Some("application/vnd.other.thing.v1".to_string()),
        config_media_type: None,
        layers: vec![source_layer],
    };
    let err = select_source_layer(&manifest).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-NO-TARBALL");
}

#[test]
fn select_source_layer_ambiguous_raises() {
    let first_layer = Layer {
        media_type: SOURCE_LAYER_MEDIA_TYPE.to_string(),
        digest: format!("sha256:{}", "3".repeat(64)),
        size: 1,
    };
    let second_layer = Layer {
        media_type: SOURCE_LAYER_MEDIA_TYPE.to_string(),
        digest: format!("sha256:{}", "4".repeat(64)),
        size: 1,
    };
    let manifest = Manifest {
        media_type: "x".to_string(),
        artifact_type: Some(SOURCE_ARTIFACT_TYPE.to_string()),
        config_media_type: None,
        layers: vec![first_layer, second_layer],
    };
    let err = select_source_layer(&manifest).unwrap_err();
    assert_eq!(err.code(), "FETCH-OCI-AMBIGUOUS-TARBALL");
}

// ---------------------------------------------------------------------------
// M8: OciRegistryClient over the REAL bounded_http::request transport
// ---------------------------------------------------------------------------
//
// Every other test in this file drives `OciRegistryClient` over a
// fixture-replaying or hand-built FAKE `OciTransport` closure — none of them
// ever call the real `bounded_http::request` transport, so this client's own
// wiring onto it (redirect-following, cap enforcement, header handling as
// seen from the CLIENT's call sites) is unexercised end-to-end
// (`bounded_http_tests.rs` covers the transport in isolation, but not driven
// through `OciRegistryClient`). This closes that gap with one real
// happy-path pull (token -> manifest -> blob) against a local in-process
// HTTP/1.1 test server, through the SAME production transport
// `fetchers::fetch_oci` uses (`Box::new(bounded_http::request)`).
//
// Minimal, self-contained HTTP/1.1 server harness — a deliberate, narrower
// duplicate of `bounded_http_tests.rs`'s own `spawn_server`/`serve_one`. That
// harness is private to `bounded_http.rs`'s own test submodule and out of
// scope to expose from here (M8 does not touch `bounded_http.rs`); this
// local copy only needs to serve fixed `(method, path) -> (status, headers,
// body)` responses, not the fuller request-capturing surface
// `bounded_http_tests.rs` needs for its own redirect/header assertions.

struct M8Response {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn m8_spawn_server<F>(handler: F) -> SocketAddr
where
    F: Fn(&str, &str) -> M8Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handler = Arc::clone(&handler);
            thread::spawn(move || m8_serve_one(stream, &*handler));
        }
    });
    addr
}

fn m8_serve_one(mut stream: TcpStream, handler: &dyn Fn(&str, &str) -> M8Response) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    // Drain (and discard) headers — this fake never needs to inspect them.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
    }
    let response = handler(&method, &path);
    let mut out = format!("HTTP/1.1 {} X\r\n", response.status);
    for (key, value) in &response.headers {
        out.push_str(&format!("{key}: {value}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
    out.push_str("Connection: close\r\n\r\n");
    let _ = stream.write_all(out.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

#[test]
fn oci_registry_client_real_transport_happy_pull_end_to_end() {
    // A valid milpa OCI artifact shape (RFC §1/§3.2 step 3), with REAL sha256
    // digests so the client's own digest-verification steps are exercised
    // for real, not against a canned expectation the test hands it.
    let blob_body = b"M8: real bounded_http::request transport, real socket".to_vec();
    let blob_digest = format!("sha256:{}", hex::encode(Sha256::digest(&blob_body)));
    let manifest_body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": SOURCE_ARTIFACT_TYPE,
        "config": { "mediaType": EMPTY_CONFIG_MEDIA_TYPE, "digest": format!("sha256:{}", "0".repeat(64)), "size": 2 },
        "layers": [{ "mediaType": SOURCE_LAYER_MEDIA_TYPE, "digest": blob_digest, "size": blob_body.len() }],
    })
    .to_string()
    .into_bytes();
    let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_body)));

    let addr_holder: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let addr_holder_for_handler = Arc::clone(&addr_holder);
    let manifest_body_for_handler = manifest_body.clone();
    let blob_body_for_handler = blob_body.clone();
    let manifest_path_prefix = format!("/v2/{REPOSITORY}/manifests/");
    let blob_path_prefix = format!("/v2/{REPOSITORY}/blobs/");

    let addr = m8_spawn_server(move |method, path| {
        if path == "/v2/" {
            let self_addr = addr_holder_for_handler
                .lock()
                .unwrap()
                .expect("addr set before the first request is issued");
            return M8Response {
                status: 401,
                headers: vec![(
                    "WWW-Authenticate",
                    format!(r#"Bearer realm="http://{self_addr}/token",service="test-registry""#),
                )],
                body: Vec::new(),
            };
        }
        if path.starts_with("/token") {
            return M8Response {
                status: 200,
                headers: vec![],
                body: br#"{"token": "real-transport-token"}"#.to_vec(),
            };
        }
        if path.starts_with(&manifest_path_prefix) {
            return M8Response {
                status: 200,
                headers: vec![],
                body: manifest_body_for_handler.clone(),
            };
        }
        if path.starts_with(&blob_path_prefix) {
            return M8Response {
                status: 200,
                headers: vec![],
                body: blob_body_for_handler.clone(),
            };
        }
        panic!("unexpected request {method} {path}");
    });
    *addr_holder.lock().unwrap() = Some(addr);

    // The production transport, unmodified — the exact value
    // `fetchers.rs::fetch_oci` passes to `OciRegistryClient::new`.
    let client = OciRegistryClient::new(Box::new(bounded_http::request), Arc::new(TokenCache::new()));
    let registry = addr.to_string();

    let token = client.token(&registry, REPOSITORY, "http").expect("token via real transport");
    assert_eq!(token, "real-transport-token");

    let manifest = client
        .manifest(&registry, REPOSITORY, &manifest_digest, &token, "http")
        .expect("manifest via real transport");
    let layer = select_source_layer(&manifest).expect("layer");
    assert_eq!(layer.digest, blob_digest);

    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("blob.tar.gz");
    client
        .blob(&registry, REPOSITORY, &layer.digest, Some(layer.size), &token, &dest, "http")
        .expect("blob via real transport");
    assert_eq!(std::fs::read(&dest).unwrap(), blob_body);
}

#[test]
fn oci_registry_client_shared_token_cache_across_clients_issues_one_challenge() {
    // #203 (production-path proof): `fetchers.rs::fetch_oci` constructs a
    // FRESH `OciRegistryClient` per dep fetch but hands each one
    // `Arc::clone(&DefaultRegistry::oci_token_cache)` — the SAME underlying
    // cache for the whole resolve. This test drives that exact shape (two
    // independently constructed `OciRegistryClient`s sharing one
    // `Arc<TokenCache>`) over the REAL, unmodified `bounded_http::request`
    // transport (the same value `fetch_oci` passes) against a real loopback
    // socket, with a request-COUNTING spy on the `/v2/` challenge path —
    // not exchange-list exhaustion — so the assertion is a direct count of
    // token challenges, not an indirect "did the fixture desync" signal.
    let challenge_count = Arc::new(Mutex::new(0u32));
    let challenge_count_for_handler = Arc::clone(&challenge_count);
    let addr_holder: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let addr_holder_for_handler = Arc::clone(&addr_holder);

    let addr = m8_spawn_server(move |_method, path| {
        if path == "/v2/" {
            *challenge_count_for_handler.lock().unwrap() += 1;
            let self_addr = addr_holder_for_handler
                .lock()
                .unwrap()
                .expect("addr set before the first request is issued");
            return M8Response {
                status: 401,
                headers: vec![(
                    "WWW-Authenticate",
                    format!(r#"Bearer realm="http://{self_addr}/token",service="test-registry""#),
                )],
                body: Vec::new(),
            };
        }
        if path.starts_with("/token") {
            return M8Response {
                status: 200,
                headers: vec![],
                body: br#"{"token": "shared-cache-token"}"#.to_vec(),
            };
        }
        panic!("unexpected request {path}");
    });
    *addr_holder.lock().unwrap() = Some(addr);
    let registry = addr.to_string();

    let shared_cache = Arc::new(TokenCache::new());

    // Client 1 — the shape `fetch_oci` constructs for the FIRST OCI dep in a
    // resolve sharing this `(registry, scope)`.
    let client1 = OciRegistryClient::new(Box::new(bounded_http::request), Arc::clone(&shared_cache));
    let token1 = client1
        .token(&registry, REPOSITORY, "http")
        .expect("first dep's token via real transport");
    assert_eq!(token1, "shared-cache-token");

    // Client 2 — a SEPARATE `OciRegistryClient` (the shape `fetch_oci`
    // constructs for a SECOND OCI dep with the same (registry, scope)),
    // sharing the identical `Arc<TokenCache>`.
    let client2 = OciRegistryClient::new(Box::new(bounded_http::request), Arc::clone(&shared_cache));
    let token2 = client2
        .token(&registry, REPOSITORY, "http")
        .expect("second dep's token must be served from the shared cache");
    assert_eq!(token2, "shared-cache-token");

    assert_eq!(
        *challenge_count.lock().unwrap(),
        1,
        "#203: two OciRegistryClients sharing one Arc<TokenCache> must trigger exactly ONE token challenge"
    );
}

// ---------------------------------------------------------------------------
// Fixture shape sanity (mirrors schema.json without a JSON Schema validator)
// ---------------------------------------------------------------------------

#[test]
fn fixtures_validate_against_schema_shape() {
    for name in [
        "happy-pull.json",
        "manifest-digest-mismatch.json",
        "blob-digest-mismatch.json",
        "manifest-list-rejected.json",
        "token-endpoint-error.json",
        "manifest-not-found.json",
        "blob-fetch-error.json",
        "www-auth-multiple-challenges.json",
        "www-auth-basic-only.json",
        "www-auth-missing-realm.json",
        "www-auth-missing-service.json",
        "blob-redirect-cross-host.json",
        "token-realm-non-http.json",
        "manifest-not-an-object.json",
        "token-access-token-only.json",
        "token-invalid-json.json",
        "token-neither-field.json",
    ] {
        let data = load_fixture(name);
        assert!(
            data.get("description").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty()),
            "{name}: missing/empty description"
        );
        for exch in data["exchanges"].as_array().expect("exchanges array") {
            let method = exch["method"].as_str().expect("method");
            assert!(
                matches!(method, "GET" | "HEAD" | "POST" | "PUT"),
                "{name}: bad method {method}"
            );
            assert!(exch["url"].is_string(), "{name}: bad url");
            assert!(exch["response"]["status"].is_u64(), "{name}: response missing status");
            let response = &exch["response"];
            let body_fields = ["body", "body_base64", "body_file"]
                .iter()
                .filter(|f| response.get(**f).is_some())
                .count();
            assert!(body_fields <= 1, "{name}: multiple body fields present");
        }
    }
}
