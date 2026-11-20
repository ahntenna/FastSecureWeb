//! 보안 동작을 테스트로 고정한다. 통제가 "있는지"가 아니라 "작동하는지"를 본다.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{json, Value};
use tower::ServiceExt;

use server::config::Config;
use server::security::crypto;
use server::{build_app, build_state};

const HOST: &str = "testserver";

struct Harness {
    app: Router,
    identity_pub: Vec<u8>,
    _dir: tempfile::TempDir,
}

/// 운영 설정으로 앱을 만든다. overrides 로 일부 값을 바꾼다.
async fn harness(overrides: &[(&str, &str)]) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let key = p256::SecretKey::from_slice(&crypto::random_bytes::<32>()).unwrap();
    let key_path = dir.path().join("server_sign_key.pem");
    std::fs::write(&key_path, key.to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();

    let mut env: HashMap<String, String> = HashMap::from([
        ("APP_ENV".to_owned(), "production".to_owned()),
        ("ALLOWED_HOSTS".to_owned(), HOST.to_owned()),
        ("DATABASE_PATH".to_owned(), dir.path().join("test.db").to_string_lossy().into_owned()),
        ("SERVER_SIGN_KEY_FILE".to_owned(), key_path.to_string_lossy().into_owned()),
    ]);
    for (k, v) in overrides {
        env.insert((*k).to_owned(), (*v).to_owned());
    }
    let state = build_state(Config::from_map(&env).unwrap()).await.unwrap();
    let identity_pub = state.identity.public_raw();
    Harness { app: build_app(state), identity_pub, _dir: dir }
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    Reply { status: parts.status, headers: parts.headers, body: to_bytes(body, usize::MAX).await.unwrap().to_vec() }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
}

/// 프론트의 security/channel.ts 와 같은 일을 하는 테스트용 클라이언트.
struct Client<'a> {
    h: &'a Harness,
    cookie: String,
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

struct Signed {
    ts: String,
    nonce: String,
    sig: String,
    body: Vec<u8>,
}

impl<'a> Client<'a> {
    fn new(h: &'a Harness) -> Self {
        Self { h, cookie: String::new(), enc_key: [0; 32], mac_key: [0; 32] }
    }

    async fn connect(h: &'a Harness) -> Self {
        let mut client = Self::new(h);
        assert_eq!(client.handshake().await.status, StatusCode::OK);
        client
    }

    async fn handshake(&mut self) -> Reply {
        let secret = crypto::ephemeral_secret();
        let client_pub = crypto::public_raw(&secret);
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/hs")
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json");
        if !self.cookie.is_empty() {
            request = request.header(header::COOKIE, &self.cookie);
        }
        let body = json!({ "pub": crypto::b64u(&client_pub) }).to_string();
        let reply = send(&self.h.app, request.body(Body::from(body)).unwrap()).await;
        if reply.status != StatusCode::OK {
            return reply;
        }
        let payload = reply.json();
        let server_pub = crypto::b64u_decode(payload["pub"].as_str().unwrap()).unwrap();
        let salt = crypto::b64u_decode(payload["salt"].as_str().unwrap()).unwrap();
        let sig = crypto::b64u_decode(payload["sig"].as_str().unwrap()).unwrap();

        // 서버 신원 검증
        let message = [crypto::HS_CONTEXT, &server_pub, &client_pub, &salt].concat();
        let verifying = VerifyingKey::from_sec1_bytes(&self.h.identity_pub).unwrap();
        verifying.verify(&message, &Signature::from_slice(&sig).unwrap()).expect("서버 서명 검증");

        let shared = crypto::ecdh(&secret, &server_pub).unwrap();
        (self.enc_key, self.mac_key) = crypto::derive_keys(&shared, &salt);
        let set_cookie = reply.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        self.cookie = set_cookie.split(';').next().unwrap().to_owned();
        reply
    }

    /// 서명·암호화된 요청 조각을 만든다. 테스트가 전송 전에 변조할 수 있게 분리했다.
    fn build(&self, method: &str, target: &str, body: Option<Value>, ts: Option<String>) -> Signed {
        let ts = ts.unwrap_or_else(|| now_ms().to_string());
        let nonce = crypto::b64u(&crypto::random_bytes::<16>());
        let sealed = match body {
            Some(value) => crypto::seal(
                &self.enc_key,
                value.to_string().as_bytes(),
                &crypto::request_aad(method, target, &ts, &nonce),
            ),
            None => Vec::new(),
        };
        let sig = crypto::b64u(&crypto::sign_request(&self.mac_key, method, target, &ts, &nonce, &sealed));
        Signed { ts, nonce, sig, body: sealed }
    }

    async fn transmit(&self, method: &str, target: &str, signed: &Signed, body: Vec<u8>) -> Reply {
        let mut request = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).unwrap())
            .uri(target)
            .header(header::HOST, HOST)
            .header(header::COOKIE, &self.cookie)
            .header("x-ts", &signed.ts)
            .header("x-nonce", &signed.nonce)
            .header("x-sig", &signed.sig);
        if !body.is_empty() {
            request = request.header(header::CONTENT_TYPE, "application/octet-stream");
        }
        send(&self.h.app, request.body(Body::from(body)).unwrap()).await
    }

    async fn call(&self, method: &str, target: &str, body: Option<Value>) -> Reply {
        let signed = self.build(method, target, body, None);
        self.transmit(method, target, &signed, signed.body.clone()).await
    }

    /// 요청을 보내고 암호화된 응답을 복호화해 (상태, JSON) 으로 돌려준다.
    async fn json(&self, method: &str, target: &str, body: Option<Value>) -> (StatusCode, Value) {
        let signed = self.build(method, target, body, None);
        let reply = self.transmit(method, target, &signed, signed.body.clone()).await;
        assert_eq!(reply.headers.get("x-enc").map(|v| v.to_str().unwrap()), Some("1"));
        let plain =
            crypto::unseal(&self.enc_key, &reply.body, &crypto::response_aad(&signed.nonce, reply.status.as_u16()))
                .expect("응답 복호화");
        (reply.status, serde_json::from_slice(&plain).unwrap())
    }
}

fn plain_request(method: Method, target: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(target).header(header::HOST, HOST)
}

// ── 설정 ────────────────────────────────────────────────────────────────
#[test]
fn production_refuses_unsafe_settings() {
    let base = |hosts: &str, channel: &str| {
        HashMap::from([
            ("ALLOWED_HOSTS".to_owned(), hosts.to_owned()),
            ("SECURE_CHANNEL".to_owned(), channel.to_owned()),
        ])
    };
    assert!(Config::from_map(&base("", "true")).is_err());
    assert!(Config::from_map(&base("*", "true")).is_err());
    assert!(Config::from_map(&base("example.com", "false")).is_err());
    assert!(Config::from_map(&base("example.com", "true")).is_ok());
}

#[tokio::test]
async fn unknown_host_rejected() {
    let h = harness(&[]).await;
    let request = Request::builder().uri("/api/health").header(header::HOST, "evil.example").body(Body::empty());
    assert_eq!(send(&h.app, request.unwrap()).await.status, StatusCode::BAD_REQUEST);
}

// ── 핸드셰이크 ──────────────────────────────────────────────────────────
#[tokio::test]
async fn health_needs_no_channel() {
    let h = harness(&[]).await;
    let reply = send(&h.app, plain_request(Method::GET, "/api/health").body(Body::empty()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.json(), json!({ "status": "ok" }));
}

#[tokio::test]
async fn handshake_sets_hardened_cookie() {
    let h = harness(&[]).await;
    let mut client = Client::new(&h);
    let reply = client.handshake().await; // 서버 서명 검증 포함
    assert_eq!(reply.status, StatusCode::OK);
    let cookie = reply.headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_ascii_lowercase();
    assert!(cookie.starts_with("__host-sid="));
    for attribute in ["httponly", "secure", "samesite=strict", "path=/"] {
        assert!(cookie.contains(attribute), "쿠키에 {attribute} 가 없다: {cookie}");
    }
    assert_eq!(reply.headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
}

#[tokio::test]
async fn handshake_rejects_invalid_input() {
    let h = harness(&[]).await;
    let post = |body: Value| {
        plain_request(Method::POST, "/api/hs")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let mut point = vec![0x04u8];
    point.extend_from_slice(&[1u8; 64]); // 곡선 위에 없는 점
    let bad = crypto::b64u(&point);
    assert_eq!(send(&h.app, post(json!({ "pub": bad }))).await.status, StatusCode::BAD_REQUEST);
    assert_eq!(send(&h.app, post(json!({ "pub": "short" }))).await.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(send(&h.app, post(json!({ "pub": bad, "extra": 1 }))).await.status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn handshake_rate_limited() {
    let h = harness(&[("HANDSHAKE_RATE_PER_MIN", "3")]).await;
    let mut client = Client::new(&h);
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(client.handshake().await.status.as_u16());
    }
    assert_eq!(statuses, [200, 200, 200, 429, 429]);
}

#[tokio::test]
async fn cross_site_origin_rejected() {
    let h = harness(&[]).await;
    let request = plain_request(Method::POST, "/api/hs")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let reply = send(&h.app, request).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json()["code"], "origin");
}

// ── 보안 채널: 정상 흐름 ────────────────────────────────────────────────
#[tokio::test]
async fn request_without_session_is_rejected() {
    let h = harness(&[]).await;
    let reply = send(&h.app, plain_request(Method::GET, "/api/notes").body(Body::empty()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.json()["code"], "channel");
    // 존재하지 않는 경로도 채널 없이는 401 이다(경로 존재 여부를 드러내지 않는다).
    let reply = send(&h.app, plain_request(Method::GET, "/api/nope").body(Body::empty()).unwrap()).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    // 평문 JSON 으로 본문을 보내도 통하지 않는다.
    let request = plain_request(Method::POST, "/api/notes")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "title": "x" }).to_string()))
        .unwrap();
    assert_eq!(send(&h.app, request).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn encrypted_roundtrip() {
    let h = harness(&[]).await;
    let client = Client::connect(&h).await;

    let signed = client.build("POST", "/api/notes", Some(json!({ "title": "hello", "body": "world" })), None);
    let reply = client.transmit("POST", "/api/notes", &signed, signed.body.clone()).await;
    assert_eq!(reply.status, StatusCode::CREATED);
    // 전송 구간의 본문은 JSON 이 아니다(프록시에서 평문이 보이지 않는다).
    assert_eq!(reply.headers.get(header::CONTENT_TYPE).unwrap(), "application/octet-stream");
    assert!(serde_json::from_slice::<Value>(&reply.body).is_err());
    let created: Value = serde_json::from_slice(
        &crypto::unseal(&client.enc_key, &reply.body, &crypto::response_aad(&signed.nonce, 201)).unwrap(),
    )
    .unwrap();
    assert_eq!(created["title"], "hello");

    let (status, notes) = client.json("GET", "/api/notes?limit=10", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(notes.as_array().unwrap().len(), 1);

    let reply = client.call("DELETE", &format!("/api/notes/{}", created["id"]), None).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.body.is_empty());
}

#[tokio::test]
async fn invalid_input_rejected() {
    let h = harness(&[]).await;
    let client = Client::connect(&h).await;
    let (status, _) = client.json("POST", "/api/notes", Some(json!({ "title": "x", "is_admin": true }))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = client.json("POST", "/api/notes", Some(json!({ "title": "" }))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = client.json("GET", "/api/notes?limit=100000", None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = client.json("DELETE", "/api/notes/999999", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── 보안 채널: 변조·재전송 ──────────────────────────────────────────────
#[tokio::test]
async fn tampered_requests_rejected() {
    let h = harness(&[]).await;
    let client = Client::connect(&h).await;

    // 본문 1비트 변조
    let signed = client.build("POST", "/api/notes", Some(json!({ "title": "legit" })), None);
    let mut tampered = signed.body.clone();
    tampered[0] ^= 0x01;
    assert_eq!(client.transmit("POST", "/api/notes", &signed, tampered).await.status, StatusCode::UNAUTHORIZED);

    // 유효한 헤더에 평문 본문 바꿔치기
    let signed = client.build("POST", "/api/notes", Some(json!({ "title": "legit" })), None);
    let forged = br#"{"title":"forged"}"#.to_vec();
    assert_eq!(client.transmit("POST", "/api/notes", &signed, forged).await.status, StatusCode::UNAUTHORIZED);

    // 쿼리 변조
    let signed = client.build("GET", "/api/notes?limit=1", None, None);
    assert_eq!(
        client.transmit("GET", "/api/notes?limit=100", &signed, Vec::new()).await.status,
        StatusCode::UNAUTHORIZED
    );

    // 메서드·경로 변조
    let signed = client.build("GET", "/api/notes", None, None);
    assert_eq!(client.transmit("DELETE", "/api/notes/1", &signed, Vec::new()).await.status, StatusCode::UNAUTHORIZED);

    // 서명 위조
    let mut signed = client.build("GET", "/api/notes", None, None);
    signed.sig = crypto::b64u(&[0u8; 32]);
    assert_eq!(client.transmit("GET", "/api/notes", &signed, Vec::new()).await.status, StatusCode::UNAUTHORIZED);
    signed.sig = "not-a-signature".to_owned();
    assert_eq!(client.transmit("GET", "/api/notes", &signed, Vec::new()).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replay_rejected() {
    let h = harness(&[]).await;
    let client = Client::connect(&h).await;
    let signed = client.build("POST", "/api/notes", Some(json!({ "title": "once" })), None);
    assert_eq!(client.transmit("POST", "/api/notes", &signed, signed.body.clone()).await.status, StatusCode::CREATED);
    assert_eq!(
        client.transmit("POST", "/api/notes", &signed, signed.body.clone()).await.status,
        StatusCode::UNAUTHORIZED
    );
    let (_, notes) = client.json("GET", "/api/notes", None).await;
    assert_eq!(notes.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn stale_timestamp_rejected() {
    let h = harness(&[]).await;
    let client = Client::connect(&h).await;
    for ts in [now_ms() - 120_000, now_ms() + 120_000] {
        let signed = client.build("GET", "/api/notes", None, Some(ts.to_string()));
        assert_eq!(client.transmit("GET", "/api/notes", &signed, Vec::new()).await.status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn keys_from_replaced_session_rejected() {
    let h = harness(&[]).await;
    let mut client = Client::connect(&h).await;
    let (old_enc, old_mac, old_cookie) = (client.enc_key, client.mac_key, client.cookie.clone());
    client.handshake().await; // 새 세션으로 교체되고 이전 세션은 삭제된다
    assert_eq!(client.call("GET", "/api/notes", None).await.status, StatusCode::OK);

    let stale = Client { h: &h, cookie: old_cookie, enc_key: old_enc, mac_key: old_mac };
    assert_eq!(stale.call("GET", "/api/notes", None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oversized_body_rejected() {
    let h = harness(&[("MAX_BODY_BYTES", "2048")]).await;
    let client = Client::connect(&h).await;
    let reply = client.call("POST", "/api/notes", Some(json!({ "title": "a", "body": "b".repeat(3000) }))).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
}

// ── 클라이언트 가드 신호 ────────────────────────────────────────────────
#[tokio::test]
async fn guard_signal_revokes_session() {
    let h = harness(&[]).await;
    let mut client = Client::connect(&h).await;

    // 오탐이 잦은 신호는 기록만 한다
    let (_, body) = client.json("POST", "/api/sec/report", Some(json!({ "signal": "devtools-size", "path": "/" }))).await;
    assert_eq!(body, json!({ "action": "none" }));
    assert_eq!(client.call("GET", "/api/notes", None).await.status, StatusCode::OK);

    // 허용 목록에 없는 신호는 거부
    let (status, _) = client.json("POST", "/api/sec/report", Some(json!({ "signal": "<script>" }))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, body) =
        client.json("POST", "/api/sec/report", Some(json!({ "signal": "devtools-timing", "path": "/" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "action": "block" }));
    let reply = client.call("GET", "/api/notes", None).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json()["code"], "revoked");

    // 무효화된 뒤 다시 핸드셰이크하면 새 세션이 발급되고 정상 동작한다
    assert_eq!(client.handshake().await.status, StatusCode::OK);
    assert_eq!(client.call("GET", "/api/notes", None).await.status, StatusCode::OK);
}

#[tokio::test]
async fn guard_report_policy_never_revokes() {
    let h = harness(&[("GUARD_POLICY", "report")]).await;
    let client = Client::connect(&h).await;
    let (_, body) = client.json("POST", "/api/sec/report", Some(json!({ "signal": "devtools-timing" }))).await;
    assert_eq!(body, json!({ "action": "none" }));
    assert_eq!(client.call("GET", "/api/notes", None).await.status, StatusCode::OK);
}
