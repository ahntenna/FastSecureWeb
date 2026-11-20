//! 보안 채널 미들웨어.
//!
//! /api/ 아래의 모든 요청에 대해 (면제 경로 제외)
//!   세션 확인 → 타임스탬프 → 서명 → nonce(재전송) → 본문 복호화 → 라우터 → 응답 암호화
//! 순서로 처리한다. 프록시 도구로 본문·경로·쿼리를 고치거나 요청을 다시 보내면 여기서 거부된다.
//!
//! 주의: 응답을 모아서 암호화하므로 /api/ 아래에서는 스트리밍 응답을 쓸 수 없다.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST, ORIGIN};
use axum::http::{Extensions, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::crypto;
use super::sessions::Lookup;
use crate::config::Config;
use crate::state::AppState;

/// 보안 채널 없이 접근하는 경로: 상태 확인, 핸드셰이크
const EXEMPT_PATHS: [&str; 2] = ["/api/health", "/api/hs"];

/// 실제 클라이언트 IP. 프록시 헤더는 설정으로 신뢰가 확인된 경우에만 쓴다.
pub fn client_ip(cfg: &Config, headers: &HeaderMap, extensions: &Extensions) -> String {
    if cfg.trust_proxy_headers {
        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            return value.chars().take(64).collect();
        }
    }
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_owned())
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for header in headers.get_all(COOKIE) {
        let Ok(text) = header.to_str() else { continue };
        for pair in text.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=') {
                if key == name {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

/// "host:port" / "[::1]:port" 에서 호스트 이름만 꺼낸다(소문자).
fn host_name(value: &str) -> String {
    let value = value.trim();
    let host = if value.starts_with('[') {
        value.split_inclusive(']').next().unwrap_or(value)
    } else {
        value.split(':').next().unwrap_or(value)
    };
    host.to_ascii_lowercase()
}

pub fn plain_json(status: StatusCode, code: &str) -> Response {
    let body = format!("{{\"detail\": \"request rejected\", \"code\": \"{code}\"}}");
    (status, [(CONTENT_TYPE, "application/json"), (CACHE_CONTROL, "no-store")], body).into_response()
}

/// Host 헤더가 허용 목록에 있는지 확인한다(Host 헤더 조작 차단).
pub async fn host_check(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let host = request.headers().get(HOST).and_then(|v| v.to_str().ok()).map(host_name).unwrap_or_default();
    if !state.cfg.allowed_hosts.iter().any(|allowed| allowed.eq_ignore_ascii_case(&host)) {
        return plain_json(StatusCode::BAD_REQUEST, "host");
    }
    next.run(request).await
}

/// 상태 변경 요청의 Origin 이 요청 Host 와 같은 호스트인지 확인한다(교차 사이트 요청 차단).
pub async fn origin_check(request: Request, next: Next) -> Response {
    let safe = matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if !safe {
        if let Some(origin) = request.headers().get(ORIGIN) {
            let origin = origin.to_str().unwrap_or("");
            let origin_host = origin
                .split_once("://")
                .map(|(_, rest)| host_name(rest.split('/').next().unwrap_or("")))
                .unwrap_or_default();
            let request_host =
                request.headers().get(HOST).and_then(|v| v.to_str().ok()).map(host_name).unwrap_or_default();
            if origin_host.is_empty() || origin_host != request_host {
                return plain_json(StatusCode::FORBIDDEN, "origin");
            }
        }
    }
    next.run(request).await
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

pub async fn secure_channel(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if !state.cfg.secure_channel || !path.starts_with("/api/") || EXEMPT_PATHS.contains(&path.as_str()) {
        return next.run(request).await;
    }

    // Body 는 Sync 가 아니므로, 헤더를 빌린 채로 await 하지 않도록 먼저 분리한다.
    let (mut parts, body) = request.into_parts();
    let ip = client_ip(&state.cfg, &parts.headers, &parts.extensions);
    let method = parts.method.as_str().to_owned();
    // 서명 대상은 받은 그대로의 경로+쿼리다.
    let target = parts.uri.path_and_query().map(|pq| pq.as_str().to_owned()).unwrap_or_else(|| path.clone());

    // 1) 세션
    let sid = cookie_value(&parts.headers, state.cfg.cookie_name()).unwrap_or_default();
    let session = match state.store.lookup(&sid) {
        // 세션 없음은 정상 흐름(만료·서버 재시작)에서도 생기므로 이벤트로 남기지 않는다.
        Lookup::Missing => return plain_json(StatusCode::UNAUTHORIZED, "channel"),
        Lookup::Revoked => return plain_json(StatusCode::FORBIDDEN, "revoked"),
        Lookup::Active(session) => session,
    };

    let reject = |status: StatusCode, code: &'static str, kind: &'static str| {
        let state = state.clone();
        let (ip, sid, path) = (ip.clone(), sid.clone(), path.clone());
        async move {
            state.events.record(kind, &ip, Some(&sid), &path).await;
            plain_json(status, code)
        }
    };

    // 2) 헤더 형식
    let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
    let (ts, nonce, sig_text) = (header("x-ts"), header("x-nonce"), header("x-sig"));
    let well_formed = !ts.is_empty()
        && ts.len() <= 15
        && ts.bytes().all(|b| b.is_ascii_digit())
        && (16..=64).contains(&nonce.len())
        && sig_text.len() == 43;
    if !well_formed {
        return reject(StatusCode::UNAUTHORIZED, "channel", "bad-headers").await;
    }

    // 3) 본문 크기 (프록시의 client_max_body_size 에 더한 두 번째 방어선)
    let limit = state.cfg.max_body_bytes;
    let declared = parts.headers.get(CONTENT_LENGTH).map(|v| v.to_str().ok().and_then(|v| v.parse::<usize>().ok()));
    if matches!(declared, Some(length) if !length.is_some_and(|n| n <= limit)) {
        return reject(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "body-too-large").await;
    }
    let Ok(body) = to_bytes(body, limit).await else {
        return reject(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "body-too-large").await;
    };

    // 4) 타임스탬프 창
    let sent_at: u128 = ts.parse().unwrap_or(0);
    if now_ms().abs_diff(sent_at) > u128::from(state.cfg.ts_skew_seconds) * 1000 {
        return reject(StatusCode::UNAUTHORIZED, "channel", "stale-timestamp").await;
    }

    // 5) 서명: 메서드·경로·쿼리·본문 중 하나라도 바뀌면 불일치
    let signature = crypto::b64u_decode(&sig_text).unwrap_or_default();
    if !crypto::verify_request(&session.mac_key, &method, &target, &ts, &nonce, &body, &signature) {
        return reject(StatusCode::UNAUTHORIZED, "channel", "bad-signature").await;
    }

    // 6) 재전송: 서명이 맞는 요청이라도 같은 nonce 는 한 번만 받는다
    if !state.store.use_nonce(&session.sid, &nonce) {
        return reject(StatusCode::UNAUTHORIZED, "channel", "replay").await;
    }

    // 7) 본문 복호화
    let mut plain = Vec::new();
    if !body.is_empty() {
        match crypto::unseal(&session.enc_key, &body, &crypto::request_aad(&method, &target, &ts, &nonce)) {
            Ok(decrypted) => plain = decrypted,
            Err(_) => return reject(StatusCode::UNAUTHORIZED, "channel", "bad-ciphertext").await,
        }
        parts.headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    } else {
        parts.headers.remove(CONTENT_TYPE);
    }
    parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(plain.len()));

    state.store.touch(&session.sid);
    let enc_key = session.enc_key;
    parts.extensions.insert(session);

    // 라우터 실행 후 응답 암호화
    let response = next.run(Request::from_parts(parts, Body::from(plain))).await;
    let (mut parts, body) = response.into_parts();
    let payload = to_bytes(body, usize::MAX).await.unwrap_or_default();
    let payload = if payload.is_empty() {
        Vec::new()
    } else {
        parts.headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        parts.headers.insert("x-enc", HeaderValue::from_static("1"));
        crypto::seal(&enc_key, &payload, &crypto::response_aad(&nonce, parts.status.as_u16()))
    };
    parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(payload.len()));
    parts.headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Response::from_parts(parts, Body::from(payload))
}
