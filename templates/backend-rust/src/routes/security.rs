//! 핸드셰이크와 클라이언트 가드 신호 수신.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;

use crate::config::GuardPolicy;
use crate::error::{ApiError, ApiJson, ClientIp};
use crate::security::crypto;
use crate::security::middleware::cookie_value;
use crate::security::sessions::SessionHandle;
use crate::state::AppState;

const GUARD_SIGNALS: [&str; 5] =
    ["devtools-size", "devtools-timing", "devtools-console", "debugger-tamper", "automation"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandshakeIn {
    /// P-256 비압축 점 65바이트의 base64url = 87자
    #[serde(rename = "pub")]
    pub public: String,
}

pub async fn handshake(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(body): ApiJson<HandshakeIn>,
) -> Result<Response, ApiError> {
    // 인증 없이 호출되는 엔드포인트이므로 IP 기준으로 제한한다(프록시의 제한에 더한 두 번째 방어선).
    if !state.handshake_limiter.hit(&ip) {
        state.events.record("handshake-rate", &ip, None, "/api/hs").await;
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many requests"));
    }
    if body.public.len() != 87 {
        return Err(ApiError::invalid());
    }
    let bad_request = ApiError::new(StatusCode::BAD_REQUEST, "bad request");
    let client_pub = crypto::b64u_decode(&body.public).map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "bad request"))?;
    let result = crypto::handshake(&state.identity, &client_pub).map_err(|_| bad_request)?;

    // 유효한 기존 세션이 있으면 데이터만 이어받고 식별자와 키는 새로 발급한다.
    let cookie_name = state.cfg.cookie_name();
    let data = cookie_value(&headers, cookie_name).and_then(|old| state.store.take(&old)).unwrap_or_default();
    let sid = state
        .store
        .create(result.enc_key, result.mac_key, data)
        .map_err(|_| ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "busy"))?;

    let mut cookie =
        format!("{cookie_name}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", state.cfg.session_max_seconds);
    if state.cfg.cookie_secure {
        cookie.push_str("; Secure");
    }
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let reply = json!({
        "pub": crypto::b64u(&result.server_pub),
        "salt": crypto::b64u(&result.salt),
        "sig": crypto::b64u(&result.signature),
        "ts": now_ms,
    });
    Ok(([(SET_COOKIE, cookie), (CACHE_CONTROL, "no-store".to_owned())], Json(reply)).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardReport {
    pub signal: String,
    #[serde(default)]
    pub path: String,
}

/// 클라이언트 가드가 보낸 탐지 신호.
///
/// 클라이언트가 보낸 값은 위조될 수 있으므로 신호 종류(허용 목록)와 경로만 기록한다.
/// 정책이 revoke 이고 신호가 GUARD_REVOKE_SIGNALS 에 있으면 그 세션을 무효화한다.
/// 오탐이 잦은 신호(devtools-size 등)는 기본적으로 기록만 한다.
pub async fn guard_report(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    session: Option<Extension<SessionHandle>>,
    ApiJson(body): ApiJson<GuardReport>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !GUARD_SIGNALS.contains(&body.signal.as_str()) || body.path.chars().count() > 200 {
        return Err(ApiError::invalid());
    }
    let sid = session.as_ref().map(|Extension(handle)| handle.sid.as_str());
    state.events.record(&format!("guard:{}", body.signal), &ip, sid, &body.path).await;

    let revoke = state.cfg.guard_policy == GuardPolicy::Revoke && state.cfg.guard_revoke_signals.contains(&body.signal);
    if let (Some(sid), true) = (sid, revoke) {
        state.store.revoke(sid);
        state.events.record("session-revoked", &ip, Some(sid), &body.path).await;
        return Ok(Json(json!({ "action": "block" })));
    }
    Ok(Json(json!({ "action": "none" })))
}
