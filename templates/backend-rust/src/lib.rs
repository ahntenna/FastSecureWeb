//! 앱 조립. main.rs 와 통합 테스트(tests/)가 함께 쓴다.

pub mod config;
pub mod error;
pub mod routes;
pub mod security;
pub mod state;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{delete, get, post};
use axum::Router;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::catch_panic::CatchPanicLayer;

use crate::config::Config;
use crate::security::crypto::ServerIdentity;
use crate::security::events::SecurityEvents;
use crate::security::middleware::{host_check, origin_check, plain_json, secure_channel};
use crate::security::ratelimit::RateLimiter;
use crate::security::sessions::SessionStore;
use crate::state::AppState;

/// 서명 키를 읽고, DB 를 열어 마이그레이션을 적용한 뒤 공유 상태를 만든다.
pub async fn build_state(cfg: Config) -> Result<AppState, String> {
    let pem = std::fs::read_to_string(&cfg.server_sign_key_file)
        .map_err(|e| format!("서명 키를 읽을 수 없습니다 ({}): {e}", cfg.server_sign_key_file))?;
    let identity = ServerIdentity::from_pem(&pem).map_err(|_| "서버 서명 키는 ECDSA P-256 (PKCS8 PEM) 이어야 합니다")?;

    if let Some(parent) = Path::new(&cfg.database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("데이터 폴더를 만들 수 없습니다: {e}"))?;
        }
    }
    let options = SqliteConnectOptions::new()
        .filename(&cfg.database_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .map_err(|e| format!("DB 를 열 수 없습니다: {e}"))?;
    // 기동 시 최신 스키마로 올린다. 스키마 변경은 migrations/ 에 파일을 추가한다.
    sqlx::migrate!("./migrations").run(&db).await.map_err(|e| format!("마이그레이션 실패: {e}"))?;

    Ok(AppState {
        store: Arc::new(SessionStore::new(
            cfg.session_idle_seconds,
            cfg.session_max_seconds,
            cfg.max_sessions,
            cfg.ts_skew_seconds * 2 + 5,
        )),
        events: Arc::new(SecurityEvents::new(db.clone())),
        handshake_limiter: Arc::new(RateLimiter::new(cfg.handshake_rate_per_min, 60)),
        identity: Arc::new(identity),
        cfg: Arc::new(cfg),
        db,
    })
}

pub fn build_app(state: AppState) -> Router {
    // 레이어는 나중에 추가한 것이 바깥쪽이다: CatchPanic → host_check → origin_check → secure_channel → 라우터
    Router::new()
        .route("/api/health", get(routes::health::health))
        .route("/api/hs", post(routes::security::handshake))
        .route("/api/sec/report", post(routes::security::guard_report))
        .route("/api/notes", get(routes::notes::list_notes).post(routes::notes::create_note))
        .route("/api/notes/{id}", delete(routes::notes::delete_note))
        .fallback(|| async { plain_json(StatusCode::NOT_FOUND, "not_found") })
        .layer(from_fn_with_state(state.clone(), secure_channel))
        .layer(from_fn(origin_check))
        .layer(from_fn_with_state(state.clone(), host_check))
        // 처리되지 않은 패닉은 일반 500 응답으로 바꾼다(상세는 로그에만).
        .layer(CatchPanicLayer::new())
        .with_state(state)
}
