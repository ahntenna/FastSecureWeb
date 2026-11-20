//! 보안 이벤트 기록. 로그와 DB(security_events) 양쪽에 남긴다.

use sha2::{Digest, Sha256};
use sqlx::SqlitePool;

use super::ratelimit::RateLimiter;

/// 세션 식별자는 원문 대신 해시 앞부분만 남긴다.
pub fn sid_fingerprint(sid: Option<&str>) -> String {
    match sid {
        Some(sid) if !sid.is_empty() => {
            Sha256::digest(sid.as_bytes()).iter().take(8).map(|byte| format!("{byte:02x}")).collect()
        }
        _ => String::new(),
    }
}

fn clip(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

pub struct SecurityEvents {
    db: SqlitePool,
    /// 한 IP 가 이벤트를 쏟아내 디스크를 채우지 못하게 DB 기록만 제한한다.
    db_limiter: RateLimiter,
}

impl SecurityEvents {
    pub fn new(db: SqlitePool) -> Self {
        Self { db, db_limiter: RateLimiter::new(60, 60) }
    }

    pub async fn record(&self, kind: &str, ip: &str, sid: Option<&str>, path: &str) {
        let fingerprint = sid_fingerprint(sid);
        let path = clip(path, 200);
        tracing::warn!(kind, ip, sid = %fingerprint, path = %path, "security-event");
        if !self.db_limiter.hit(ip) {
            return;
        }
        let result = sqlx::query("INSERT INTO security_events (kind, ip, sid_hash, path) VALUES (?, ?, ?, ?)")
            .bind(clip(kind, 40))
            .bind(clip(ip, 64))
            .bind(fingerprint)
            .bind(path)
            .execute(&self.db)
            .await;
        if let Err(error) = result {
            // 기록 실패가 요청 처리를 막지 않게 한다.
            tracing::error!(%error, "security-event 기록 실패");
        }
    }
}
