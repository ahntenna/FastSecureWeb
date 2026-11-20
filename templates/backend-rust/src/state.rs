use std::sync::Arc;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::security::crypto::ServerIdentity;
use crate::security::events::SecurityEvents;
use crate::security::ratelimit::RateLimiter;
use crate::security::sessions::SessionStore;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: SqlitePool,
    pub identity: Arc<ServerIdentity>,
    pub store: Arc<SessionStore>,
    pub events: Arc<SecurityEvents>,
    pub handshake_limiter: Arc<RateLimiter>,
}
