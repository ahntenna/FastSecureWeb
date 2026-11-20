//! 보안 세션 저장소와 재전송(nonce) 방지.
//!
//! 프로세스 메모리에 둔다. 그래서 api 는 인스턴스 1개로 운영한다. 여러 인스턴스로
//! 늘리려면 이 저장소를 Redis 같은 공유 저장소로 먼저 옮겨야 한다.
//! 서버가 재시작되면 세션이 사라지고, 클라이언트는 401 을 받아 자동으로 다시
//! 핸드셰이크한다.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::crypto::{b64u, random_bytes};

/// 한 세션이 허용 시간 창 안에서 쓸 수 있는 nonce 수. 넘으면 요청을 거부한다.
const MAX_NONCES_PER_SESSION: usize = 4096;

/// 로그인 기능을 붙일 때 user_id 등을 여기에 둔다. 재핸드셰이크 때 이어받는다.
pub type SessionData = HashMap<String, String>;

struct Session {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
    created: Instant,
    last_seen: Instant,
    revoked: bool,
    data: SessionData,
    nonces: HashMap<String, Instant>,
}

/// 요청 처리에 필요한 세션 정보의 사본. 라우터에서는 Extension<SessionHandle> 로 받는다.
#[derive(Clone)]
pub struct SessionHandle {
    pub sid: String,
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub data: SessionData,
}

pub enum Lookup {
    Missing,
    Revoked,
    Active(SessionHandle),
}

/// 세션 수 상한 초과. 인증 없는 핸드셰이크로 메모리를 채우는 것을 막는다.
#[derive(Debug)]
pub struct StoreFull;

pub struct SessionStore {
    idle: Duration,
    max_age: Duration,
    max_sessions: usize,
    nonce_ttl: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    sessions: HashMap<String, Session>,
    last_purge: Instant,
}

impl SessionStore {
    pub fn new(idle_seconds: u64, max_seconds: u64, max_sessions: usize, nonce_ttl_seconds: u64) -> Self {
        Self {
            idle: Duration::from_secs(idle_seconds),
            max_age: Duration::from_secs(max_seconds),
            max_sessions,
            nonce_ttl: Duration::from_secs(nonce_ttl_seconds),
            inner: Mutex::new(Inner { sessions: HashMap::new(), last_purge: Instant::now() }),
        }
    }

    fn expired(&self, session: &Session, now: Instant) -> bool {
        now.duration_since(session.last_seen) > self.idle || now.duration_since(session.created) > self.max_age
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // 다른 스레드가 패닉으로 락을 오염시켜도 저장소는 계속 쓸 수 있게 한다.
        self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn create(&self, enc_key: [u8; 32], mac_key: [u8; 32], data: SessionData) -> Result<String, StoreFull> {
        let now = Instant::now();
        let mut inner = self.lock();
        if now.duration_since(inner.last_purge) > Duration::from_secs(60) || inner.sessions.len() >= self.max_sessions {
            let dead: Vec<String> =
                inner.sessions.iter().filter(|(_, s)| self.expired(s, now)).map(|(sid, _)| sid.clone()).collect();
            for sid in dead {
                inner.sessions.remove(&sid);
            }
            inner.last_purge = now;
        }
        if inner.sessions.len() >= self.max_sessions {
            return Err(StoreFull);
        }
        let sid = b64u(&random_bytes::<32>());
        inner.sessions.insert(
            sid.clone(),
            Session { enc_key, mac_key, created: now, last_seen: now, revoked: false, data, nonces: HashMap::new() },
        );
        Ok(sid)
    }

    pub fn lookup(&self, sid: &str) -> Lookup {
        if sid.is_empty() || sid.len() > 128 {
            return Lookup::Missing;
        }
        let now = Instant::now();
        let mut inner = self.lock();
        let Some(session) = inner.sessions.get(sid) else {
            return Lookup::Missing;
        };
        if self.expired(session, now) {
            inner.sessions.remove(sid);
            return Lookup::Missing;
        }
        if session.revoked {
            return Lookup::Revoked;
        }
        Lookup::Active(SessionHandle {
            sid: sid.to_owned(),
            enc_key: session.enc_key,
            mac_key: session.mac_key,
            data: session.data.clone(),
        })
    }

    pub fn touch(&self, sid: &str) {
        if let Some(session) = self.lock().sessions.get_mut(sid) {
            session.last_seen = Instant::now();
        }
    }

    /// 세션을 지우고, 유효(무효화되지 않음)했다면 데이터를 돌려준다. 재핸드셰이크에서 쓴다.
    pub fn take(&self, sid: &str) -> Option<SessionData> {
        let now = Instant::now();
        let session = self.lock().sessions.remove(sid)?;
        if session.revoked || self.expired(&session, now) {
            return None;
        }
        Some(session.data)
    }

    pub fn revoke(&self, sid: &str) {
        if let Some(session) = self.lock().sessions.get_mut(sid) {
            session.revoked = true;
            session.data.clear();
        }
    }

    /// 세션 데이터를 바꾼다(로그인 기능을 붙일 때 사용).
    pub fn set_data(&self, sid: &str, data: SessionData) {
        if let Some(session) = self.lock().sessions.get_mut(sid) {
            session.data = data;
        }
    }

    /// 처음 보는 nonce 면 기록하고 true. 이미 쓴 nonce(재전송)면 false.
    pub fn use_nonce(&self, sid: &str, nonce: &str) -> bool {
        let now = Instant::now();
        let mut inner = self.lock();
        let Some(session) = inner.sessions.get_mut(sid) else {
            return false;
        };
        if session.nonces.contains_key(nonce) {
            return false;
        }
        if session.nonces.len() >= MAX_NONCES_PER_SESSION {
            session.nonces.retain(|_, expires| *expires > now);
            if session.nonces.len() >= MAX_NONCES_PER_SESSION {
                return false;
            }
        }
        session.nonces.insert(nonce.to_owned(), now + self.nonce_ttl);
        true
    }
}
