//! 환경별 설정을 한 구조체로 모은다.
//!
//! 기본값은 전부 "운영" 기준이다. 환경 변수를 빠뜨렸을 때 디버그 상태로 뜨는 대신
//! 기동에 실패하도록 한다. 개발용 값은 backend/.env (.env.dev.example 참고)에 둔다.

use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardPolicy {
    /// guard_revoke_signals 에 포함된 신호가 오면 세션을 무효화
    Revoke,
    /// 기록만 한다
    Report,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub is_dev: bool,
    pub database_path: String,
    /// 허용 Host 목록. 운영에서 비어 있거나 "*" 가 있으면 기동 실패.
    pub allowed_hosts: Vec<String>,
    /// 서버 장기 서명 키(ECDSA P-256, PKCS8 PEM) 경로
    pub server_sign_key_file: String,
    /// 보안 채널(요청 서명 + 본문 암호화). 운영에서는 끌 수 없다.
    pub secure_channel: bool,
    pub cookie_secure: bool,
    /// web 컨테이너(nginx)가 넣어 주는 X-Real-IP 를 신뢰할지.
    /// api 가 nginx 를 통해서만 도달될 때(Docker)만 true 로 둔다.
    pub trust_proxy_headers: bool,
    pub session_idle_seconds: u64,
    pub session_max_seconds: u64,
    pub max_sessions: usize,
    pub ts_skew_seconds: u64,
    pub max_body_bytes: usize,
    pub handshake_rate_per_min: u32,
    pub guard_policy: GuardPolicy,
    pub guard_revoke_signals: HashSet<String>,
    pub port: u16,
}

fn csv(value: &str) -> Vec<String> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect()
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        other => Err(format!("{key}: true/false 여야 합니다 (받은 값: {other})")),
    }
}

/// 현재 폴더의 .env 를 읽는다(개발 편의). 이미 설정된 환경 변수가 우선한다.
pub fn load_dotenv() -> HashMap<String, String> {
    let mut values = HashMap::new();
    if let Ok(text) = std::fs::read_to_string(".env") {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                values.insert(key.trim().to_owned(), value.trim().to_owned());
            }
        }
    }
    for (key, value) in std::env::vars() {
        values.insert(key, value);
    }
    values
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_map(&load_dotenv())
    }

    pub fn from_map(env: &HashMap<String, String>) -> Result<Self, String> {
        let get = |key: &str, default: &str| env.get(key).cloned().unwrap_or_else(|| default.to_owned());
        let number = |key: &str, default: &str| -> Result<u64, String> {
            get(key, default).trim().parse::<u64>().map_err(|_| format!("{key}: 숫자여야 합니다"))
        };

        let app_env = get("APP_ENV", "production");
        let is_dev = match app_env.as_str() {
            "production" => false,
            "development" => true,
            other => return Err(format!("APP_ENV: production 또는 development 여야 합니다 (받은 값: {other})")),
        };
        let guard_policy = match get("GUARD_POLICY", "revoke").as_str() {
            "revoke" => GuardPolicy::Revoke,
            "report" => GuardPolicy::Report,
            other => return Err(format!("GUARD_POLICY: revoke 또는 report 여야 합니다 (받은 값: {other})")),
        };

        let config = Config {
            is_dev,
            database_path: get("DATABASE_PATH", "./data/app.db"),
            allowed_hosts: csv(&get("ALLOWED_HOSTS", "")),
            server_sign_key_file: get("SERVER_SIGN_KEY_FILE", "/run/secrets/server_sign_key"),
            secure_channel: parse_bool("SECURE_CHANNEL", &get("SECURE_CHANNEL", "true"))?,
            cookie_secure: parse_bool("COOKIE_SECURE", &get("COOKIE_SECURE", "true"))?,
            trust_proxy_headers: parse_bool("TRUST_PROXY_HEADERS", &get("TRUST_PROXY_HEADERS", "false"))?,
            session_idle_seconds: number("SESSION_IDLE_SECONDS", "1800")?,
            session_max_seconds: number("SESSION_MAX_SECONDS", "28800")?,
            max_sessions: number("MAX_SESSIONS", "20000")? as usize,
            ts_skew_seconds: number("TS_SKEW_SECONDS", "30")?,
            max_body_bytes: number("MAX_BODY_BYTES", "1048576")? as usize,
            handshake_rate_per_min: number("HANDSHAKE_RATE_PER_MIN", "30")? as u32,
            guard_policy,
            guard_revoke_signals: csv(&get("GUARD_REVOKE_SIGNALS", "devtools-timing,debugger-tamper"))
                .into_iter()
                .collect(),
            port: number("API_PORT", "8000")? as u16,
        };
        config.refuse_unsafe_production()?;
        Ok(config)
    }

    fn refuse_unsafe_production(&self) -> Result<(), String> {
        if !self.is_dev {
            if self.allowed_hosts.is_empty() || self.allowed_hosts.iter().any(|h| h.contains('*')) {
                return Err("운영에서는 ALLOWED_HOSTS 에 정확한 호스트를 지정해야 합니다".into());
            }
            if !self.secure_channel {
                return Err("운영에서는 SECURE_CHANNEL 을 끌 수 없습니다".into());
            }
        }
        Ok(())
    }

    /// __Host- 접두사는 Secure + Path=/ + Domain 없음 을 브라우저가 강제한다.
    pub fn cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-sid"
        } else {
            "sid"
        }
    }
}
