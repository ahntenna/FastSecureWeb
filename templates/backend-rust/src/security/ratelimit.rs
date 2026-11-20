//! 고정 창 속도 제한기 (프로세스 메모리).
//!
//! - 키 수에 상한을 둔다. 넘으면 만료된 키를 지우고, 그래도 넘으면 거부한다(안전한 쪽으로 실패).
//! - 조회만으로 키가 생기지 않는다. hit() 만 키를 만든다.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    max_keys: usize,
    buckets: Mutex<HashMap<String, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window_seconds: u64) -> Self {
        Self { limit, window: Duration::from_secs(window_seconds), max_keys: 100_000, buckets: Mutex::new(HashMap::new()) }
    }

    /// 한 번 사용을 기록한다. 한도 안이면 true, 초과면 false.
    pub fn hit(&self, key: &str) -> bool {
        let key: String = key.chars().take(64).collect();
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let live = matches!(buckets.get(&key), Some((reset, _)) if now < *reset);
        if !live {
            buckets.remove(&key);
            if buckets.len() >= self.max_keys {
                buckets.retain(|_, (reset, _)| now < *reset);
                if buckets.len() >= self.max_keys {
                    return false;
                }
            }
            buckets.insert(key.clone(), (now + self.window, 0));
        }
        let bucket = buckets.get_mut(&key).expect("방금 넣었거나 살아 있는 키다");
        bucket.1 += 1;
        bucket.1 <= self.limit
    }
}
