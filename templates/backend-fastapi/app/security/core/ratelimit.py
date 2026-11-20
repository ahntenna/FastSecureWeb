"""고정 창 속도 제한기 (프로세스 메모리).

- 키 수에 상한을 둔다. 넘으면 만료된 키를 지우고, 그래도 넘으면 거부한다(안전한 쪽으로 실패).
- 조회만으로 키가 생기지 않는다. hit() 만 키를 만든다.
"""
import threading
import time


class RateLimiter:
    def __init__(self, limit, window_seconds, max_keys=100_000):
        self._limit = limit
        self._window = window_seconds
        self._max_keys = max_keys
        self._buckets = {}
        self._lock = threading.Lock()

    def hit(self, key):
        """한 번 사용을 기록한다. 한도 안이면 True, 초과면 False."""
        key = key[:64]
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None and now >= bucket[0]:
                bucket = None
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    for k in [k for k, b in self._buckets.items() if now >= b[0]]:
                        del self._buckets[k]
                    if len(self._buckets) >= self._max_keys:
                        return False
                bucket = [now + self._window, 0]
                self._buckets[key] = bucket
            bucket[1] += 1
            return bucket[1] <= self._limit
