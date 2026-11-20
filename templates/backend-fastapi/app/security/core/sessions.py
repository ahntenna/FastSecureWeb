"""보안 세션 저장소와 재전송(nonce) 방지.

프로세스 메모리에 둔다. 그래서 uvicorn 워커는 1개로 고정한다(Dockerfile 참고).
워커를 늘리려면 이 저장소를 Redis 같은 공유 저장소로 먼저 옮겨야 한다.
서버가 재시작되면 세션이 사라지고, 클라이언트는 401 을 받아 자동으로 다시
핸드셰이크한다.
"""
import secrets
import threading
import time


class StoreFull(Exception):
    """세션 수 상한 초과. 인증 없는 핸드셰이크로 메모리를 채우는 것을 막는다."""


class Session:
    __slots__ = ("sid", "enc_key", "mac_key", "created", "last_seen", "ip", "revoked", "data", "nonces")

    def __init__(self, sid, enc_key, mac_key, ip, data, now):
        self.sid = sid
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.created = now
        self.last_seen = now
        self.ip = ip
        self.revoked = False
        # 로그인 기능을 붙일 때 user_id 등을 여기에 둔다. 재핸드셰이크 때 이어받는다.
        self.data = data
        self.nonces = {}


class SessionStore:
    # 한 세션이 허용 시간 창 안에서 쓸 수 있는 nonce 수. 넘으면 요청을 거부한다.
    MAX_NONCES_PER_SESSION = 4096

    def __init__(self, idle_seconds, max_seconds, max_sessions, nonce_ttl_seconds):
        self._idle = idle_seconds
        self._max_age = max_seconds
        self._max_sessions = max_sessions
        self._nonce_ttl = nonce_ttl_seconds
        self._sessions = {}
        self._lock = threading.Lock()
        self._last_purge = 0.0

    def _expired(self, session, now):
        return now - session.last_seen > self._idle or now - session.created > self._max_age

    def _purge(self, now):
        dead = [sid for sid, s in self._sessions.items() if self._expired(s, now)]
        for sid in dead:
            del self._sessions[sid]
        self._last_purge = now

    def create(self, enc_key, mac_key, ip, data=None):
        now = time.time()
        with self._lock:
            if now - self._last_purge > 60 or len(self._sessions) >= self._max_sessions:
                self._purge(now)
            if len(self._sessions) >= self._max_sessions:
                raise StoreFull()
            sid = secrets.token_urlsafe(32)
            session = Session(sid, enc_key, mac_key, ip, data if data is not None else {}, now)
            self._sessions[sid] = session
            return session

    def get(self, sid):
        """만료되지 않은 세션을 돌려준다. 무효화된 세션도 돌려주므로 호출자가 revoked 를 확인한다."""
        if not sid or len(sid) > 128:
            return None
        now = time.time()
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            if self._expired(session, now):
                del self._sessions[sid]
                return None
            return session

    def touch(self, session):
        session.last_seen = time.time()

    def delete(self, sid):
        with self._lock:
            self._sessions.pop(sid, None)

    def revoke(self, sid):
        with self._lock:
            session = self._sessions.get(sid)
            if session is not None:
                session.revoked = True
                session.data = {}

    def use_nonce(self, session, nonce):
        """처음 보는 nonce 면 기록하고 True. 이미 쓴 nonce(재전송)면 False."""
        now = time.time()
        with self._lock:
            nonces = session.nonces
            if nonce in nonces:
                return False
            if len(nonces) >= self.MAX_NONCES_PER_SESSION:
                for key in [k for k, exp in nonces.items() if exp <= now]:
                    del nonces[key]
                if len(nonces) >= self.MAX_NONCES_PER_SESSION:
                    return False
            nonces[nonce] = now + self._nonce_ttl
            return True

    def __len__(self):
        return len(self._sessions)
