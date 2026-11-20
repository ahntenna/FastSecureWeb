"""보안 이벤트 기록. 로그와 DB(security_events) 양쪽에 남긴다."""
import hashlib
import logging

from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from app.models import SecurityEvent
from app.security.core.ratelimit import RateLimiter

logger = logging.getLogger("app.security")


def sid_fingerprint(sid: str | None) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()[:16] if sid else ""


class SecurityEvents:
    def __init__(self, session_factory: sessionmaker[DbSession]) -> None:
        self._session_factory = session_factory
        # 한 IP 가 이벤트를 쏟아내 디스크를 채우지 못하게 DB 기록만 제한한다.
        self._db_limiter = RateLimiter(limit=60, window_seconds=60)

    def record(self, kind: str, ip: str, sid: str | None = None, path: str = "") -> None:
        fingerprint = sid_fingerprint(sid)
        path = path[:200]
        logger.warning("security-event kind=%s ip=%s sid=%s path=%r", kind, ip, fingerprint, path)
        if not self._db_limiter.hit(ip):
            return
        try:
            with self._session_factory() as db:
                db.add(SecurityEvent(kind=kind[:40], ip=ip[:64], sid_hash=fingerprint, path=path))
                db.commit()
        except Exception:  # 기록 실패가 요청 처리를 막지 않게 한다.
            logger.exception("security-event 기록 실패")
