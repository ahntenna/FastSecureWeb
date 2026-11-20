"""DB 모델. 요청·응답 스키마(schemas.py)와 분리한다(대량 할당 방지)."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Note(Base):
    """예제 리소스. 실제 프로젝트의 테이블로 교체한다."""

    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(100))
    body: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SecurityEvent(Base):
    """보안 이벤트 기록(서명 불일치, 재전송, 가드 신호 등)."""

    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    ip: Mapped[str] = mapped_column(String(64))
    # 세션 식별자는 원문 대신 해시 앞부분만 남긴다.
    sid_hash: Mapped[str] = mapped_column(String(16), default="")
    path: Mapped[str] = mapped_column(String(200), default="")
