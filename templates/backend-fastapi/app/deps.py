"""라우터 공용 의존성."""
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session as DbSession

from app.security.core.sessions import Session


def get_db(request: Request) -> Iterator[DbSession]:
    with request.app.state.session_factory() as db:
        yield db


def get_channel_session(request: Request) -> Session | None:
    """보안 채널 세션. 개발에서 SECURE_CHANNEL=false 로 끈 경우에만 None 이다.

    로그인 기능을 붙일 때는 session.data["user_id"] 를 읽는 get_current_user 의존성을
    만들고, 보호할 라우터에 APIRouter(dependencies=[Depends(get_current_user)]) 로 건다.
    로그인 성공 시에는 세션 고정을 막기 위해 새 세션을 발급한다.
    """
    return getattr(request.state, "session", None)


Db = Annotated[DbSession, Depends(get_db)]
ChannelSession = Annotated[Session | None, Depends(get_channel_session)]
