"""핸드셰이크와 클라이언트 가드 신호 수신."""
import time

from fastapi import APIRouter, HTTPException, Request, Response

from app.deps import ChannelSession
from app.schemas import GuardAction, GuardReport, HandshakeIn, HandshakeOut
from app.security.core import crypto
from app.security.core.sessions import StoreFull
from app.security.middleware import client_ip

router = APIRouter()


@router.post("/hs", response_model=HandshakeOut)
def handshake(body: HandshakeIn, request: Request, response: Response) -> HandshakeOut:
    state = request.app.state
    settings = state.settings
    ip = client_ip(request.scope, settings)

    # 인증 없이 호출되는 엔드포인트이므로 IP 기준으로 제한한다(프록시의 제한에 더한 두 번째 방어선).
    if not state.handshake_limiter.hit(ip):
        state.events.record("handshake-rate", ip)
        raise HTTPException(status_code=429, detail="too many requests")

    try:
        result = crypto.handshake(state.identity, crypto.b64u_decode(body.pub))
    except crypto.CryptoError:
        raise HTTPException(status_code=400, detail="bad request") from None

    # 유효한 기존 세션이 있으면 데이터만 이어받고 식별자와 키는 새로 발급한다.
    data: dict = {}
    old = state.store.get(request.cookies.get(settings.cookie_name))
    if old is not None:
        if not old.revoked:
            data = old.data
        state.store.delete(old.sid)

    try:
        session = state.store.create(result.enc_key, result.mac_key, ip, data)
    except StoreFull:
        raise HTTPException(status_code=503, detail="busy") from None

    response.set_cookie(
        key=settings.cookie_name,
        value=session.sid,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        max_age=settings.session_max_seconds,
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return HandshakeOut(
        pub=crypto.b64u(result.server_pub),
        salt=crypto.b64u(result.salt),
        sig=crypto.b64u(result.signature),
        ts=int(time.time() * 1000),
    )


@router.post("/sec/report", response_model=GuardAction)
def guard_report(body: GuardReport, request: Request, session: ChannelSession) -> GuardAction:
    """클라이언트 가드가 보낸 탐지 신호.

    클라이언트가 보낸 값은 위조될 수 있으므로 신호 종류(허용 목록)와 경로만 기록한다.
    정책이 revoke 이고 신호가 GUARD_REVOKE_SIGNALS 에 있으면 그 세션을 무효화한다.
    오탐이 잦은 신호(devtools-size 등)는 기본적으로 기록만 한다.
    """
    state = request.app.state
    settings = state.settings
    ip = client_ip(request.scope, settings)
    sid = session.sid if session else None
    state.events.record(f"guard:{body.signal}", ip, sid, body.path)

    if session and settings.guard_policy == "revoke" and body.signal in settings.guard_revoke_signal_set:
        state.store.revoke(session.sid)
        state.events.record("session-revoked", ip, sid, body.path)
        return GuardAction(action="block")
    return GuardAction(action="none")
