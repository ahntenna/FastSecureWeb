"""앱 조립. 테스트는 create_app(settings) 로 설정을 주입해 만든다."""
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.config import Settings, get_settings
from app.db import make_engine, run_migrations
from app.routers import health, notes, security
from app.security.core.crypto import ServerIdentity
from app.security.core.ratelimit import RateLimiter
from app.security.core.sessions import SessionStore
from app.security.events import SecurityEvents
from app.security.middleware import OriginCheckMiddleware, SecureChannelMiddleware

logger = logging.getLogger("app")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    # 운영에서는 API 문서를 열지 않는다(API 구조 전체가 노출된다).
    app = FastAPI(
        docs_url="/api/docs" if settings.is_dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.is_dev else None,
    )

    run_migrations(settings.database_path)
    engine = make_engine(settings.database_path)
    session_factory = sessionmaker(engine, expire_on_commit=False)

    app.state.settings = settings
    app.state.session_factory = session_factory
    app.state.identity = ServerIdentity(Path(settings.server_sign_key_file).read_bytes())
    app.state.store = SessionStore(
        idle_seconds=settings.session_idle_seconds,
        max_seconds=settings.session_max_seconds,
        max_sessions=settings.max_sessions,
        nonce_ttl_seconds=settings.ts_skew_seconds * 2 + 5,
    )
    app.state.events = SecurityEvents(session_factory)
    app.state.handshake_limiter = RateLimiter(limit=settings.handshake_rate_per_min, window_seconds=60)

    # 미들웨어는 나중에 추가한 것이 바깥쪽이다: TrustedHost → OriginCheck → SecureChannel → 라우터
    app.add_middleware(
        SecureChannelMiddleware, settings=settings, store=app.state.store, events=app.state.events
    )
    app.add_middleware(OriginCheckMiddleware)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list or ["localhost"])

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # 상세는 서버 로그에만 남기고 응답은 일반 메시지로 통일한다.
        logger.exception("unhandled error: %s %s", request.method, request.url.path)
        return JSONResponse({"detail": "internal error"}, status_code=500)

    app.include_router(health.router, prefix="/api")
    app.include_router(security.router, prefix="/api")
    app.include_router(notes.router, prefix="/api")
    return app
