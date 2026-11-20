"""보안 채널 미들웨어 (순수 ASGI).

/api/ 아래의 모든 요청에 대해 (면제 경로 제외)
  세션 확인 → 타임스탬프 → 서명 → nonce(재전송) → 본문 복호화 → 라우터 → 응답 암호화
순서로 처리한다. 프록시 도구로 본문·경로·쿼리를 고치거나 요청을 다시 보내면 여기서 거부된다.

주의: 응답을 모아서 암호화하므로 /api/ 아래에서는 스트리밍 응답을 쓸 수 없다.
"""
import json
import time
from urllib.parse import urlsplit

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import Settings
from app.security.core import crypto
from app.security.core.sessions import SessionStore
from app.security.events import SecurityEvents

# 보안 채널 없이 접근하는 경로: 상태 확인, 핸드셰이크
EXEMPT_PATHS = frozenset({"/api/health", "/api/hs"})
DEV_ONLY_EXEMPT = frozenset({"/api/docs", "/api/openapi.json"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def client_ip(scope: Scope, settings: Settings) -> str:
    """실제 클라이언트 IP. 프록시 헤더는 설정으로 신뢰가 확인된 경우에만 쓴다."""
    if settings.trust_proxy_headers:
        for name, value in scope.get("headers", []):
            if name == b"x-real-ip":
                return value.decode("latin-1")[:64]
    client = scope.get("client")
    return client[0] if client else "unknown"


async def _plain_json(send: Send, status: int, code: str) -> None:
    body = json.dumps({"detail": "request rejected", "code": code}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class OriginCheckMiddleware:
    """상태 변경 요청의 Origin 이 요청 Host 와 같은 호스트인지 확인한다(교차 사이트 요청 차단)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] not in SAFE_METHODS:
            headers = Request(scope).headers
            origin = headers.get("origin")
            if origin is not None:
                origin_host = urlsplit(origin).hostname
                request_host = urlsplit("//" + headers.get("host", "")).hostname
                if not origin_host or origin_host != request_host:
                    await _plain_json(send, 403, "origin")
                    return
        await self.app(scope, receive, send)


class SecureChannelMiddleware:
    def __init__(
        self, app: ASGIApp, *, settings: Settings, store: SessionStore, events: SecurityEvents
    ) -> None:
        self.app = app
        self.settings = settings
        self.store = store
        self.events = events

    def _exempt(self, path: str) -> bool:
        if not path.startswith("/api/"):
            return True
        if path in EXEMPT_PATHS:
            return True
        return self.settings.is_dev and path in DEV_ONLY_EXEMPT

    async def _reject(
        self, send: Send, status: int, code: str, kind: str, ip: str, sid: str | None, path: str
    ) -> None:
        await run_in_threadpool(self.events.record, kind, ip, sid, path)
        await _plain_json(send, status, code)

    async def _read_body(self, receive: Receive) -> bytes | None:
        """본문을 한도까지 읽는다. 한도를 넘으면 None."""
        limit = self.settings.max_body_bytes
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break  # http.disconnect
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > limit:
                return None
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        return b"".join(chunks)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.settings.secure_channel or self._exempt(scope["path"]):
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        headers = request.headers
        path = scope["path"]
        ip = client_ip(scope, self.settings)

        # 1) 세션
        sid = request.cookies.get(self.settings.cookie_name)
        session = self.store.get(sid) if sid else None
        if session is None:
            # 세션 없음은 정상 흐름(만료·서버 재시작)에서도 생기므로 이벤트로 남기지 않는다.
            await _plain_json(send, 401, "channel")
            return
        if session.revoked:
            await _plain_json(send, 403, "revoked")
            return

        # 2) 헤더 형식
        ts = headers.get("x-ts", "")
        nonce = headers.get("x-nonce", "")
        sig_text = headers.get("x-sig", "")
        if not (ts.isascii() and ts.isdigit() and len(ts) <= 15 and 16 <= len(nonce) <= 64 and len(sig_text) == 43):
            await self._reject(send, 401, "channel", "bad-headers", ip, sid, path)
            return

        # 3) 본문 크기 (프록시의 client_max_body_size 에 더한 두 번째 방어선)
        declared = headers.get("content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.settings.max_body_bytes):
            await self._reject(send, 413, "too_large", "body-too-large", ip, sid, path)
            return
        body = await self._read_body(receive)
        if body is None:
            await self._reject(send, 413, "too_large", "body-too-large", ip, sid, path)
            return

        # 4) 타임스탬프 창
        if abs(time.time() * 1000 - int(ts)) > self.settings.ts_skew_seconds * 1000:
            await self._reject(send, 401, "channel", "stale-timestamp", ip, sid, path)
            return

        # 5) 서명: 메서드·경로·쿼리·본문 중 하나라도 바뀌면 불일치
        raw_path = scope.get("raw_path")
        target = raw_path.decode("latin-1") if raw_path else path
        if scope.get("query_string"):
            target += "?" + scope["query_string"].decode("latin-1")
        method = scope["method"]
        try:
            signature = crypto.b64u_decode(sig_text)
        except crypto.CryptoError:
            signature = b""
        if not crypto.verify_request(session.mac_key, method, target, ts, nonce, body, signature):
            await self._reject(send, 401, "channel", "bad-signature", ip, sid, path)
            return

        # 6) 재전송: 서명이 맞는 요청이라도 같은 nonce 는 한 번만 받는다
        if not self.store.use_nonce(session, nonce):
            await self._reject(send, 401, "channel", "replay", ip, sid, path)
            return

        # 7) 본문 복호화
        plain = b""
        if body:
            try:
                plain = crypto.unseal(session.enc_key, body, crypto.request_aad(method, target, ts, nonce))
            except crypto.CryptoError:
                await self._reject(send, 401, "channel", "bad-ciphertext", ip, sid, path)
                return

        self.store.touch(session)

        new_headers = [(k, v) for k, v in scope["headers"] if k not in (b"content-length", b"content-type")]
        if body:
            new_headers.append((b"content-type", b"application/json"))
        new_headers.append((b"content-length", str(len(plain)).encode()))
        inner_scope = dict(scope)
        inner_scope["headers"] = new_headers
        inner_scope["state"] = {**scope.get("state", {}), "session": session}

        delivered = False

        async def inner_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": plain, "more_body": False}
            return await receive()

        start: Message | None = None
        chunks: list[bytes] = []
        enc_key = session.enc_key

        async def inner_send(message: Message) -> None:
            nonlocal start
            if message["type"] == "http.response.start":
                start = message
                return
            if message["type"] != "http.response.body" or start is None:
                return
            chunks.append(message.get("body", b""))
            if message.get("more_body", False):
                return
            payload = b"".join(chunks)
            out_headers = MutableHeaders(raw=list(start["headers"]))
            if payload:
                payload = crypto.seal(enc_key, payload, crypto.response_aad(nonce, start["status"]))
                out_headers["content-type"] = "application/octet-stream"
                out_headers["x-enc"] = "1"
            out_headers["content-length"] = str(len(payload))
            out_headers["cache-control"] = "no-store"
            await send({"type": "http.response.start", "status": start["status"], "headers": out_headers.raw})
            await send({"type": "http.response.body", "body": payload})

        await self.app(inner_scope, inner_receive, inner_send)
