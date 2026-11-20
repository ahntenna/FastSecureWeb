"""보안 동작을 테스트로 고정한다. 통제가 "있는지"가 아니라 "작동하는지"를 본다."""
import json
import time

import pytest
from pydantic import ValidationError

from app.security.core import crypto
from tests.conftest import ChannelClient


# ── 설정 ────────────────────────────────────────────────────────────────
def test_production_requires_allowed_hosts(make_settings):
    with pytest.raises(ValidationError):
        make_settings(allowed_hosts="")
    with pytest.raises(ValidationError):
        make_settings(allowed_hosts="*")


def test_production_cannot_disable_secure_channel(make_settings):
    with pytest.raises(ValidationError):
        make_settings(secure_channel=False)


def test_docs_closed_in_production(make_client):
    http = make_client()
    assert http.get("/api/docs").status_code in (401, 404)
    assert http.get("/api/openapi.json").status_code in (401, 404)
    assert http.get("/docs").status_code == 404
    assert http.get("/openapi.json").status_code == 404


def test_docs_open_only_in_development(make_client):
    http = make_client(app_env="development")
    assert http.get("/api/openapi.json").status_code == 200


def test_unknown_host_rejected(make_client):
    http = make_client()
    assert http.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


# ── 핸드셰이크 ──────────────────────────────────────────────────────────
def test_health_needs_no_channel(make_client):
    response = make_client().get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_handshake_sets_hardened_cookie(make_client, sign_key):
    client = ChannelClient(make_client(), sign_key[1])
    response = client.handshake()  # 서버 서명 검증 포함
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("__host-sid=")
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert response.headers["cache-control"] == "no-store"


def test_handshake_rejects_invalid_point(make_client):
    http = make_client()
    bad = crypto.b64u(b"\x04" + b"\x01" * 64)  # 곡선 위에 없는 점
    assert http.post("/api/hs", json={"pub": bad}).status_code == 400
    assert http.post("/api/hs", json={"pub": "short"}).status_code == 422
    assert http.post("/api/hs", json={"pub": bad, "extra": 1}).status_code == 422


def test_handshake_rate_limited(make_client, sign_key):
    client = ChannelClient(make_client(handshake_rate_per_min=3), sign_key[1])
    assert [client.handshake().status_code for _ in range(5)] == [200, 200, 200, 429, 429]


def test_cross_site_origin_rejected(make_client):
    http = make_client()
    response = http.post("/api/hs", json={"pub": "x" * 87}, headers={"Origin": "https://evil.example"})
    assert response.status_code == 403
    assert response.json()["code"] == "origin"


# ── 보안 채널: 정상 흐름 ────────────────────────────────────────────────
def test_request_without_session_is_rejected(make_client):
    http = make_client()
    response = http.get("/api/notes")
    assert response.status_code == 401
    assert response.json()["code"] == "channel"
    # 평문 JSON 으로 본문을 보내도 통하지 않는다.
    assert http.post("/api/notes", json={"title": "x"}).status_code == 401


def test_encrypted_roundtrip(channel):
    response, created = channel.json("POST", "/api/notes", {"title": "hello", "body": "world"})
    assert response.status_code == 201
    assert created["title"] == "hello"
    # 전송 구간의 본문은 JSON 이 아니다(프록시에서 평문이 보이지 않는다).
    assert response.headers["content-type"] == "application/octet-stream"
    with pytest.raises(ValueError):
        json.loads(response.content)

    response, notes = channel.json("GET", "/api/notes?limit=10")
    assert response.status_code == 200
    assert [n["title"] for n in notes] == ["hello"]

    response = channel.call("DELETE", f"/api/notes/{created['id']}")
    assert response.status_code == 204
    assert response.content == b""


def test_unknown_field_rejected(channel):
    response, body = channel.json("POST", "/api/notes", {"title": "x", "is_admin": True})
    assert response.status_code == 422


def test_missing_object_is_404(channel):
    response, _ = channel.json("DELETE", "/api/notes/999999")
    assert response.status_code == 404


# ── 보안 채널: 변조·재전송 ──────────────────────────────────────────────
def test_tampered_body_rejected(channel):
    headers, sealed = channel.build("POST", "/api/notes", {"title": "legit"})
    tampered = bytes([sealed[0] ^ 0x01]) + sealed[1:]
    assert channel.send("POST", "/api/notes", headers, tampered).status_code == 401


def test_plaintext_body_with_valid_headers_rejected(channel):
    headers, _ = channel.build("POST", "/api/notes", {"title": "legit"})
    response = channel.http.post("/api/notes", headers=headers, content=b'{"title":"forged"}')
    assert response.status_code == 401


def test_tampered_query_rejected(channel):
    headers, sealed = channel.build("GET", "/api/notes?limit=1")
    assert channel.send("GET", "/api/notes?limit=100", headers, sealed).status_code == 401


def test_tampered_method_or_path_rejected(channel):
    headers, sealed = channel.build("GET", "/api/notes")
    assert channel.send("DELETE", "/api/notes/1", headers, sealed).status_code == 401


def test_bad_signature_rejected(channel):
    headers, sealed = channel.build("GET", "/api/notes")
    headers["X-Sig"] = crypto.b64u(b"\x00" * 32)
    assert channel.send("GET", "/api/notes", headers, sealed).status_code == 401
    headers["X-Sig"] = "not-a-signature"
    assert channel.send("GET", "/api/notes", headers, sealed).status_code == 401


def test_replay_rejected(channel):
    headers, sealed = channel.build("POST", "/api/notes", {"title": "once"})
    assert channel.send("POST", "/api/notes", headers, sealed).status_code == 201
    assert channel.send("POST", "/api/notes", headers, sealed).status_code == 401
    _, notes = channel.json("GET", "/api/notes")
    assert len(notes) == 1


def test_stale_timestamp_rejected(channel):
    old = str(int((time.time() - 120) * 1000))
    assert channel.call("GET", "/api/notes", ts=old).status_code == 401
    future = str(int((time.time() + 120) * 1000))
    assert channel.call("GET", "/api/notes", ts=future).status_code == 401


def test_keys_from_another_session_rejected(make_client, sign_key):
    http = make_client()
    first = ChannelClient(http, sign_key[1])
    first.handshake()
    second = ChannelClient(http, sign_key[1])
    second.handshake()  # 쿠키가 두 번째 세션으로 교체되고 첫 세션은 삭제된다
    assert first.call("GET", "/api/notes").status_code == 401
    assert second.call("GET", "/api/notes").status_code == 200


def test_oversized_body_rejected(make_client, sign_key):
    client = ChannelClient(make_client(max_body_bytes=2048), sign_key[1])
    client.handshake()
    assert client.call("POST", "/api/notes", {"title": "a", "body": "b" * 3000}).status_code == 413


# ── 클라이언트 가드 신호 ────────────────────────────────────────────────
def test_guard_signal_revokes_session(channel):
    response, body = channel.json("POST", "/api/sec/report", {"signal": "devtools-timing", "path": "/"})
    assert response.status_code == 200
    assert body == {"action": "block"}
    response = channel.call("GET", "/api/notes")
    assert response.status_code == 403
    assert response.json()["code"] == "revoked"


def test_noisy_guard_signal_only_logged(channel):
    _, body = channel.json("POST", "/api/sec/report", {"signal": "devtools-size", "path": "/"})
    assert body == {"action": "none"}
    assert channel.call("GET", "/api/notes").status_code == 200


def test_guard_report_policy_never_revokes(make_client, sign_key):
    client = ChannelClient(make_client(guard_policy="report"), sign_key[1])
    client.handshake()
    _, body = client.json("POST", "/api/sec/report", {"signal": "devtools-timing"})
    assert body == {"action": "none"}
    assert client.call("GET", "/api/notes").status_code == 200


def test_guard_rejects_unknown_signal(channel):
    response, _ = channel.json("POST", "/api/sec/report", {"signal": "<script>", "path": "/"})
    assert response.status_code == 422


def test_revoked_session_data_not_inherited(channel):
    channel.json("POST", "/api/sec/report", {"signal": "debugger-tamper"})
    # 무효화된 뒤 다시 핸드셰이크하면 새 세션이 발급되고 정상 동작한다(데이터는 이어받지 않는다).
    assert channel.handshake().status_code == 200
    assert channel.call("GET", "/api/notes").status_code == 200
