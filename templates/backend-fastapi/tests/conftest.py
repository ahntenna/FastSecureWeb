"""테스트 공용 도구: 운영 설정으로 만든 앱과, 브라우저 역할을 하는 보안 채널 클라이언트."""
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi.testclient import TestClient

from app.config import Settings
from app.factory import create_app
from app.security.core import crypto


@pytest.fixture
def sign_key(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    path = tmp_path / "server_sign_key.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return path, key.public_key()


@pytest.fixture
def make_settings(tmp_path, sign_key):
    def _make(**overrides) -> Settings:
        values = {
            "app_env": "production",
            "allowed_hosts": "testserver",
            "database_path": str(tmp_path / "test.db"),
            "server_sign_key_file": str(sign_key[0]),
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    return _make


@pytest.fixture
def make_client(make_settings):
    def _make(**overrides) -> TestClient:
        # https 로 두어야 Secure 쿠키가 다시 전송된다.
        return TestClient(create_app(make_settings(**overrides)), base_url="https://testserver")

    return _make


class ChannelClient:
    """프론트의 security/channel.ts 와 같은 일을 하는 테스트용 클라이언트."""

    def __init__(self, http: TestClient, identity_public: ec.EllipticCurvePublicKey) -> None:
        self.http = http
        self.identity_public = identity_public
        self.enc_key = b""
        self.mac_key = b""

    def handshake(self):
        private = ec.generate_private_key(ec.SECP256R1())
        client_pub = private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        response = self.http.post("/api/hs", json={"pub": crypto.b64u(client_pub)})
        if response.status_code != 200:
            return response
        payload = response.json()
        server_pub = crypto.b64u_decode(payload["pub"])
        salt = crypto.b64u_decode(payload["salt"])
        sig = crypto.b64u_decode(payload["sig"])
        # 서버 신원 검증: 실패하면 InvalidSignature 예외
        der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
        self.identity_public.verify(
            der, crypto.HS_CONTEXT + server_pub + client_pub + salt, ec.ECDSA(hashes.SHA256())
        )
        shared = private.exchange(
            ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub)
        )
        self.enc_key, self.mac_key = crypto.derive_keys(shared, salt)
        return response

    def build(self, method: str, target: str, body=None, *, ts: str | None = None, nonce: str | None = None):
        """(headers, 암호화된 본문) 을 만든다. 테스트가 전송 전에 변조할 수 있게 분리했다."""
        ts = ts or str(int(time.time() * 1000))
        nonce = nonce or crypto.b64u(os.urandom(16))
        sealed = b""
        if body is not None:
            sealed = crypto.seal(
                self.enc_key, json.dumps(body).encode(), crypto.request_aad(method, target, ts, nonce)
            )
        sig = crypto.sign_request(self.mac_key, method, target, ts, nonce, sealed)
        headers = {"X-Ts": ts, "X-Nonce": nonce, "X-Sig": crypto.b64u(sig)}
        if sealed:
            headers["Content-Type"] = "application/octet-stream"
        return headers, sealed

    def send(self, method: str, target: str, headers: dict, sealed: bytes):
        return self.http.request(method, target, headers=headers, content=sealed or None)

    def call(self, method: str, target: str, body=None, **kwargs):
        headers, sealed = self.build(method, target, body, **kwargs)
        return self.send(method, target, headers, sealed)

    def open(self, response, nonce: str):
        """암호화된 응답 본문을 복호화해 JSON 으로 돌려준다."""
        assert response.headers.get("x-enc") == "1"
        plain = crypto.unseal(
            self.enc_key, response.content, crypto.response_aad(nonce, response.status_code)
        )
        return json.loads(plain)

    def json(self, method: str, target: str, body=None):
        headers, sealed = self.build(method, target, body)
        response = self.send(method, target, headers, sealed)
        return response, self.open(response, headers["X-Nonce"])


@pytest.fixture
def channel(make_client, sign_key):
    client = ChannelClient(make_client(), sign_key[1])
    assert client.handshake().status_code == 200
    return client
