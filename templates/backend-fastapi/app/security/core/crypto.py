"""보안 채널 암호 연산.

프로토콜 (fsw-v1)
  1. 핸드셰이크: 클라이언트 임시 ECDH P-256 공개키 → 서버 임시 공개키 + salt + 서명
     - 공유 비밀 → HKDF-SHA256(salt, info="fsw-v1") 64바이트 → enc_key(32) | mac_key(32)
     - 서명: 서버 장기 키로 ECDSA-SHA256("fsw-v1-hs" | server_pub | client_pub | salt)
       클라이언트는 번들에 박힌 공개키로 검증한다. 중간의 프록시가 키 합의에
       끼어들면 서명을 만들 수 없어 클라이언트가 핸드셰이크를 거부한다.
  2. 요청: X-Ts, X-Nonce, X-Sig 헤더 + (본문이 있으면) iv(12) | AES-256-GCM 암호문
     - 서명 대상: METHOD \n PATH?QUERY \n TS \n NONCE \n b64u(SHA256(전송된 본문))
     - 본문 AAD : "req" \n METHOD \n PATH?QUERY \n TS \n NONCE
  3. 응답: 본문이 있으면 iv(12) | AES-256-GCM 암호문, 헤더 X-Enc: 1
     - 본문 AAD : "res" \n NONCE \n STATUS   (응답을 해당 요청에 묶는다)
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL = b"fsw-v1"
HS_CONTEXT = b"fsw-v1-hs"
IV_LEN = 12
TAG_LEN = 16
RAW_POINT_LEN = 65  # 0x04 | X(32) | Y(32)


class CryptoError(Exception):
    """복호화·검증 실패. 원인을 구분해 응답하지 않는다."""


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    try:
        raw = text.encode("ascii")
        return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    except Exception as exc:  # 잘못된 문자·길이
        raise CryptoError("bad base64") from exc


class ServerIdentity:
    """서버 장기 서명 키. 핸드셰이크 응답의 진위를 클라이언트가 확인하는 근거."""

    def __init__(self, pem):
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("서버 서명 키는 ECDSA P-256 이어야 합니다")
        self._key = key

    def sign(self, message):
        """WebCrypto 가 기대하는 r|s (IEEE P1363, 64바이트) 형식으로 서명한다."""
        der = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public_raw(self):
        return self._key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )


class HandshakeResult:
    __slots__ = ("server_pub", "salt", "signature", "enc_key", "mac_key")

    def __init__(self, server_pub, salt, signature, enc_key, mac_key):
        self.server_pub = server_pub
        self.salt = salt
        self.signature = signature
        self.enc_key = enc_key
        self.mac_key = mac_key


def derive_keys(shared, salt):
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=PROTOCOL).derive(shared)
    return okm[:32], okm[32:]


def handshake(identity, client_pub_raw):
    if len(client_pub_raw) != RAW_POINT_LEN:
        raise CryptoError("bad public key")
    try:
        # 곡선 위의 점인지도 여기서 검증된다.
        client_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_raw)
    except ValueError as exc:
        raise CryptoError("bad public key") from exc

    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), client_pub)
    salt = os.urandom(32)
    enc_key, mac_key = derive_keys(shared, salt)
    server_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    signature = identity.sign(HS_CONTEXT + server_pub + client_pub_raw + salt)
    return HandshakeResult(server_pub, salt, signature, enc_key, mac_key)


def canonical_request(method, target, ts, nonce, body):
    digest = b64u(hashlib.sha256(body).digest())
    return "\n".join((method.upper(), target, ts, nonce, digest)).encode("utf-8")


def sign_request(mac_key, method, target, ts, nonce, body):
    return hmac.new(mac_key, canonical_request(method, target, ts, nonce, body), hashlib.sha256).digest()


def verify_request(mac_key, method, target, ts, nonce, body, signature):
    expected = sign_request(mac_key, method, target, ts, nonce, body)
    return hmac.compare_digest(expected, signature)


def request_aad(method, target, ts, nonce):
    return "\n".join(("req", method.upper(), target, ts, nonce)).encode("utf-8")


def response_aad(nonce, status):
    return "\n".join(("res", nonce, str(status))).encode("utf-8")


def seal(key, plaintext, aad):
    iv = os.urandom(IV_LEN)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


def unseal(key, sealed, aad):
    if len(sealed) < IV_LEN + TAG_LEN:
        raise CryptoError("short ciphertext")
    try:
        return AESGCM(key).decrypt(sealed[:IV_LEN], sealed[IV_LEN:], aad)
    except InvalidTag as exc:
        raise CryptoError("decrypt failed") from exc
