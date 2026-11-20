//! 보안 채널 암호 연산.
//!
//! 프로토콜 (fsw-v1)
//!   1. 핸드셰이크: 클라이언트 임시 ECDH P-256 공개키 → 서버 임시 공개키 + salt + 서명
//!      - 공유 비밀 → HKDF-SHA256(salt, info="fsw-v1") 64바이트 → enc_key(32) | mac_key(32)
//!      - 서명: 서버 장기 키로 ECDSA-SHA256("fsw-v1-hs" | server_pub | client_pub | salt)
//!        클라이언트는 번들에 박힌 공개키로 검증한다. 중간의 프록시가 키 합의에
//!        끼어들면 서명을 만들 수 없어 클라이언트가 핸드셰이크를 거부한다.
//!   2. 요청: X-Ts, X-Nonce, X-Sig 헤더 + (본문이 있으면) iv(12) | AES-256-GCM 암호문
//!      - 서명 대상: METHOD \n PATH?QUERY \n TS \n NONCE \n b64u(SHA256(전송된 본문))
//!      - 본문 AAD : "req" \n METHOD \n PATH?QUERY \n TS \n NONCE
//!   3. 응답: 본문이 있으면 iv(12) | AES-256-GCM 암호문, 헤더 X-Enc: 1
//!      - 본문 AAD : "res" \n NONCE \n STATUS   (응답을 해당 요청에 묶는다)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

pub const PROTOCOL: &[u8] = b"fsw-v1";
pub const HS_CONTEXT: &[u8] = b"fsw-v1-hs";
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const RAW_POINT_LEN: usize = 65; // 0x04 | X(32) | Y(32)

/// 복호화·검증 실패. 원인을 구분해 응답하지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

pub fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn b64u_decode(text: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')).map_err(|_| CryptoError)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buffer = [0u8; N];
    getrandom::fill(&mut buffer).expect("운영체제 난수원을 사용할 수 없습니다");
    buffer
}

/// 서버 장기 서명 키. 핸드셰이크 응답의 진위를 클라이언트가 확인하는 근거.
pub struct ServerIdentity {
    key: SigningKey,
}

impl ServerIdentity {
    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        SigningKey::from_pkcs8_pem(pem).map(|key| Self { key }).map_err(|_| CryptoError)
    }

    /// WebCrypto 가 기대하는 r|s (IEEE P1363, 64바이트) 형식으로 서명한다.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.key.sign(message);
        signature.to_bytes().to_vec()
    }

    pub fn public_raw(&self) -> Vec<u8> {
        self.key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
}

pub struct HandshakeResult {
    pub server_pub: Vec<u8>,
    pub salt: [u8; 32],
    pub signature: Vec<u8>,
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

pub fn derive_keys(shared: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(salt), shared)
        .expand(PROTOCOL, &mut okm)
        .expect("HKDF 출력 길이는 고정이다");
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    enc_key.copy_from_slice(&okm[..32]);
    mac_key.copy_from_slice(&okm[32..]);
    (enc_key, mac_key)
}

/// 임시 ECDH 키 쌍을 만든다. (난수 바이트가 유효한 스칼라가 아닐 확률은 무시할 수준이지만 재시도한다)
pub fn ephemeral_secret() -> SecretKey {
    loop {
        if let Ok(secret) = SecretKey::from_slice(&random_bytes::<32>()) {
            return secret;
        }
    }
}

pub fn public_raw(secret: &SecretKey) -> Vec<u8> {
    secret.public_key().to_sec1_point(false).as_bytes().to_vec()
}

/// 상대 공개키(비압축 65바이트)와 ECDH 를 수행한다. 곡선 위의 점인지도 여기서 검증된다.
pub fn ecdh(secret: &SecretKey, peer_pub_raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if peer_pub_raw.len() != RAW_POINT_LEN || peer_pub_raw[0] != 0x04 {
        return Err(CryptoError);
    }
    let peer = PublicKey::from_sec1_bytes(peer_pub_raw).map_err(|_| CryptoError)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

pub fn handshake(identity: &ServerIdentity, client_pub_raw: &[u8]) -> Result<HandshakeResult, CryptoError> {
    let ephemeral = ephemeral_secret();
    let shared = ecdh(&ephemeral, client_pub_raw)?;
    let salt = random_bytes::<32>();
    let (enc_key, mac_key) = derive_keys(&shared, &salt);
    let server_pub = public_raw(&ephemeral);

    let mut message = Vec::with_capacity(HS_CONTEXT.len() + server_pub.len() + client_pub_raw.len() + salt.len());
    message.extend_from_slice(HS_CONTEXT);
    message.extend_from_slice(&server_pub);
    message.extend_from_slice(client_pub_raw);
    message.extend_from_slice(&salt);
    let signature = identity.sign(&message);

    Ok(HandshakeResult { server_pub, salt, signature, enc_key, mac_key })
}

pub fn canonical_request(method: &str, target: &str, ts: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
    let digest = b64u(&Sha256::digest(body));
    [method.to_ascii_uppercase().as_str(), target, ts, nonce, digest.as_str()].join("\n").into_bytes()
}

fn request_mac(mac_key: &[u8], method: &str, target: &str, ts: &str, nonce: &str, body: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(mac_key).expect("HMAC 은 모든 키 길이를 받는다");
    mac.update(&canonical_request(method, target, ts, nonce, body));
    mac
}

pub fn sign_request(mac_key: &[u8], method: &str, target: &str, ts: &str, nonce: &str, body: &[u8]) -> Vec<u8> {
    request_mac(mac_key, method, target, ts, nonce, body).finalize().into_bytes().to_vec()
}

/// 상수 시간 비교로 서명을 검증한다.
pub fn verify_request(
    mac_key: &[u8],
    method: &str,
    target: &str,
    ts: &str,
    nonce: &str,
    body: &[u8],
    signature: &[u8],
) -> bool {
    request_mac(mac_key, method, target, ts, nonce, body).verify_slice(signature).is_ok()
}

pub fn request_aad(method: &str, target: &str, ts: &str, nonce: &str) -> Vec<u8> {
    ["req", method.to_ascii_uppercase().as_str(), target, ts, nonce].join("\n").into_bytes()
}

pub fn response_aad(nonce: &str, status: u16) -> Vec<u8> {
    format!("res\n{nonce}\n{status}").into_bytes()
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("키 길이는 32바이트다");
    let iv = random_bytes::<IV_LEN>();
    let sealed = cipher
        .encrypt(&iv.into(), Payload { msg: plaintext, aad })
        .expect("AES-GCM 암호화는 실패하지 않는다");
    let mut out = Vec::with_capacity(IV_LEN + sealed.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&sealed);
    out
}

pub fn unseal(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < IV_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError)?;
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&sealed[..IV_LEN]);
    cipher
        .decrypt(&iv.into(), Payload { msg: &sealed[IV_LEN..], aad })
        .map_err(|_| CryptoError)
}
