/**
 * 보안 채널 (fsw-v1) — 서버와 세션 키를 합의하고, 요청 서명·본문 암호화에 쓴다.
 *
 * 흐름
 *  1. 임시 ECDH P-256 키 쌍을 만들고 공개키를 /api/hs 로 보낸다.
 *  2. 서버가 보낸 임시 공개키·salt·서명을 받는다. 서명은 번들에 박힌 서버 공개키
 *     (__SERVER_SIGN_PUB__)로 검증한다. 가로채기 프록시가 키 합의에 끼어들면
 *     서명을 만들 수 없으므로 여기서 실패한다.
 *  3. 공유 비밀 → HKDF → AES-GCM 키 + HMAC 키. 둘 다 추출 불가(non-extractable)로
 *     들여와 메모리에만 둔다. localStorage 등에 저장하지 않는다.
 *
 * 기대 수준: 브라우저를 직접 조작하는 공격자는 이 코드를 고쳐 쓸 수 있다. 이 채널은
 * 프록시에서의 평문 열람·변조·재전송을 막고 분석 비용을 올리는 장치이며, 인가·입력
 * 검증 같은 결정은 언제나 서버가 한다.
 */
import { b64u, concat, unb64u, utf8, type Bytes } from './codec'

const PROTOCOL = 'fsw-v1'
const HS_CONTEXT = 'fsw-v1-hs'
const EC = { name: 'ECDH', namedCurve: 'P-256' } as const

export interface ChannelKeys {
  enc: CryptoKey
  mac: CryptoKey
  /** 서버 시각 - 클라이언트 시각(ms). 사용자의 시계가 틀려도 타임스탬프 검사를 통과하게 한다. */
  clockOffset: number
}

export class ChannelError extends Error {
  constructor(message: string, readonly status = 0) {
    super(message)
    this.name = 'ChannelError'
  }
}

/** 운영 빌드에서는 항상 켠다. 개발에서만 VITE_SECURE_CHANNEL=off 로 끌 수 있다. */
export const channelEnabled: boolean = import.meta.env.PROD || import.meta.env.VITE_SECURE_CHANNEL !== 'off'

let keys: ChannelKeys | null = null
let pending: Promise<ChannelKeys> | null = null

async function handshake(): Promise<ChannelKeys> {
  if (!globalThis.crypto?.subtle) {
    // WebCrypto 는 보안 컨텍스트(HTTPS 또는 localhost)에서만 제공된다.
    throw new ChannelError('이 페이지는 HTTPS(또는 localhost)에서만 동작합니다')
  }
  const subtle = crypto.subtle
  const pair = await subtle.generateKey(EC, false, ['deriveBits'])
  const clientPub = new Uint8Array(await subtle.exportKey('raw', pair.publicKey))

  const response = await fetch('/api/hs', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pub: b64u(clientPub) }),
  })
  if (!response.ok) throw new ChannelError('보안 채널을 열 수 없습니다', response.status)
  const reply = (await response.json()) as { pub: string; salt: string; sig: string; ts: number }
  const serverPub = unb64u(reply.pub)
  const salt = unb64u(reply.salt)

  // 서버 신원 검증
  const identity = await subtle.importKey(
    'raw',
    unb64u(__SERVER_SIGN_PUB__),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const trusted = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    identity,
    unb64u(reply.sig),
    concat(utf8(HS_CONTEXT), serverPub, clientPub, salt),
  )
  if (!trusted) throw new ChannelError('서버 신원을 확인할 수 없습니다')

  // 키 유도
  const peer = await subtle.importKey('raw', serverPub, EC, false, [])
  const shared = await subtle.deriveBits({ name: 'ECDH', public: peer }, pair.privateKey, 256)
  const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits'])
  const okm: Bytes = new Uint8Array(
    await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8(PROTOCOL) }, material, 512),
  )
  const enc = await subtle.importKey('raw', okm.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt'])
  const mac = await subtle.importKey('raw', okm.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  okm.fill(0)

  return { enc, mac, clockOffset: reply.ts - Date.now() }
}

/** 세션 키를 돌려준다. 없으면 핸드셰이크한다(동시 호출은 한 번만 수행). */
export function ensureChannel(): Promise<ChannelKeys> {
  if (keys) return Promise.resolve(keys)
  pending ??= handshake()
    .then((k) => {
      keys = k
      return k
    })
    .finally(() => {
      pending = null
    })
  return pending
}

/** 서버가 세션을 모른다고 답했을 때(만료·재시작) 호출한다. 다음 요청에서 다시 핸드셰이크한다. */
export function resetChannel(): void {
  keys = null
}
