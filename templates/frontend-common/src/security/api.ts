/**
 * API 클라이언트 — 서버 호출은 반드시 이 모듈의 api() 를 거친다.
 *
 *   const notes = await api<Note[]>('GET', '/api/notes?limit=20')
 *   await api('POST', '/api/notes', { title: '제목' })
 *
 * 요청마다 타임스탬프·nonce·HMAC 서명을 붙이고 본문을 AES-GCM 으로 암호화한다.
 * 응답은 복호화해서 돌려준다. 암호화되지 않은 성공 응답은 신뢰하지 않는다
 * (프록시가 가짜 성공 응답을 끼워 넣는 것을 막는다).
 */
import { channelEnabled, ensureChannel, resetChannel } from './channel'
import { b64u, concat, fromUtf8, randomBytes, utf8, type Bytes } from './codec'

export type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export class ApiError extends Error {
  constructor(readonly status: number, readonly detail: unknown = null) {
    super(`API ${status}`)
    this.name = 'ApiError'
  }
}

// ── 차단 상태: 서버가 세션을 무효화하면 화면을 차단 안내로 바꾼다 ──────────
let blocked = false
const blockListeners = new Set<() => void>()

export function isBlocked(): boolean {
  return blocked
}

export function onBlocked(listener: () => void): () => void {
  blockListeners.add(listener)
  if (blocked) listener()
  return () => blockListeners.delete(listener)
}

export function markBlocked(): void {
  if (blocked) return
  blocked = true
  for (const listener of blockListeners) listener()
}

// ── 요청 ────────────────────────────────────────────────────────────────
function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(fromUtf8(bytes))
  } catch {
    return null
  }
}

async function plainRequest<T>(method: Method, target: string, body: unknown): Promise<T> {
  const response = await fetch(target, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const data = parseJson(new Uint8Array(await response.arrayBuffer()))
  if (!response.ok) throw new ApiError(response.status, data)
  return data as T
}

export async function api<T = unknown>(method: Method, path: string, body?: unknown): Promise<T> {
  if (blocked) throw new ApiError(403, { code: 'revoked' })

  // 서명 대상은 실제로 전송되는 경로+쿼리와 정확히 같아야 한다.
  const url = new URL(path, location.origin)
  if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) {
    throw new Error('api() 는 같은 출처의 /api/ 경로만 호출합니다')
  }
  const target = url.pathname + url.search
  if (!channelEnabled) return plainRequest<T>(method, target, body)

  const subtle = crypto.subtle
  for (let attempt = 0; ; attempt += 1) {
    const keys = await ensureChannel()
    const ts = String(Date.now() + keys.clockOffset)
    const nonce = b64u(randomBytes(16))

    let payload: Bytes = new Uint8Array(0)
    if (body !== undefined) {
      const iv = randomBytes(12)
      const additionalData = utf8(['req', method, target, ts, nonce].join('\n'))
      const sealed = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, keys.enc, utf8(JSON.stringify(body)))
      payload = concat(iv, new Uint8Array(sealed))
    }
    const digest = b64u(new Uint8Array(await subtle.digest('SHA-256', payload)))
    const signature = await subtle.sign('HMAC', keys.mac, utf8([method, target, ts, nonce, digest].join('\n')))

    // 객체 리터럴의 키는 난독화기가 문자열로 취급하지 않아 평문으로 남는다.
    // 헤더 이름이 번들에 그대로 드러나지 않도록 set() 의 인자로 넘긴다.
    const headers = new Headers()
    headers.set('X-Ts', ts)
    headers.set('X-Nonce', nonce)
    headers.set('X-Sig', b64u(new Uint8Array(signature)))
    if (payload.length > 0) headers.set('Content-Type', 'application/octet-stream')

    const response = await fetch(target, {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers,
      body: payload.length > 0 ? payload : undefined,
    })
    const raw = new Uint8Array(await response.arrayBuffer())

    if (response.headers.get('x-enc') === '1') {
      const additionalData = utf8(['res', nonce, String(response.status)].join('\n'))
      let plain: ArrayBuffer
      try {
        plain = await subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData }, keys.enc, raw.slice(12))
      } catch {
        throw new ApiError(response.status, { code: 'tampered-response' })
      }
      const data = parseJson(new Uint8Array(plain))
      if (!response.ok) throw new ApiError(response.status, data)
      return data as T
    }

    // 여기부터는 암호화되지 않은 응답: 본문 없는 성공(204) 또는 채널 밖에서 난 오류뿐이어야 한다.
    const info = raw.length > 0 ? (parseJson(raw) as { code?: string } | null) : null
    if (response.status === 401 && info?.code === 'channel' && attempt === 0) {
      resetChannel() // 세션 만료·서버 재시작: 한 번만 다시 핸드셰이크해 재시도
      continue
    }
    if (response.status === 403 && info?.code === 'revoked') {
      markBlocked()
    }
    if (!response.ok) throw new ApiError(response.status, info)
    if (raw.length > 0) throw new ApiError(response.status, { code: 'unprotected-response' })
    return undefined as T
  }
}
