/** 바이트 ↔ base64url, 바이트 이어 붙이기. */

export type Bytes = Uint8Array<ArrayBuffer>

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function utf8(text: string): Bytes {
  return new Uint8Array(encoder.encode(text))
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function b64u(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function unb64u(text: string): Bytes {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length))
}
