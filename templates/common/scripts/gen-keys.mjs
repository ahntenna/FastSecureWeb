/**
 * 서버 장기 서명 키(ECDSA P-256)를 만든다.
 *
 *   node scripts/gen-keys.mjs           키가 없을 때만 생성
 *   node scripts/gen-keys.mjs --force   새 키로 교체 (프론트를 반드시 다시 빌드·배포해야 한다)
 *
 * 결과
 *   secrets/server_sign_key.pem   개인키. 백엔드만 읽는다. 커밋·공유하지 않는다.
 *   secrets/server_sign_pub.txt   공개키(base64url). 프론트 번들에 박힌다. 비밀이 아니다.
 *
 * 개발용 키와 운영용 키는 따로 쓴다. 운영 서버에서 이 스크립트를 한 번 실행해 그 서버만의
 * 키를 만들고, 그 공개키로 web 이미지를 빌드한다.
 */
import { generateKeyPairSync } from 'node:crypto'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const secretsDir = join(root, 'secrets')
const keyFile = join(secretsDir, 'server_sign_key.pem')
const pubFile = join(secretsDir, 'server_sign_pub.txt')
const force = process.argv.includes('--force')

if (existsSync(keyFile) && !force) {
  console.log('[gen-keys] 이미 키가 있습니다. 교체하려면 --force 를 붙이세요.')
  process.exit(0)
}

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
const jwk = publicKey.export({ format: 'jwk' })
// WebCrypto 의 'raw' 형식: 0x04 | X(32) | Y(32)
const rawPublic = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')])

mkdirSync(secretsDir, { recursive: true })
writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
writeFileSync(pubFile, rawPublic.toString('base64url') + '\n')

console.log(`[gen-keys] 개인키: ${keyFile}`)
console.log(`[gen-keys] 공개키: ${pubFile}`)
if (force) console.log('[gen-keys] 키를 교체했습니다. 프론트(web 이미지)를 다시 빌드하고 백엔드를 재시작하세요.')
