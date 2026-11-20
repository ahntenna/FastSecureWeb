/**
 * 릴리즈 번들 점검 (npm run build:release 의 마지막 단계). 하나라도 걸리면 빌드를 실패시킨다.
 *  - 소스맵(.map 파일, sourceMappingURL 주석)이 없어야 한다
 *  - 개인키·비밀로 보이는 문자열이 없어야 한다
 *  - 앱 코드에 console 호출이 남아 있지 않아야 한다
 *  - 앱 코드에 보안 모듈의 식별자 원문이 남아 있지 않아야 한다(난독화가 실제로 적용됐는지)
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const problems = []

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? walk(path) : [path]
  })
}

const SECRET_PATTERNS = [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bAKIA[0-9A-Z]{16}\b/, /\bsk_live_[0-9a-zA-Z]{16,}/]
const PLAIN_IDENTIFIERS = ['ensureChannel', 'startClientGuard', 'X-Nonce', 'fsw-v1-hs']

for (const path of walk('dist')) {
  if (path.endsWith('.map')) {
    problems.push(`소스맵 파일: ${path}`)
    continue
  }
  if (!/\.(js|css|html)$/.test(path)) continue
  const text = readFileSync(path, 'utf8')
  if (text.includes('sourceMappingURL=')) problems.push(`sourceMappingURL 주석: ${path}`)
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(text)) problems.push(`비밀로 보이는 문자열(${pattern}): ${path}`)
  }
  const isAppChunk = path.endsWith('.js') && !/[\\/]vendor[^\\/]*$/.test(path)
  if (isAppChunk) {
    if (/\bconsole\.(log|debug|info|warn|error)\(/.test(text)) problems.push(`console 호출이 남음: ${path}`)
    for (const name of PLAIN_IDENTIFIERS) {
      if (text.includes(name)) problems.push(`난독화되지 않은 식별자 "${name}": ${path}`)
    }
  }
  console.log(`[verify] ${path}  ${(statSync(path).size / 1024).toFixed(1)}KB`)
}

if (problems.length > 0) {
  console.error('\n[verify] 릴리즈 번들 점검 실패:')
  for (const p of problems) console.error(`  - ${p}`)
  process.exit(1)
}
console.log('[verify] 릴리즈 번들 점검 통과')
