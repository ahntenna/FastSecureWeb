/**
 * 릴리즈 빌드 난독화 옵션 (javascript-obfuscator). scripts/obfuscate.mjs 가 읽는다.
 *
 * - target: 'browser-no-eval' → eval/new Function 을 쓰지 않는 출력. CSP(script-src 'self')와 충돌하지 않는다.
 * - debugProtection 은 Function 생성자를 써서 CSP 에 걸리므로 켜지 않는다.
 *   안티 디버깅은 src/security/clientGuard.ts 가 담당한다.
 * - 난독화는 번들 크기와 실행 속도를 희생한다. 화면이 느려지면 threshold 값을 낮춘다.
 */

// 쉼표로 구분한 도메인 목록. 지정하면 그 도메인에서만 실행된다(번들 복제 방지).
// 예: OBF_DOMAIN_LOCK=example.com,.example.com  (로컬 테스트 시에는 비워 둔다)
const domainLock = (process.env.OBF_DOMAIN_LOCK ?? '')
  .split(',')
  .map((d) => d.trim())
  .filter(Boolean)

export default {
  target: 'browser-no-eval',
  compact: true,
  simplify: true,
  identifierNamesGenerator: 'hexadecimal',
  renameGlobals: false,

  controlFlowFlattening: true,
  controlFlowFlatteningThreshold: 0.5,
  deadCodeInjection: true,
  deadCodeInjectionThreshold: 0.2,
  numbersToExpressions: true,
  transformObjectKeys: true,

  stringArray: true,
  stringArrayThreshold: 1, // 모든 문자열을 인코딩한다(헤더 이름 같은 단서가 평문으로 남지 않게)
  stringArrayEncoding: ['rc4'],
  stringArrayCallsTransform: true,
  stringArrayRotate: true,
  stringArrayShuffle: true,
  stringArrayWrappersCount: 2,
  stringArrayWrappersType: 'function',
  splitStrings: true,
  splitStringsChunkLength: 8,

  selfDefending: true,
  debugProtection: false,
  disableConsoleOutput: false,

  domainLock,
  sourceMap: false,
}
