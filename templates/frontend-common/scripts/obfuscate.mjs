/**
 * dist/assets 의 앱 코드 청크를 난독화한다 (npm run build:release 의 한 단계).
 * vendor 청크(프레임워크·라이브러리)는 건드리지 않는다. 공개된 코드를 난독화해도
 * 얻는 것이 없고 크기와 속도만 나빠진다.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import JavaScriptObfuscator from 'javascript-obfuscator'
import options from '../obfuscator.config.mjs'

const assets = join('dist', 'assets')
let count = 0

for (const file of readdirSync(assets)) {
  if (!file.endsWith('.js')) continue
  if (file.startsWith('vendor')) {
    console.log(`[obfuscate] skip   ${file}`)
    continue
  }
  const path = join(assets, file)
  const source = readFileSync(path, 'utf8')
  const result = JavaScriptObfuscator.obfuscate(source, { ...options, inputFileName: file })
  const output = result.getObfuscatedCode()
  writeFileSync(path, output)
  count += 1
  console.log(`[obfuscate] done   ${file}  ${(source.length / 1024).toFixed(1)}KB -> ${(output.length / 1024).toFixed(1)}KB`)
}

if (count === 0) {
  console.error('[obfuscate] 난독화할 앱 청크를 찾지 못했습니다. 빌드 결과를 확인하세요.')
  process.exit(1)
}
