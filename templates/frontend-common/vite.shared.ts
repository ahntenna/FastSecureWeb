/**
 * Vite 공통 설정. vite.config.ts 가 프레임워크 플러그인만 얹어서 쓴다.
 *
 * - 포트는 프로젝트 루트의 ports.env 한 곳에서 읽는다.
 * - 개발 서버와 preview 모두 /api 를 로컬 백엔드로 프록시한다(같은 출처 유지, CORS 불필요).
 * - preview 는 nginx/snippets/csp.conf 의 CSP 를 그대로 붙여, 난독화된 릴리즈 번들이
 *   CSP 아래에서 동작하는지 로컬에서 확인할 수 있게 한다.
 */
import { existsSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { UserConfig } from 'vite'

const here = dirname(fileURLToPath(import.meta.url))
const projectRoot = resolve(here, '..')

function readEnvFile(file: string): Record<string, string> {
  const values: Record<string, string> = {}
  if (!existsSync(file)) return values
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line)
    if (match) values[match[1]] = match[2]
  }
  return values
}

function readCsp(): string {
  const snippet = readFileSync(resolve(here, 'nginx/snippets/csp.conf'), 'utf8')
  const match = /Content-Security-Policy\s+"([^"]+)"/.exec(snippet)
  if (!match) throw new Error('nginx/snippets/csp.conf 에서 CSP 를 찾지 못했습니다')
  return match[1]
}

function readSignPublicKey(): string {
  const file = resolve(projectRoot, 'secrets/server_sign_pub.txt')
  if (!existsSync(file)) {
    throw new Error('secrets/server_sign_pub.txt 가 없습니다. 프로젝트 루트에서 `node scripts/gen-keys.mjs` 를 실행하세요.')
  }
  return readFileSync(file, 'utf8').trim()
}

export function sharedConfig(): UserConfig {
  const ports = readEnvFile(resolve(projectRoot, 'ports.env'))
  const webPort = Number(ports.DEV_WEB_PORT ?? 5173)
  const apiPort = Number(ports.DEV_API_PORT ?? 8000)
  const proxy = { '/api': { target: `http://127.0.0.1:${apiPort}`, changeOrigin: false } }

  return {
    define: {
      // 공개키는 비밀이 아니다. 비밀(서명 개인키, API 키 등)은 절대 번들에 넣지 않는다.
      __SERVER_SIGN_PUB__: JSON.stringify(readSignPublicKey()),
    },
    server: { port: webPort, strictPort: true, proxy },
    preview: {
      port: webPort,
      strictPort: true,
      proxy,
      headers: { 'Content-Security-Policy': readCsp() },
    },
    build: {
      sourcemap: false, // 운영 번들에 .map 을 배포하지 않는다
      rolldownOptions: {
        output: {
          // 라이브러리 코드는 vendor 청크로 분리한다. 난독화는 앱 코드 청크에만 건다.
          codeSplitting: {
            groups: [{ name: 'vendor', test: /node_modules/ }],
          },
          minify: {
            compress: {
              dropConsole: true,
              // 클라이언트 가드의 debugger 문은 남겨야 한다(안티 디버깅).
              dropDebugger: false,
            },
          },
        },
      },
    },
  }
}
