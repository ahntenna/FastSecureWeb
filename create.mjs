#!/usr/bin/env node
/**
 * FastSecureWeb 프로젝트 생성기.
 *
 *   node create.mjs                         대화형
 *   node create.mjs --name my-app --backend fastapi --frontend vue --dir C:\work --no-install
 *
 * templates/ 의 조각을 조합해 새 프로젝트를 만든다.
 *   common/             → <프로젝트>/            (docker-compose, ports.env, 스크립트, 문서)
 *   backend-<선택>/     → <프로젝트>/backend/
 *   frontend-common/    → <프로젝트>/frontend/   (보안 모듈, nginx, 난독화 스크립트)
 *   frontend-<선택>/    → <프로젝트>/frontend/   (프레임워크별 화면 코드)
 */
import { spawnSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs } from 'node:util'
import * as p from '@clack/prompts'

const here = dirname(fileURLToPath(import.meta.url))
const templates = join(here, 'templates')

const BACKENDS = {
  fastapi: { label: 'FastAPI', hint: 'Python · SQLAlchemy · Alembic', dir: 'backend-fastapi', needs: ['python'] },
  rust: { label: 'Rust', hint: 'Axum · sqlx', dir: 'backend-rust', needs: ['cargo'] },
}
const FRONTENDS = {
  vue: { label: 'Vue', hint: 'Vue 3 · TypeScript · Vite', dir: 'frontend-vue' },
  react: { label: 'React', hint: 'React 19 · TypeScript · Vite', dir: 'frontend-react' },
}

// 템플릿 폴더에 남아 있을 수 있는 빌드 산출물·의존성은 복사하지 않는다.
const SKIP = new Set(['node_modules', 'dist', 'target', '.venv', 'venv', '__pycache__', '.pytest_cache', 'out', 'data'])
const TEXT_EXT = new Set([
  '.md', '.json', '.yml', '.yaml', '.toml', '.env', '.example', '.txt', '.html', '.css', '.ts', '.tsx', '.vue',
  '.mjs', '.js', '.py', '.rs', '.sql', '.bat', '.sh', '.conf', '.template', '.ini', '.mako', '',
])
const NAME_RULE = /^[a-z][a-z0-9-]{1,38}[a-z0-9]$/

function validateName(value) {
  if (!value) return '프로젝트 이름을 입력하세요'
  if (!NAME_RULE.test(value)) return '영문 소문자로 시작하고 소문자·숫자·하이픈만 사용 (3~40자)'
  return undefined
}

function fail(message) {
  p.cancel(message)
  process.exit(1)
}

function ask(value) {
  if (p.isCancel(value)) fail('취소했습니다.')
  return value
}

function copyTree(from, to) {
  cpSync(from, to, {
    recursive: true,
    filter: (source) => !SKIP.has(source.split(/[\\/]/).pop()),
  })
}

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    return statSync(path).isDirectory() ? walk(path) : [path]
  })
}

function hasCommand(command) {
  const probe = process.platform === 'win32' ? 'where' : 'which'
  return spawnSync(probe, [command], { stdio: 'ignore' }).status === 0
}

const { values: flags } = parseArgs({
  options: {
    name: { type: 'string' },
    backend: { type: 'string' },
    frontend: { type: 'string' },
    dir: { type: 'string' },
    install: { type: 'boolean' },
    'no-install': { type: 'boolean' },
    help: { type: 'boolean', short: 'h' },
  },
})

if (flags.help) {
  console.log(`사용법: node create.mjs [옵션]
  --name <이름>         프로젝트 이름 (소문자·숫자·하이픈)
  --backend <종류>      ${Object.keys(BACKENDS).join(' | ')}
  --frontend <종류>     ${Object.keys(FRONTENDS).join(' | ')}
  --dir <경로>          프로젝트 폴더를 만들 상위 경로 (기본: 이 저장소의 상위 폴더)
  --install             생성 후 의존성 설치(scripts\\setup.bat)까지 실행
  --no-install          의존성 설치를 묻지 않고 건너뜀
옵션을 생략하면 대화형으로 묻습니다.`)
  process.exit(0)
}

p.intro('FastSecureWeb — 보안 강화 웹 서비스 프로젝트 생성')

if (flags.name && validateName(flags.name)) fail(`--name: ${validateName(flags.name)}`)
if (flags.backend && !BACKENDS[flags.backend]) fail(`--backend 는 ${Object.keys(BACKENDS).join(', ')} 중 하나여야 합니다`)
if (flags.frontend && !FRONTENDS[flags.frontend]) fail(`--frontend 는 ${Object.keys(FRONTENDS).join(', ')} 중 하나여야 합니다`)

const name =
  flags.name ?? ask(await p.text({ message: '프로젝트 이름', placeholder: 'my-secure-app', validate: validateName }))

const backendKey =
  flags.backend ??
  ask(
    await p.select({
      message: '백엔드',
      options: Object.entries(BACKENDS).map(([value, b]) => ({ value, label: b.label, hint: b.hint })),
    }),
  )

const frontendKey =
  flags.frontend ??
  ask(
    await p.select({
      message: '프론트엔드',
      options: Object.entries(FRONTENDS).map(([value, f]) => ({ value, label: f.label, hint: f.hint })),
    }),
  )

/**
 * 프로젝트 폴더를 만들 상위 경로를 정한다.
 * 경로가 없으면 만들지 묻고, 거절하거나 만들 수 없으면 다시 입력받는다.
 */
async function chooseParentDir() {
  const fallback = resolve(here, '..')
  // --dir 로 받은 값은 첫 시도에만 쓴다. 그 경로를 쓰지 못하게 되면 대화형으로 다시 묻는다.
  let preset = flags.dir

  for (;;) {
    const input =
      preset ?? ask(await p.text({ message: '프로젝트 폴더를 만들 위치', initialValue: fallback, defaultValue: fallback }))
    preset = undefined
    const dir = resolve(String(input).trim())

    if (existsSync(dir)) {
      if (statSync(dir).isDirectory()) return dir
      p.log.error(`폴더가 아니라 파일입니다: ${dir}`)
      continue
    }

    const create = ask(await p.confirm({ message: `경로가 없습니다: ${dir}\n새로 만들까요?`, initialValue: true }))
    if (!create) {
      p.log.info('다른 위치를 입력하세요. (취소: Ctrl+C)')
      continue
    }
    try {
      mkdirSync(dir, { recursive: true })
      p.log.success(`폴더를 만들었습니다: ${dir}`)
      return dir
    } catch (error) {
      p.log.error(`폴더를 만들 수 없습니다: ${error.message}`)
    }
  }
}

const parent = await chooseParentDir()
const target = join(parent, name)
if (existsSync(target)) fail(`이미 존재하는 폴더입니다: ${target} (기존 파일은 덮어쓰지 않습니다)`)

const backend = BACKENDS[backendKey]
const frontend = FRONTENDS[frontendKey]

// ── 생성 ────────────────────────────────────────────────────────────────
const spin = p.spinner()
spin.start('템플릿을 복사하는 중')
copyTree(join(templates, 'common'), target)
copyTree(join(templates, backend.dir), join(target, 'backend'))
copyTree(join(templates, 'frontend-common'), join(target, 'frontend'))
copyTree(join(templates, frontend.dir), join(target, 'frontend'))

const replacements = {
  __PROJECT_NAME__: name,
  __BACKEND_LABEL__: backend.label,
  __FRONTEND_LABEL__: frontend.label,
}
for (const file of walk(target)) {
  const base = file.split(/[\\/]/).pop()
  if (base === '_gitignore') {
    renameSync(file, join(dirname(file), '.gitignore'))
    continue
  }
  if (!TEXT_EXT.has(extname(file)) && !base.startsWith('.')) continue
  const before = readFileSync(file, 'utf8')
  let after = before
  for (const [token, value] of Object.entries(replacements)) after = after.split(token).join(value)
  if (after !== before) writeFileSync(file, after)
}
spin.stop('템플릿 복사 완료')

// 서버 서명 키 생성 (개발용). 운영 서버에서는 그 서버에서 다시 만든다.
const keygen = spawnSync(process.execPath, [join(target, 'scripts', 'gen-keys.mjs')], { stdio: 'ignore' })
if (keygen.status !== 0) fail('서명 키 생성에 실패했습니다: node scripts/gen-keys.mjs 를 직접 실행해 보세요')
p.log.success('서버 서명 키 생성 (secrets/)')

const missing = backend.needs.filter((command) => !hasCommand(command))
if (missing.length > 0) p.log.warn(`이 PC 에서 찾지 못한 도구: ${missing.join(', ')} — 로컬 실행 전에 설치가 필요합니다`)

// ── 의존성 설치(선택) ───────────────────────────────────────────────────
let install = false
if (process.platform === 'win32' && !flags['no-install']) {
  install = flags.install ?? ask(await p.confirm({ message: '지금 의존성을 설치할까요? (scripts\\setup.bat, 몇 분 걸립니다)', initialValue: false }))
}
if (install) {
  p.log.step('scripts\\setup.bat 실행')
  const setup = spawnSync('cmd', ['/c', join(target, 'scripts', 'setup.bat')], { stdio: 'inherit' })
  if (setup.status !== 0) p.log.warn('설치 중 오류가 있었습니다. scripts\\setup.bat 을 다시 실행해 확인하세요.')
}

p.note(
  [
    `cd ${target}`,
    install ? '' : 'scripts\\setup.bat            의존성 설치 (최초 1회)',
    'scripts\\dev.bat              로컬 개발 서버 (Docker 없이)',
    'scripts\\test.bat             보안 테스트 + 타입 검사',
    'scripts\\preview-release.bat  난독화된 릴리즈 번들을 로컬에서 확인',
    'scripts\\docker.bat local up  Docker 로 로컬 테스트',
    '',
    '포트: ports.env   ·   운영 배포: docs/DEPLOY.md   ·   보안 설계: docs/SECURITY.md',
  ]
    .filter((line, index, lines) => line !== '' || lines[index - 1] !== '')
    .join('\n'),
  '다음 단계',
)
p.outro(`${name} 생성 완료 (${backend.label} + ${frontend.label})`)
