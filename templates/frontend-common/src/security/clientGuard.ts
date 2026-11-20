/**
 * client-guard — 개발자 도구 탐지 · 안티 디버깅 (프레임워크 비의존 TypeScript)
 *
 * ────────────────────────────────────────────────────────────────────────
 * 먼저 읽을 것. 이 모듈은 보안 경계가 아니라 "지연 수단"이다.
 *
 * - 프록시 도구(Burp 등)로 API를 직접 호출하면 이 코드는 실행되지 않는다.
 *   따라서 인가·검증·가격 계산 같은 결정은 반드시 서버에서 한다. 이 모듈은
 *   그 위에 얹는 추가 마찰일 뿐, 서버 측 통제를 대신하지 못한다.
 * - 수정된 브라우저, Local Overrides, 이 스크립트 제거, 브레이크포인트
 *   비활성화로 모두 우회된다. "막는다"가 아니라 "비용을 올리고 신호를 남긴다"로
 *   기대치를 잡는다.
 * - 그래서 기본 동작은 "차단"이 아니라 "탐지 → 서버 보고"다. 서버가 그 신호를
 *   위험 점수에 반영해 추가 인증·속도 제한·세션 종료를 결정하게 한다. 클라이언트에서
 *   화면을 막는 것은 그 코드를 지우면 끝이라 효과가 약하고 오탐 피해만 크다.
 *
 * 적용 판단: 자동화·봇·대량 스크래핑을 늦춰야 하는 서비스(티켓팅, 응모, 게임,
 * 콘텐츠 보호)에만 선택적으로 켠다. 일반 업무·사내 도구에는 켜지 않는다. 장애
 * 분석만 어려워진다. CSP와의 충돌(일부 기법이 eval/new Function 사용)과 접근성
 * 도구 오탐을 반드시 확인한다.
 * ────────────────────────────────────────────────────────────────────────
 */

export type GuardSignal =
  | 'devtools-size'      // 창 안팎 크기 차이 → 도킹된 개발자 도구 추정
  | 'devtools-timing'    // debugger 문 실행이 비정상적으로 오래 걸림
  | 'devtools-console'   // 콘솔이 객체를 렌더링하며 getter를 건드림
  | 'debugger-tamper'    // 네이티브 함수가 교체됨(후킹) 추정
  | 'automation'         // 헤드리스·자동화 브라우저 특성

export interface GuardConfig {
  /** 탐지 시 호출. 여기서 서버로 보고하는 것을 권장(기본 동작). */
  onDetect: (signal: GuardSignal, detail: Record<string, unknown>) => void
  /** 폴링 간격(ms). 기본 2000. 너무 짧으면 CPU·배터리에 부담. */
  intervalMs?: number
  /** 같은 신호 재보고 억제 간격(ms). 기본 30000. */
  throttleMs?: number
  /** 개발자 도구 크기 판정 임계값(px). 기본 180. 낮추면 오탐 증가. */
  sizeThreshold?: number
  /**
   * 안티 디버깅 debugger 루프를 켤지. 기본 false.
   * 켜면 개발자 도구가 열려 있을 때 페이지가 반복해서 멈춘다. 분석을 느리게 하지만
   * 정당한 사용자가 도구를 열었을 때도 멈추므로, 보호 가치가 큰 화면에만 쓴다.
   */
  antiDebugger?: boolean
  /**
   * 우클릭·단축키(F12, Ctrl+Shift+I/J/C, Ctrl+U) 차단. 기본 false.
   * 사용자 경험과 접근성을 해치고 브라우저 메뉴로 쉽게 우회된다. 권장하지 않으며,
   * 요구가 있을 때만 켠다.
   */
  blockShortcuts?: boolean
}

type Cleanup = () => void

const DEFAULTS = {
  intervalMs: 2000,
  throttleMs: 30000,
  sizeThreshold: 180,
  antiDebugger: false,
  blockShortcuts: false,
}

/**
 * 가드를 시작한다. 반환된 함수를 호출하면 모든 타이머·리스너를 해제한다.
 * SSR·비브라우저 환경에서는 아무것도 하지 않는다.
 */
export function startClientGuard(config: GuardConfig): Cleanup {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return () => {}
  }
  const cfg = { ...DEFAULTS, ...config }
  const lastSent = new Map<GuardSignal, number>()
  const cleanups: Cleanup[] = []

  const report = (signal: GuardSignal, detail: Record<string, unknown> = {}) => {
    const now = Date.now()
    const prev = lastSent.get(signal) ?? 0
    if (now - prev < cfg.throttleMs) return
    lastSent.set(signal, now)
    try {
      cfg.onDetect(signal, detail)
    } catch {
      // 보고 콜백의 예외가 페이지를 멈추지 않게 한다.
    }
  }

  // ── 1) 크기 기반: 도킹된 개발자 도구 추정 ────────────────────────────
  // 분리된 창으로 띄우면 잡지 못한다. 반응형 모드·사이드바에서 오탐이 날 수 있어
  // 임계값을 넉넉히 둔다.
  const checkSize = () => {
    const wGap = window.outerWidth - window.innerWidth
    const hGap = window.outerHeight - window.innerHeight
    if (wGap > cfg.sizeThreshold || hGap > cfg.sizeThreshold) {
      report('devtools-size', { wGap, hGap })
    }
  }

  // ── 2) 타이밍 기반: debugger 문이 멈추면 느려진다 ───────────────────
  // antiDebugger가 켜졌을 때만 debugger를 쓴다. 꺼져 있으면 순수 타이밍만 본다.
  const checkTiming = () => {
    const t0 = performance.now()
    if (cfg.antiDebugger) {
      // 열려 있고 브레이크포인트가 활성이면 여기서 멈춘다. 분석을 느리게 한다.
      // 브레이크포인트를 끄면 바로 우회되므로 결정적 방어가 아니다.
      // eslint-disable-next-line no-debugger
      debugger
    }
    const elapsed = performance.now() - t0
    if (elapsed > 100) {
      report('devtools-timing', { elapsed: Math.round(elapsed) })
    }
  }

  // ── 3) 콘솔 getter 트릭: 콘솔이 객체를 그릴 때 id getter가 불린다 ────
  const bait = Object.create(null)
  let consoleHits = 0
  Object.defineProperty(bait, 'id', {
    get() {
      consoleHits += 1
      report('devtools-console', { hits: consoleHits })
      return ''
    },
  })
  const checkConsole = () => {
    // 콘솔 패널이 열려 이 객체를 렌더링하면 위 getter가 실행된다.
    // 눈에 보이는 출력이 남지 않도록 debug 레벨로 찍고 바로 지운다.
    // eslint-disable-next-line no-console
    console.debug(bait)
    // eslint-disable-next-line no-console
    console.clear?.()
  }

  // ── 4) 네이티브 함수 무결성: 후킹되면 toString이 달라진다 ────────────
  const checkTamper = () => {
    const suspects: [string, (...a: never[]) => unknown][] = [
      ['fetch', window.fetch],
      ['setInterval', window.setInterval],
      ['toString', Function.prototype.toString],
    ]
    for (const [name, fn] of suspects) {
      try {
        if (typeof fn === 'function' && !/\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(fn))) {
          report('debugger-tamper', { fn: name })
        }
      } catch {
        report('debugger-tamper', { fn: name, threw: true })
      }
    }
  }

  // ── 5) 자동화 브라우저 신호(한 번만) ─────────────────────────────────
  const checkAutomation = () => {
    const nav = navigator as Navigator & { webdriver?: boolean }
    if (nav.webdriver === true) {
      report('automation', { reason: 'navigator.webdriver' })
    }
    if (/\bHeadless/i.test(navigator.userAgent)) {
      report('automation', { reason: 'ua-headless' })
    }
  }

  // ── 폴링 루프 ────────────────────────────────────────────────────────
  const tick = () => {
    checkSize()
    checkTiming()
    checkConsole()
    checkTamper()
  }
  checkAutomation()
  tick()
  const timer = window.setInterval(tick, cfg.intervalMs)
  cleanups.push(() => window.clearInterval(timer))

  // ── 선택: 우클릭·단축키 차단 ─────────────────────────────────────────
  if (cfg.blockShortcuts) {
    const onContext = (e: Event) => e.preventDefault()
    const onKey = (e: KeyboardEvent) => {
      const k = e.key.toUpperCase()
      const block =
        k === 'F12' ||
        (e.ctrlKey && e.shiftKey && (k === 'I' || k === 'J' || k === 'C')) ||
        (e.ctrlKey && k === 'U')
      if (block) {
        e.preventDefault()
        report('devtools-size', { via: 'shortcut', key: k }) // 열기 시도 신호
      }
    }
    document.addEventListener('contextmenu', onContext)
    document.addEventListener('keydown', onKey)
    cleanups.push(() => {
      document.removeEventListener('contextmenu', onContext)
      document.removeEventListener('keydown', onKey)
    })
  }

  return () => {
    for (const c of cleanups) c()
    lastSent.clear()
  }
}

/**
 * 서버 보고용 onDetect 구현. 신호를 디바운스해 엔드포인트로 보낸다.
 * 서버는 이 신호를 위험 점수에 반영하고(차단은 서버가 결정), 응답을 기다리지 않는다.
 * sendBeacon을 쓰면 페이지 전환 중에도 전송이 보장된다.
 */
export function reportToServer(endpoint: string): GuardConfig['onDetect'] {
  return (signal, detail) => {
    const body = JSON.stringify({ signal, detail, path: location.pathname, ts: Date.now() })
    try {
      if (navigator.sendBeacon) {
        navigator.sendBeacon(endpoint, new Blob([body], { type: 'application/json' }))
      } else {
        void fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body,
          credentials: 'same-origin',
          keepalive: true,
        })
      }
    } catch {
      // 네트워크 실패가 페이지에 영향을 주지 않게 한다.
    }
  }
}
