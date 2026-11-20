/**
 * 클라이언트 가드 연결 — 탐지 신호를 보안 채널로 서버에 보고하고,
 * 서버가 세션을 무효화하면(action: "block") 화면을 차단 상태로 바꾼다.
 *
 * - 운영 빌드에서만 동작한다. 개발 중에는 개발자 도구를 써야 하므로 켜지 않는다.
 * - 차단 여부는 서버가 정한다(GUARD_POLICY, GUARD_REVOKE_SIGNALS). 클라이언트는 보고만 한다.
 * - 운영 빌드에서 임시로 끄려면 VITE_CLIENT_GUARD=off 로 빌드한다.
 */
import { api, markBlocked } from './api'
import { startClientGuard } from './clientGuard'

export function startGuard(): void {
  if (!import.meta.env.PROD || import.meta.env.VITE_CLIENT_GUARD === 'off') return

  startClientGuard({
    // 개발자 도구가 열려 있으면 debugger 문에서 멈추고, 그 지연을 devtools-timing 신호로 잡는다.
    antiDebugger: true,
    onDetect: (signal) => {
      api<{ action: string }>('POST', '/api/sec/report', { signal, path: location.pathname })
        .then((result) => {
          if (result?.action === 'block') markBlocked()
        })
        .catch(() => {
          // 보고 실패가 화면 동작을 막지 않게 한다.
        })
    },
  })
}
