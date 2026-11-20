/// <reference types="vite/client" />

/** 서버 장기 서명 공개키(base64url). 빌드 시 secrets/server_sign_pub.txt 에서 주입된다. 공개값이다. */
declare const __SERVER_SIGN_PUB__: string

interface ImportMetaEnv {
  /** 개발 전용: 'off' 면 보안 채널 없이 평문으로 호출한다. 운영 빌드에서는 무시된다. */
  readonly VITE_SECURE_CHANNEL?: string
  /** 'off' 면 운영 빌드에서도 클라이언트 가드를 켜지 않는다. */
  readonly VITE_CLIENT_GUARD?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
