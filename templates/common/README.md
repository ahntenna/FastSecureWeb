# __PROJECT_NAME__

__BACKEND_LABEL__ + __FRONTEND_LABEL__ + SQLite 웹 서비스. FastSecureWeb 보일러플레이트로 생성했다.

- 보안 설계와 한계: [docs/SECURITY.md](docs/SECURITY.md)
- 운영 배포(Docker + Nginx Proxy Manager): [docs/DEPLOY.md](docs/DEPLOY.md)

## 빠른 시작 (Windows, Docker 없이)

```bat
scripts\setup.bat     :: 최초 1회: 서명 키 생성, 백엔드·프론트 의존성 설치
scripts\dev.bat       :: 백엔드 + Vite 개발 서버 (각각 새 창)
```

브라우저에서 `http://localhost:5173` (포트는 `ports.env` 의 `DEV_WEB_PORT`).

## 스크립트

| 스크립트 | 용도 |
|---|---|
| `scripts\setup.bat` | 최초 설정 |
| `scripts\dev.bat` | 로컬 개발 서버 |
| `scripts\test.bat` | 백엔드 보안 테스트 + 프론트 타입 검사 |
| `scripts\build-release.bat` | 프론트 릴리즈 빌드(난독화 + 번들 점검) → `frontend\dist` |
| `scripts\preview-release.bat` | 난독화된 릴리즈 번들을 CSP 와 함께 로컬에서 실행해 보기 |
| `scripts\docker.bat local up` | Docker 로 로컬 테스트 (`http://127.0.0.1:8080`) |
| `scripts/docker.sh npm up` | 운영 서버에서 NPM 뒤에 기동 |
| `node scripts/gen-keys.mjs` | 서버 서명 키 생성 (`--force` 로 교체) |

## 설정 파일

| 파일 | 내용 | 커밋 |
|---|---|---|
| `ports.env` | **모든 포트** (Docker, 로컬 개발) | O |
| `.env` | 운영 설정. `.env.example` 을 복사해 작성 | X |
| `backend/.env` | 로컬 개발 설정. `backend/.env.dev.example` 에서 복사됨 | X |
| `secrets/server_sign_key.pem` | 서버 서명 개인키 | X |
| `secrets/server_sign_pub.txt` | 서버 서명 공개키 (프론트 번들에 포함됨) | X |

## 폴더 구조

```
backend/            API 서버 (보안 채널 미들웨어, 예제 CRUD, 보안 테스트)
frontend/
  src/security/     보안 채널(channel.ts), API 클라이언트(api.ts), 클라이언트 가드
  nginx/            web 컨테이너 설정 (CSP, /api 프록시, 속도 제한)
  scripts/          난독화(obfuscate.mjs), 번들 점검(verify-dist.mjs)
docker-compose.yml          기본 구성 (호스트 포트 없음)
docker-compose.local.yml    로컬 테스트용: 127.0.0.1 에 포트 게시
docker-compose.npm.yml      운영용: NPM 네트워크에 연결
```

## 개발할 때 알아 둘 것

- **API 호출은 `frontend/src/security/api.ts` 의 `api()` 만 쓴다.** 요청 서명·본문 암호화·응답 복호화를 여기서 한다. `fetch` 를 직접 쓰면 서버가 401 로 거부한다.
- **개발 중 평문으로 요청을 보고 싶으면** `backend/.env` 에 `SECURE_CHANNEL=false`, `frontend/.env.development.local` 에 `VITE_SECURE_CHANNEL=off` 를 넣는다. 운영 설정·운영 빌드에서는 끌 수 없다.
- **개발자 도구 탐지(클라이언트 가드)는 운영 빌드에서만 동작한다.** `preview-release.bat` 으로 띄운 화면에서 개발자 도구를 열면 세션이 끊길 수 있다(`backend/.env` 의 `GUARD_POLICY` 가 `revoke` 일 때).
- **예제 리소스(`notes`)는 본보기다.** 백엔드의 notes 라우터·모델과 프론트의 `src/notes.ts`, 화면 코드를 실제 기능으로 교체한다.
- 인증(로그인)은 포함돼 있지 않다. 붙일 때의 주의점은 `docs/SECURITY.md` 6절에 있다.
