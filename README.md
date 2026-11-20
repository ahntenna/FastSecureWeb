# FastSecureWeb

보안을 최우선으로 둔 웹 서비스 보일러플레이트 생성기.
대화형 CLI 로 백엔드·프론트엔드를 골라 새 프로젝트를 만든다.

| 선택 | 종류 |
|---|---|
| 백엔드 | **FastAPI** (Python · SQLAlchemy · Alembic) 또는 **Rust** (Axum · sqlx) |
| 프론트엔드 | **Vue 3** 또는 **React 19** (TypeScript · Vite) |
| DB | SQLite |
| 배포 | Docker (web + api 컨테이너), Nginx Proxy Manager 뒤 |

## 사용법

```bat
.\create.bat
```

또는 옵션을 직접 지정:

```bat
node create.mjs --name my-app --backend fastapi --frontend vue --dir C:\Projects --no-install
```

| 옵션 | 설명 |
|---|---|
| `--name` | 프로젝트 이름 (영문 소문자·숫자·하이픈, 3~40자) |
| `--backend` | `fastapi` \| `rust` |
| `--frontend` | `vue` \| `react` |
| `--dir` | 프로젝트 폴더를 만들 상위 경로 (기본: 이 저장소의 상위 폴더) |
| `--install` / `--no-install` | 생성 직후 의존성 설치 여부 |

필요한 도구: Node.js 22+, 그리고 백엔드에 따라 Python 3.12+ 또는 Rust(rustup). Docker 는 컨테이너로 실행할 때만 필요하다.

## 생성된 프로젝트에 들어 있는 것

**가로채기 프록시 대응 (보안 채널)**
- 세션마다 ECDH 로 키를 합의하고, 서버가 장기 키로 서명해 프록시의 중간자 개입을 막는다
- 요청마다 HMAC 서명 + 타임스탬프 + nonce → 변조·재전송 거부
- 요청·응답 본문 AES-GCM 암호화 → 프록시에서 평문이 보이지 않는다

**리버싱 방지**
- 프론트 릴리즈 빌드: 소스맵 없음, console 제거, 앱 코드 난독화(CSP 호환), 번들 점검 자동화, 선택적 도메인 잠금
- 클라이언트 가드: 개발자 도구·디버거·함수 후킹 탐지 → 서버 보고 → 서버가 세션 무효화
- 백엔드: FastAPI 는 Cython 네이티브 컴파일 + `.pyc`(소스 제거), Rust 는 LTO + 심볼 제거 + distroless 이미지

**서버·배포 기본기**
- 운영 기본값 설정(누락 시 기동 거부), Host·Origin 검사, 엄격한 입력 스키마, 속도 제한, 보안 이벤트 기록
- CSP(`script-src 'self'`), HttpOnly·Secure·SameSite=Strict 쿠키
- 컨테이너: non-root, 읽기 전용 루트, capability 제거, 내부 전용 네트워크, 호스트 포트 미공개
- **포트는 `ports.env` 한 파일**에서 설정
- 로컬 테스트용 배치 스크립트 (`setup` · `dev` · `test` · `build-release` · `preview-release` · `docker`)
- 보안 동작을 고정하는 자동 테스트 (FastAPI 28개, Rust 17개)

무엇을 막고 무엇을 막지 못하는지는 생성된 프로젝트의 `docs/SECURITY.md` 에 정리돼 있다.
요약하면 **보안 경계는 서버**이고, 난독화·안티 디버깅·클라이언트 쪽 채널 코드는 분석을 늦추는 지연 수단이다.

## 저장소 구조

```
create.mjs / create.bat      생성기
templates/
  common/                    docker-compose, ports.env, 스크립트, 문서
  backend-fastapi/           FastAPI 백엔드
  backend-rust/              Rust(Axum) 백엔드
  frontend-common/           보안 모듈, nginx 설정, 난독화·점검 스크립트, Dockerfile
  frontend-vue/              Vue 화면 코드
  frontend-react/            React 화면 코드
```

두 백엔드는 같은 프로토콜(fsw-v1)과 같은 API 를 구현하고, 두 프론트는 `frontend-common/src/security` 를 공유한다.
프로토콜을 바꿀 때는 백엔드 두 곳(`security/crypto`)과 프론트(`channel.ts`, `api.ts`)를 함께 고치고 양쪽 테스트를 돌린다.

템플릿 안의 `__PROJECT_NAME__`, `__BACKEND_LABEL__`, `__FRONTEND_LABEL__` 은 생성 시 치환된다.

## 검증 상태

| 항목 | 상태 |
|---|---|
| FastAPI 보안 테스트, 보호 빌드(Cython + .pyc) 결과물로 재실행 | 통과 |
| Rust 보안 테스트, release 빌드 | 통과 |
| Vue·React 타입 검사, 난독화 릴리즈 빌드, 번들 점검 | 통과 |
| 난독화 번들 + CSP 로 실제 브라우저에서 핸드셰이크·암호화 요청·후킹 탐지 차단 | 통과 |
| **Docker 이미지 빌드, compose 기동, nginx 설정, NPM 연동** | **미검증** (작성 환경에 Docker 없음) |
