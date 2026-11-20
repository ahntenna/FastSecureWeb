# 운영 배포 (Docker + Nginx Proxy Manager)

외부에 공개되는 것은 NPM 의 80/443 뿐이다. 이 프로젝트의 컨테이너는 호스트 포트를 열지 않는다.

> 아래 절차 중 Docker·NPM 과 관련된 부분은 이 보일러플레이트를 만든 환경에 Docker 가 없어
> 실제 실행으로 검증되지 않았다. 첫 배포 때 8절의 확인 항목을 반드시 실행한다.

## 1. 서버 준비

```sh
git clone <저장소> && cd __PROJECT_NAME__

# 이 서버만의 서명 키를 만든다 (개발용 키를 운영에 쓰지 않는다)
node scripts/gen-keys.mjs
# Node 가 없으면 Docker 로 실행:
#   docker run --rm -v "$PWD":/w -w /w node:22-alpine node scripts/gen-keys.mjs

# api 컨테이너 사용자(uid 10001)만 개인키를 읽게 한다
sudo chown 10001 secrets/server_sign_key.pem
sudo chmod 400 secrets/server_sign_key.pem

cp .env.example .env    # 그리고 값을 채운다 (아래 2절)
```

서명 키를 교체하면(`--force`) 공개키가 프론트 번들에 박혀 있으므로 **web 이미지를 다시 빌드**해야 한다.

## 2. 설정

| 파일 | 내용 |
|---|---|
| `ports.env` | 포트. `WEB_PORT`(web 컨테이너 내부 포트)를 NPM 의 Forward Port 에 적는다 |
| `.env` | `ALLOWED_HOSTS`(서비스 도메인), `TRUSTED_PROXY_CIDR`, `PROXY_NETWORK`, 가드 정책, 도메인 잠금 |

- `ALLOWED_HOSTS` 가 비어 있거나 `*` 가 들어 있으면 api 가 기동을 거부한다.
- `TRUSTED_PROXY_CIDR` 은 NPM 이 속한 Docker 네트워크 대역으로 좁힌다. 넓게 두면 그 대역의 클라이언트가 `X-Forwarded-For` 로 IP 를 위조해 속도 제한을 피할 수 있다.
  ```sh
  docker network inspect proxy --format '{{(index .IPAM.Config 0).Subnet}}'
  ```
- `OBF_DOMAIN_LOCK=example.com` 을 지정하면 프론트 코드가 그 도메인에서만 실행된다(번들 복제 방지). 지정했다면 로컬 Docker 테스트(127.0.0.1)에서는 화면이 뜨지 않는 것이 정상이다.

## 3. 기동

```sh
scripts/docker.sh npm up      # 빌드 + 기동 (docker-compose.yml + docker-compose.npm.yml)
scripts/docker.sh npm ps      # web, api 가 healthy 인지 확인
scripts/docker.sh npm logs
```

`npm` 모드는 web 컨테이너를 NPM 과 같은 외부 네트워크(`PROXY_NETWORK`, 기본 `proxy`)에 연결한다. 그 네트워크가 없으면 NPM 의 compose 에서 먼저 만든다.

## 4. NPM 프록시 호스트

**Details**

| 항목 | 값 |
|---|---|
| Scheme | `http` |
| Forward Hostname | `__PROJECT_NAME__-web` (컨테이너 이름. 호스트 IP 를 쓰지 않는다) |
| Forward Port | `ports.env` 의 `WEB_PORT` |
| Block Common Exploits | 켬 |
| Cache Assets | 끔 (캐시는 web 컨테이너가 제어한다) |

Custom location 은 만들지 않는다. `/api` 는 web 컨테이너의 nginx 가 api 로 넘긴다.

**SSL**: Let's Encrypt 인증서, Force SSL 켬, HTTP/2 켬. HTTPS 가 안정적으로 동작하는 것을 확인한 뒤 HSTS 를 켠다.

**Advanced** (공통 보안 헤더)

```nginx
more_set_headers "X-Content-Type-Options: nosniff";
more_set_headers "Referrer-Policy: strict-origin-when-cross-origin";
more_set_headers "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()";
more_set_headers "X-Frame-Options: DENY";
more_clear_headers "Server";
more_clear_headers "X-Powered-By";

client_max_body_size 1m;
```

- `more_set_headers` 는 NPM 이미지에 headers-more 모듈이 있어야 동작한다. NPM 컨테이너에서 `nginx -V 2>&1 | grep -o headers-more` 로 확인한다. 저장 후 프록시 호스트가 Offline 이 되면 지시어를 인식하지 못한 것이므로 `add_header <이름> "<값>" always;` 로 바꾼다.
- **CSP 는 여기에 넣지 않는다.** `frontend/nginx/snippets/csp.conf` 에서 관리한다. 양쪽에 넣으면 두 정책이 모두 적용된다.
- HSTS 는 SSL 탭의 토글로만 켠다.

## 5. NPM 자체 보호

- 관리 화면(81 포트)을 인터넷에 공개하지 않는다. `127.0.0.1:81:81` 로 바인딩하고 SSH 터널로 접속한다.
- 초기 관리자 계정의 이메일·비밀번호를 설치 직후 바꾼다.
- NPM 이미지를 주기적으로 갱신한다.

## 6. 운영 제약

- **api 는 인스턴스 1개.** 보안 세션·nonce·속도 제한이 프로세스 메모리에 있다 (`docs/SECURITY.md` 3절).
- **SQLite 백업**: 데이터는 `api_data` 볼륨의 `app.db` 에 있다. 정기적으로 백업하고 복원을 실제로 해 본다.
  ```sh
  docker run --rm -v __PROJECT_NAME___api_data:/data -v "$PWD":/backup alpine \
    sh -c "apk add --no-cache sqlite >/dev/null && sqlite3 /data/app.db \".backup '/backup/app-$(date +%F).db'\""
  ```
- 베이스 이미지를 주기적으로 다시 빌드해 OS 패치를 반영하고, `trivy image __PROJECT_NAME__-api` 등으로 취약점을 점검한다.
- 의존성 점검: `npm audit --omit=dev`(frontend), `pip-audit` 또는 `cargo audit`(backend).

## 7. 로컬에서 Docker 로 먼저 확인하기

```bat
scripts\docker.bat local up
```

`http://127.0.0.1:<WEB_HOST_PORT>` 로 접속한다. 루프백에만 게시되며, 로컬 테스트용으로 `ALLOWED_HOSTS`·`COOKIE_SECURE` 가 완화된다(`docker-compose.local.yml`). 이 파일을 운영 서버에서 쓰지 않는다.

## 8. 배포 후 확인 (자신의 서비스에서만 실행)

```sh
# 헤더: 기대한 헤더가 한 번씩만 나오는지. 세 경로를 모두 본다
curl -sI https://example.com/
curl -sI https://example.com/assets/<실제 파일명>.js
curl -s -o /dev/null -D - https://example.com/api/health

# HTTP → HTTPS
curl -sI http://example.com/

# 보안 채널 없이는 거부되는지 (401)
curl -s -o /dev/null -w "%{http_code}\n" https://example.com/api/notes

# 소스맵·숨김 파일이 서빙되지 않는지 (404)
curl -s -o /dev/null -w "%{http_code}\n" https://example.com/assets/<실제 파일명>.js.map
curl -s -o /dev/null -w "%{http_code}\n" https://example.com/.env

# 핸드셰이크 속도 제한이 걸리는지 (429 가 나오기 시작해야 한다)
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " -X POST https://example.com/api/hs; done

# 호스트 포트가 열려 있지 않은지 (서버 밖에서)
nmap -p 8000,8080 <서버 IP>
```

- 브라우저에서 화면을 열어 개발자 도구 콘솔에 CSP 위반이 없는지 확인한다(가드 정책이 `revoke` 면 세션이 끊기므로, 이 확인을 할 때만 잠시 `GUARD_POLICY=report` 로 둔다).
- api 로그의 `security-event` 에 찍히는 IP 가 NPM 컨테이너 IP 하나가 아니라 실제 클라이언트 IP 인지 확인한다. 전부 같은 IP 라면 `TRUSTED_PROXY_CIDR` 이 NPM 네트워크 대역과 맞지 않는 것이다.
