# syntax=docker/dockerfile:1
# 빌드 컨텍스트는 프로젝트 루트다 (ports.env 와 서버 공개키를 읽어야 한다).
# 루트의 .dockerignore 가 개인키·백엔드·.env 를 컨텍스트에서 제외한다.

# ── 빌드 단계: Node 와 소스는 최종 이미지에 남지 않는다
FROM node:22-alpine AS build
WORKDIR /src
COPY ports.env ./ports.env
COPY secrets/server_sign_pub.txt ./secrets/server_sign_pub.txt
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY frontend/ ./
# 번들 복제 방지용 도메인 잠금(선택). 예: --build-arg OBF_DOMAIN_LOCK=example.com
ARG OBF_DOMAIN_LOCK=""
ENV OBF_DOMAIN_LOCK=${OBF_DOMAIN_LOCK}
# 타입 검사 → 빌드 → 난독화 → 번들 점검(소스맵·비밀·console 잔존 여부)
RUN npm run build:release

# ── 서빙 단계: 비특권 nginx (uid 101)
FROM nginxinc/nginx-unprivileged:stable-alpine
COPY frontend/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY frontend/nginx/snippets/ /etc/nginx/snippets/
COPY --from=build /src/frontend/dist /usr/share/nginx/html
ENV WEB_PORT=8080 \
    API_HOST=api \
    API_PORT=8000 \
    TRUSTED_PROXY_CIDR=172.16.0.0/12
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${WEB_PORT}/healthz" || exit 1
