#!/bin/sh
# Docker helper (Linux 운영 서버용).
#   scripts/docker.sh npm up       NPM 뒤에서 기동 (docs/DEPLOY.md)
#   scripts/docker.sh npm down | logs | ps | build
#   scripts/docker.sh local up     127.0.0.1:WEB_HOST_PORT 에 게시 (서버에서 임시 확인용)
# 포트: ports.env    설정: .env (.env.example 을 복사해 작성)
set -eu
cd "$(dirname "$0")/.."

MODE="${1:-}"
ACTION="${2:-}"
case "$MODE" in local|npm) ;; *) echo "usage: scripts/docker.sh <local|npm> <up|down|logs|ps|build>"; exit 1 ;; esac

if [ ! -f secrets/server_sign_key.pem ]; then
  echo "[docker] secrets/server_sign_key.pem 이 없습니다. 먼저 실행: node scripts/gen-keys.mjs"
  exit 1
fi
if [ ! -f .env ]; then
  echo "[docker] .env 가 없습니다. .env.example 을 .env 로 복사하고 ALLOWED_HOSTS 를 설정하세요."
  exit 1
fi

compose() {
  docker compose --env-file ports.env --env-file .env -f docker-compose.yml -f "docker-compose.$MODE.yml" "$@"
}

case "$ACTION" in
  up)    compose up -d --build ;;
  down)  compose down ;;
  logs)  compose logs -f --tail 100 ;;
  ps)    compose ps ;;
  build) compose build ;;
  *)     echo "usage: scripts/docker.sh <local|npm> <up|down|logs|ps|build>"; exit 1 ;;
esac
