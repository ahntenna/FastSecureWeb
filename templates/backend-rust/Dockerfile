# syntax=docker/dockerfile:1
# 빌드 이미지와 실행 이미지의 Debian 버전(bookworm = debian12)을 맞춘다. 어긋나면 glibc 버전 오류로 실행되지 않는다.
ARG RUST_VERSION=1

# ── 빌드 단계: 컴파일러와 소스는 최종 이미지에 남지 않는다
FROM rust:${RUST_VERSION}-slim-bookworm AS build
WORKDIR /build
# 바이너리에 빌드 경로(소스 위치, 의존성 경로)가 문자열로 남지 않게 바꿔 적는다.
ENV RUSTFLAGS="--remap-path-prefix=/build=app --remap-path-prefix=/usr/local/cargo/registry/src=deps"
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
# release 프로필: LTO + 심볼 제거(strip) — Cargo.toml 참고
RUN cargo build --release --locked \
 && mkdir -p /out/data \
 && cp target/release/server /out/server

# ── 실행 단계: 셸·패키지 관리자가 없는 최소 이미지
FROM gcr.io/distroless/cc-debian12
COPY --from=build --chown=10001:10001 /out /app
WORKDIR /app
USER 10001:10001
ENV API_PORT=8000
EXPOSE 8000

# 셸이 없으므로 바이너리의 healthcheck 하위 명령을 쓴다.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/app/server", "healthcheck"]

# 세션·nonce·속도 제한이 프로세스 메모리에 있으므로 api 는 인스턴스 1개로 운영한다.
CMD ["/app/server"]
