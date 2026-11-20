# syntax=docker/dockerfile:1
ARG PYTHON_VERSION=3.13

# ── 빌드 단계: 의존성 설치 + 코드 보호(Cython/.pyc). 컴파일러와 소스는 최종 이미지에 남지 않는다.
FROM python:${PYTHON_VERSION}-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt requirements-build.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt \
 && pip install --no-cache-dir -r requirements-build.txt
COPY app ./app
COPY migrations ./migrations
COPY build_protect.py ./
RUN python build_protect.py out \
 && mkdir -p out/data

# ── 실행 단계
FROM python:${PYTHON_VERSION}-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    API_PORT=8000
RUN useradd --system --uid 10001 --no-create-home appuser
COPY --from=build /install /usr/local
COPY --from=build --chown=10001:10001 /build/out /app
COPY healthcheck.py /app/healthcheck.py
WORKDIR /app
USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["python", "/app/healthcheck.py"]

# 세션·nonce·속도 제한이 프로세스 메모리에 있으므로 워커는 1개로 고정한다(--workers 를 넣지 않는다).
# --reload 는 개발 전용이다.
CMD ["sh", "-c", "exec python -m uvicorn app.main:app --host 0.0.0.0 --port ${API_PORT} --no-server-header"]
