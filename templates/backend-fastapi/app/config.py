"""환경별 설정을 한 객체로 모은다.

기본값은 전부 "운영" 기준이다. 환경 변수를 빠뜨렸을 때 디버그 상태로 뜨는 대신
기동에 실패하도록 한다. 개발용 값은 backend/.env (.env.dev.example 참고)에 둔다.
"""
from functools import lru_cache
from typing import Literal

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: Literal["production", "development"] = "production"
    database_path: str = "./data/app.db"

    # 쉼표로 구분한 허용 Host 목록. 운영에서 비어 있거나 "*"면 기동 실패.
    allowed_hosts: str = ""

    # 서버 장기 서명 키(ECDSA P-256, PKCS8 PEM). 핸드셰이크 응답에 서명한다.
    server_sign_key_file: str = "/run/secrets/server_sign_key"

    # 보안 채널(요청 서명 + 본문 암호화). 운영에서는 끌 수 없다.
    secure_channel: bool = True
    cookie_secure: bool = True

    # web 컨테이너(nginx)가 넣어 주는 X-Real-IP 를 신뢰할지.
    # api 가 nginx 를 통해서만 도달될 때(Docker)만 true 로 둔다.
    trust_proxy_headers: bool = False

    session_idle_seconds: int = 1800
    session_max_seconds: int = 28800
    max_sessions: int = 20000
    ts_skew_seconds: int = 30
    max_body_bytes: int = 1_048_576

    handshake_rate_per_min: int = 30

    # 클라이언트 가드(개발자 도구/디버거 탐지) 신호 처리 정책
    #   revoke: guard_revoke_signals 에 포함된 신호가 오면 세션을 무효화
    #   report: 기록만 한다
    guard_policy: Literal["revoke", "report"] = "revoke"
    guard_revoke_signals: str = "devtools-timing,debugger-tamper"

    @property
    def is_dev(self) -> bool:
        return self.app_env == "development"

    @property
    def allowed_host_list(self) -> list[str]:
        return _csv(self.allowed_hosts)

    @property
    def guard_revoke_signal_set(self) -> frozenset[str]:
        return frozenset(_csv(self.guard_revoke_signals))

    @property
    def cookie_name(self) -> str:
        # __Host- 접두사는 Secure + Path=/ + Domain 없음 을 브라우저가 강제한다.
        return "__Host-sid" if self.cookie_secure else "sid"

    @model_validator(mode="after")
    def _refuse_unsafe_production(self) -> "Settings":
        if self.app_env == "production":
            hosts = self.allowed_host_list
            if not hosts or any("*" in h for h in hosts):
                raise ValueError("운영에서는 ALLOWED_HOSTS 에 정확한 호스트를 지정해야 합니다")
            if not self.secure_channel:
                raise ValueError("운영에서는 SECURE_CHANNEL 을 끌 수 없습니다")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
