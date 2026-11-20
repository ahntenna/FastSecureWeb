//! 응답 오류와 요청 추출기. 상세는 서버 로그에만 남기고 응답은 일반 메시지로 통일한다.

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::security::middleware::client_ip;
use crate::state::AppState;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub detail: &'static str,
}

impl ApiError {
    pub const fn new(status: StatusCode, detail: &'static str) -> Self {
        Self { status, detail }
    }
    pub const fn invalid() -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid request")
    }
    pub const fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not found")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "detail": self.detail }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

/// JSON 본문 추출기. 형식 오류·정의하지 않은 필드(deny_unknown_fields)는 422 로 통일한다.
pub struct ApiJson<T>(pub T);

impl<T: DeserializeOwned> FromRequest<AppState> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Self(value)),
            Err(JsonRejection::MissingJsonContentType(_)) => {
                Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid request"))
            }
            Err(_) => Err(ApiError::invalid()),
        }
    }
}

/// 쿼리 문자열 추출기. 형식 오류는 422.
pub struct ApiQuery<T>(pub T);

impl<T: DeserializeOwned + Send> FromRequestParts<AppState> for ApiQuery<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let result: Result<Query<T>, QueryRejection> = Query::from_request_parts(parts, state).await;
        result.map(|Query(value)| Self(value)).map_err(|_| ApiError::invalid())
    }
}

/// 실제 클라이언트 IP (프록시 헤더 신뢰 여부는 설정을 따른다).
pub struct ClientIp(pub String);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // ConnectInfo 가 없는 환경(테스트)에서는 "unknown" 이 된다.
        Ok(Self(client_ip(&state.cfg, &parts.headers, &parts.extensions)))
    }
}
