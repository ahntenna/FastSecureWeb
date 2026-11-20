//! 예제 CRUD. 보안 채널(서명·암호화) 위에서 동작하는 엔드포인트의 본보기다.
//!
//! 인증은 포함하지 않았다. 사용자별 데이터를 다루게 되면 소유자 컬럼을 추가하고
//! 조회·삭제 쿼리에 소유자 조건을 반드시 넣는다(남의 객체는 404).
//! SQL 은 바인딩 파라미터만 쓴다. format! 으로 쿼리를 조립하지 않는다.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, ApiJson, ApiQuery};
use crate::state::AppState;

/// 응답 스키마. 내보낼 필드만 둔다.
#[derive(Serialize, sqlx::FromRow)]
pub struct NoteOut {
    pub id: i64,
    pub title: String,
    pub body: String,
    pub created_at: String,
}

/// 요청 스키마. 정의하지 않은 필드가 오면 거부한다(대량 할당 방지).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteCreate {
    pub title: String,
    #[serde(default)]
    pub body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_notes(
    State(state): State<AppState>,
    ApiQuery(params): ApiQuery<ListParams>,
) -> Result<Json<Vec<NoteOut>>, ApiError> {
    let limit = params.limit.unwrap_or(50);
    let offset = params.offset.unwrap_or(0);
    if !(1..=100).contains(&limit) || offset > 100_000 {
        return Err(ApiError::invalid());
    }
    let notes = sqlx::query_as::<_, NoteOut>(
        "SELECT id, title, body, created_at FROM notes ORDER BY id DESC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(notes))
}

pub async fn create_note(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<NoteCreate>,
) -> Result<(StatusCode, Json<NoteOut>), ApiError> {
    let title_len = body.title.chars().count();
    if !(1..=100).contains(&title_len) || body.body.chars().count() > 4000 {
        return Err(ApiError::invalid());
    }
    let note = sqlx::query_as::<_, NoteOut>(
        "INSERT INTO notes (title, body) VALUES (?, ?) RETURNING id, title, body, created_at",
    )
    .bind(body.title)
    .bind(body.body)
    .fetch_one(&state.db)
    .await?;
    Ok((StatusCode::CREATED, Json(note)))
}

pub async fn delete_note(State(state): State<AppState>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM notes WHERE id = ?").bind(id).execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}
