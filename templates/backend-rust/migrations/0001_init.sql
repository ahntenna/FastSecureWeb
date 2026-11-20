-- 초기 스키마. 스키마를 바꿀 때는 이 파일을 고치지 말고 0002_*.sql 을 추가한다
-- (기동 시 sqlx 가 아직 적용되지 않은 파일만 순서대로 실행한다).

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE security_events (
    id         INTEGER PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    kind       TEXT NOT NULL,
    ip         TEXT NOT NULL,
    sid_hash   TEXT NOT NULL DEFAULT '',
    path       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX ix_security_events_created_at ON security_events (created_at);
CREATE INDEX ix_security_events_kind ON security_events (kind);
