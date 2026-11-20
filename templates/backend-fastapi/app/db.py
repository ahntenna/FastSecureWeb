"""SQLite 연결과 마이그레이션."""
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Base(DeclarativeBase):
    pass


def sqlite_url(database_path: str) -> str:
    return f"sqlite:///{Path(database_path).resolve().as_posix()}"


def make_engine(database_path: str) -> Engine:
    Path(database_path).resolve().parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(sqlite_url(database_path), connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection, _record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine


def run_migrations(database_path: str) -> None:
    """기동 시 최신 스키마로 올린다. 스키마 변경은 migrations/versions 에 추가한다."""
    Path(database_path).resolve().parent.mkdir(parents=True, exist_ok=True)
    config = Config()
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    config.set_main_option("sqlalchemy.url", sqlite_url(database_path))
    command.upgrade(config, "head")
