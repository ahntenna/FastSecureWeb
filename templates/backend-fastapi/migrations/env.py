"""Alembic 환경. 앱 기동 시 app.db.run_migrations 가 호출한다.

새 마이그레이션 만들기 (backend 폴더에서):
    alembic revision --autogenerate -m "설명"
"""
from alembic import context
from sqlalchemy import create_engine

from app import models  # noqa: F401  (모델을 메타데이터에 등록)
from app.db import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    engine = create_engine(config.get_main_option("sqlalchemy.url"))
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


run_migrations_online()
