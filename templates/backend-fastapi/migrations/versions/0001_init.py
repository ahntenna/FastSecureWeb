"""initial schema: notes, security_events

Revision ID: 0001
Revises:
"""
# 위 첫 줄은 기동 로그에 그대로 찍힌다. Windows 콘솔에서 깨지지 않게 영문으로 쓴다.
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(100), nullable=False),
        sa.Column("body", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("sid_hash", sa.String(16), nullable=False, server_default=""),
        sa.Column("path", sa.String(200), nullable=False, server_default=""),
    )
    op.create_index("ix_security_events_created_at", "security_events", ["created_at"])
    op.create_index("ix_security_events_kind", "security_events", ["kind"])


def downgrade() -> None:
    op.drop_table("security_events")
    op.drop_table("notes")
