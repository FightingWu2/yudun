"""add mock state and snapshots

Revision ID: 7d0f0e42c815
Revises: 1ff960285b68
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7d0f0e42c815"
down_revision: str | None = "1ff960285b68"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "mock_scenario_states",
        sa.Column("scenario_id", sa.String(length=128), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("scenario_id"),
    )
    op.create_table(
        "state_snapshots",
        sa.Column("snapshot_id", sa.String(length=64), nullable=False),
        sa.Column("scenario_id", sa.String(length=128), nullable=False),
        sa.Column("operation_id", sa.String(length=128), nullable=False),
        sa.Column("phase", sa.String(length=16), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scenario_id"], ["mock_scenario_states.scenario_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("snapshot_id"),
    )


def downgrade() -> None:
    op.drop_table("state_snapshots")
    op.drop_table("mock_scenario_states")
