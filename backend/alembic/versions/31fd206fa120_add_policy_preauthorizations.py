"""add policy preauthorizations

Revision ID: 31fd206fa120
Revises: 7d0f0e42c815
Create Date: 2026-08-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "31fd206fa120"
down_revision: str | None = "7d0f0e42c815"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policy_preauthorizations",
        sa.Column("preauthorization_id", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=64), nullable=False),
        sa.Column("action_request_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("run_mode", sa.String(length=32), nullable=False),
        sa.Column("request_digest", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["action_request_id"], ["action_requests.action_request_id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"], ["security_incidents.incident_id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("preauthorization_id"),
        sa.UniqueConstraint("action_request_id"),
    )
    op.create_index(
        "ix_policy_preauthorizations_incident_id",
        "policy_preauthorizations",
        ["incident_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_policy_preauthorizations_incident_id", table_name="policy_preauthorizations")
    op.drop_table("policy_preauthorizations")
