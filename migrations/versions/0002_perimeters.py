"""Add organization and information-system perimeter storage."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_perimeters"
down_revision = "0001_repository_schema"
branch_labels = None
depends_on = None


PERIMETER_TABLES = (
    "organizations",
    "information_systems",
    "organization_information_systems",
    "scope_assignments",
)


def upgrade() -> None:
    for name in PERIMETER_TABLES:
        op.create_table(
            name,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("payload", sa.Text(), nullable=False),
            sa.Column("created_at", sa.Text()),
            sa.Column("provider", sa.Text()),
            sa.Column("name", sa.Text()),
            sa.Column("version", sa.Integer()),
        )


def downgrade() -> None:
    for name in reversed(PERIMETER_TABLES):
        op.drop_table(name)
