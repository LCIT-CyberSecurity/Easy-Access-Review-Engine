"""Create the existing EARE repository schema.

Revision ID: 0001_repository_schema
Revises:
"""

from alembic import op

from access_review_engine.storage import create_repository_schema, repository_metadata

revision = "0001_repository_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    create_repository_schema(op.get_bind())


def downgrade() -> None:
    metadata, _ = repository_metadata()
    bind = op.get_bind()
    bind.exec_driver_sql("DROP INDEX IF EXISTS ix_access_relations_child")
    bind.exec_driver_sql("DROP INDEX IF EXISTS ix_snapshot_functional_models_snapshot")
    metadata.drop_all(bind)
