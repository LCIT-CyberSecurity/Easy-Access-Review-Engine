"""Create the EARE V1 persistence schema.

This revision intentionally contains its complete schema definition. A historical migration must
not import mutable runtime metadata from ``storage.py``.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_repository_schema"
down_revision = None
branch_labels = None
depends_on = None

REPOSITORY_TABLES = (
    "providers",
    "identities",
    "resources",
    "accesses",
    "access_assignments",
    "access_relations",
    "imports",
    "golden_sources",
    "golden_source_versions",
    "golden_source_assignments",
    "snapshots",
    "snapshot_identities",
    "snapshot_resources",
    "snapshot_accesses",
    "snapshot_assignments",
    "snapshot_functional_access_models",
    "campaigns",
    "review_items",
    "decisions",
    "audit_events",
    "remediation_actions",
    "finding_tracking",
    "access_enrichments",
    "campaign_access_contexts",
    "golden_assignment_annotations",
    "business_context_feedback",
    "capabilities",
    "permission_capability_mappings",
    "golden_applications",
    "chatbot_conversations",
    "chatbot_messages",
    "chatbot_traces",
)


def _create_repository_tables() -> None:
    for name in REPOSITORY_TABLES:
        op.create_table(
            name,
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("payload", sa.Text(), nullable=False),
            sa.Column("created_at", sa.Text()),
            sa.Column("provider", sa.Text()),
            sa.Column("name", sa.Text()),
            sa.Column("version", sa.Integer()),
        )
    op.create_index("uq_providers_name", "providers", ["name"], unique=True)
    op.create_index("uq_identity_ref", "identities", ["provider", "name"], unique=True)
    op.create_index("uq_access_ref", "accesses", ["provider", "name"], unique=True)
    op.create_index("ix_assignments_access", "access_assignments", ["provider", "name"])
    op.create_index("ix_assignments_identity", "access_assignments", ["provider"])
    op.create_index("uq_access_relation_ref", "access_relations", ["provider", "name"], unique=True)
    op.create_index("ix_access_relations_parent", "access_relations", ["provider", "name"])
    op.create_index("uq_golden_source_name", "golden_sources", ["name"], unique=True)
    op.create_index("uq_golden_version", "golden_source_versions", ["name", "version"], unique=True)


def _create_system_tables() -> None:
    op.create_table(
        "system_users",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("enabled", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("password_hash", sa.Text()),
        sa.Column("must_change_password", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("api_access_enabled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mcp_access_enabled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("chatbot_access_enabled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("session_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("auth_source", sa.Text(), nullable=False, server_default="local"),
        sa.Column("external_id", sa.Text()),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index("uq_system_users_username", "system_users", ["username"], unique=True)
    op.create_table(
        "identity_provider_configs",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("settings", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.Text(), nullable=False),
    )
    op.create_index(
        "uq_identity_provider_configs_name", "identity_provider_configs", ["name"], unique=True
    )
    op.create_table(
        "system_settings",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
    )
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("token_prefix", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("last_used_at", sa.Text()),
        sa.Column("revoked_at", sa.Text()),
    )
    op.create_index("uq_api_tokens_hash", "api_tokens", ["token_hash"], unique=True)
    op.create_index("ix_api_tokens_user", "api_tokens", ["user_id"])
    op.create_index(
        "uq_api_tokens_one_active",
        "api_tokens",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
        sqlite_where=sa.text("revoked_at IS NULL"),
    )
    op.create_table(
        "mcp_tokens",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column("token_prefix", sa.Text(), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("last_used_at", sa.Text()),
        sa.Column("revoked_at", sa.Text()),
    )
    op.create_index("uq_mcp_tokens_hash", "mcp_tokens", ["token_hash"], unique=True)
    op.create_index("ix_mcp_tokens_user", "mcp_tokens", ["user_id"])
    op.create_index(
        "uq_mcp_tokens_one_active",
        "mcp_tokens",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
        sqlite_where=sa.text("revoked_at IS NULL"),
    )
    op.create_table(
        "web_jobs",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("progress", sa.Text(), nullable=False),
        sa.Column("result", sa.Text()),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("started_at", sa.Text()),
        sa.Column("finished_at", sa.Text()),
        sa.Column("created_by", sa.Text()),
        sa.Column("provider", sa.Text()),
        sa.Column("campaign_id", sa.Text()),
    )
    event_id = (
        sa.Column("id", sa.Integer(), sa.Identity(), primary_key=True)
        if op.get_bind().dialect.name == "postgresql"
        else sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True)
    )
    op.create_table(
        "web_job_events",
        event_id,
        sa.Column("job_id", sa.Text(), nullable=False),
        sa.Column("event", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text()),
        sa.Column("created_at", sa.Text(), nullable=False),
    )


def _create_payload_indexes() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            "CREATE INDEX ix_snapshot_functional_models_snapshot "
            "ON snapshot_functional_access_models ((payload::json ->> 'snapshot_id'))"
        )
        op.execute(
            "CREATE INDEX ix_access_relations_child "
            "ON access_relations ((payload::json ->> 'child_provider'), "
            "(payload::json ->> 'child_access_name'))"
        )
    else:
        op.execute(
            "CREATE INDEX ix_snapshot_functional_models_snapshot "
            "ON snapshot_functional_access_models(json_extract(payload, '$.snapshot_id'))"
        )
        op.execute(
            "CREATE INDEX ix_access_relations_child "
            "ON access_relations(json_extract(payload, '$.child_provider'), "
            "json_extract(payload, '$.child_access_name'))"
        )


def upgrade() -> None:
    _create_repository_tables()
    _create_system_tables()
    _create_payload_indexes()


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_access_relations_child")
    op.execute("DROP INDEX IF EXISTS ix_snapshot_functional_models_snapshot")
    for index_name, table_name in (
        ("uq_mcp_tokens_one_active", "mcp_tokens"),
        ("ix_mcp_tokens_user", "mcp_tokens"),
        ("uq_mcp_tokens_hash", "mcp_tokens"),
        ("uq_api_tokens_one_active", "api_tokens"),
        ("ix_api_tokens_user", "api_tokens"),
        ("uq_api_tokens_hash", "api_tokens"),
        ("uq_identity_provider_configs_name", "identity_provider_configs"),
        ("uq_system_users_username", "system_users"),
        ("uq_golden_version", "golden_source_versions"),
        ("uq_golden_source_name", "golden_sources"),
        ("ix_access_relations_parent", "access_relations"),
        ("uq_access_relation_ref", "access_relations"),
        ("ix_assignments_identity", "access_assignments"),
        ("ix_assignments_access", "access_assignments"),
        ("uq_access_ref", "accesses"),
        ("uq_identity_ref", "identities"),
        ("uq_providers_name", "providers"),
    ):
        op.drop_index(index_name, table_name=table_name)
    for table_name in (
        "web_job_events",
        "web_jobs",
        "mcp_tokens",
        "api_tokens",
        "system_settings",
        "identity_provider_configs",
        "system_users",
        *reversed(REPOSITORY_TABLES),
    ):
        op.drop_table(table_name)
