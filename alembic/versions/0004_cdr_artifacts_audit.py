"""Add CDR lineage, versioned artifacts, and append-only audit events.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(
            sa.Column("origin", sa.String(length=32), nullable=False, server_default="UPLOAD")
        )
        batch.add_column(sa.Column("parent_scan_id", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("analysis_metadata_json", sa.JSON(), nullable=True))
        batch.create_foreign_key(
            "fk_scans_parent_scan_id_scans",
            "scans",
            ["parent_scan_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_index("ix_scans_parent_scan_id", ["parent_scan_id"])

    with op.batch_alter_table("artifacts") as batch:
        batch.add_column(sa.Column("derived_scan_id", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("size_bytes", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("sanitizer_version", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("sanitizer_fingerprint", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("policy_version", sa.String(length=32), nullable=True))
        batch.add_column(sa.Column("policy_fingerprint", sa.String(length=64), nullable=True))
        batch.create_foreign_key(
            "fk_artifacts_derived_scan_id_scans",
            "scans",
            ["derived_scan_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_index("ix_artifacts_derived_scan_id", ["derived_scan_id"])
        batch.create_unique_constraint(
            "uq_artifacts_source_sanitizer", ["scan_id", "sanitizer_fingerprint"]
        )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=32), nullable=True),
        sa.Column("artifact_id", sa.String(length=32), nullable=True),
        sa.Column("actor_type", sa.String(length=32), nullable=False),
        sa.Column("actor_id", sa.String(length=128), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("details_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_events_event_type", "audit_events", ["event_type"])
    op.create_index("ix_audit_events_scan_id", "audit_events", ["scan_id"])
    op.create_index("ix_audit_events_artifact_id", "audit_events", ["artifact_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_artifact_id", table_name="audit_events")
    op.drop_index("ix_audit_events_scan_id", table_name="audit_events")
    op.drop_index("ix_audit_events_event_type", table_name="audit_events")
    op.drop_table("audit_events")
    with op.batch_alter_table("artifacts") as batch:
        batch.drop_constraint("uq_artifacts_source_sanitizer", type_="unique")
        batch.drop_index("ix_artifacts_derived_scan_id")
        batch.drop_constraint("fk_artifacts_derived_scan_id_scans", type_="foreignkey")
        batch.drop_column("policy_fingerprint")
        batch.drop_column("policy_version")
        batch.drop_column("sanitizer_fingerprint")
        batch.drop_column("sanitizer_version")
        batch.drop_column("size_bytes")
        batch.drop_column("derived_scan_id")
    with op.batch_alter_table("scans") as batch:
        batch.drop_index("ix_scans_parent_scan_id")
        batch.drop_constraint("fk_scans_parent_scan_id_scans", type_="foreignkey")
        batch.drop_column("analysis_metadata_json")
        batch.drop_column("parent_scan_id")
        batch.drop_column("origin")
