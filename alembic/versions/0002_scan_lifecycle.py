"""Add secure ingestion and analysis lifecycle fields.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "display_filename",
            sa.String(length=255),
            nullable=False,
            server_default="unnamed-document",
        ),
    )
    op.add_column("scans", sa.Column("claimed_content_type", sa.String(length=255)))
    op.add_column(
        "scans",
        sa.Column("state", sa.String(length=32), nullable=False, server_default="QUARANTINED"),
    )
    op.add_column("scans", sa.Column("detected_type", sa.String(length=100)))
    op.add_column("scans", sa.Column("analysis_error_code", sa.String(length=64)))
    op.add_column("scans", sa.Column("analysis_started_at", sa.DateTime(timezone=True)))
    op.add_column("scans", sa.Column("analysis_completed_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("scans", "analysis_completed_at")
    op.drop_column("scans", "analysis_started_at")
    op.drop_column("scans", "analysis_error_code")
    op.drop_column("scans", "detected_type")
    op.drop_column("scans", "state")
    op.drop_column("scans", "claimed_content_type")
    op.drop_column("scans", "display_filename")
