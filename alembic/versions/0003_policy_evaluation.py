"""Persist trusted policy identity and complete bounded evaluation.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("policy_version", sa.String(length=32)))
    op.add_column("scans", sa.Column("policy_fingerprint", sa.String(length=64)))
    op.add_column(
        "scans",
        sa.Column(
            "release_eligible",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("scans", sa.Column("policy_evaluation_json", sa.JSON()))


def downgrade() -> None:
    op.drop_column("scans", "policy_evaluation_json")
    op.drop_column("scans", "release_eligible")
    op.drop_column("scans", "policy_fingerprint")
    op.drop_column("scans", "policy_version")
