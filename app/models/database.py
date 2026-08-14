"""SQLAlchemy 2 persistence models for scans, findings, and artifacts."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_database_id() -> str:
    return secrets.token_hex(16)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_database_id)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    display_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    origin: Mapped[str] = mapped_column(String(32), nullable=False, default="UPLOAD")
    parent_scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    claimed_extension: Mapped[str | None] = mapped_column(String(32), nullable=True)
    claimed_content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    detected_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    detected_mime: Mapped[str | None] = mapped_column(String(255), nullable=True)
    analysis_error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    release_eligible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    policy_evaluation_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    analysis_metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    worker_status: Mapped[str] = mapped_column(String(32), nullable=False)
    analysis_duration_ms: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    analysis_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    analysis_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    findings: Mapped[list[FindingRecord]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", foreign_keys="Artifact.scan_id"
    )


class FindingRecord(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_database_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    score_delta: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Artifact(Base, TimestampMixin):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_database_id)
    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    artifact_type: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    derived_scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sanitizer_version: Mapped[str] = mapped_column(String(32), nullable=False)
    sanitizer_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="artifacts", foreign_keys=[scan_id])

    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "sanitizer_fingerprint",
            name="uq_artifacts_source_sanitizer",
        ),
    )


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_database_id)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    artifact_id: Mapped[str | None] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class OperatorUser(Base, TimestampMixin):
    __tablename__ = "operators"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_database_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (CheckConstraint("role = 'OPERATOR'", name="ck_operators_role"),)


class ServerSession(Base, TimestampMixin):
    __tablename__ = "auth_sessions"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_database_id)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("operators.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
