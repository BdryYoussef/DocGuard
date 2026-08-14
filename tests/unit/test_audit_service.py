from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditEventType, AuditService
from app.models.database import AuditEvent, Base
from app.models.domain import AuditOutcome


def audit_service(tmp_path: Path) -> tuple[AuditService, sessionmaker[Session]]:
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    return AuditService(sessions), sessions


def test_audit_service_only_appends_bounded_system_events(tmp_path: Path) -> None:
    service, sessions = audit_service(tmp_path)
    service.append(
        AuditEventType.CDR_STARTED,
        scan_id=None,
        outcome=AuditOutcome.SUCCESS,
        details={"sanitizer_version": "1.0.0"},
    )
    service.append(
        AuditEventType.CDR_RENDER_FAILED,
        scan_id=None,
        outcome=AuditOutcome.FAILURE,
        reason_code="render_failed",
    )

    with sessions() as session:
        events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.created_at)))
    assert [event.event_type for event in events] == ["CDR_STARTED", "CDR_RENDER_FAILED"]
    assert all(event.actor_type == "SYSTEM" and event.actor_id is None for event in events)
    assert not hasattr(service, "update")
    assert not hasattr(service, "delete")


def test_audit_details_reject_oversized_or_non_json_values(tmp_path: Path) -> None:
    service, _ = audit_service(tmp_path)
    with pytest.raises(ValueError, match="too long"):
        service.append(
            AuditEventType.CDR_STARTED,
            scan_id=None,
            outcome=AuditOutcome.SUCCESS,
            details={"secret": "x" * 257},
        )
    with pytest.raises(ValueError, match="JSON"):
        service.append(
            AuditEventType.CDR_STARTED,
            scan_id=None,
            outcome=AuditOutcome.SUCCESS,
            details={"raw": b"document bytes"},
        )
