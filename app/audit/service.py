"""Security audit append operations; intentionally no update or delete API."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import DocGuardError
from app.models.database import AuditEvent
from app.models.domain import AuditActorType, AuditOutcome

MAX_AUDIT_DETAILS_BYTES = 4_096


class AuditEventType(StrEnum):
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    SCAN_UPLOAD_REQUESTED = "SCAN_UPLOAD_REQUESTED"
    CDR_REQUESTED = "CDR_REQUESTED"
    ARTIFACT_DOWNLOADED = "ARTIFACT_DOWNLOADED"
    ARTIFACT_DOWNLOAD_DENIED = "ARTIFACT_DOWNLOAD_DENIED"
    CDR_ELIGIBILITY_CHECKED = "CDR_ELIGIBILITY_CHECKED"
    CDR_STARTED = "CDR_STARTED"
    CDR_RENDER_COMPLETED = "CDR_RENDER_COMPLETED"
    CDR_RENDER_FAILED = "CDR_RENDER_FAILED"
    CDR_DERIVED_SCAN_CREATED = "CDR_DERIVED_SCAN_CREATED"
    CDR_RESCAN_COMPLETED = "CDR_RESCAN_COMPLETED"
    CDR_APPROVED = "CDR_APPROVED"
    CDR_REJECTED = "CDR_REJECTED"
    CDR_PROMOTION_FAILED = "CDR_PROMOTION_FAILED"
    RECOVERY_STALE_SCAN_DETECTED = "RECOVERY_STALE_SCAN_DETECTED"
    RECOVERY_STALE_SCAN_QUARANTINED = "RECOVERY_STALE_SCAN_QUARANTINED"
    STORAGE_ORPHAN_DETECTED = "STORAGE_ORPHAN_DETECTED"
    ARTIFACT_INTEGRITY_FAILURE = "ARTIFACT_INTEGRITY_FAILURE"
    TEMP_OBJECT_CLEANED = "TEMP_OBJECT_CLEANED"


class AuditPersistenceError(DocGuardError):
    pass


class AuditService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def append(
        self,
        event_type: AuditEventType,
        *,
        scan_id: str | None,
        outcome: AuditOutcome,
        reason_code: str | None = None,
        artifact_id: str | None = None,
        details: dict[str, object] | None = None,
        actor_type: AuditActorType = AuditActorType.SYSTEM,
        actor_id: str | None = None,
    ) -> None:
        try:
            with self._sessions.begin() as session:
                self.add_to_transaction(
                    session,
                    event_type,
                    scan_id=scan_id,
                    outcome=outcome,
                    reason_code=reason_code,
                    artifact_id=artifact_id,
                    details=details,
                    actor_type=actor_type,
                    actor_id=actor_id,
                )
        except SQLAlchemyError as exc:
            raise AuditPersistenceError("security audit append failed") from exc

    @staticmethod
    def add_to_transaction(
        session: Session,
        event_type: AuditEventType,
        *,
        scan_id: str | None,
        outcome: AuditOutcome,
        reason_code: str | None = None,
        artifact_id: str | None = None,
        details: dict[str, object] | None = None,
        actor_type: AuditActorType = AuditActorType.SYSTEM,
        actor_id: str | None = None,
    ) -> AuditEvent:
        bounded = _bounded_details(details or {})
        event = AuditEvent(
            event_type=event_type.value,
            scan_id=scan_id,
            artifact_id=artifact_id,
            actor_type=actor_type.value,
            actor_id=actor_id,
            outcome=outcome.value,
            reason_code=reason_code,
            details_json=bounded,
        )
        session.add(event)
        return event


def _bounded_details(details: dict[str, object]) -> dict[str, Any]:
    def validate(value: object, *, depth: int = 0) -> object:
        if depth > 4:
            raise ValueError("audit details nesting is too deep")
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            if len(value) > 256:
                raise ValueError("audit detail string is too long")
            return value
        if isinstance(value, list):
            if len(value) > 32:
                raise ValueError("audit detail list is too long")
            return [validate(item, depth=depth + 1) for item in value]
        if isinstance(value, dict):
            if len(value) > 32:
                raise ValueError("audit detail object is too large")
            return {
                str(key): validate(item, depth=depth + 1)
                for key, item in value.items()
                if len(str(key)) <= 64
            }
        raise ValueError("audit details must be JSON serializable")

    validated = validate(details)
    assert isinstance(validated, dict)
    encoded = json.dumps(validated, allow_nan=False, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > MAX_AUDIT_DETAILS_BYTES:
        raise ValueError("audit details exceed the size limit")
    return validated


__all__ = [
    "MAX_AUDIT_DETAILS_BYTES",
    "AuditEventType",
    "AuditPersistenceError",
    "AuditService",
]
