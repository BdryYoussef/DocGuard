"""Allowlisted, bounded queries for authenticated operator APIs and pages."""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased, sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from app.core.constants import MAX_LIST_PAGE_SIZE
from app.core.errors import DocGuardError
from app.models.database import Artifact, AuditEvent, OperatorUser, Scan
from app.models.domain import ArtifactType, Decision


class OperatorQueryError(DocGuardError):
    pass


@dataclass(frozen=True, slots=True)
class Page[T]:
    items: list[T]
    page: int
    page_size: int
    total: int


@dataclass(frozen=True, slots=True)
class AuditRow:
    event: AuditEvent
    actor_username: str | None


@dataclass(frozen=True, slots=True)
class DashboardData:
    decision_counts: dict[str, int]
    recent_scans: list[Scan]
    contained_scans: list[Scan]
    approved_artifact_count: int


class OperatorQueryService:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self._sessions = sessions

    def list_scans(
        self,
        *,
        page: int,
        page_size: int,
        decision: Decision | None = None,
        state: str | None = None,
        detected_type: str | None = None,
        contained_only: bool = False,
    ) -> Page[Scan]:
        page, page_size = _validated_page(page, page_size)
        filters: list[ColumnElement[bool]] = []
        if contained_only:
            filters.append(
                Scan.decision.in_(
                    (Decision.REVIEW.value, Decision.QUARANTINE.value, Decision.BLOCK.value)
                )
            )
        elif decision is not None:
            filters.append(Scan.decision == decision.value)
        if state is not None:
            filters.append(Scan.state == state)
        if detected_type is not None:
            filters.append(Scan.detected_type == detected_type)
        try:
            with self._sessions() as session:
                total = int(
                    session.execute(
                        select(func.count()).select_from(Scan).where(*filters)
                    ).scalar_one()
                )
                items = list(
                    session.scalars(
                        select(Scan)
                        .where(*filters)
                        .order_by(Scan.created_at.desc(), Scan.id.desc())
                        .offset((page - 1) * page_size)
                        .limit(page_size)
                    )
                )
                for item in items:
                    session.expunge(item)
            return Page(items, page, page_size, total)
        except SQLAlchemyError as exc:
            raise OperatorQueryError("scan list query failed") from exc

    def list_artifacts(self, *, page: int, page_size: int) -> Page[Artifact]:
        page, page_size = _validated_page(page, page_size)
        derived = aliased(Scan)
        approved = (
            Artifact.artifact_type == ArtifactType.PDF_CDR.value,
            derived.decision == Decision.ALLOW.value,
            derived.release_eligible.is_(True),
        )
        try:
            with self._sessions() as session:
                total = int(
                    session.scalar(
                        select(func.count())
                        .select_from(Artifact)
                        .join(derived, derived.id == Artifact.derived_scan_id)
                        .where(*approved)
                    )
                    or 0
                )
                items = list(
                    session.scalars(
                        select(Artifact)
                        .join(derived, derived.id == Artifact.derived_scan_id)
                        .where(*approved)
                        .order_by(Artifact.created_at.desc(), Artifact.id.desc())
                        .offset((page - 1) * page_size)
                        .limit(page_size)
                    )
                )
                for item in items:
                    session.expunge(item)
            return Page(items, page, page_size, total)
        except SQLAlchemyError as exc:
            raise OperatorQueryError("artifact list query failed") from exc

    def get_artifact(self, artifact_id: str) -> Artifact | None:
        derived = aliased(Scan)
        try:
            with self._sessions() as session:
                artifact = session.execute(
                    select(Artifact)
                    .join(derived, derived.id == Artifact.derived_scan_id)
                    .where(
                        Artifact.id == artifact_id,
                        Artifact.artifact_type == ArtifactType.PDF_CDR.value,
                        derived.decision == Decision.ALLOW.value,
                        derived.release_eligible.is_(True),
                    )
                ).scalar_one_or_none()
                if artifact is not None:
                    session.expunge(artifact)
                return artifact
        except SQLAlchemyError as exc:
            raise OperatorQueryError("artifact lookup failed") from exc

    def list_audit_events(self, *, page: int, page_size: int) -> Page[AuditRow]:
        page, page_size = _validated_page(page, page_size)
        try:
            with self._sessions() as session:
                total = int(session.scalar(select(func.count()).select_from(AuditEvent)) or 0)
                rows = session.execute(
                    select(AuditEvent, OperatorUser.username)
                    .outerjoin(OperatorUser, OperatorUser.id == AuditEvent.actor_id)
                    .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                ).all()
                items = [AuditRow(event=row[0], actor_username=row[1]) for row in rows]
                for item in items:
                    session.expunge(item.event)
            return Page(items, page, page_size, total)
        except SQLAlchemyError as exc:
            raise OperatorQueryError("audit list query failed") from exc

    def dashboard(self) -> DashboardData:
        derived = aliased(Scan)
        try:
            with self._sessions() as session:
                counts = {
                    str(decision): int(count)
                    for decision, count in session.execute(
                        select(Scan.decision, func.count()).group_by(Scan.decision)
                    )
                    if decision is not None
                }
                recent = list(
                    session.scalars(
                        select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(5)
                    )
                )
                contained = list(
                    session.scalars(
                        select(Scan)
                        .where(
                            Scan.decision.in_(
                                (
                                    Decision.REVIEW.value,
                                    Decision.QUARANTINE.value,
                                    Decision.BLOCK.value,
                                )
                            )
                        )
                        .order_by(Scan.created_at.desc(), Scan.id.desc())
                        .limit(5)
                    )
                )
                approved_count = int(
                    session.scalar(
                        select(func.count())
                        .select_from(Artifact)
                        .join(derived, derived.id == Artifact.derived_scan_id)
                        .where(
                            Artifact.artifact_type == ArtifactType.PDF_CDR.value,
                            derived.decision == Decision.ALLOW.value,
                            derived.release_eligible.is_(True),
                        )
                    )
                    or 0
                )
            # `recent` and `contained` can share rows (e.g. a QUARANTINE source scan
            # is both "recent" and "contained"); SQLAlchemy's identity map returns the
            # *same* Python instance for that row in both lists, so expunging it twice
            # would raise InvalidRequestError. Exiting the `with` block above already
            # closes the session, which expunges every object exactly once regardless
            # of how many query results reference it; `expire_on_commit=False` keeps
            # already-loaded scalar attributes readable afterward.
            return DashboardData(counts, recent, contained, approved_count)
        except SQLAlchemyError as exc:
            raise OperatorQueryError("dashboard query failed") from exc


def safe_audit_details(event: AuditEvent) -> dict[str, object]:
    allowed = {
        "decision",
        "derived_decision",
        "derived_scan_id",
        "duration_ms",
        "output_bytes",
        "page_count",
        "policy_version",
        "reason_codes",
        "requested_scan_id",
        "requested_artifact_id",
        "role",
        "sanitizer_version",
        "source_decision",
        "source_scan_id",
    }
    return {key: value for key, value in event.details_json.items() if key in allowed}


def _validated_page(page: int, page_size: int) -> tuple[int, int]:
    if page < 1 or not 1 <= page_size <= MAX_LIST_PAGE_SIZE:
        raise ValueError("pagination is outside permitted bounds")
    return page, page_size


__all__ = [
    "AuditRow",
    "DashboardData",
    "OperatorQueryError",
    "OperatorQueryService",
    "Page",
    "safe_audit_details",
]
