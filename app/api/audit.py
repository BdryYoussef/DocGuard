"""Bounded authenticated audit-history API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request

from app.api.schemas import AuditEventListResponse, AuditEventResponse
from app.auth.http import require_capability
from app.auth.models import AuthenticatedPrincipal, Capability
from app.core.request_limits import enforce_operator_limit
from app.operator.service import safe_audit_details

router = APIRouter(prefix="/api/v1", tags=["audit"])


@router.get("/audit-events", response_model=AuditEventListResponse)
async def list_audit_events(
    request: Request,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.AUDIT_READ))
    ],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> AuditEventListResponse:
    enforce_operator_limit(
        request,
        principal,
        action="audit_list",
        limit=request.app.state.settings.expensive_reads_per_operator_minute,
        window_seconds=60,
    )
    result = request.app.state.operator_query_service.list_audit_events(
        page=page, page_size=page_size
    )
    return AuditEventListResponse(
        items=[
            AuditEventResponse(
                event_id=row.event.id,
                event_type=row.event.event_type,
                actor_type=row.event.actor_type,
                actor_id=row.event.actor_id,
                actor_username=row.actor_username,
                outcome=row.event.outcome,
                reason_code=row.event.reason_code,
                scan_id=row.event.scan_id,
                artifact_id=row.event.artifact_id,
                details=safe_audit_details(row.event),
                created_at=row.event.created_at,
            )
            for row in result.items
        ],
        page=result.page,
        page_size=result.page_size,
        total=result.total,
    )


__all__ = ["router"]
