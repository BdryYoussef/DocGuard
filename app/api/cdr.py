"""Authenticated operator entry point into the trusted Phase-8 CDR service."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Request, status
from fastapi.responses import JSONResponse

from app.api.schemas import SanitizationResponse
from app.audit.service import AuditEventType
from app.auth.http import enforce_csrf, require_capability
from app.auth.models import AuthenticatedPrincipal, Capability
from app.core.request_limits import enforce_operator_limit
from app.models.domain import AuditActorType, AuditOutcome
from app.orchestrator.scan_service import ScanNotFound

router = APIRouter(prefix="/api/v1", tags=["cdr"])


@router.post("/scans/{scan_id}/sanitize", response_model=SanitizationResponse)
async def sanitize_scan(
    request: Request,
    scan_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.CDR_REQUEST))
    ],
    _csrf: Annotated[None, Depends(enforce_csrf)],
) -> SanitizationResponse | JSONResponse:
    enforce_operator_limit(
        request,
        principal,
        action="cdr_request",
        limit=request.app.state.settings.cdr_requests_per_operator_hour,
        window_seconds=3_600,
    )
    try:
        request.app.state.scan_service.get(scan_id)
    except ScanNotFound:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"detail": "scan not found"}
        )
    request.app.state.audit_service.append(
        AuditEventType.CDR_REQUESTED,
        scan_id=scan_id,
        outcome=AuditOutcome.SUCCESS,
        actor_type=AuditActorType.OPERATOR,
        actor_id=principal.user_id,
    )
    result = request.app.state.cdr_service.sanitize_pdf(scan_id)
    response = SanitizationResponse(
        source_scan_id=result.source_scan_id,
        derived_scan_id=result.derived_scan_id,
        artifact_id=result.artifact_id,
        approved=result.approved,
        reused=result.reused,
        failure_code=result.failure_code.value if result.failure_code is not None else None,
    )
    if result.approved:
        return response
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content=response.model_dump(mode="json"),
    )


__all__ = ["router"]
