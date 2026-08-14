"""Escaped, bounded server-rendered operator pages."""

from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Path, Query, Request, status
from fastapi.responses import HTMLResponse

from app.api.scans import _scan_response
from app.auth.http import require_html_authenticated
from app.auth.models import AuthenticatedPrincipal
from app.core.request_limits import enforce_operator_limit
from app.models.domain import Decision
from app.operator.service import safe_audit_details
from app.orchestrator.scan_service import ScanNotFound

router = APIRouter(prefix="/app", tags=["operator-ui"])


@router.get("", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
) -> HTMLResponse:
    _limit_operator_page(request, principal, "dashboard")
    data = request.app.state.operator_query_service.dashboard()
    return _template(
        request,
        "dashboard.html",
        principal,
        active="dashboard",
        dashboard=data,
        maximum_upload_bytes=request.app.state.settings.maximum_upload_bytes,
    )


@router.get("/scans", response_class=HTMLResponse)
async def scans(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    _limit_operator_page(request, principal, "web_scan_list")
    result = request.app.state.operator_query_service.list_scans(page=page, page_size=25)
    return _template(
        request,
        "scans.html",
        principal,
        active="scans",
        page=result,
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
async def scan_detail(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
    scan_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
) -> HTMLResponse:
    _limit_operator_page(request, principal, "web_scan_detail")
    try:
        scan = request.app.state.scan_service.get(scan_id)
    except ScanNotFound:
        return _error(request, principal, status.HTTP_404_NOT_FOUND, "Resource not found.")
    response = _scan_response(scan)
    eligibility = request.app.state.cdr_service.inspect_cdr_eligibility(scan.id)
    artifact = request.app.state.cdr_service.get_existing_cdr_artifact(scan.id)
    derived = None
    if artifact is not None:
        try:
            derived = request.app.state.scan_service.get(artifact.derived_scan_id)
        except ScanNotFound:
            artifact = None
    return _template(
        request,
        "scan_detail.html",
        principal,
        active="scans",
        scan=scan,
        result=response,
        cdr_eligibility=eligibility,
        artifact=artifact,
        derived=derived,
        decision_messages={
            Decision.ALLOW.value: (
                "Analysis completed without a condition requiring review or containment under "
                "the active DocGuard policy."
            ),
            Decision.REVIEW.value: (
                "Characteristics were identified that require operator review before release."
            ),
            Decision.QUARANTINE.value: (
                "Significant risk or incomplete analysis requires containment."
            ),
            Decision.BLOCK.value: "An explicit security-policy violation prevents normal release.",
        },
    )


@router.get("/quarantine", response_class=HTMLResponse)
async def quarantine(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    _limit_operator_page(request, principal, "web_quarantine")
    result = request.app.state.operator_query_service.list_scans(
        page=page, page_size=25, contained_only=True
    )
    return _template(
        request,
        "quarantine.html",
        principal,
        active="quarantine",
        page=result,
    )


@router.get("/artifacts", response_class=HTMLResponse)
async def artifacts(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    _limit_operator_page(request, principal, "web_artifacts")
    result = request.app.state.operator_query_service.list_artifacts(page=page, page_size=25)
    return _template(
        request,
        "artifacts.html",
        principal,
        active="artifacts",
        page=result,
    )


@router.get("/audit", response_class=HTMLResponse)
async def audit(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    _limit_operator_page(request, principal, "web_audit")
    result = request.app.state.operator_query_service.list_audit_events(page=page, page_size=25)
    rows = [(row, safe_audit_details(row.event)) for row in result.items]
    return _template(
        request,
        "audit.html",
        principal,
        active="audit",
        page=result,
        rows=rows,
    )


def _template(
    request: Request,
    name: str,
    principal: AuthenticatedPrincipal,
    **context: object,
) -> HTMLResponse:
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name=name,
            context={"principal": principal, "csrf_token": principal.csrf_token, **context},
        ),
    )


def _limit_operator_page(request: Request, principal: AuthenticatedPrincipal, action: str) -> None:
    enforce_operator_limit(
        request,
        principal,
        action=action,
        limit=request.app.state.settings.expensive_reads_per_operator_minute,
        window_seconds=60,
    )


def _error(
    request: Request,
    principal: AuthenticatedPrincipal,
    status_code: int,
    message: str,
) -> HTMLResponse:
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "principal": principal,
                "csrf_token": principal.csrf_token,
                "message": message,
            },
            status_code=status_code,
        ),
    )


__all__ = ["router"]
