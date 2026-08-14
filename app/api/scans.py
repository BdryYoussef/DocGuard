"""Single-document raw streaming ingestion endpoint."""

from __future__ import annotations

import json
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, status
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from app.api.schemas import (
    FindingResponse,
    PolicyContributionResponse,
    PolicyReasonResponse,
    ScanListResponse,
    ScanResponse,
    ScanSummaryResponse,
)
from app.audit.service import AuditEventType
from app.auth.http import enforce_csrf, require_capability
from app.auth.models import AuthenticatedPrincipal, Capability
from app.core.logging import log_event
from app.core.request_limits import enforce_operator_limit
from app.models.database import Scan
from app.models.domain import AuditActorType, AuditOutcome, Decision, ScanState
from app.operator.service import OperatorQueryService
from app.orchestrator.scan_service import ScanNotFound
from app.policies.models import PolicyEvaluation
from app.storage.ingestion import EmptyUpload, UploadTooLarge, stream_document_to_quarantine
from app.storage.paths import normalize_display_filename

router = APIRouter(prefix="/api/v1", tags=["scans"])
logger = logging.getLogger(__name__)

_DECISION_MESSAGES = {
    Decision.ALLOW: (
        "Analysis completed without a condition requiring review or containment under the active "
        "DocGuard policy."
    ),
    Decision.REVIEW: "Characteristics were identified that require operator review before release.",
    Decision.QUARANTINE: ("Significant risk or incomplete analysis requires containment."),
    Decision.BLOCK: ("An explicit security-policy violation prevents normal release."),
}
_DISCLAIMER = (
    "DocGuard decisions describe the configured detection model. "
    "ALLOW is not proof that a document is benign."
)


@router.post("/scans", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: Request,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.SCAN_UPLOAD))
    ],
    _csrf: Annotated[None, Depends(enforce_csrf)],
    filename: Annotated[str, Query(min_length=1, max_length=255)] = "unnamed-document",
) -> ScanResponse | JSONResponse:
    settings = request.app.state.settings
    enforce_operator_limit(
        request,
        principal,
        action="scan_upload",
        limit=settings.uploads_per_operator_hour,
        window_seconds=3_600,
    )
    claimed_content_type = _bounded_content_type(request.headers.get("content-type"))
    if claimed_content_type is not None and claimed_content_type.casefold().startswith(
        "multipart/form-data"
    ):
        return JSONResponse(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            content={"detail": "send the document as the raw request body"},
        )
    content_length = _content_length(request.headers.get("content-length"))
    if content_length is not None and content_length > settings.maximum_upload_bytes:
        return JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content={"detail": "upload exceeds configured maximum"},
        )

    body_stream = request.stream()
    try:
        document = await stream_document_to_quarantine(
            body_stream,
            paths=request.app.state.storage_paths,
            maximum_bytes=settings.maximum_upload_bytes,
        )
    except UploadTooLarge:
        log_event(logger, logging.WARNING, "upload_rejected", reason="too_large")
        return JSONResponse(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            content={"detail": "upload exceeds configured maximum"},
        )
    except EmptyUpload:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "zero-byte documents are not accepted"},
        )
    except ClientDisconnect:
        log_event(logger, logging.WARNING, "upload_interrupted")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "upload was interrupted"},
        )
    finally:
        await body_stream.aclose()

    scan = request.app.state.scan_service.register_and_analyze(
        document,
        original_filename=filename,
        display_filename=normalize_display_filename(filename),
        claimed_content_type=claimed_content_type,
    )
    request.app.state.audit_service.append(
        AuditEventType.SCAN_UPLOAD_REQUESTED,
        scan_id=scan.id,
        outcome=AuditOutcome.SUCCESS,
        actor_type=AuditActorType.OPERATOR,
        actor_id=principal.user_id,
        details={"size_bytes": scan.size_bytes},
    )
    log_event(
        logger,
        logging.INFO,
        "scan_ingested",
        scan_id=scan.id,
        state=scan.state,
        size_bytes=scan.size_bytes,
        worker_status=scan.worker_status,
    )
    return _scan_response(scan)


@router.get("/scans", response_model=ScanListResponse)
async def list_scans(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_capability(Capability.SCAN_READ))],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    decision: Decision | None = None,
    state: ScanState | None = None,
) -> ScanListResponse:
    enforce_operator_limit(
        request,
        principal,
        action="scan_list",
        limit=request.app.state.settings.expensive_reads_per_operator_minute,
        window_seconds=60,
    )
    service: OperatorQueryService = request.app.state.operator_query_service
    result = service.list_scans(
        page=page,
        page_size=page_size,
        decision=decision,
        state=state.value if state is not None else None,
    )
    return ScanListResponse(
        items=[_scan_summary(scan) for scan in result.items],
        page=result.page,
        page_size=result.page_size,
        total=result.total,
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_capability(Capability.SCAN_READ))],
    scan_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
) -> ScanResponse | JSONResponse:
    enforce_operator_limit(
        request,
        principal,
        action="scan_detail",
        limit=request.app.state.settings.expensive_reads_per_operator_minute,
        window_seconds=60,
    )
    try:
        scan = request.app.state.scan_service.get(scan_id)
    except ScanNotFound:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"detail": "scan not found"},
        )
    return _scan_response(scan)


def _scan_summary(scan: Scan) -> ScanSummaryResponse:
    return ScanSummaryResponse(
        scan_id=scan.id,
        state=scan.state,
        display_filename=scan.display_filename,
        created_at=scan.created_at,
        detected_type=scan.detected_type,
        analysis_status=scan.worker_status,
        decision=scan.decision or Decision.QUARANTINE.value,
        release_eligible=scan.release_eligible,
        risk_score=scan.risk_score or 0,
        risk_band=scan.severity or "LOW",
    )


def _scan_response(scan: Scan) -> ScanResponse:
    evaluation = _persisted_evaluation(scan)
    decision = evaluation.decision if evaluation is not None else Decision.QUARANTINE
    return ScanResponse(
        scan_id=scan.id,
        state=scan.state,
        sha256=scan.sha256,
        size_bytes=scan.size_bytes,
        display_filename=scan.display_filename,
        claimed_content_type=scan.claimed_content_type,
        analysis_status=scan.worker_status,
        decision=decision.value,
        decision_message=_DECISION_MESSAGES[decision],
        release_eligible=evaluation.release_eligible if evaluation is not None else False,
        risk_score=evaluation.risk_score if evaluation is not None else 0,
        risk_band=evaluation.risk_band.value if evaluation is not None else "LOW",
        policy_version=evaluation.policy_version if evaluation is not None else "PRE_POLICY",
        policy_fingerprint=(
            evaluation.policy_fingerprint if evaluation is not None else scan.policy_fingerprint
        ),
        analysis_complete=evaluation.analysis_complete if evaluation is not None else False,
        hard_block_reasons=(list(evaluation.hard_block_reasons) if evaluation else []),
        mandatory_quarantine_reasons=(
            list(evaluation.mandatory_quarantine_reasons)
            if evaluation
            else ["POLICY_EVALUATION_MISSING"]
        ),
        compound_rules_triggered=(list(evaluation.compound_rules_triggered) if evaluation else []),
        decision_reasons=(
            [PolicyReasonResponse(**reason.model_dump()) for reason in evaluation.decision_reasons]
            if evaluation
            else [
                PolicyReasonResponse(
                    code="POLICY_EVALUATION_MISSING",
                    explanation="This historical scan predates persisted policy evaluation.",
                )
            ]
        ),
        contributions=(
            [
                PolicyContributionResponse(**contribution.model_dump())
                for contribution in evaluation.contributions
            ]
            if evaluation
            else []
        ),
        disclaimer=_DISCLAIMER,
        detected_type=scan.detected_type,
        detected_mime=scan.detected_mime,
        findings=[
            FindingResponse(
                code=finding.code,
                title=finding.title,
                description=finding.description,
                category=finding.category,
                severity=finding.severity,
                mitre_techniques=finding.mitre_techniques,
                metadata=finding.metadata_json,
            )
            for finding in scan.findings
        ],
    )


def _persisted_evaluation(scan: Scan) -> PolicyEvaluation | None:
    if scan.policy_evaluation_json is None:
        return None
    try:
        evaluation = PolicyEvaluation.model_validate_json(
            json.dumps(scan.policy_evaluation_json, separators=(",", ":"), sort_keys=True)
        )
        persisted_identity = (
            scan.policy_version,
            scan.policy_fingerprint,
            scan.risk_score,
            scan.severity,
            scan.decision,
            scan.release_eligible,
        )
        evaluation_identity = (
            evaluation.policy_version,
            evaluation.policy_fingerprint,
            evaluation.risk_score,
            evaluation.risk_band.value,
            evaluation.decision.value,
            evaluation.release_eligible,
        )
        if persisted_identity != evaluation_identity:
            raise ValueError("persisted policy columns disagree with evaluation")
        return evaluation
    except ValueError:
        log_event(logger, logging.ERROR, "persisted_policy_evaluation_rejected", scan_id=scan.id)
        return None


def _content_length(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _bounded_content_type(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip()[:255] or None
