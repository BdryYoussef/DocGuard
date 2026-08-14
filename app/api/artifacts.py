"""Authenticated approved-artifact metadata and controlled downloads."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse

from app.api.schemas import ArtifactListResponse, ArtifactResponse
from app.artifacts.service import (
    ArtifactAuditUnavailable,
    ArtifactNotFound,
    ArtifactUnavailable,
    iter_download,
)
from app.auth.http import require_capability
from app.auth.models import AuthenticatedPrincipal, Capability
from app.core.request_limits import enforce_operator_limit
from app.models.database import Artifact

router = APIRouter(prefix="/api/v1", tags=["artifacts"])


@router.get("/artifacts", response_model=ArtifactListResponse)
async def list_artifacts(
    request: Request,
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.ARTIFACT_READ))
    ],
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> ArtifactListResponse:
    enforce_operator_limit(
        request,
        principal,
        action="artifact_list",
        limit=request.app.state.settings.expensive_reads_per_operator_minute,
        window_seconds=60,
    )
    result = request.app.state.operator_query_service.list_artifacts(page=page, page_size=page_size)
    return ArtifactListResponse(
        items=[_artifact_response(artifact) for artifact in result.items],
        page=result.page,
        page_size=result.page_size,
        total=result.total,
    )


@router.get("/artifacts/{artifact_id}", response_model=ArtifactResponse)
async def get_artifact(
    request: Request,
    artifact_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.ARTIFACT_READ))
    ],
) -> ArtifactResponse | JSONResponse:
    enforce_operator_limit(
        request,
        principal,
        action="artifact_detail",
        limit=request.app.state.settings.expensive_reads_per_operator_minute,
        window_seconds=60,
    )
    artifact = request.app.state.operator_query_service.get_artifact(artifact_id)
    if artifact is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"detail": "artifact not found"}
        )
    return _artifact_response(artifact)


@router.get("/artifacts/{artifact_id}/download", response_model=None)
async def download_artifact(
    request: Request,
    artifact_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    principal: Annotated[
        AuthenticatedPrincipal, Depends(require_capability(Capability.ARTIFACT_READ))
    ],
) -> StreamingResponse | JSONResponse:
    enforce_operator_limit(
        request,
        principal,
        action="artifact_download",
        limit=request.app.state.settings.artifact_downloads_per_operator_hour,
        window_seconds=3_600,
    )
    try:
        download = request.app.state.artifact_download_service.prepare(artifact_id, principal)
    except ArtifactNotFound:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND, content={"detail": "artifact not found"}
        )
    except (ArtifactUnavailable, ArtifactAuditUnavailable):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": "artifact is unavailable"},
        )
    return StreamingResponse(
        iter_download(download),
        media_type="application/pdf",
        headers={
            "Cache-Control": "no-store, private",
            "Content-Disposition": f'attachment; filename="{download.download_filename}"',
            "Content-Length": str(download.size_bytes),
            "X-Content-Type-Options": "nosniff",
        },
    )


def _artifact_response(artifact: Artifact) -> ArtifactResponse:
    return ArtifactResponse(
        artifact_id=artifact.id,
        source_scan_id=artifact.scan_id,
        derived_scan_id=artifact.derived_scan_id,
        artifact_type=artifact.artifact_type,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        sanitizer_version=artifact.sanitizer_version,
        policy_version=artifact.policy_version,
        created_at=artifact.created_at,
    )


__all__ = ["router"]
