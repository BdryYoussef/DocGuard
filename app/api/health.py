"""Liveness and dependency-aware readiness endpoints."""

import logging
from typing import Any

from fastapi import APIRouter, Request, Response, status
from sqlalchemy import text

from app.cdr.registry import sanitizer_registry_is_valid
from app.core.config import AppEnvironment
from app.core.qualification import qualify_database, qualify_filesystem, qualify_runtime
from app.policies.registry import policy_registry_is_valid

router = APIRouter(prefix="/health", tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/live")
async def live() -> dict[str, str]:
    return {"status": "alive"}


@router.get("/ready")
async def ready(request: Request, response: Response) -> dict[str, Any]:
    checks: dict[str, bool] = {}
    checks["policy_registry"] = policy_registry_is_valid()
    checks["sanitizer_registry"] = sanitizer_registry_is_valid(request.app.state.settings)
    backend = request.app.state.isolation_backend
    checks["isolation_backend"] = backend.ready
    storage_paths = request.app.state.storage_paths
    checks["storage"] = all(
        path.is_dir()
        for path in (
            storage_paths.incoming,
            storage_paths.quarantine,
            storage_paths.sanitized,
            storage_paths.work,
        )
    )
    try:
        with request.app.state.database_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            if request.app.state.settings.env is AppEnvironment.PRODUCTION:
                checks.update(qualify_database(request.app.state.database_engine).checks)
        checks["database"] = True
    except Exception:  # readiness converts dependency failure to a closed state
        logger.exception("readiness_database_check_failed")
        checks["database"] = False
    if request.app.state.settings.env is AppEnvironment.PRODUCTION:
        checks.update(
            qualify_filesystem(
                request.app.state.settings,
                storage_paths,
                static_root=request.app.state.web_root / "static",
                project_root=request.app.state.project_root,
            ).checks
        )
        checks.update(
            qualify_runtime(
                request.app.state.settings, project_root=request.app.state.project_root
            ).checks
        )

    checks.update(
        request.app.state.authentication_service.readiness(
            require_active_operator=request.app.state.settings.env is AppEnvironment.PRODUCTION
        )
    )
    settings = request.app.state.settings
    checks["authentication_configuration"] = all(
        (
            settings.csrf_required,
            settings.effective_session_cookie_secure
            if settings.env is AppEnvironment.PRODUCTION
            else True,
            settings.application_origin.startswith("https://")
            if settings.env is AppEnvironment.PRODUCTION
            else True,
        )
    )

    is_ready = all(checks.values())
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    if request.app.state.settings.env is AppEnvironment.PRODUCTION:
        if not is_ready:
            logger.error(
                "production_readiness_failed", extra={"structured_fields": {"checks": checks}}
            )
        return {"status": "ready" if is_ready else "not_ready"}
    return {"status": "ready" if is_ready else "not_ready", "checks": checks}
