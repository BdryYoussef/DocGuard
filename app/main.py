"""FastAPI application factory for the trusted DocGuard process."""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session, sessionmaker
from starlette.templating import Jinja2Templates

from app.api.artifacts import router as artifacts_router
from app.api.audit import router as audit_router
from app.api.cdr import router as cdr_router
from app.api.health import router as health_router
from app.api.scans import router as scans_router
from app.artifacts.service import ArtifactDownloadService
from app.audit.service import AuditService
from app.auth.http import clear_session_cookie
from app.auth.passwords import PasswordService
from app.auth.rate_limit import LoginRateLimiter
from app.auth.routes import router as auth_router
from app.auth.service import AuthenticationPersistenceError, AuthenticationService
from app.cdr.orchestrator import PdfCdrOrchestrator
from app.cdr.service import CdrService
from app.core.abuse import AbuseRateLimiter
from app.core.config import AppEnvironment, Settings
from app.core.constants import REQUEST_ID_BYTES
from app.core.database import create_database_engine
from app.core.errors import DocGuardError
from app.core.logging import configure_logging, log_event
from app.core.proxy import host_is_allowed, resolve_client_address
from app.operator.service import OperatorQueryService
from app.orchestrator.factory import create_isolation_backend
from app.orchestrator.scan_service import ScanService
from app.orchestrator.service import AnalysisOrchestrator
from app.storage.paths import StoragePaths
from app.web.routes import router as web_router
from app.web.security import apply_security_headers

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings()
    configure_logging(active_settings.log_level)
    storage_paths = StoragePaths(active_settings.storage_root)
    database_engine = create_database_engine(
        active_settings.database_url, busy_timeout_ms=active_settings.sqlite_busy_timeout_ms
    )
    isolation_backend = create_isolation_backend(active_settings)
    sessions = sessionmaker(database_engine, class_=Session, expire_on_commit=False)
    orchestrator = AnalysisOrchestrator(
        isolation_backend, timeout_seconds=active_settings.worker_timeout_seconds
    )
    scan_service = ScanService(sessions, orchestrator)
    audit_service = AuditService(sessions)
    password_service = PasswordService()
    login_rate_limiter = LoginRateLimiter(
        per_minute=active_settings.login_attempts_per_minute,
        per_hour=active_settings.login_attempts_per_hour,
    )
    abuse_rate_limiter = AbuseRateLimiter()
    authentication_service = AuthenticationService(
        sessions,
        active_settings,
        password_service,
        audit_service,
        login_rate_limiter,
    )
    operator_query_service = OperatorQueryService(sessions)
    cdr_orchestrator = PdfCdrOrchestrator(isolation_backend, active_settings)
    cdr_service = CdrService(
        sessions,
        scan_service,
        cdr_orchestrator,
        audit_service,
        storage_paths,
        active_settings,
    )
    artifact_download_service = ArtifactDownloadService(
        sessions, storage_paths, active_settings, audit_service
    )
    web_root = Path(__file__).parent / "web"
    template_environment = Environment(
        loader=FileSystemLoader(web_root / "templates"),
        autoescape=select_autoescape(("html", "xml"), default_for_string=True),
        auto_reload=active_settings.env.value != "production",
    )
    templates = Jinja2Templates(env=template_environment)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        storage_paths.initialize(
            strict_existing_permissions=active_settings.env is AppEnvironment.PRODUCTION
        )
        app.state.settings = active_settings
        app.state.storage_paths = storage_paths
        app.state.database_engine = database_engine
        app.state.sessions = sessions
        app.state.isolation_backend = isolation_backend
        app.state.scan_service = scan_service
        app.state.audit_service = audit_service
        app.state.authentication_service = authentication_service
        app.state.abuse_rate_limiter = abuse_rate_limiter
        app.state.operator_query_service = operator_query_service
        app.state.cdr_service = cdr_service
        app.state.artifact_download_service = artifact_download_service
        app.state.templates = templates
        app.state.web_root = web_root
        app.state.project_root = Path.cwd().resolve()
        try:
            yield
        finally:
            database_engine.dispose()

    expose_api_docs = active_settings.env is not AppEnvironment.PRODUCTION
    app = FastAPI(
        title="DocGuard",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if expose_api_docs else None,
        redoc_url="/redoc" if expose_api_docs else None,
        openapi_url="/openapi.json" if expose_api_docs else None,
    )
    app.mount("/static", StaticFiles(directory=web_root / "static"), name="static")
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(scans_router)
    app.include_router(cdr_router)
    app.include_router(artifacts_router)
    app.include_router(audit_router)
    app.include_router(web_router)

    @app.middleware("http")
    async def browser_security_and_session(request: Request, call_next):  # type: ignore[no-untyped-def]
        started = time.monotonic()
        request_id = secrets.token_hex(REQUEST_ID_BYTES)
        request.state.request_id = request_id
        request.state.client_address = resolve_client_address(request, active_settings)
        host_values = request.headers.getlist("host")
        if len(host_values) != 1 or not host_is_allowed(host_values[0], active_settings):
            response = JSONResponse(status_code=400, content={"detail": "invalid host"})
            response.headers["X-Request-ID"] = request_id
            apply_security_headers(request, response, active_settings)
            log_event(
                logger,
                logging.WARNING,
                "request_rejected_invalid_host",
                request_id=request_id,
                method=request.method,
                status_code=400,
            )
            return response
        raw_token = request.cookies.get(active_settings.effective_session_cookie_name)
        principal = None
        if not request.url.path.startswith("/static/"):
            try:
                principal = authentication_service.authenticate(raw_token)
            except AuthenticationPersistenceError:
                logger.exception("session_authentication_failed")
        request.state.principal = principal
        response = await call_next(request)
        if raw_token is not None and principal is None:
            clear_session_cookie(response, active_settings)
        apply_security_headers(request, response, active_settings)
        response.headers["X-Request-ID"] = request_id
        route = request.scope.get("route")
        route_template = getattr(route, "path", "unmatched")
        actor_id = getattr(principal, "user_id", None)
        log_event(
            logger,
            logging.INFO,
            "request_completed",
            request_id=request_id,
            route=route_template,
            method=request.method,
            status_code=response.status_code,
            duration_ms=max(0, round((time.monotonic() - started) * 1_000)),
            actor_id=actor_id,
            client_address=request.state.client_address,
        )
        return response

    @app.exception_handler(DocGuardError)
    async def handle_docguard_error(
        request: Request, exc: DocGuardError
    ) -> JSONResponse | HTMLResponse:
        logger.exception(
            "docguard_request_error",
            extra={
                "structured_fields": {
                    "request_id": getattr(request.state, "request_id", "unavailable"),
                    "exception_class": type(exc).__name__,
                }
            },
        )
        if request.url.path.startswith("/app"):
            principal = getattr(request.state, "principal", None)
            return templates.TemplateResponse(
                request=request,
                name="error.html",
                context={
                    "principal": principal,
                    "csrf_token": getattr(principal, "csrf_token", ""),
                    "message": "DocGuard could not complete the request.",
                    "request_id": getattr(request.state, "request_id", None),
                },
                status_code=500,
            )
        return JSONResponse(
            status_code=500,
            content={
                "detail": "DocGuard could not complete the request.",
                "request_id": getattr(request.state, "request_id", None),
            },
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "unavailable")
        logger.exception(
            "unexpected_request_error",
            extra={
                "structured_fields": {
                    "request_id": request_id,
                    "exception_class": type(exc).__name__,
                }
            },
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error.", "request_id": request_id},
        )

    return app


app = create_app()
