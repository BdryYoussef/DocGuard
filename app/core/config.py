"""Typed environment-driven settings with fail-closed production validation."""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from pathlib import Path
from typing import Self
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import (
    DEFAULT_ARTIFACT_DOWNLOADS_PER_HOUR,
    DEFAULT_CDR_REQUESTS_PER_HOUR,
    DEFAULT_CDR_TIMEOUT_SECONDS,
    DEFAULT_EXPENSIVE_READS_PER_MINUTE,
    DEFAULT_LOGIN_ATTEMPTS_PER_HOUR,
    DEFAULT_LOGIN_ATTEMPTS_PER_MINUTE,
    DEFAULT_MAX_UPLOAD_BYTES,
    DEFAULT_RECONCILIATION_STALE_SECONDS,
    DEFAULT_SESSION_ABSOLUTE_SECONDS,
    DEFAULT_SESSION_INACTIVITY_SECONDS,
    DEFAULT_SESSION_REFRESH_SECONDS,
    DEFAULT_SQLITE_BUSY_TIMEOUT_MS,
    DEFAULT_UPLOADS_PER_HOUR,
    DEFAULT_WORKER_CPU_LIMIT_SECONDS,
    DEFAULT_WORKER_FILE_SIZE_LIMIT_BYTES,
    DEFAULT_WORKER_MEMORY_LIMIT_BYTES,
    DEFAULT_WORKER_OPEN_FILES_LIMIT,
    DEFAULT_WORKER_STDERR_MAX_BYTES,
    DEFAULT_WORKER_STDOUT_MAX_BYTES,
    DEFAULT_WORKER_TASKS_LIMIT,
    DEFAULT_WORKER_TIMEOUT_SECONDS,
    DEFAULT_WORKER_TMPFS_BYTES,
)
from docguard_contract.cdr import (
    PDF_CDR_MAX_HEIGHT_PIXELS,
    PDF_CDR_MAX_HEIGHT_POINTS,
    PDF_CDR_MAX_OUTPUT_BYTES,
    PDF_CDR_MAX_PAGES,
    PDF_CDR_MAX_PIXELS_PER_PAGE,
    PDF_CDR_MAX_RASTER_BYTES,
    PDF_CDR_MAX_TOTAL_PIXELS,
    PDF_CDR_MAX_WIDTH_PIXELS,
    PDF_CDR_MAX_WIDTH_POINTS,
)


class AppEnvironment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class IsolationBackendName(StrEnum):
    BUBBLEWRAP = "bubblewrap"
    UNSAFE_DEVELOPMENT = "unsafe-development"


class Settings(BaseSettings):
    """Settings are immutable after validation and never contain source-code secrets."""

    model_config = SettingsConfigDict(
        env_prefix="DOCGUARD_",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    env: AppEnvironment = AppEnvironment.PRODUCTION
    database_url: str = "sqlite:///var/docguard.db"
    storage_root: Path = Path("var")
    maximum_upload_bytes: int = Field(default=DEFAULT_MAX_UPLOAD_BYTES, gt=0)
    isolation_backend: IsolationBackendName = IsolationBackendName.BUBBLEWRAP
    worker_timeout_seconds: float = Field(default=DEFAULT_WORKER_TIMEOUT_SECONDS, gt=0)
    cdr_timeout_seconds: float = Field(default=DEFAULT_CDR_TIMEOUT_SECONDS, gt=0, le=300)
    cdr_max_pages: int = Field(default=PDF_CDR_MAX_PAGES, ge=1, le=1_000)
    cdr_max_width_points: float = Field(default=PDF_CDR_MAX_WIDTH_POINTS, gt=0, le=10_000)
    cdr_max_height_points: float = Field(default=PDF_CDR_MAX_HEIGHT_POINTS, gt=0, le=10_000)
    cdr_max_width_pixels: int = Field(default=PDF_CDR_MAX_WIDTH_PIXELS, ge=1, le=20_000)
    cdr_max_height_pixels: int = Field(default=PDF_CDR_MAX_HEIGHT_PIXELS, ge=1, le=20_000)
    cdr_max_pixels_per_page: int = Field(default=PDF_CDR_MAX_PIXELS_PER_PAGE, ge=1, le=100_000_000)
    cdr_max_total_pixels: int = Field(default=PDF_CDR_MAX_TOTAL_PIXELS, ge=1, le=1_000_000_000)
    cdr_max_raster_bytes: int = Field(default=PDF_CDR_MAX_RASTER_BYTES, ge=1, le=3_000_000_000)
    cdr_max_output_bytes: int = Field(default=PDF_CDR_MAX_OUTPUT_BYTES, ge=1, le=1_000_000_000)
    worker_stdout_max_bytes: int = Field(default=DEFAULT_WORKER_STDOUT_MAX_BYTES, ge=4_096)
    worker_stderr_max_bytes: int = Field(default=DEFAULT_WORKER_STDERR_MAX_BYTES, ge=4_096)
    worker_memory_limit_bytes: int = Field(default=DEFAULT_WORKER_MEMORY_LIMIT_BYTES, ge=128 << 20)
    worker_file_size_limit_bytes: int = Field(
        default=DEFAULT_WORKER_FILE_SIZE_LIMIT_BYTES, ge=1 << 20
    )
    worker_open_files_limit: int = Field(default=DEFAULT_WORKER_OPEN_FILES_LIMIT, ge=32)
    worker_tasks_limit: int = Field(default=DEFAULT_WORKER_TASKS_LIMIT, ge=8)
    worker_cpu_limit_seconds: int = Field(default=DEFAULT_WORKER_CPU_LIMIT_SECONDS, ge=1)
    worker_tmpfs_bytes: int = Field(default=DEFAULT_WORKER_TMPFS_BYTES, ge=16 << 20)
    worker_source_root: Path = Path("worker")
    worker_contract_root: Path = Path("docguard_contract")
    worker_dependency_root: Path = Path(".worker-deps")
    bubblewrap_path: Path = Path("/usr/bin/bwrap")
    prlimit_path: Path = Path("/usr/bin/prlimit")
    systemd_run_path: Path = Path("/usr/bin/systemd-run")
    isolation_self_test_cache_seconds: float = Field(default=60.0, ge=0)
    log_level: str = "INFO"
    allow_unsafe_development_backend: bool = False
    session_absolute_lifetime_seconds: int = Field(
        default=DEFAULT_SESSION_ABSOLUTE_SECONDS, ge=300, le=86_400
    )
    session_inactivity_lifetime_seconds: int = Field(
        default=DEFAULT_SESSION_INACTIVITY_SECONDS, ge=60, le=43_200
    )
    session_refresh_interval_seconds: int = Field(
        default=DEFAULT_SESSION_REFRESH_SECONDS, ge=30, le=3_600
    )
    session_cookie_name: str | None = None
    session_cookie_secure: bool | None = None
    session_cookie_samesite: str = "lax"
    csrf_required: bool = True
    login_attempts_per_minute: int = Field(default=DEFAULT_LOGIN_ATTEMPTS_PER_MINUTE, ge=1, le=100)
    login_attempts_per_hour: int = Field(default=DEFAULT_LOGIN_ATTEMPTS_PER_HOUR, ge=1, le=1_000)
    application_origin: str = "https://127.0.0.1:8000"
    trusted_proxy_ips: str = ""
    require_origin_header: bool | None = None
    uploads_per_operator_hour: int = Field(default=DEFAULT_UPLOADS_PER_HOUR, ge=1, le=10_000)
    cdr_requests_per_operator_hour: int = Field(
        default=DEFAULT_CDR_REQUESTS_PER_HOUR, ge=1, le=10_000
    )
    artifact_downloads_per_operator_hour: int = Field(
        default=DEFAULT_ARTIFACT_DOWNLOADS_PER_HOUR, ge=1, le=100_000
    )
    expensive_reads_per_operator_minute: int = Field(
        default=DEFAULT_EXPENSIVE_READS_PER_MINUTE, ge=1, le=100_000
    )
    sqlite_busy_timeout_ms: int = Field(default=DEFAULT_SQLITE_BUSY_TIMEOUT_MS, ge=100, le=60_000)
    reconciliation_stale_seconds: int = Field(
        default=DEFAULT_RECONCILIATION_STALE_SECONDS, ge=60, le=86_400
    )

    @property
    def effective_require_origin_header(self) -> bool:
        if self.require_origin_header is not None:
            return self.require_origin_header
        return self.env is AppEnvironment.PRODUCTION

    @property
    def parsed_trusted_proxy_ips(self) -> frozenset[ipaddress.IPv4Address | ipaddress.IPv6Address]:
        values = (item.strip() for item in self.trusted_proxy_ips.split(","))
        return frozenset(ipaddress.ip_address(item) for item in values if item)

    @property
    def effective_session_cookie_name(self) -> str:
        if self.session_cookie_name is not None:
            return self.session_cookie_name
        if self.env is AppEnvironment.PRODUCTION:
            return "__Host-docguard_session"
        return "docguard_session"

    @property
    def effective_session_cookie_secure(self) -> bool:
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.env is AppEnvironment.PRODUCTION

    @model_validator(mode="after")
    def enforce_isolation_policy(self) -> Self:
        if any(part.casefold() in {"public", "static"} for part in self.storage_root.parts):
            raise ValueError("storage root must not be inside a public/static directory")
        if self.isolation_backend is IsolationBackendName.UNSAFE_DEVELOPMENT:
            if self.env is AppEnvironment.PRODUCTION:
                raise ValueError("unsafe development backend is forbidden in production")
            if not self.allow_unsafe_development_backend:
                raise ValueError("unsafe development backend requires explicit opt-in")
        if self.session_inactivity_lifetime_seconds > self.session_absolute_lifetime_seconds:
            raise ValueError("session inactivity lifetime must not exceed absolute lifetime")
        if self.session_refresh_interval_seconds >= self.session_inactivity_lifetime_seconds:
            raise ValueError("session refresh interval must be shorter than inactivity lifetime")
        if self.login_attempts_per_hour < self.login_attempts_per_minute:
            raise ValueError("hourly login limit must not be lower than the minute limit")
        minimum_reconciliation_age = int(
            max(self.worker_timeout_seconds, self.cdr_timeout_seconds) * 2 + 60
        )
        if self.reconciliation_stale_seconds < minimum_reconciliation_age:
            raise ValueError(
                "reconciliation stale threshold must exceed worker and CDR timeout windows"
            )
        if self.session_cookie_samesite.casefold() not in {"lax", "strict"}:
            raise ValueError("session cookie SameSite must be Lax or Strict")
        cookie_name = self.effective_session_cookie_name
        if not cookie_name or any(character.isspace() for character in cookie_name):
            raise ValueError("session cookie name is invalid")
        origin = urlsplit(self.application_origin)
        if (
            origin.scheme not in {"http", "https"}
            or not origin.netloc
            or origin.username is not None
            or origin.password is not None
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
        ):
            raise ValueError("application origin must be an absolute HTTP(S) origin without a path")
        try:
            _ = self.parsed_trusted_proxy_ips
        except ValueError as exc:
            raise ValueError(
                "trusted proxy addresses must be comma-separated individual IPs"
            ) from exc
        if self.env is AppEnvironment.PRODUCTION:
            if not self.effective_session_cookie_secure:
                raise ValueError("production session cookies must be Secure")
            if not cookie_name.startswith("__Host-"):
                raise ValueError("production session cookie must use __Host- semantics")
            if origin.scheme != "https":
                raise ValueError("production application origin must use HTTPS")
            if not self.csrf_required:
                raise ValueError("CSRF protection cannot be disabled in production")
            if not self.effective_require_origin_header:
                raise ValueError("production mutation requests must require an Origin header")
        return self
