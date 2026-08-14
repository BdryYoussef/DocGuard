"""Bounded domain contracts for PDF CDR."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from app.models.domain import ContractModel
from docguard_contract import ANALYSIS_SCHEMA_VERSION


class CdrStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class CdrFailureCode(StrEnum):
    INELIGIBLE = "ineligible"
    RENDERER_UNAVAILABLE = "renderer_unavailable"
    RENDER_FAILED = "render_failed"
    RENDER_TIMEOUT = "render_timeout"
    OUTPUT_LIMIT = "output_limit"
    OUTPUT_INVALID = "output_invalid"
    PAGE_LIMIT = "page_limit"
    PIXEL_LIMIT = "pixel_limit"
    ENCRYPTED = "encrypted"
    MALFORMED = "malformed"
    DERIVED_ANALYSIS_REJECTED = "derived_analysis_rejected"
    HASH_MISMATCH = "hash_mismatch"
    STORAGE_FAILURE = "storage_failure"
    DATABASE_FAILURE = "database_failure"
    AUDIT_FAILURE = "audit_failure"
    PROMOTION_FAILURE = "promotion_failure"


class PdfCdrResult(ContractModel):
    schema_version: str
    operation: str
    status: CdrStatus
    sanitizer_version: str = Field(min_length=1, max_length=32)
    sanitizer_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    renderer_version: str = Field(min_length=1, max_length=64)
    engine_version: str = Field(min_length=1, max_length=64)
    page_count: int = Field(ge=0, le=1_000)
    total_pixels: int = Field(ge=0, le=1_000_000_000)
    output_bytes: int = Field(ge=0, le=1_000_000_000)
    duration_ms: int = Field(ge=0)
    failure_code: CdrFailureCode | None = None

    @model_validator(mode="after")
    def validate_semantics(self) -> PdfCdrResult:
        if self.schema_version != ANALYSIS_SCHEMA_VERSION or self.operation != "SANITIZE_PDF":
            raise ValueError("unsupported CDR result contract")
        if self.status is CdrStatus.SUCCESS:
            if self.failure_code is not None or self.page_count < 1 or self.output_bytes < 1:
                raise ValueError("successful CDR result is incomplete")
        elif self.failure_code is None:
            raise ValueError("failed CDR result requires a bounded failure code")
        return self


class CdrEligibility(ContractModel):
    eligible: bool
    scan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    reason_codes: tuple[str, ...] = Field(max_length=16)
    sanitizer_version: str
    sanitizer_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class CdrServiceResult(ContractModel):
    source_scan_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    derived_scan_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    artifact_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    approved: bool
    reused: bool = False
    failure_code: CdrFailureCode | None = None


__all__ = [
    "CdrEligibility",
    "CdrFailureCode",
    "CdrServiceResult",
    "CdrStatus",
    "PdfCdrResult",
]
