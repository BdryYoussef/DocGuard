"""Small versioned input contract sent from the trusted side to the worker."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import Field, field_validator, model_validator

from app.core.constants import ANALYSIS_SCHEMA_VERSION
from app.models.domain import ContractModel


class WorkerOperation(StrEnum):
    ANALYZE = "ANALYZE"
    SANITIZE_PDF = "SANITIZE_PDF"


class PdfCdrRequestConfig(ContractModel):
    sanitizer_version: str = Field(min_length=1, max_length=32)
    sanitizer_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    dpi: int = Field(ge=72, le=300)
    max_pages: int = Field(ge=1, le=1_000)
    max_width_points: float = Field(gt=0, le=10_000)
    max_height_points: float = Field(gt=0, le=10_000)
    max_width_pixels: int = Field(ge=1, le=20_000)
    max_height_pixels: int = Field(ge=1, le=20_000)
    max_pixels_per_page: int = Field(ge=1, le=100_000_000)
    max_total_pixels: int = Field(ge=1, le=1_000_000_000)
    max_raster_bytes: int = Field(ge=1, le=3_000_000_000)
    max_output_bytes: int = Field(ge=1, le=1_000_000_000)


class WorkerRequest(ContractModel):
    schema_version: str = ANALYSIS_SCHEMA_VERSION
    job_id: str = Field(min_length=16, max_length=128, pattern=r"^[0-9a-f]+$")
    sample_path: str = Field(min_length=1, max_length=4_096)
    original_filename: str = Field(default="unnamed-document", max_length=255)
    claimed_content_type: str | None = Field(default=None, max_length=255)
    operation: WorkerOperation = WorkerOperation.ANALYZE
    cdr: PdfCdrRequestConfig | None = None

    @field_validator("schema_version")
    @classmethod
    def require_supported_schema(cls, value: str) -> str:
        if value != ANALYSIS_SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version: {value}")
        return value

    @field_validator("sample_path")
    @classmethod
    def require_absolute_sample_path(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("worker sample path must be absolute")
        return value

    @model_validator(mode="after")
    def require_operation_configuration(self) -> WorkerRequest:
        if (self.operation is WorkerOperation.SANITIZE_PDF) is (self.cdr is None):
            raise ValueError("SANITIZE_PDF requires CDR configuration and ANALYZE forbids it")
        return self
