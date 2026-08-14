"""Versioned public response models with no internal storage paths."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from docguard_contract import API_SCHEMA_VERSION


class FindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    title: str
    description: str
    category: str
    severity: str
    mitre_techniques: list[str]
    metadata: dict[str, object]


class PolicyReasonResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    explanation: str


class PolicyContributionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    contribution: int
    explanation: str


class ScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    scan_id: str
    state: str
    sha256: str
    size_bytes: int
    display_filename: str
    claimed_content_type: str | None
    analysis_status: str
    decision: str
    decision_message: str
    release_eligible: bool
    risk_score: int
    risk_band: str
    policy_version: str
    policy_fingerprint: str | None
    analysis_complete: bool
    hard_block_reasons: list[str]
    mandatory_quarantine_reasons: list[str]
    compound_rules_triggered: list[str]
    decision_reasons: list[PolicyReasonResponse]
    contributions: list[PolicyContributionResponse]
    disclaimer: str
    detected_type: str | None
    detected_mime: str | None
    findings: list[FindingResponse]


class ScanSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    state: str
    display_filename: str
    created_at: datetime
    detected_type: str | None
    analysis_status: str
    decision: str
    release_eligible: bool
    risk_score: int
    risk_band: str


class ScanListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    items: list[ScanSummaryResponse]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class SanitizationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    source_scan_id: str
    derived_scan_id: str | None
    artifact_id: str | None
    approved: bool
    reused: bool
    failure_code: str | None


class ArtifactResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    artifact_id: str
    source_scan_id: str
    derived_scan_id: str
    artifact_type: str
    sha256: str
    size_bytes: int
    sanitizer_version: str
    policy_version: str
    created_at: datetime


class ArtifactListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    items: list[ArtifactResponse]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    actor_type: str
    actor_id: str | None
    actor_username: str | None
    outcome: str
    reason_code: str | None
    scan_id: str | None
    artifact_id: str | None
    details: dict[str, object]
    created_at: datetime


class AuditEventListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    items: list[AuditEventResponse]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
