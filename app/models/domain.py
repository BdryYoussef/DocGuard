"""Validated, deterministic worker and policy domain models."""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.constants import ANALYSIS_SCHEMA_VERSION
from docguard_contract import (
    MAX_ANALYZER_METADATA_BYTES,
    MAX_FINDING_METADATA_BYTES,
    MAX_FINDINGS_PER_ANALYSIS,
)
from docguard_contract.findings import FINDING_DEFINITIONS
from docguard_contract.yara_rules import (
    MAX_YARA_OFFSETS_PER_FINDING,
    MAX_YARA_REPORTED_MATCH_COUNT,
    MAX_YARA_STRING_IDS_PER_FINDING,
    YARA_RULE_DEFINITIONS,
    YARA_RULE_PACK_SHA256,
    YARA_RULE_PACK_VERSION,
)

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class Severity(StrEnum):
    """Finding severity, independent from any final document decision."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AnalysisStatus(StrEnum):
    SUCCESS = "SUCCESS"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    QUARANTINE = "QUARANTINE"
    BLOCK = "BLOCK"


class ScanState(StrEnum):
    STORED = "STORED"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"


class ScanOrigin(StrEnum):
    UPLOAD = "UPLOAD"
    CDR_DERIVED = "CDR_DERIVED"


class ArtifactType(StrEnum):
    PDF_CDR = "PDF_CDR"


class AuditActorType(StrEnum):
    SYSTEM = "SYSTEM"
    OPERATOR = "OPERATOR"
    ANONYMOUS = "ANONYMOUS"


class AuditOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class ContractModel(BaseModel):
    """Strict base model with a canonical JSON representation."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    def to_json(self) -> str:
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )


class Finding(ContractModel):
    code: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z0-9_]+$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    category: str = Field(min_length=1, max_length=100)
    severity: Severity
    score_delta: int = Field(ge=-100, le=100)
    mitre_techniques: list[str] = Field(default_factory=list)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("score_delta")
    @classmethod
    def reject_worker_scoring(cls, value: int) -> int:
        if value != 0:
            raise ValueError("worker findings cannot supply policy score")
        return value

    @field_validator("mitre_techniques")
    @classmethod
    def validate_mitre_techniques(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 32:
                raise ValueError("MITRE technique identifiers must be 1-32 characters")
        return values

    @field_validator("metadata")
    @classmethod
    def bound_metadata(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _require_bounded_json(value, MAX_FINDING_METADATA_BYTES, "finding metadata")
        return value

    @model_validator(mode="after")
    def require_registered_product_metadata(self) -> Finding:
        definition = FINDING_DEFINITIONS.get(self.code)
        if definition is None:
            raise ValueError(f"unregistered finding code: {self.code}")
        expected_mitre = definition.mitre_techniques
        if self.code in {
            "YARA_TEST_SIGNATURE",
            "YARA_SIGNATURE_MATCH",
            "YARA_HEURISTIC_MATCH",
        }:
            expected_mitre = _validate_yara_match_metadata(self)
        elif self.code == "YARA_PARTIAL_ANALYSIS":
            _validate_yara_partial_metadata(self.metadata)
        observed = (
            self.title,
            self.description,
            self.severity.value,
            self.category,
            tuple(self.mitre_techniques),
        )
        expected = (
            definition.title,
            definition.description,
            definition.default_severity,
            definition.category,
            expected_mitre,
        )
        if observed != expected:
            raise ValueError(f"finding metadata does not match registry: {self.code}")
        return self


class AnalysisResult(ContractModel):
    schema_version: str
    worker_version: str = Field(min_length=1, max_length=64)
    status: AnalysisStatus
    detected_type: str | None = Field(default=None, max_length=200)
    size_bytes: int = Field(ge=0)
    findings: list[Finding] = Field(default_factory=list, max_length=MAX_FINDINGS_PER_ANALYSIS)
    analyzer_metadata: dict[str, JsonValue] = Field(default_factory=dict)
    started_at: datetime
    completed_at: datetime
    duration_ms: int = Field(ge=0)

    @field_validator("schema_version")
    @classmethod
    def require_supported_schema(cls, value: str) -> str:
        if value != ANALYSIS_SCHEMA_VERSION:
            raise ValueError(f"unsupported schema version: {value}")
        return value

    @field_validator("started_at", "completed_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must be timezone-aware")
        return value

    @field_validator("analyzer_metadata")
    @classmethod
    def bound_analyzer_metadata(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        _require_bounded_json(value, MAX_ANALYZER_METADATA_BYTES, "analyzer metadata")
        return value

    @model_validator(mode="after")
    def validate_timing(self) -> AnalysisResult:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


def _require_bounded_json(value: JsonValue, maximum_bytes: int, label: str) -> None:
    try:
        size = len(
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be finite JSON data") from exc
    if size > maximum_bytes:
        raise ValueError(f"{label} exceeds {maximum_bytes} bytes")


def _validate_yara_match_metadata(finding: Finding) -> tuple[str, ...]:
    expected_keys = {
        "rule_id",
        "rule_title",
        "rule_explanation",
        "rule_category",
        "confidence_class",
        "rule_pack_version",
        "rule_pack_sha256",
        "scope",
        "match_count",
        "string_ids",
        "offsets",
    }
    if set(finding.metadata) != expected_keys:
        raise ValueError("YARA match metadata shape is invalid")
    rule_id = finding.metadata.get("rule_id")
    if not isinstance(rule_id, str) or rule_id not in YARA_RULE_DEFINITIONS:
        raise ValueError("unregistered YARA rule ID")
    rule = YARA_RULE_DEFINITIONS[rule_id]
    trusted_values = {
        "rule_title": rule.title,
        "rule_explanation": rule.explanation,
        "rule_category": rule.category,
        "confidence_class": rule.confidence,
        "rule_pack_version": YARA_RULE_PACK_VERSION,
        "rule_pack_sha256": YARA_RULE_PACK_SHA256,
        "scope": "TOP_LEVEL",
    }
    if any(finding.metadata.get(key) != value for key, value in trusted_values.items()):
        raise ValueError("YARA metadata does not match the trusted rule registry")
    if finding.code != rule.finding_code or finding.severity.value != rule.severity:
        raise ValueError("YARA finding class does not match the trusted rule registry")

    match_count = finding.metadata.get("match_count")
    if (
        isinstance(match_count, bool)
        or not isinstance(match_count, int)
        or not 1 <= match_count <= MAX_YARA_REPORTED_MATCH_COUNT
    ):
        raise ValueError("YARA match count is invalid")
    string_ids = finding.metadata.get("string_ids")
    if not isinstance(string_ids, list) or len(string_ids) > MAX_YARA_STRING_IDS_PER_FINDING:
        raise ValueError("YARA string identifier metadata is invalid")
    if any(
        not isinstance(value, str) or not value.startswith("$") or len(value) > 128
        for value in string_ids
    ):
        raise ValueError("YARA string identifiers are invalid")
    trusted_string_ids = cast(list[str], string_ids)
    if trusted_string_ids != sorted(set(trusted_string_ids)):
        raise ValueError("YARA string identifiers are invalid")
    offsets = finding.metadata.get("offsets")
    if not isinstance(offsets, list) or len(offsets) > MAX_YARA_OFFSETS_PER_FINDING:
        raise ValueError("YARA offset metadata is invalid")
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in offsets):
        raise ValueError("YARA offsets are invalid")
    trusted_offsets = cast(list[int], offsets)
    if trusted_offsets != sorted(set(trusted_offsets)):
        raise ValueError("YARA offsets must be deterministic and unique")
    return rule.mitre_techniques


def _validate_yara_partial_metadata(metadata: dict[str, JsonValue]) -> None:
    if set(metadata) != {"reasons", "rule_pack_version", "rule_pack_sha256"}:
        raise ValueError("YARA partial metadata shape is invalid")
    if (
        metadata.get("rule_pack_version") != YARA_RULE_PACK_VERSION
        or metadata.get("rule_pack_sha256") != YARA_RULE_PACK_SHA256
    ):
        raise ValueError("YARA partial metadata has an untrusted rule-pack identity")
    allowed_reasons = {
        "engine_match_warning",
        "engine_warning",
        "internal_timeout",
        "match_instance_limit",
        "matched_rule_limit",
        "metadata_limit",
        "offset_limit",
        "scanner_error",
        "string_identifier_limit",
    }
    reasons = metadata.get("reasons")
    if (
        not isinstance(reasons, list)
        or not reasons
        or len(reasons) > len(allowed_reasons)
        or any(not isinstance(reason, str) or reason not in allowed_reasons for reason in reasons)
    ):
        raise ValueError("YARA partial reasons are invalid")
    trusted_reasons = cast(list[str], reasons)
    if trusted_reasons != sorted(set(trusted_reasons)):
        raise ValueError("YARA partial reasons are invalid")
