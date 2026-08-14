"""Typed, deterministic, serializable models for the Phase 11 evaluation framework.

These models describe the evaluation corpus (ground truth), the result shape Phase 11B
will populate when the real DocGuard pipeline is exercised, and reproducibility metadata.
Nothing here executes analysis; it is pure data modeling reused by manifest, corpus,
metrics, and reporting code.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, field_validator, model_validator

from app.models.domain import ContractModel, Decision, JsonValue
from docguard_contract.findings import FINDING_DEFINITIONS

CANONICAL_FINDING_CODES: frozenset[str] = frozenset(FINDING_DEFINITIONS)


class CaseCategory(StrEnum):
    """The eight coverage buckets described by the Phase 11A corpus design."""

    BENIGN_PDF = "BENIGN_PDF"
    RISKY_PDF = "RISKY_PDF"
    BENIGN_OFFICE = "BENIGN_OFFICE"
    RISKY_OFFICE = "RISKY_OFFICE"
    BENIGN_ARCHIVE = "BENIGN_ARCHIVE"
    RISKY_ARCHIVE = "RISKY_ARCHIVE"
    FILE_IDENTITY = "FILE_IDENTITY"
    YARA = "YARA"


class CaseClass(StrEnum):
    BENIGN = "BENIGN"
    RISKY = "RISKY"


class GeneratorKind(StrEnum):
    """How a fixture generator reference must be invoked during materialization."""

    WRITE_PATH = "WRITE_PATH"
    """``function(path, **kwargs) -> Path`` — writes the fixture at ``path``."""
    BYTES_FACTORY = "BYTES_FACTORY"
    """``function(**kwargs) -> bytes`` — the caller writes the returned bytes."""
    BYTES_CONST = "BYTES_CONST"
    """A module-level ``bytes`` attribute; no call is made."""


class CdrExpectedOutcome(StrEnum):
    """Prepared for Phase 11B; Phase 11A never executes CDR."""

    RECONSTRUCT_SUCCESS = "RECONSTRUCT_SUCCESS"
    REMAINS_NON_RELEASE = "REMAINS_NON_RELEASE"
    BLOCK_INELIGIBLE = "BLOCK_INELIGIBLE"


class AnalysisCompletenessClass(StrEnum):
    """Buckets for metric F (analysis completeness counts)."""

    COMPLETE = "COMPLETE"
    INTENTIONAL_PARTIAL = "INTENTIONAL_PARTIAL"
    PARSER_FAILURE = "PARSER_FAILURE"
    RESOURCE_LIMIT_FAILURE = "RESOURCE_LIMIT_FAILURE"
    TIMEOUT = "TIMEOUT"
    OTHER_FAIL_CLOSED = "OTHER_FAIL_CLOSED"


class FixtureGenerator(ContractModel):
    """A pointer to an existing, reused fixture factory function or constant.

    ``module`` and ``attribute`` are resolved with :func:`importlib.import_module` /
    :func:`getattr` at materialization time; nothing is imported eagerly here so that
    manifest validation stays cheap and side-effect free.
    """

    module: str = Field(min_length=1, max_length=200)
    attribute: str = Field(min_length=1, max_length=200)
    kind: GeneratorKind
    kwargs: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("module")
    @classmethod
    def require_dotted_module(cls, value: str) -> str:
        if not all(part.isidentifier() for part in value.split(".")):
            raise ValueError("generator module must be a dotted Python module path")
        return value

    @field_validator("attribute")
    @classmethod
    def require_identifier_attribute(cls, value: str) -> str:
        if not value.isidentifier():
            raise ValueError("generator attribute must be a Python identifier")
        return value


class EvaluationCase(ContractModel):
    """One controlled, ground-truthed corpus entry."""

    case_id: str = Field(pattern=r"^[A-Z0-9][A-Z0-9_-]{1,63}$")
    category: CaseCategory
    case_class: CaseClass
    description: str = Field(min_length=1, max_length=500)
    filename: str = Field(min_length=1, max_length=255)
    claimed_content_type: str | None = Field(default=None, max_length=255)
    generator: FixtureGenerator
    expected_findings: tuple[str, ...] = Field(default=(), max_length=32)
    acceptable_additional_findings: tuple[str, ...] = Field(default=(), max_length=32)
    allow_any_additional_findings: bool = False
    acceptable_decisions: tuple[Decision, ...] = Field(min_length=1, max_length=4)
    expected_analysis_complete: bool | None = None
    fail_secure: bool = False
    cdr_case: bool = False
    cdr_expected_outcome: CdrExpectedOutcome | None = None
    notes: str = Field(default="", max_length=1_000)

    @field_validator("expected_findings", "acceptable_additional_findings")
    @classmethod
    def require_known_sorted_unique_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(values) - CANONICAL_FINDING_CODES)
        if unknown:
            raise ValueError(f"unknown finding code(s) referenced: {unknown}")
        if tuple(sorted(set(values))) != tuple(values):
            raise ValueError("finding code collections must be sorted and unique")
        return values

    @field_validator("acceptable_decisions", mode="before")
    @classmethod
    def coerce_decision_strings(cls, values: object) -> object:
        if not isinstance(values, list | tuple):
            return values
        return tuple(Decision(item) if isinstance(item, str) else item for item in values)

    @field_validator("acceptable_decisions")
    @classmethod
    def require_sorted_unique_decisions(cls, values: tuple[Decision, ...]) -> tuple[Decision, ...]:
        ordered = tuple(sorted(set(values), key=lambda item: item.value))
        if ordered != values:
            raise ValueError("acceptable decisions must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_case_semantics(self) -> EvaluationCase:
        overlap = set(self.expected_findings) & set(self.acceptable_additional_findings)
        if overlap:
            raise ValueError(
                f"expected and acceptable-additional findings must be disjoint: {sorted(overlap)}"
            )
        if self.allow_any_additional_findings and self.acceptable_additional_findings:
            raise ValueError(
                "allow_any_additional_findings makes an explicit additional-findings list "
                "redundant and contradictory"
            )
        if self.fail_secure:
            if Decision.ALLOW in self.acceptable_decisions:
                raise ValueError("a fail-secure case cannot accept ALLOW as a decision")
            if self.expected_analysis_complete is True:
                raise ValueError("a fail-secure case cannot expect complete analysis")
        if self.cdr_case:
            if self.category not in {CaseCategory.BENIGN_PDF, CaseCategory.RISKY_PDF}:
                raise ValueError("CDR-prepared cases must be PDF cases")
            if self.cdr_expected_outcome is CdrExpectedOutcome.BLOCK_INELIGIBLE and (
                Decision.BLOCK not in self.acceptable_decisions
                or len(self.acceptable_decisions) != 1
            ):
                raise ValueError(
                    "a BLOCK_INELIGIBLE CDR case must accept exactly the BLOCK decision"
                )
        elif self.cdr_expected_outcome is not None:
            raise ValueError("cdr_expected_outcome requires cdr_case to be true")
        return self


class CdrEvaluationOutcome(ContractModel):
    """Prepared for Phase 11B: the CDR-specific slice of one case's outcome.

    Preserves the fields section 19 requires: the immutable original/source decision,
    CDR eligibility, the derived scan's identity and decision, and derived release
    eligibility. Phase 11A never populates this from a real run.
    """

    source_decision: Decision
    source_decision_unchanged: bool
    cdr_eligible: bool
    derived_scan_id: str | None = Field(default=None, max_length=64)
    derived_decision: Decision | None = None
    derived_release_eligible: bool | None = None

    @model_validator(mode="after")
    def validate_derived_shape(self) -> CdrEvaluationOutcome:
        if not self.cdr_eligible and (
            self.derived_scan_id is not None or self.derived_decision is not None
        ):
            raise ValueError("an ineligible case cannot have a derived scan")
        return self


class EvaluationResult(ContractModel):
    """Machine-readable, privacy-safe outcome of running one case through the real pipeline.

    Deliberately excludes document bytes, VBA bodies, raw YARA matched content, session
    tokens, passwords, cookies, and private absolute paths.
    """

    case_id: str = Field(min_length=1, max_length=64)
    category: CaseCategory
    case_class: CaseClass
    expected_findings: tuple[str, ...] = Field(default=())
    actual_findings: tuple[str, ...] = Field(default=())
    missing_expected_findings: tuple[str, ...] = Field(default=())
    unexpected_findings: tuple[str, ...] = Field(default=())
    acceptable_decisions: tuple[Decision, ...] = Field(default=())
    actual_decision: Decision | None = None
    release_eligible: bool | None = None
    analysis_complete: bool | None = None
    worker_status: str | None = Field(default=None, max_length=32)
    completeness_class: AnalysisCompletenessClass | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    decision_compliant: bool | None = None
    findings_recall_pass: bool | None = None
    error: str | None = Field(default=None, max_length=500)
    cdr_outcome: CdrEvaluationOutcome | None = None
    notes: str = Field(default="", max_length=1_000)

    @field_validator("expected_findings", "actual_findings", "missing_expected_findings")
    @classmethod
    def require_known_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(values) - CANONICAL_FINDING_CODES)
        if unknown:
            raise ValueError(f"unknown finding code(s) in result: {unknown}")
        return values


class ReproducibilityMetadata(ContractModel):
    """Privacy-safe identity of the evaluated build, captured once per run.

    Never includes username, home path, temporary absolute paths, passwords, session
    tokens, or environment secrets.
    """

    timestamp: datetime
    git_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{7,40}$")
    corpus_version: str = Field(min_length=1, max_length=32)
    corpus_case_count: int = Field(ge=0)
    policy_version: str = Field(min_length=1, max_length=32)
    policy_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    yara_rule_pack_version: str = Field(min_length=1, max_length=32)
    yara_rule_pack_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sanitizer_version: str = Field(min_length=1, max_length=32)
    sanitizer_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    python_version: str = Field(min_length=1, max_length=32)
    platform: str = Field(min_length=1, max_length=100)
    bubblewrap_version: str | None = Field(default=None, max_length=64)
    qpdf_version: str | None = Field(default=None, max_length=64)
    worker_dependency_versions: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reproducibility timestamp must be timezone-aware")
        return value


class EvaluationRun(ContractModel):
    """The full, deterministic output of one Phase 11B execution."""

    metadata: ReproducibilityMetadata
    results: tuple[EvaluationResult, ...] = Field(default=())


__all__ = [
    "CANONICAL_FINDING_CODES",
    "AnalysisCompletenessClass",
    "CaseCategory",
    "CaseClass",
    "CdrEvaluationOutcome",
    "CdrExpectedOutcome",
    "EvaluationCase",
    "EvaluationResult",
    "EvaluationRun",
    "FixtureGenerator",
    "GeneratorKind",
    "ReproducibilityMetadata",
]
