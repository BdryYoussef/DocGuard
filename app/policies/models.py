"""Strongly typed, bounded output from the trusted policy engine."""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.domain import Decision


class RiskBand(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PolicyContribution(PolicyModel):
    code: str = Field(min_length=1, max_length=128)
    contribution: int = Field(ge=0, le=100)
    explanation: str = Field(min_length=1, max_length=500)


class PolicyReason(PolicyModel):
    code: str = Field(min_length=1, max_length=128)
    explanation: str = Field(min_length=1, max_length=500)


class PolicyEvaluation(PolicyModel):
    policy_version: str = Field(min_length=1, max_length=32)
    policy_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    risk_score: int = Field(ge=0, le=100)
    risk_band: RiskBand
    decision: Decision
    release_eligible: bool
    analysis_complete: bool
    hard_block_reasons: tuple[str, ...] = Field(default=(), max_length=16)
    mandatory_quarantine_reasons: tuple[str, ...] = Field(default=(), max_length=32)
    compound_rules_triggered: tuple[str, ...] = Field(default=(), max_length=16)
    decision_reasons: tuple[PolicyReason, ...] = Field(default=(), max_length=64)
    contributions: tuple[PolicyContribution, ...] = Field(default=(), max_length=64)
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("policy evaluation timestamp must be timezone-aware")
        return value

    @field_validator(
        "hard_block_reasons",
        "mandatory_quarantine_reasons",
        "compound_rules_triggered",
    )
    @classmethod
    def require_sorted_unique_codes(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("policy reason codes must be sorted and unique")
        return values

    @model_validator(mode="after")
    def validate_release_semantics(self) -> PolicyEvaluation:
        if self.release_eligible is not (self.decision is Decision.ALLOW):
            raise ValueError("release eligibility must be true only for ALLOW")
        if self.hard_block_reasons and self.decision is not Decision.BLOCK:
            raise ValueError("hard-block reasons require BLOCK")
        if self.decision is Decision.ALLOW and not self.analysis_complete:
            raise ValueError("incomplete analysis cannot be ALLOW")
        return self

    def normalized_json(self, *, include_evaluated_at: bool = True) -> str:
        excluded = set() if include_evaluated_at else {"evaluated_at"}
        return json.dumps(
            self.model_dump(mode="json", exclude=excluded),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )


__all__ = [
    "PolicyContribution",
    "PolicyEvaluation",
    "PolicyReason",
    "RiskBand",
]
