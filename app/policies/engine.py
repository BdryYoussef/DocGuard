"""Deterministic trusted policy evaluation over validated worker observations."""

from __future__ import annotations

from datetime import UTC, datetime

from app.models.domain import AnalysisResult, AnalysisStatus, Decision, ScanState
from app.policies.models import (
    PolicyContribution,
    PolicyEvaluation,
    PolicyReason,
    RiskBand,
)
from app.policies.registry import (
    COMPOUND_POLICIES,
    FINDING_POLICIES,
    POLICY_FINGERPRINT,
    validate_policy_registry,
)
from app.policies.version import POLICY_VERSION

_SUPPORTED_RELEASE_TYPES = frozenset(
    {
        "PDF",
        "ZIP",
        "TEXT",
        "OFFICE_WORD_OOXML",
        "OFFICE_EXCEL_OOXML",
        "OFFICE_POWERPOINT_OOXML",
        "OFFICE_WORD_OLE",
        "OFFICE_EXCEL_OLE",
        "OFFICE_POWERPOINT_OLE",
    }
)

_ANALYSIS_REASON_EXPLANATIONS = {
    "POLICY_ANALYSIS_RESULT_MISSING": "No validated worker result was available.",
    "POLICY_ANALYSIS_STATUS_FAILED": "The worker reported failed analysis.",
    "POLICY_ANALYSIS_STATUS_TIMEOUT": "The trusted parent terminated analysis on timeout.",
    "POLICY_ANALYSIS_STATUS_UNSUPPORTED": "The submitted content was unsupported.",
    "POLICY_ANALYSIS_FAILURE": "Trusted orchestration reported an analysis failure.",
    "POLICY_LIFECYCLE_INCONSISTENCY": "The scan lifecycle was not valid for policy evaluation.",
    "POLICY_UNSUPPORTED_DETECTED_TYPE": "The observed content family is not release-supported.",
    "POLICY_ANALYSIS_CONTRADICTION": (
        "The worker status conflicts with a finding that reports incomplete analysis."
    ),
    "POLICY_EVALUATION_FAILURE": "The trusted policy engine failed; release remains prohibited.",
}


class PolicyEvaluationError(RuntimeError):
    """A validated result could not be evaluated safely."""


def risk_band_for_score(score: int) -> RiskBand:
    if not 0 <= score <= 100:
        raise ValueError("risk score must be within 0-100")
    if score >= 70:
        return RiskBand.CRITICAL
    if score >= 40:
        return RiskBand.HIGH
    if score >= 20:
        return RiskBand.MODERATE
    return RiskBand.LOW


def evaluate_policy(
    result: AnalysisResult | None,
    *,
    failure_code: str | None = None,
    scan_state: ScanState = ScanState.ANALYZING,
    evaluated_at: datetime | None = None,
) -> PolicyEvaluation:
    validate_policy_registry()
    finding_codes = sorted({finding.code for finding in result.findings}) if result else []
    unknown_codes = set(finding_codes) - set(FINDING_POLICIES)
    if unknown_codes:
        raise PolicyEvaluationError("validated findings lack trusted policy definitions")

    contributions = [
        PolicyContribution(
            code=code,
            contribution=FINDING_POLICIES[code].contribution,
            explanation=FINDING_POLICIES[code].explanation,
        )
        for code in finding_codes
    ]
    present = set(finding_codes)
    triggered_compounds = [
        compound for compound in COMPOUND_POLICIES if compound.required_findings <= present
    ]
    contributions.extend(
        PolicyContribution(
            code=compound.name,
            contribution=compound.contribution,
            explanation=compound.explanation,
        )
        for compound in triggered_compounds
    )
    contributions.sort(key=lambda item: item.code)
    risk_score = min(100, sum(item.contribution for item in contributions))
    risk_band = risk_band_for_score(risk_score)

    hard_block_reasons = sorted(code for code in finding_codes if FINDING_POLICIES[code].hard_block)
    mandatory_reasons = {
        code
        for code in finding_codes
        if FINDING_POLICIES[code].minimum_decision is Decision.QUARANTINE
    }
    mandatory_reasons.update(
        compound.name
        for compound in triggered_compounds
        if compound.minimum_decision is Decision.QUARANTINE
    )

    completeness_reasons = _completeness_reasons(
        result,
        failure_code=failure_code,
        scan_state=scan_state,
        finding_codes=present,
    )
    mandatory_reasons.update(completeness_reasons)
    analysis_complete = not completeness_reasons

    if hard_block_reasons:
        decision = Decision.BLOCK
    elif mandatory_reasons or risk_score >= 40:
        decision = Decision.QUARANTINE
    elif risk_score >= 20:
        decision = Decision.REVIEW
    else:
        decision = Decision.ALLOW

    reasons = _decision_reasons(
        finding_codes,
        triggered_compounds=[compound.name for compound in triggered_compounds],
        completeness_reasons=completeness_reasons,
    )
    return PolicyEvaluation(
        policy_version=POLICY_VERSION,
        policy_fingerprint=POLICY_FINGERPRINT,
        risk_score=risk_score,
        risk_band=risk_band,
        decision=decision,
        release_eligible=decision is Decision.ALLOW,
        analysis_complete=analysis_complete,
        hard_block_reasons=tuple(hard_block_reasons),
        mandatory_quarantine_reasons=tuple(sorted(mandatory_reasons)),
        compound_rules_triggered=tuple(sorted(compound.name for compound in triggered_compounds)),
        decision_reasons=tuple(reasons),
        contributions=tuple(contributions),
        evaluated_at=evaluated_at or datetime.now(UTC),
    )


def fail_closed_policy_evaluation(*, evaluated_at: datetime | None = None) -> PolicyEvaluation:
    reason = PolicyReason(
        code="POLICY_EVALUATION_FAILURE",
        explanation=_ANALYSIS_REASON_EXPLANATIONS["POLICY_EVALUATION_FAILURE"],
    )
    return PolicyEvaluation(
        policy_version=POLICY_VERSION,
        policy_fingerprint=POLICY_FINGERPRINT,
        risk_score=0,
        risk_band=RiskBand.LOW,
        decision=Decision.QUARANTINE,
        release_eligible=False,
        analysis_complete=False,
        mandatory_quarantine_reasons=("POLICY_EVALUATION_FAILURE",),
        decision_reasons=(reason,),
        evaluated_at=evaluated_at or datetime.now(UTC),
    )


def _completeness_reasons(
    result: AnalysisResult | None,
    *,
    failure_code: str | None,
    scan_state: ScanState,
    finding_codes: set[str],
) -> set[str]:
    reasons: set[str] = set()
    if result is None:
        reasons.add("POLICY_ANALYSIS_RESULT_MISSING")
    else:
        status_reasons = {
            AnalysisStatus.FAILED: "POLICY_ANALYSIS_STATUS_FAILED",
            AnalysisStatus.TIMEOUT: "POLICY_ANALYSIS_STATUS_TIMEOUT",
            AnalysisStatus.UNSUPPORTED: "POLICY_ANALYSIS_STATUS_UNSUPPORTED",
        }
        if result.status is not AnalysisStatus.SUCCESS:
            reasons.add(status_reasons[result.status])
        if result.detected_type not in _SUPPORTED_RELEASE_TYPES:
            reasons.add("POLICY_UNSUPPORTED_DETECTED_TYPE")
        partial_codes = {
            code
            for code in finding_codes
            if code.endswith("_PARTIAL_ANALYSIS") or code.endswith("_MALFORMED")
        }
        if result.status is AnalysisStatus.SUCCESS and partial_codes:
            reasons.add("POLICY_ANALYSIS_CONTRADICTION")
    if failure_code is not None:
        reasons.add("POLICY_ANALYSIS_FAILURE")
    if scan_state not in {ScanState.ANALYZING, ScanState.COMPLETED}:
        reasons.add("POLICY_LIFECYCLE_INCONSISTENCY")
    return reasons


def _decision_reasons(
    finding_codes: list[str],
    *,
    triggered_compounds: list[str],
    completeness_reasons: set[str],
) -> list[PolicyReason]:
    reasons = [
        PolicyReason(code=code, explanation=FINDING_POLICIES[code].explanation)
        for code in finding_codes
    ]
    compound_by_name = {compound.name: compound for compound in COMPOUND_POLICIES}
    reasons.extend(
        PolicyReason(code=name, explanation=compound_by_name[name].explanation)
        for name in triggered_compounds
    )
    reasons.extend(
        PolicyReason(code=code, explanation=_ANALYSIS_REASON_EXPLANATIONS[code])
        for code in completeness_reasons
    )
    return sorted(reasons, key=lambda item: item.code)


__all__ = [
    "PolicyEvaluationError",
    "evaluate_policy",
    "fail_closed_policy_evaluation",
    "risk_band_for_score",
]
