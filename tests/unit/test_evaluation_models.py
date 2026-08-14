from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.domain import Decision
from evaluation.models import (
    CaseCategory,
    CaseClass,
    CdrExpectedOutcome,
    EvaluationCase,
    EvaluationResult,
    FixtureGenerator,
    GeneratorKind,
    ReproducibilityMetadata,
)


def _generator() -> FixtureGenerator:
    return FixtureGenerator(
        module="tests.fixtures.pdf_factory",
        attribute="write_benign_pdf",
        kind=GeneratorKind.WRITE_PATH,
    )


def _case(**overrides: object) -> EvaluationCase:
    fields: dict[str, object] = {
        "case_id": "TEST-001",
        "category": CaseCategory.BENIGN_PDF,
        "case_class": CaseClass.BENIGN,
        "description": "a controlled fixture case",
        "filename": "fixture.pdf",
        "generator": _generator(),
        "acceptable_decisions": ("ALLOW",),
    }
    fields.update(overrides)
    return EvaluationCase(**fields)  # type: ignore[arg-type]


def test_valid_case_constructs() -> None:
    case = _case()
    assert case.acceptable_decisions == (Decision.ALLOW,)


def test_unknown_finding_code_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unknown finding code"):
        _case(expected_findings=("NOT_A_REAL_FINDING_CODE",))


def test_unsorted_finding_codes_are_rejected() -> None:
    with pytest.raises(ValidationError, match="sorted and unique"):
        _case(expected_findings=("PDF_OPEN_ACTION", "PDF_ACROFORM"))


def test_overlapping_expected_and_additional_findings_are_rejected() -> None:
    with pytest.raises(ValidationError, match="disjoint"):
        _case(
            expected_findings=("PDF_ACROFORM",),
            acceptable_additional_findings=("PDF_ACROFORM",),
        )


def test_fail_secure_case_cannot_accept_allow() -> None:
    with pytest.raises(ValidationError, match="fail-secure case cannot accept ALLOW"):
        _case(fail_secure=True, acceptable_decisions=("ALLOW",))


def test_fail_secure_case_cannot_expect_complete_analysis() -> None:
    with pytest.raises(ValidationError, match="cannot expect complete analysis"):
        _case(
            fail_secure=True,
            acceptable_decisions=("QUARANTINE",),
            expected_analysis_complete=True,
        )


def test_cdr_case_must_be_a_pdf_category() -> None:
    with pytest.raises(ValidationError, match="CDR-prepared cases must be PDF cases"):
        _case(category=CaseCategory.BENIGN_OFFICE, cdr_case=True)


def test_cdr_expected_outcome_requires_cdr_case() -> None:
    with pytest.raises(ValidationError, match="requires cdr_case"):
        _case(cdr_case=False, cdr_expected_outcome=CdrExpectedOutcome.BLOCK_INELIGIBLE)


def test_allow_any_additional_findings_conflicts_with_explicit_list() -> None:
    with pytest.raises(ValidationError, match="redundant and contradictory"):
        _case(
            allow_any_additional_findings=True,
            acceptable_additional_findings=("PDF_ACROFORM",),
        )


def test_evaluation_result_round_trips_through_json() -> None:
    result = EvaluationResult(
        case_id="TEST-001",
        category=CaseCategory.BENIGN_PDF,
        case_class=CaseClass.BENIGN,
        expected_findings=(),
        actual_findings=(),
        acceptable_decisions=(Decision.ALLOW,),
        actual_decision=Decision.ALLOW,
        release_eligible=True,
        analysis_complete=True,
        worker_status="SUCCESS",
        latency_ms=42,
        decision_compliant=True,
        findings_recall_pass=True,
    )
    restored = EvaluationResult.model_validate_json(result.to_json())
    assert restored == result


def test_evaluation_result_rejects_unknown_finding_code() -> None:
    with pytest.raises(ValidationError, match="unknown finding code"):
        EvaluationResult(
            case_id="TEST-001",
            category=CaseCategory.BENIGN_PDF,
            case_class=CaseClass.BENIGN,
            actual_findings=("NOT_A_REAL_CODE",),
            acceptable_decisions=(Decision.ALLOW,),
        )


def test_reproducibility_metadata_requires_aware_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        ReproducibilityMetadata(
            timestamp=datetime.now(),
            corpus_version="11A.1",
            corpus_case_count=1,
            policy_version="1.0.1",
            policy_fingerprint="0" * 64,
            yara_rule_pack_version="2026.08.1",
            yara_rule_pack_sha256="0" * 64,
            sanitizer_version="1.0.0",
            sanitizer_fingerprint="0" * 64,
            python_version="3.12.0",
            platform="Linux-x86_64",
        )


def test_reproducibility_metadata_serializes_without_secrets() -> None:
    metadata = ReproducibilityMetadata(
        timestamp=datetime.now(UTC),
        corpus_version="11A.1",
        corpus_case_count=59,
        policy_version="1.0.1",
        policy_fingerprint="0" * 64,
        yara_rule_pack_version="2026.08.1",
        yara_rule_pack_sha256="0" * 64,
        sanitizer_version="1.0.0",
        sanitizer_fingerprint="0" * 64,
        python_version="3.12.0",
        platform="Linux-x86_64",
    )
    payload = json.loads(metadata.to_json())
    assert "username" not in payload
    assert "home" not in json.dumps(payload).lower()
