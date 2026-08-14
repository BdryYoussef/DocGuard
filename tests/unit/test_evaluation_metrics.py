from __future__ import annotations

from app.models.domain import Decision
from evaluation.metrics import (
    benign_allow_rate,
    benign_escalation_rate,
    cdr_recovery_rate,
    completeness_counts,
    decision_compliance_rate,
    fail_secure_rate,
    finding_level_recall,
    latency_stats,
    risky_case_detection_recall,
)
from evaluation.models import (
    AnalysisCompletenessClass,
    CaseCategory,
    CaseClass,
    CdrEvaluationOutcome,
    EvaluationCase,
    EvaluationResult,
    FixtureGenerator,
    GeneratorKind,
)


def _generator() -> FixtureGenerator:
    return FixtureGenerator(
        module="tests.fixtures.pdf_factory",
        attribute="write_benign_pdf",
        kind=GeneratorKind.WRITE_PATH,
    )


def _case(case_id: str, **overrides: object) -> EvaluationCase:
    fields: dict[str, object] = {
        "case_id": case_id,
        "category": CaseCategory.RISKY_PDF,
        "case_class": CaseClass.RISKY,
        "description": "fixture",
        "filename": "fixture.pdf",
        "generator": _generator(),
        "expected_findings": ("PDF_ACROFORM",),
        "acceptable_decisions": ("ALLOW",),
    }
    fields.update(overrides)
    return EvaluationCase(**fields)  # type: ignore[arg-type]


def _result(case: EvaluationCase, **overrides: object) -> EvaluationResult:
    fields: dict[str, object] = {
        "case_id": case.case_id,
        "category": case.category,
        "case_class": case.case_class,
        "expected_findings": case.expected_findings,
        "actual_findings": case.expected_findings,
        "acceptable_decisions": case.acceptable_decisions,
        "actual_decision": case.acceptable_decisions[0],
        "release_eligible": case.acceptable_decisions[0] is Decision.ALLOW,
    }
    fields.update(overrides)
    return EvaluationResult(**fields)  # type: ignore[arg-type]


def test_risky_case_detection_recall_counts_full_matches() -> None:
    hit = _case("HIT-001")
    miss = _case("MISS-001")
    results = [
        _result(hit),
        _result(miss, actual_findings=(), missing_expected_findings=("PDF_ACROFORM",)),
    ]

    rate = risky_case_detection_recall([hit, miss], results)

    assert rate.numerator == 1
    assert rate.denominator == 2
    assert rate.value == 0.5


def test_risky_case_detection_recall_excludes_benign_and_empty_expected() -> None:
    benign = _case("BEN-001", case_class=CaseClass.BENIGN, expected_findings=())
    empty_risky = _case("RISK-EMPTY", expected_findings=())
    results = [_result(benign, actual_findings=()), _result(empty_risky, actual_findings=())]

    rate = risky_case_detection_recall([benign, empty_risky], results)

    assert rate.denominator == 0
    assert rate.value is None


def test_finding_level_recall_counts_individual_findings() -> None:
    case = _case("CASE-001", expected_findings=("PDF_ACROFORM", "PDF_EXTERNAL_URI"))
    result = _result(case, actual_findings=("PDF_ACROFORM",))

    rate = finding_level_recall([case], [result])

    assert rate.numerator == 1
    assert rate.denominator == 2
    assert rate.value == 0.5


def test_missing_expected_findings_reduce_recall() -> None:
    case = _case("CASE-001", expected_findings=("PDF_ACROFORM",))
    result = _result(case, actual_findings=(), missing_expected_findings=("PDF_ACROFORM",))

    rate = finding_level_recall([case], [result])

    assert rate.value == 0.0


def test_benign_escalation_rate() -> None:
    allowed = _case("BEN-001", case_class=CaseClass.BENIGN, expected_findings=())
    escalated = _case("BEN-002", case_class=CaseClass.BENIGN, expected_findings=())
    results = [
        _result(allowed, actual_findings=(), actual_decision=Decision.ALLOW),
        _result(escalated, actual_findings=(), actual_decision=Decision.REVIEW),
    ]

    rate = benign_escalation_rate([allowed, escalated], results)

    assert rate.numerator == 1
    assert rate.denominator == 2
    assert rate.value == 0.5


def test_benign_allow_rate_is_complementary_view() -> None:
    allowed = _case("BEN-001", case_class=CaseClass.BENIGN, expected_findings=())
    escalated = _case("BEN-002", case_class=CaseClass.BENIGN, expected_findings=())
    results = [
        _result(allowed, actual_findings=(), actual_decision=Decision.ALLOW),
        _result(escalated, actual_findings=(), actual_decision=Decision.REVIEW),
    ]

    rate = benign_allow_rate([allowed, escalated], results)

    assert rate.numerator == 1
    assert rate.denominator == 2
    assert rate.value == 0.5


def test_decision_compliance_uses_per_case_acceptable_set_not_ordering() -> None:
    # QUARANTINE would fail a naive "escalation is always fine" rule, but here it is one
    # of two explicitly acceptable outcomes, so it must count as compliant.
    ambiguous = _case(
        "AMBIG-001", acceptable_decisions=("QUARANTINE", "REVIEW"), expected_findings=()
    )
    unexpected_block = _case("BLOCK-001", acceptable_decisions=("ALLOW",), expected_findings=())
    results = [
        _result(ambiguous, actual_findings=(), actual_decision=Decision.QUARANTINE),
        _result(unexpected_block, actual_findings=(), actual_decision=Decision.BLOCK),
    ]

    rate = decision_compliance_rate([ambiguous, unexpected_block], results)

    assert rate.numerator == 1
    assert rate.denominator == 2


def test_fail_secure_rate_requires_explicit_false_release_eligible() -> None:
    contained = _case(
        "FS-001", fail_secure=True, acceptable_decisions=("QUARANTINE",), expected_findings=()
    )
    leaked = _case(
        "FS-002", fail_secure=True, acceptable_decisions=("QUARANTINE",), expected_findings=()
    )
    unknown = _case(
        "FS-003", fail_secure=True, acceptable_decisions=("QUARANTINE",), expected_findings=()
    )
    results = [
        _result(
            contained,
            actual_findings=(),
            actual_decision=Decision.QUARANTINE,
            release_eligible=False,
        ),
        _result(
            leaked, actual_findings=(), actual_decision=Decision.QUARANTINE, release_eligible=True
        ),
        _result(
            unknown, actual_findings=(), actual_decision=Decision.QUARANTINE, release_eligible=None
        ),
    ]

    rate = fail_secure_rate([contained, leaked, unknown], results)

    assert rate.numerator == 1
    assert rate.denominator == 3


def test_zero_denominator_metrics_return_none_not_zero_or_one() -> None:
    assert risky_case_detection_recall([], []).value is None
    assert finding_level_recall([], []).value is None
    assert benign_escalation_rate([], []).value is None
    assert benign_allow_rate([], []).value is None
    assert decision_compliance_rate([], []).value is None
    assert fail_secure_rate([], []).value is None
    assert cdr_recovery_rate([]).value is None


def test_completeness_counts_buckets_by_class() -> None:
    case = _case("CASE-001", expected_findings=())
    results = [
        _result(case, actual_findings=(), completeness_class=AnalysisCompletenessClass.COMPLETE),
        _result(
            case,
            actual_findings=(),
            completeness_class=AnalysisCompletenessClass.INTENTIONAL_PARTIAL,
        ),
        _result(case, actual_findings=()),  # no completeness_class recorded
    ]

    counts = completeness_counts(results)

    assert counts["COMPLETE"] == 1
    assert counts["INTENTIONAL_PARTIAL"] == 1
    assert counts["UNKNOWN"] == 1


def test_cdr_recovery_rate_only_counts_eligible_attempts() -> None:
    case = _case("CASE-001", cdr_case=True, expected_findings=())
    eligible_recovered = _result(
        case,
        actual_findings=(),
        cdr_outcome=CdrEvaluationOutcome(
            source_decision=Decision.QUARANTINE,
            source_decision_unchanged=True,
            cdr_eligible=True,
            derived_scan_id="a" * 32,
            derived_decision=Decision.ALLOW,
            derived_release_eligible=True,
        ),
    )
    eligible_not_recovered = _result(
        case,
        actual_findings=(),
        cdr_outcome=CdrEvaluationOutcome(
            source_decision=Decision.QUARANTINE,
            source_decision_unchanged=True,
            cdr_eligible=True,
            derived_scan_id="b" * 32,
            derived_decision=Decision.QUARANTINE,
            derived_release_eligible=False,
        ),
    )
    ineligible = _result(
        case,
        actual_findings=(),
        cdr_outcome=CdrEvaluationOutcome(
            source_decision=Decision.BLOCK,
            source_decision_unchanged=True,
            cdr_eligible=False,
        ),
    )

    rate = cdr_recovery_rate([eligible_recovered, eligible_not_recovered, ineligible])

    assert rate.numerator == 1
    assert rate.denominator == 2


def test_latency_stats_are_deterministic() -> None:
    case = _case("CASE-001", expected_findings=())
    results = [
        _result(case, actual_findings=(), latency_ms=value) for value in (100, 200, 300, 400, 500)
    ]

    stats = latency_stats(results)

    assert stats.count == 5
    assert stats.min_ms == 100
    assert stats.max_ms == 500
    assert stats.median_ms == 300
    assert stats.mean_ms == 300.0
    assert stats.p95_ms == 500


def test_latency_stats_empty_returns_none_fields() -> None:
    stats = latency_stats([])

    assert stats.count == 0
    assert stats.mean_ms is None
    assert stats.p95_ms is None
