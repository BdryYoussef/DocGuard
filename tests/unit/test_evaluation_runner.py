from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import IsolationBackendName
from app.models.domain import Decision
from evaluation.models import (
    CaseCategory,
    CaseClass,
    EvaluationCase,
    FixtureGenerator,
    GeneratorKind,
)
from evaluation.runner import (
    _infer_completeness_class,
    _result_from_payload,
    dry_run_mode,
    execute_mode,
    list_cases_mode,
    validate_manifest_mode,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _snapshot_var() -> set[str]:
    var = _REPO_ROOT / "var"
    if not var.exists():
        return set()
    return {str(path.relative_to(var)) for path in var.rglob("*")}


def test_validate_manifest_mode_does_not_touch_var() -> None:
    before = _snapshot_var()

    ok, message = validate_manifest_mode()

    assert ok, message
    assert _snapshot_var() == before


def test_dry_run_mode_does_not_touch_var() -> None:
    before = _snapshot_var()

    ok, message = dry_run_mode()

    assert ok, message
    assert _snapshot_var() == before


def test_list_cases_mode_is_sorted_and_non_empty() -> None:
    output = list_cases_mode()
    lines = output.splitlines()

    ids = [line.split()[0] for line in lines]
    assert ids == sorted(ids)
    assert len(ids) >= 45


def test_execute_mode_requires_explicit_case_ids() -> None:
    with pytest.raises(ValueError, match="requires at least one explicit case_id"):
        execute_mode([])


def test_execute_mode_rejects_unknown_case_id() -> None:
    with pytest.raises(ValueError, match="unknown case_id"):
        execute_mode(["NOT-A-REAL-CASE"])


def test_execute_mode_runs_a_small_smoke_set_through_the_real_pipeline() -> None:
    """A deliberately tiny (2-case) smoke run — not the full corpus — proving the
    execute path reaches the real create_app + policy-engine pipeline and produces a
    correctly shaped, ground-truth-matching result. Uses the unsafe-development
    isolation backend purely for test speed/portability; production-path Bubblewrap
    execution was verified manually per the Phase 11A completion report."""
    run = execute_mode(
        ["PDF-BEN-001", "PDF-RISK-011"],
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
    )

    by_id = {result.case_id: result for result in run.results}
    assert by_id["PDF-BEN-001"].actual_decision is Decision.ALLOW
    assert by_id["PDF-BEN-001"].decision_compliant is True
    assert by_id["PDF-RISK-011"].actual_decision is Decision.QUARANTINE
    assert by_id["PDF-RISK-011"].release_eligible is False
    assert by_id["PDF-RISK-011"].analysis_complete is False
    assert run.metadata.corpus_case_count >= 45


def _generator() -> FixtureGenerator:
    return FixtureGenerator(
        module="tests.fixtures.pdf_factory",
        attribute="write_benign_pdf",
        kind=GeneratorKind.WRITE_PATH,
    )


def test_result_from_payload_treats_acceptable_additional_findings_as_expected() -> None:
    case = EvaluationCase(
        case_id="TEST-001",
        category=CaseCategory.FILE_IDENTITY,
        case_class=CaseClass.RISKY,
        description="fixture",
        filename="fixture.pdf",
        generator=_generator(),
        expected_findings=("FILE_TYPE_MISMATCH",),
        acceptable_additional_findings=("FILE_CLIENT_MIME_MISMATCH",),
        acceptable_decisions=(Decision.REVIEW,),
    )
    payload = {
        "decision": "REVIEW",
        "release_eligible": False,
        "analysis_complete": True,
        "analysis_status": "SUCCESS",
        "findings": [
            {"code": "FILE_TYPE_MISMATCH"},
            {"code": "FILE_CLIENT_MIME_MISMATCH"},
        ],
    }

    result = _result_from_payload(case, payload, latency_ms=10)

    assert result.unexpected_findings == ()
    assert result.missing_expected_findings == ()


def test_result_from_payload_flags_truly_unexpected_findings() -> None:
    case = EvaluationCase(
        case_id="TEST-002",
        category=CaseCategory.FILE_IDENTITY,
        case_class=CaseClass.RISKY,
        description="fixture",
        filename="fixture.pdf",
        generator=_generator(),
        expected_findings=("FILE_TYPE_MISMATCH",),
        acceptable_decisions=(Decision.QUARANTINE, Decision.REVIEW),
    )
    payload = {
        "decision": "QUARANTINE",
        "release_eligible": False,
        "analysis_complete": True,
        "analysis_status": "SUCCESS",
        "findings": [
            {"code": "FILE_TYPE_MISMATCH"},
            {"code": "FILE_DOUBLE_EXTENSION"},
        ],
    }

    result = _result_from_payload(case, payload, latency_ms=10)

    assert result.unexpected_findings == ("FILE_DOUBLE_EXTENSION",)


def test_result_from_payload_allow_any_additional_suppresses_unexpected() -> None:
    case = EvaluationCase(
        case_id="TEST-003",
        category=CaseCategory.FILE_IDENTITY,
        case_class=CaseClass.RISKY,
        description="fixture",
        filename="fixture.pdf",
        generator=_generator(),
        expected_findings=("FILE_DOUBLE_EXTENSION",),
        allow_any_additional_findings=True,
        acceptable_decisions=(Decision.QUARANTINE, Decision.REVIEW),
    )
    payload = {
        "decision": "QUARANTINE",
        "release_eligible": False,
        "analysis_complete": True,
        "analysis_status": "SUCCESS",
        "findings": [
            {"code": "FILE_DOUBLE_EXTENSION"},
            {"code": "FILE_TYPE_MISMATCH"},
        ],
    }

    result = _result_from_payload(case, payload, latency_ms=10)

    assert result.unexpected_findings == ()


@pytest.mark.parametrize(
    ("analysis_complete", "worker_status", "codes", "expected"),
    [
        (True, "SUCCESS", (), "COMPLETE"),
        (None, "SUCCESS", (), None),
        (False, "TIMEOUT", (), "TIMEOUT"),
        (False, "FAILED", ("PDF_MALFORMED",), "PARSER_FAILURE"),
        (False, "FAILED", ("ARCHIVE_RESOURCE_LIMIT",), "RESOURCE_LIMIT_FAILURE"),
        (False, "FAILED", ("PDF_ENCRYPTED", "PDF_PARTIAL_ANALYSIS"), "INTENTIONAL_PARTIAL"),
        (False, "FAILED", (), "OTHER_FAIL_CLOSED"),
    ],
)
def test_infer_completeness_class(
    analysis_complete: object, worker_status: str, codes: tuple[str, ...], expected: str | None
) -> None:
    result = _infer_completeness_class(analysis_complete, worker_status, codes)

    assert (result.value if result is not None else None) == expected
