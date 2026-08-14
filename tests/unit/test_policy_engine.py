from __future__ import annotations

from datetime import UTC, datetime

import pytest

import app.policies.registry as registry_module
from app.core.constants import ANALYSIS_SCHEMA_VERSION, WORKER_VERSION
from app.models.domain import AnalysisResult, AnalysisStatus, Decision, Finding, Severity
from app.policies.engine import evaluate_policy, risk_band_for_score
from app.policies.models import RiskBand
from app.policies.registry import (
    COMPOUND_POLICIES,
    FINDING_POLICIES,
    POLICY_FINGERPRINT,
    PolicyRegistryError,
    compute_policy_fingerprint,
    policy_registry_is_valid,
    validate_policy_registry,
)
from app.policies.version import POLICY_VERSION
from docguard_contract.findings import FINDING_DEFINITIONS
from docguard_contract.yara_rules import (
    YARA_RULE_DEFINITIONS,
    YARA_RULE_PACK_SHA256,
    YARA_RULE_PACK_VERSION,
)


def finding(code: str) -> Finding:
    definition = FINDING_DEFINITIONS[code]
    metadata: dict[str, object] = {}
    mitre = list(definition.mitre_techniques)
    if code in {"YARA_TEST_SIGNATURE", "YARA_HEURISTIC_MATCH"}:
        rule_id = (
            "DOCGUARD_EICAR_TEST"
            if code == "YARA_TEST_SIGNATURE"
            else "DOCGUARD_POWERSHELL_ENCODED"
        )
        rule = YARA_RULE_DEFINITIONS[rule_id]
        metadata = {
            "rule_id": rule.rule_id,
            "rule_title": rule.title,
            "rule_explanation": rule.explanation,
            "rule_category": rule.category,
            "confidence_class": rule.confidence,
            "rule_pack_version": YARA_RULE_PACK_VERSION,
            "rule_pack_sha256": YARA_RULE_PACK_SHA256,
            "scope": "TOP_LEVEL",
            "match_count": 1,
            "string_ids": ["$controlled"],
            "offsets": [0],
        }
        mitre = list(rule.mitre_techniques)
    elif code == "YARA_PARTIAL_ANALYSIS":
        metadata = {
            "reasons": ["internal_timeout"],
            "rule_pack_version": YARA_RULE_PACK_VERSION,
            "rule_pack_sha256": YARA_RULE_PACK_SHA256,
        }
    return Finding(
        code=definition.code,
        title=definition.title,
        description=definition.description,
        category=definition.category,
        severity=Severity(definition.default_severity),
        score_delta=0,
        mitre_techniques=mitre,
        metadata=metadata,
    )


def result(
    *codes: str,
    status: AnalysisStatus = AnalysisStatus.SUCCESS,
    detected_type: str = "PDF",
) -> AnalysisResult:
    now = datetime(2026, 8, 14, tzinfo=UTC)
    return AnalysisResult(
        schema_version=ANALYSIS_SCHEMA_VERSION,
        worker_version=WORKER_VERSION,
        status=status,
        detected_type=detected_type,
        size_bytes=1,
        findings=[finding(code) for code in codes],
        analyzer_metadata={},
        started_at=now,
        completed_at=now,
        duration_ms=0,
    )


def test_registry_exactly_covers_all_findings_and_is_valid() -> None:
    validate_policy_registry()

    assert set(FINDING_POLICIES) == set(FINDING_DEFINITIONS)
    assert len(FINDING_POLICIES) == 43
    assert all(0 <= policy.contribution <= 100 for policy in FINDING_POLICIES.values())
    assert all(
        policy.hard_block == (policy.minimum_decision is Decision.BLOCK)
        for policy in FINDING_POLICIES.values()
    )
    assert policy_registry_is_valid()
    assert "DUMMY_TEST_MARKER" not in FINDING_DEFINITIONS
    assert "DUMMY_TEST_MARKER" not in FINDING_POLICIES


def test_policy_version_and_fingerprint_are_deterministic() -> None:
    assert POLICY_VERSION == "1.0.1"
    assert compute_policy_fingerprint() == POLICY_FINGERPRINT
    assert len(POLICY_FINGERPRINT) == 64


def test_compound_registry_is_unique_and_references_known_findings() -> None:
    names = [compound.name for compound in COMPOUND_POLICIES]

    assert len(names) == len(set(names))
    assert all(
        compound.required_findings <= set(FINDING_DEFINITIONS) for compound in COMPOUND_POLICIES
    )
    assert all(compound.minimum_decision is not Decision.BLOCK for compound in COMPOUND_POLICIES)


def test_missing_policy_mapping_makes_registry_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incomplete = dict(FINDING_POLICIES)
    incomplete.pop("PDF_JAVASCRIPT")
    monkeypatch.setattr(registry_module, "FINDING_POLICIES", incomplete)

    with pytest.raises(PolicyRegistryError, match="coverage"):
        validate_policy_registry()
    assert not policy_registry_is_valid()


def test_empty_complete_supported_analysis_is_allow() -> None:
    evaluation = evaluate_policy(result(detected_type="PDF"))

    assert evaluation.risk_score == 0
    assert evaluation.risk_band is RiskBand.LOW
    assert evaluation.decision is Decision.ALLOW
    assert evaluation.release_eligible
    assert evaluation.analysis_complete


def test_finding_order_and_duplicates_do_not_change_evaluation() -> None:
    evaluated_at = datetime(2026, 8, 14, tzinfo=UTC)
    first = evaluate_policy(
        result("PDF_EXTERNAL_URI", "PDF_JAVASCRIPT", "PDF_JAVASCRIPT"),
        evaluated_at=evaluated_at,
    )
    second = evaluate_policy(
        result("PDF_JAVASCRIPT", "PDF_EXTERNAL_URI"),
        evaluated_at=evaluated_at,
    )

    assert first.risk_score == 28
    assert first.normalized_json() == second.normalized_json()
    assert [item.code for item in first.contributions] == ["PDF_EXTERNAL_URI", "PDF_JAVASCRIPT"]


def test_normalized_evaluation_is_byte_deterministic_without_timestamp() -> None:
    first = evaluate_policy(result("PDF_ACROFORM"))
    second = evaluate_policy(result("PDF_ACROFORM"))

    assert first.normalized_json(include_evaluated_at=False) == second.normalized_json(
        include_evaluated_at=False
    )


@pytest.mark.parametrize(
    ("codes", "expected_decision"),
    [
        ((), Decision.ALLOW),
        (("PDF_JAVASCRIPT",), Decision.REVIEW),
        (("YARA_HEURISTIC_MATCH",), Decision.QUARANTINE),
        (
            (
                "OFFICE_VBA_MACRO",
                "OFFICE_VBA_AUTOEXEC",
                "OFFICE_VBA_EXECUTION_INDICATOR",
                "YARA_HEURISTIC_MATCH",
            ),
            Decision.QUARANTINE,
        ),
    ],
)
def test_score_bands_do_not_create_semantic_block(
    codes: tuple[str, ...], expected_decision: Decision
) -> None:
    detected_type = (
        "OFFICE_WORD_OOXML" if any(code.startswith("OFFICE_") for code in codes) else "PDF"
    )
    evaluation = evaluate_policy(result(*codes, detected_type=detected_type))

    assert evaluation.decision is expected_decision
    assert evaluation.release_eligible is (expected_decision is Decision.ALLOW)
    if evaluation.risk_score == 100:
        assert evaluation.risk_band is RiskBand.CRITICAL
        assert evaluation.decision is not Decision.BLOCK


def test_score_is_clamped_and_risk_bands_are_exact() -> None:
    evaluation = evaluate_policy(
        result(
            "PDF_JAVASCRIPT",
            "PDF_OPEN_ACTION",
            "PDF_LAUNCH_ACTION",
            "PDF_EMBEDDED_FILE",
            "PDF_XFA",
            "YARA_HEURISTIC_MATCH",
        )
    )

    assert evaluation.risk_score == 100
    assert risk_band_for_score(0) is RiskBand.LOW
    assert risk_band_for_score(19) is RiskBand.LOW
    assert risk_band_for_score(20) is RiskBand.MODERATE
    assert risk_band_for_score(40) is RiskBand.HIGH
    assert risk_band_for_score(70) is RiskBand.CRITICAL
    assert risk_band_for_score(100) is RiskBand.CRITICAL


@pytest.mark.parametrize(
    "code",
    [
        "FILE_EXECUTABLE_MASQUERADE",
        "ARCHIVE_PATH_TRAVERSAL",
        "ARCHIVE_ABSOLUTE_PATH",
        "ARCHIVE_SYMLINK",
        "YARA_TEST_SIGNATURE",
    ],
)
def test_semantic_hard_blocks(code: str) -> None:
    detected_type = "ZIP" if code.startswith("ARCHIVE_") else "PDF"
    evaluation = evaluate_policy(result(code, detected_type=detected_type))

    assert evaluation.decision is Decision.BLOCK
    assert evaluation.hard_block_reasons == (code,)
    assert not evaluation.release_eligible


@pytest.mark.parametrize(
    ("code", "status", "detected_type"),
    [
        ("PDF_PARTIAL_ANALYSIS", AnalysisStatus.FAILED, "PDF"),
        ("OFFICE_PARTIAL_ANALYSIS", AnalysisStatus.FAILED, "OFFICE_WORD_OOXML"),
        ("ARCHIVE_PARTIAL_ANALYSIS", AnalysisStatus.FAILED, "ZIP"),
        ("YARA_PARTIAL_ANALYSIS", AnalysisStatus.FAILED, "PDF"),
        ("PDF_MALFORMED", AnalysisStatus.FAILED, "PDF"),
    ],
)
def test_incomplete_and_malformed_results_are_quarantined(
    code: str, status: AnalysisStatus, detected_type: str
) -> None:
    evaluation = evaluate_policy(result(code, status=status, detected_type=detected_type))

    assert evaluation.decision is Decision.QUARANTINE
    assert not evaluation.analysis_complete
    assert not evaluation.release_eligible


def test_unsupported_timeout_missing_and_contradictory_results_fail_closed() -> None:
    unsupported = evaluate_policy(
        result(status=AnalysisStatus.UNSUPPORTED, detected_type="UNKNOWN")
    )
    timeout = evaluate_policy(None, failure_code="timeout")
    contradiction = evaluate_policy(result("PDF_PARTIAL_ANALYSIS", status=AnalysisStatus.SUCCESS))

    for evaluation in (unsupported, timeout, contradiction):
        assert evaluation.decision is Decision.QUARANTINE
        assert not evaluation.analysis_complete
        assert not evaluation.release_eligible
    assert "POLICY_ANALYSIS_CONTRADICTION" in contradiction.mandatory_quarantine_reasons


@pytest.mark.parametrize(
    ("codes", "compound"),
    [
        (("PDF_JAVASCRIPT", "PDF_OPEN_ACTION"), "POLICY_COMPOUND_PDF_AUTO_JS"),
        (
            ("OFFICE_VBA_MACRO", "OFFICE_VBA_AUTOEXEC", "OFFICE_VBA_EXECUTION_INDICATOR"),
            "POLICY_COMPOUND_OFFICE_MACRO_EXECUTION_CHAIN",
        ),
        (
            ("ARCHIVE_DANGEROUS_MEMBER", "ARCHIVE_MEMBER_DOUBLE_EXTENSION"),
            "POLICY_COMPOUND_ARCHIVE_MEMBER_MASQUERADE",
        ),
        (
            ("OFFICE_VBA_AUTOEXEC", "YARA_HEURISTIC_MATCH"),
            "POLICY_COMPOUND_OFFICE_AUTOEXEC_YARA",
        ),
    ],
)
def test_compound_rules_trigger_once(codes: tuple[str, ...], compound: str) -> None:
    if codes[0].startswith("ARCHIVE_"):
        detected_type = "ZIP"
    elif codes[0].startswith("OFFICE_"):
        detected_type = "OFFICE_WORD_OOXML"
    else:
        detected_type = "PDF"
    evaluation = evaluate_policy(result(*codes, *codes, detected_type=detected_type))

    assert compound in evaluation.compound_rules_triggered
    assert [item.code for item in evaluation.contributions].count(compound) == 1
    assert evaluation.decision is Decision.QUARANTINE


def test_heuristic_yara_is_never_automatic_block() -> None:
    evaluation = evaluate_policy(result("YARA_HEURISTIC_MATCH", detected_type="TEXT"))

    assert evaluation.decision is Decision.QUARANTINE
    assert evaluation.hard_block_reasons == ()
