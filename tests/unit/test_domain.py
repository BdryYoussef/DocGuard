from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.core.constants import ANALYSIS_SCHEMA_VERSION
from app.models.domain import AnalysisResult, Decision, Finding, Severity
from docguard_contract import MAX_ANALYZER_METADATA_BYTES, MAX_FINDING_METADATA_BYTES
from docguard_contract.findings import FINDING_DEFINITIONS
from docguard_contract.yara_rules import (
    YARA_RULE_DEFINITIONS,
    YARA_RULE_PACK_SHA256,
    YARA_RULE_PACK_VERSION,
)


def test_finding_serialization_and_validation() -> None:
    definition = FINDING_DEFINITIONS["PDF_JAVASCRIPT"]
    finding = Finding(
        code=definition.code,
        title=definition.title,
        description=definition.description,
        category=definition.category,
        severity=Severity(definition.default_severity),
        score_delta=0,
        mitre_techniques=list(definition.mitre_techniques),
        metadata={"nested": {"enabled": True}, "count": 1},
    )

    assert json.loads(finding.to_json())["code"] == "PDF_JAVASCRIPT"
    assert finding.to_json() == finding.to_json()


def test_finding_rejects_non_json_metadata() -> None:
    definition = FINDING_DEFINITIONS["PDF_JAVASCRIPT"]
    with pytest.raises(ValidationError):
        Finding(
            code=definition.code,
            title=definition.title,
            description=definition.description,
            category=definition.category,
            severity=Severity(definition.default_severity),
            score_delta=0,
            metadata={"invalid": object()},
        )


def test_analysis_result_round_trip(valid_analysis_result: AnalysisResult) -> None:
    serialized = valid_analysis_result.to_json()
    parsed = AnalysisResult.model_validate_json(serialized)

    assert parsed == valid_analysis_result
    assert serialized == parsed.to_json()


@pytest.mark.parametrize(
    ("model", "field", "value"),
    [
        (Finding, "severity", "EXTREME"),
        (AnalysisResult, "status", "CLEAN"),
    ],
)
def test_unknown_enum_values_rejected(
    model: type[Finding] | type[AnalysisResult], field: str, value: str
) -> None:
    if model is Finding:
        definition = FINDING_DEFINITIONS["PDF_JAVASCRIPT"]
        payload: dict[str, object] = {
            "code": definition.code,
            "title": definition.title,
            "description": definition.description,
            "category": definition.category,
            "severity": value,
            "score_delta": 0,
        }
    else:
        now = datetime.now(UTC).isoformat()
        payload = {
            "schema_version": ANALYSIS_SCHEMA_VERSION,
            "worker_version": "test",
            "status": value,
            "detected_type": None,
            "size_bytes": 0,
            "findings": [],
            "analyzer_metadata": {},
            "started_at": now,
            "completed_at": now,
            "duration_ms": 0,
        }

    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_decision_rejects_unknown_value() -> None:
    with pytest.raises(ValueError):
        Decision("CLEAN")


def test_analysis_result_rejects_naive_timestamps() -> None:
    with pytest.raises(ValidationError):
        AnalysisResult(
            schema_version=ANALYSIS_SCHEMA_VERSION,
            worker_version="test",
            status="SUCCESS",  # type: ignore[arg-type]
            detected_type=None,
            size_bytes=0,
            started_at=datetime.now(),
            completed_at=datetime.now(),
            duration_ms=0,
        )


def test_finding_rejects_unregistered_or_spoofed_product_metadata() -> None:
    definition = FINDING_DEFINITIONS["PDF_JAVASCRIPT"]
    payload = {
        "code": definition.code,
        "title": "Spoofed title",
        "description": definition.description,
        "category": definition.category,
        "severity": Severity(definition.default_severity),
        "score_delta": 0,
        "mitre_techniques": list(definition.mitre_techniques),
    }

    with pytest.raises(ValidationError, match="does not match registry"):
        Finding.model_validate(payload)
    payload["code"] = "PDF_UNKNOWN_CAPABILITY"
    with pytest.raises(ValidationError, match="unregistered finding code"):
        Finding.model_validate(payload)


def test_worker_cannot_supply_policy_score() -> None:
    definition = FINDING_DEFINITIONS["PDF_JAVASCRIPT"]
    payload = {
        "code": definition.code,
        "title": definition.title,
        "description": definition.description,
        "category": definition.category,
        "severity": Severity(definition.default_severity),
        "score_delta": 99,
        "mitre_techniques": list(definition.mitre_techniques),
        "metadata": {},
    }

    with pytest.raises(ValidationError, match="cannot supply policy score"):
        Finding.model_validate(payload)


def test_office_finding_definition_cannot_be_spoofed() -> None:
    definition = FINDING_DEFINITIONS["OFFICE_VBA_AUTOEXEC"]
    payload = {
        "code": definition.code,
        "title": definition.title,
        "description": definition.description,
        "category": definition.category,
        "severity": Severity.LOW,
        "score_delta": 0,
        "mitre_techniques": list(definition.mitre_techniques),
        "metadata": {"triggers": ["AutoOpen"]},
    }

    with pytest.raises(ValidationError, match="does not match registry"):
        Finding.model_validate(payload)


def test_archive_finding_definition_cannot_be_spoofed() -> None:
    definition = FINDING_DEFINITIONS["ARCHIVE_RESOURCE_LIMIT"]
    payload = {
        "code": definition.code,
        "title": definition.title,
        "description": definition.description,
        "category": definition.category,
        "severity": Severity.LOW,
        "score_delta": 0,
        "mitre_techniques": list(definition.mitre_techniques),
        "metadata": {"reasons": ["member_actual_byte_limit"]},
    }

    with pytest.raises(ValidationError, match="does not match registry"):
        Finding.model_validate(payload)


def test_yara_rule_id_presentation_and_attack_context_are_trusted() -> None:
    finding_definition = FINDING_DEFINITIONS["YARA_HEURISTIC_MATCH"]
    rule = YARA_RULE_DEFINITIONS["DOCGUARD_POWERSHELL_ENCODED"]
    payload = {
        "code": finding_definition.code,
        "title": finding_definition.title,
        "description": finding_definition.description,
        "category": finding_definition.category,
        "severity": Severity(finding_definition.default_severity),
        "score_delta": 0,
        "mitre_techniques": list(rule.mitre_techniques),
        "metadata": {
            "rule_id": rule.rule_id,
            "rule_title": rule.title,
            "rule_explanation": rule.explanation,
            "rule_category": rule.category,
            "confidence_class": rule.confidence,
            "rule_pack_version": YARA_RULE_PACK_VERSION,
            "rule_pack_sha256": YARA_RULE_PACK_SHA256,
            "scope": "TOP_LEVEL",
            "match_count": 2,
            "string_ids": ["$encoded_flag", "$powershell"],
            "offsets": [10, 20],
        },
    }

    assert Finding.model_validate(payload).metadata["rule_id"] == rule.rule_id
    payload["metadata"] = {**payload["metadata"], "rule_id": "DOCGUARD_UNKNOWN"}
    with pytest.raises(ValidationError, match="unregistered YARA rule ID"):
        Finding.model_validate(payload)

    payload["metadata"] = {
        **payload["metadata"],
        "rule_id": rule.rule_id,
        "rule_title": "Spoofed trusted title",
    }
    with pytest.raises(ValidationError, match="trusted rule registry"):
        Finding.model_validate(payload)

    payload["metadata"] = {
        **payload["metadata"],
        "rule_title": rule.title,
    }
    payload["mitre_techniques"] = ["T0000"]
    with pytest.raises(ValidationError, match="does not match registry"):
        Finding.model_validate(payload)


def test_contract_rejects_oversized_worker_metadata(
    valid_analysis_result: AnalysisResult,
) -> None:
    definition = FINDING_DEFINITIONS["PDF_JAVASCRIPT"]
    with pytest.raises(ValidationError, match="finding metadata exceeds"):
        Finding(
            code=definition.code,
            title=definition.title,
            description=definition.description,
            category=definition.category,
            severity=Severity(definition.default_severity),
            score_delta=0,
            mitre_techniques=list(definition.mitre_techniques),
            metadata={"oversized": "x" * (MAX_FINDING_METADATA_BYTES + 1)},
        )

    payload = valid_analysis_result.model_dump()
    payload["analyzer_metadata"] = {"oversized": "x" * (MAX_ANALYZER_METADATA_BYTES + 1)}
    with pytest.raises(ValidationError, match="analyzer metadata exceeds"):
        AnalysisResult.model_validate(payload)
