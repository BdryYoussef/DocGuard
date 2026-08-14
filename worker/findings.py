"""Worker-side construction of registry-backed finding payloads."""

from __future__ import annotations

from docguard_contract.findings import FINDING_DEFINITIONS
from docguard_contract.yara_rules import YARA_RULE_DEFINITIONS


def finding_payload(code: str, metadata: dict[str, object]) -> dict[str, object]:
    definition = FINDING_DEFINITIONS[code]
    return {
        "code": definition.code,
        "title": definition.title,
        "description": definition.description,
        "category": definition.category,
        "severity": definition.default_severity,
        "score_delta": 0,
        "mitre_techniques": list(definition.mitre_techniques),
        "metadata": metadata,
    }


def yara_finding_payload(rule_id: str, metadata: dict[str, object]) -> dict[str, object]:
    rule_definition = YARA_RULE_DEFINITIONS[rule_id]
    finding_definition = FINDING_DEFINITIONS[rule_definition.finding_code]
    return {
        "code": finding_definition.code,
        "title": finding_definition.title,
        "description": finding_definition.description,
        "category": finding_definition.category,
        "severity": finding_definition.default_severity,
        "score_delta": 0,
        "mitre_techniques": list(rule_definition.mitre_techniques),
        "metadata": metadata,
    }
