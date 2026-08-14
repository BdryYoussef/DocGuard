"""Trusted DocGuard YARA rule manifest shared across the worker boundary."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

type YaraConfidence = Literal["TEST", "SIGNATURE", "HEURISTIC"]
type YaraFindingCode = Literal[
    "YARA_TEST_SIGNATURE",
    "YARA_SIGNATURE_MATCH",
    "YARA_HEURISTIC_MATCH",
]

YARA_RULE_PACK_VERSION = "2026.08.1"
YARA_RULE_PACK_FILENAME = "docguard_v1.yar"
YARA_RULE_PACK_SHA256 = "7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7"
YARA_RULE_NAMESPACE = "docguard"

MAX_YARA_STRING_IDS_PER_FINDING = 16
MAX_YARA_OFFSETS_PER_FINDING = 16
MAX_YARA_REPORTED_MATCH_COUNT = 1_000_000


@dataclass(frozen=True, slots=True)
class YaraRuleDefinition:
    rule_id: str
    title: str
    explanation: str
    category: str
    confidence: YaraConfidence
    finding_code: YaraFindingCode
    severity: Literal["MEDIUM", "HIGH"]
    mitre_techniques: tuple[str, ...] = ()


_RULES = (
    YaraRuleDefinition(
        rule_id="DOCGUARD_EICAR_TEST",
        title="EICAR anti-malware test signature",
        explanation=(
            "The standard EICAR anti-malware test string was observed. EICAR is a controlled "
            "test artifact, not real malware."
        ),
        category="yara-test-signature",
        confidence="TEST",
        finding_code="YARA_TEST_SIGNATURE",
        severity="HIGH",
    ),
    YaraRuleDefinition(
        rule_id="DOCGUARD_POWERSHELL_ENCODED",
        title="PowerShell encoded-command pattern",
        explanation=(
            "A PowerShell executable reference and encoded-command argument with a substantial "
            "Base64-like value were both observed."
        ),
        category="yara-command-pattern",
        confidence="HEURISTIC",
        finding_code="YARA_HEURISTIC_MATCH",
        severity="MEDIUM",
        mitre_techniques=("T1059.001",),
    ),
    YaraRuleDefinition(
        rule_id="DOCGUARD_WSCRIPT_ENGINE_INVOCATION",
        title="Windows Script Host engine invocation pattern",
        explanation=(
            "A Windows Script Host command pattern selects a script engine and names a supported "
            "script-file extension."
        ),
        category="yara-command-pattern",
        confidence="HEURISTIC",
        finding_code="YARA_HEURISTIC_MATCH",
        severity="MEDIUM",
        mitre_techniques=("T1059.005",),
    ),
    YaraRuleDefinition(
        rule_id="DOCGUARD_CMD_CHAIN_INVOCATION",
        title="Windows command-shell chain pattern",
        explanation=(
            "A cmd.exe command execution argument and a chained command operator were observed in "
            "a bounded command-line pattern."
        ),
        category="yara-command-pattern",
        confidence="HEURISTIC",
        finding_code="YARA_HEURISTIC_MATCH",
        severity="MEDIUM",
        mitre_techniques=("T1059.003",),
    ),
    YaraRuleDefinition(
        rule_id="DOCGUARD_MSHTA_SCRIPT_SCHEME",
        title="Mshta inline script-scheme pattern",
        explanation=("An mshta invocation is followed by an inline JavaScript or VBScript scheme."),
        category="yara-proxy-execution-pattern",
        confidence="HEURISTIC",
        finding_code="YARA_HEURISTIC_MATCH",
        severity="MEDIUM",
        mitre_techniques=("T1218.005",),
    ),
    YaraRuleDefinition(
        rule_id="DOCGUARD_CERTUTIL_URLCACHE",
        title="Certutil URL-cache transfer pattern",
        explanation=(
            "A certutil invocation combines URL-cache and split arguments with an HTTP target."
        ),
        category="yara-transfer-pattern",
        confidence="HEURISTIC",
        finding_code="YARA_HEURISTIC_MATCH",
        severity="MEDIUM",
        mitre_techniques=("T1105",),
    ),
)

YARA_RULE_DEFINITIONS = MappingProxyType({definition.rule_id: definition for definition in _RULES})
YARA_EXPECTED_RULE_IDS = frozenset(YARA_RULE_DEFINITIONS)

__all__ = [
    "MAX_YARA_OFFSETS_PER_FINDING",
    "MAX_YARA_REPORTED_MATCH_COUNT",
    "MAX_YARA_STRING_IDS_PER_FINDING",
    "YARA_EXPECTED_RULE_IDS",
    "YARA_RULE_DEFINITIONS",
    "YARA_RULE_NAMESPACE",
    "YARA_RULE_PACK_FILENAME",
    "YARA_RULE_PACK_SHA256",
    "YARA_RULE_PACK_VERSION",
    "YaraConfidence",
    "YaraFindingCode",
    "YaraRuleDefinition",
]
