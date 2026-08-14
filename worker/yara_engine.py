"""Bounded top-level YARA scanning with a fixed trusted DocGuard rule pack."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, fields
from enum import StrEnum
from pathlib import Path
from time import monotonic_ns
from typing import Protocol, cast

import yara

from docguard_contract.yara_rules import (
    MAX_YARA_OFFSETS_PER_FINDING,
    MAX_YARA_REPORTED_MATCH_COUNT,
    MAX_YARA_STRING_IDS_PER_FINDING,
    YARA_EXPECTED_RULE_IDS,
    YARA_RULE_DEFINITIONS,
    YARA_RULE_NAMESPACE,
    YARA_RULE_PACK_FILENAME,
    YARA_RULE_PACK_SHA256,
    YARA_RULE_PACK_VERSION,
)
from worker.findings import finding_payload, yara_finding_payload

_MAX_RULE_PACK_BYTES = 128 * 1024
_RULE_DECLARATION = re.compile(
    rb"(?m)^[ \t]*(?:(?:private|global)[ \t]+)?rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_FORBIDDEN_DIRECTIVE = re.compile(rb"(?m)^[ \t]*(?:include|import)[ \t]+")


class _StringMatchInstance(Protocol):
    offset: int


class _StringMatch(Protocol):
    identifier: str
    instances: list[_StringMatchInstance]


class _RuleMatch(Protocol):
    rule: str
    namespace: str
    strings: list[_StringMatch]


class _CompiledRules(Protocol):
    def match(
        self,
        filepath: str | None = None,
        *,
        data: bytes | None = None,
        timeout: int | None = None,
        warnings_callback: Callable[[int, object], int] | None = None,
    ) -> list[_RuleMatch]: ...


class YaraParserStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True, slots=True)
class YaraScanLimits:
    timeout_seconds: int = 3
    max_matched_rules: int = 32
    max_match_instances_per_rule: int = 4_096
    max_string_ids_per_rule: int = MAX_YARA_STRING_IDS_PER_FINDING
    max_offsets_per_rule: int = MAX_YARA_OFFSETS_PER_FINDING
    max_total_metadata_bytes: int = 12 * 1024
    max_match_data_bytes: int = 1

    def __post_init__(self) -> None:
        if any(getattr(self, item.name) <= 0 for item in fields(self)):
            raise ValueError("YARA scan limits must be positive")
        if self.max_string_ids_per_rule > MAX_YARA_STRING_IDS_PER_FINDING:
            raise ValueError("YARA string identifier limit exceeds the trusted contract")
        if self.max_offsets_per_rule > MAX_YARA_OFFSETS_PER_FINDING:
            raise ValueError("YARA offset limit exceeds the trusted contract")
        if self.max_match_instances_per_rule > MAX_YARA_REPORTED_MATCH_COUNT:
            raise ValueError("YARA match count limit exceeds the trusted contract")


DEFAULT_YARA_LIMITS = YaraScanLimits()


@dataclass(frozen=True, slots=True)
class CompiledRulePack:
    rules: _CompiledRules
    rule_ids: frozenset[str]
    sha256: str


@dataclass(frozen=True, slots=True)
class YaraAnalysis:
    parser_status: YaraParserStatus
    findings: tuple[dict[str, object], ...]
    metadata: dict[str, object]

    @property
    def complete(self) -> bool:
        return self.parser_status is YaraParserStatus.COMPLETE


class YaraRulePackError(RuntimeError):
    """The trusted product rule pack failed integrity or manifest validation."""


def rule_pack_path(rules_root: Path | None = None) -> Path:
    root = rules_root if rules_root is not None else Path(__file__).resolve().parent / "rules"
    return root / YARA_RULE_PACK_FILENAME


def compile_rule_pack(
    *,
    rules_root: Path | None = None,
    expected_sha256: str = YARA_RULE_PACK_SHA256,
    expected_rule_ids: frozenset[str] = YARA_EXPECTED_RULE_IDS,
) -> CompiledRulePack:
    path = rule_pack_path(rules_root)
    try:
        source = path.read_bytes()
    except OSError as exc:
        raise YaraRulePackError("trusted YARA rule pack is unavailable") from exc
    if not source or len(source) > _MAX_RULE_PACK_BYTES:
        raise YaraRulePackError("trusted YARA rule pack size is invalid")
    fingerprint = hashlib.sha256(source).hexdigest()
    if fingerprint != expected_sha256:
        raise YaraRulePackError("trusted YARA rule pack fingerprint mismatch")
    if _FORBIDDEN_DIRECTIVE.search(source):
        raise YaraRulePackError("trusted YARA rule pack uses a forbidden directive")
    declared_ids = [value.decode("ascii") for value in _RULE_DECLARATION.findall(source)]
    if len(declared_ids) != len(set(declared_ids)):
        raise YaraRulePackError("trusted YARA rule IDs are not unique")
    observed_ids = frozenset(declared_ids)
    if observed_ids != expected_rule_ids:
        raise YaraRulePackError("trusted YARA manifest does not match rule declarations")
    try:
        compiled = yara.compile(filepaths={YARA_RULE_NAMESPACE: str(path)})
    except yara.Error as exc:
        raise YaraRulePackError("trusted YARA rule pack did not compile") from exc
    return CompiledRulePack(cast(_CompiledRules, compiled), observed_ids, fingerprint)


def yara_production_self_test(*, rules_root: Path | None = None) -> bool:
    try:
        pack = compile_rule_pack(rules_root=rules_root)
        eicar_matches = pack.rules.match(data=_eicar_fixture(), timeout=1)
        benign_matches = pack.rules.match(
            data=b"DocGuard controlled benign YARA readiness fixture.", timeout=1
        )
    except (OSError, yara.Error, YaraRulePackError):
        return False
    return {match.rule for match in eicar_matches} == {
        "DOCGUARD_EICAR_TEST"
    } and benign_matches == []


def scan_top_level_file(
    sample_path: Path,
    *,
    limits: YaraScanLimits = DEFAULT_YARA_LIMITS,
    compiled_pack: CompiledRulePack | None = None,
) -> YaraAnalysis:
    started_ns = monotonic_ns()
    partial_reasons: set[str] = set()
    findings: list[dict[str, object]] = []
    warnings: list[str] = []

    try:
        yara.set_config(max_match_data=limits.max_match_data_bytes)
        pack = compiled_pack or compile_rule_pack()

        def warning_callback(warning_type: int, message: object) -> int:
            del message
            reason = (
                "engine_match_warning"
                if warning_type == yara.CALLBACK_TOO_MANY_MATCHES
                else "engine_warning"
            )
            if not warnings:
                warnings.append(reason)
            return int(yara.CALLBACK_CONTINUE)

        matches = pack.rules.match(
            str(sample_path),
            timeout=limits.timeout_seconds,
            warnings_callback=warning_callback,
        )
    except yara.TimeoutError:
        partial_reasons.add("internal_timeout")
        return _result(findings, partial_reasons, 0, started_ns)
    except yara.Error:
        partial_reasons.add("scanner_error")
        return _result(findings, partial_reasons, 0, started_ns)
    partial_reasons.update(warnings)

    ordered_matches = sorted(matches, key=lambda item: item.rule)
    matched_rule_count = len(ordered_matches)
    if matched_rule_count > limits.max_matched_rules:
        partial_reasons.add("matched_rule_limit")
        ordered_matches = ordered_matches[: limits.max_matched_rules]

    metadata_bytes = 0
    for match in ordered_matches:
        if match.namespace != YARA_RULE_NAMESPACE or match.rule not in YARA_RULE_DEFINITIONS:
            raise YaraRulePackError("YARA returned a rule outside the trusted manifest")
        definition = YARA_RULE_DEFINITIONS[match.rule]
        string_ids = sorted({item.identifier for item in match.strings})
        if len(string_ids) > limits.max_string_ids_per_rule:
            partial_reasons.add("string_identifier_limit")
            string_ids = string_ids[: limits.max_string_ids_per_rule]

        all_offsets: list[int] = []
        actual_match_count = 0
        for string_match in match.strings:
            actual_match_count += len(string_match.instances)
            remaining = max(0, limits.max_offsets_per_rule - len(all_offsets))
            if remaining:
                all_offsets.extend(
                    instance.offset for instance in string_match.instances[:remaining]
                )
        if actual_match_count > limits.max_match_instances_per_rule:
            partial_reasons.add("match_instance_limit")
        if actual_match_count > len(all_offsets):
            partial_reasons.add("offset_limit")
        retained_count = min(actual_match_count, limits.max_match_instances_per_rule)
        metadata: dict[str, object] = {
            "rule_id": definition.rule_id,
            "rule_title": definition.title,
            "rule_explanation": definition.explanation,
            "rule_category": definition.category,
            "confidence_class": definition.confidence,
            "rule_pack_version": YARA_RULE_PACK_VERSION,
            "rule_pack_sha256": pack.sha256,
            "scope": "TOP_LEVEL",
            "match_count": retained_count,
            "string_ids": string_ids,
            "offsets": sorted(set(all_offsets))[: limits.max_offsets_per_rule],
        }
        encoded_size = len(
            json.dumps(metadata, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
        )
        if metadata_bytes + encoded_size > limits.max_total_metadata_bytes:
            partial_reasons.add("metadata_limit")
            break
        metadata_bytes += encoded_size
        findings.append(yara_finding_payload(definition.rule_id, metadata))

    return _result(findings, partial_reasons, matched_rule_count, started_ns)


def _result(
    findings: list[dict[str, object]],
    partial_reasons: set[str],
    matched_rule_count: int,
    started_ns: int,
) -> YaraAnalysis:
    if partial_reasons:
        findings.append(
            finding_payload(
                "YARA_PARTIAL_ANALYSIS",
                {
                    "reasons": sorted(partial_reasons),
                    "rule_pack_version": YARA_RULE_PACK_VERSION,
                    "rule_pack_sha256": YARA_RULE_PACK_SHA256,
                },
            )
        )
        parser_status = YaraParserStatus.PARTIAL
    else:
        parser_status = YaraParserStatus.COMPLETE
    metadata: dict[str, object] = {
        "engine": "yara-python",
        "yara_python_version": yara.__version__,
        "yara_runtime_version": yara.YARA_VERSION,
        "rule_pack_version": YARA_RULE_PACK_VERSION,
        "rule_pack_sha256": YARA_RULE_PACK_SHA256,
        "scope": "TOP_LEVEL",
        "parser_status": parser_status.value,
        "matched_rule_count": matched_rule_count,
        "retained_finding_count": len(findings),
        "partial_reasons": sorted(partial_reasons),
        "duration_ms": max(0, (monotonic_ns() - started_ns) // 1_000_000),
    }
    return YaraAnalysis(parser_status, tuple(findings), metadata)


def _eicar_fixture() -> bytes:
    return b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


__all__ = [
    "DEFAULT_YARA_LIMITS",
    "CompiledRulePack",
    "YaraAnalysis",
    "YaraParserStatus",
    "YaraRulePackError",
    "YaraScanLimits",
    "compile_rule_pack",
    "rule_pack_path",
    "scan_top_level_file",
    "yara_production_self_test",
]
