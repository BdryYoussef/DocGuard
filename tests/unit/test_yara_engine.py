from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yara

from app.models.domain import Finding
from docguard_contract.yara_rules import (
    YARA_EXPECTED_RULE_IDS,
    YARA_RULE_PACK_SHA256,
    YARA_RULE_PACK_VERSION,
)
from tests.fixtures.yara_factory import (
    BENIGN_CMD_PROSE,
    BENIGN_POWERSHELL_PROSE,
    BENIGN_TEXT,
    BENIGN_WSCRIPT_PROSE,
    CERTUTIL_INVOCATION_PATTERN,
    CMD_INVOCATION_PATTERN,
    EICAR_TEST_BYTES,
    MSHTA_INVOCATION_PATTERN,
    POWERSHELL_ENCODED_PATTERN,
    WSCRIPT_INVOCATION_PATTERN,
)
from worker.yara_engine import (
    CompiledRulePack,
    YaraAnalysis,
    YaraParserStatus,
    YaraRulePackError,
    YaraScanLimits,
    compile_rule_pack,
    rule_pack_path,
    scan_top_level_file,
    yara_production_self_test,
)


def analyze(
    tmp_path: Path,
    payload: bytes,
    limits: YaraScanLimits | None = None,
) -> YaraAnalysis:
    sample = tmp_path / "sample"
    sample.write_bytes(payload)
    return scan_top_level_file(sample, limits=limits or YaraScanLimits())


def codes(result: YaraAnalysis) -> set[str]:
    return {str(item["code"]) for item in result.findings}


def validate_worker_finding(payload: dict[str, object]) -> Finding:
    return Finding.model_validate_json(json.dumps(payload))


def test_production_rule_pack_compiles_and_manifest_is_exact() -> None:
    pack = compile_rule_pack()

    assert pack.rule_ids == YARA_EXPECTED_RULE_IDS
    assert pack.sha256 == YARA_RULE_PACK_SHA256
    assert len(pack.rule_ids) == 6
    assert yara_production_self_test()


def test_broken_rule_pack_is_rejected_even_with_matching_fixture_fingerprint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    source = (
        rule_pack_path()
        .read_bytes()
        .replace(
            b"$eicar\n}\n\nrule DOCGUARD_POWERSHELL",
            b"$eicar and\n}\n\nrule DOCGUARD_POWERSHELL",
        )
    )
    (root / rule_pack_path().name).write_bytes(source)

    with pytest.raises(YaraRulePackError, match="did not compile"):
        compile_rule_pack(
            rules_root=root,
            expected_sha256=hashlib.sha256(source).hexdigest(),
        )
    assert not yara_production_self_test(rules_root=root)


def test_unexpected_extra_rule_is_rejected_by_strict_manifest(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    source = rule_pack_path().read_bytes() + b"\nrule DOCGUARD_UNEXPECTED { condition: true }\n"
    (root / rule_pack_path().name).write_bytes(source)

    with pytest.raises(YaraRulePackError, match="manifest"):
        compile_rule_pack(
            rules_root=root,
            expected_sha256=hashlib.sha256(source).hexdigest(),
        )
    assert not yara_production_self_test(rules_root=root)


def test_eicar_is_classified_as_a_controlled_test_signature(tmp_path: Path) -> None:
    result = analyze(tmp_path, EICAR_TEST_BYTES)

    assert result.parser_status is YaraParserStatus.COMPLETE
    assert codes(result) == {"YARA_TEST_SIGNATURE"}
    finding = validate_worker_finding(result.findings[0])
    assert finding.metadata["rule_id"] == "DOCGUARD_EICAR_TEST"
    assert finding.metadata["confidence_class"] == "TEST"
    assert "not real malware" in str(finding.metadata["rule_explanation"])


@pytest.mark.parametrize(
    ("payload", "rule_id"),
    [
        (POWERSHELL_ENCODED_PATTERN, "DOCGUARD_POWERSHELL_ENCODED"),
        (WSCRIPT_INVOCATION_PATTERN, "DOCGUARD_WSCRIPT_ENGINE_INVOCATION"),
        (CMD_INVOCATION_PATTERN, "DOCGUARD_CMD_CHAIN_INVOCATION"),
        (MSHTA_INVOCATION_PATTERN, "DOCGUARD_MSHTA_SCRIPT_SCHEME"),
        (CERTUTIL_INVOCATION_PATTERN, "DOCGUARD_CERTUTIL_URLCACHE"),
    ],
)
def test_controlled_heuristic_patterns_match(tmp_path: Path, payload: bytes, rule_id: str) -> None:
    result = analyze(tmp_path, payload)

    assert result.parser_status is YaraParserStatus.COMPLETE
    assert codes(result) == {"YARA_HEURISTIC_MATCH"}
    metadata = result.findings[0]["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["rule_id"] == rule_id
    validate_worker_finding(result.findings[0])


@pytest.mark.parametrize(
    "payload",
    [BENIGN_TEXT, BENIGN_POWERSHELL_PROSE, BENIGN_WSCRIPT_PROSE, BENIGN_CMD_PROSE],
)
def test_benign_and_false_positive_oriented_prose_does_not_match(
    tmp_path: Path, payload: bytes
) -> None:
    result = analyze(tmp_path, payload)

    assert result.parser_status is YaraParserStatus.COMPLETE
    assert result.findings == ()


def test_match_privacy_discards_raw_bytes_and_bounds_identifiers_and_offsets(
    tmp_path: Path,
) -> None:
    payload = b"\n".join([POWERSHELL_ENCODED_PATTERN] * 20)
    result = analyze(
        tmp_path,
        payload,
        YaraScanLimits(
            max_match_instances_per_rule=4,
            max_string_ids_per_rule=1,
            max_offsets_per_rule=2,
        ),
    )

    assert result.parser_status is YaraParserStatus.PARTIAL
    match = next(item for item in result.findings if item["code"] == "YARA_HEURISTIC_MATCH")
    metadata = match["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["match_count"] == 4
    assert len(metadata["string_ids"]) == 1  # type: ignore[arg-type]
    assert len(metadata["offsets"]) == 2  # type: ignore[arg-type]
    serialized = str(result.findings)
    assert "QUJDREVGR0hJSktMTU5PUA" not in serialized
    assert "powershell.exe" not in serialized.casefold()
    assert {"YARA_HEURISTIC_MATCH", "YARA_PARTIAL_ANALYSIS"}.issubset(codes(result))


def test_matched_rule_and_total_metadata_limits_fail_closed(tmp_path: Path) -> None:
    payload = b"\n".join(
        [
            EICAR_TEST_BYTES,
            POWERSHELL_ENCODED_PATTERN,
            WSCRIPT_INVOCATION_PATTERN,
            CMD_INVOCATION_PATTERN,
            MSHTA_INVOCATION_PATTERN,
            CERTUTIL_INVOCATION_PATTERN,
        ]
    )
    matched_limit = analyze(tmp_path, payload, YaraScanLimits(max_matched_rules=1))
    metadata_limit = analyze(tmp_path, payload, YaraScanLimits(max_total_metadata_bytes=1))

    assert matched_limit.parser_status is YaraParserStatus.PARTIAL
    assert "matched_rule_limit" in matched_limit.metadata["partial_reasons"]
    assert metadata_limit.parser_status is YaraParserStatus.PARTIAL
    assert codes(metadata_limit) == {"YARA_PARTIAL_ANALYSIS"}
    assert "metadata_limit" in metadata_limit.metadata["partial_reasons"]


def test_yara_internal_timeout_is_controlled_and_fail_closed(tmp_path: Path) -> None:
    class TimeoutRules:
        def match(self, *args: object, **kwargs: object) -> list[object]:
            del args, kwargs
            raise yara.TimeoutError("controlled timeout")

    sample = tmp_path / "sample"
    sample.write_bytes(BENIGN_TEXT)
    pack = CompiledRulePack(TimeoutRules(), YARA_EXPECTED_RULE_IDS, YARA_RULE_PACK_SHA256)  # type: ignore[arg-type]

    result = scan_top_level_file(sample, compiled_pack=pack)

    assert result.parser_status is YaraParserStatus.PARTIAL
    assert codes(result) == {"YARA_PARTIAL_ANALYSIS"}
    assert result.metadata["partial_reasons"] == ["internal_timeout"]
    validate_worker_finding(result.findings[0])


def test_analysis_metadata_has_only_trusted_pack_identity(tmp_path: Path) -> None:
    result = analyze(tmp_path, BENIGN_TEXT)

    assert result.metadata["rule_pack_version"] == YARA_RULE_PACK_VERSION
    assert result.metadata["rule_pack_sha256"] == YARA_RULE_PACK_SHA256
    assert result.metadata["scope"] == "TOP_LEVEL"
    assert "path" not in result.metadata
