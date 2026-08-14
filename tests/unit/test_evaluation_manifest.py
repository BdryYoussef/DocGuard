from __future__ import annotations

import json
from pathlib import Path

import pytest

from evaluation.corpus import CASES
from evaluation.manifest import (
    ManifestValidationError,
    dump_manifest,
    load_manifest,
    manifest_payload,
)


def test_load_manifest_succeeds(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    dump_manifest(CASES, path)

    loaded = load_manifest(path)

    assert len(loaded) == len(CASES)
    assert [case.case_id for case in loaded] == sorted(case.case_id for case in CASES)


def test_manifest_covers_45_to_60_cases() -> None:
    assert 45 <= len(CASES) <= 60


def test_duplicate_case_id_is_rejected(tmp_path: Path) -> None:
    payload = manifest_payload(CASES)
    payload.append(payload[0])
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="duplicate case_id"):
        load_manifest(path)


def test_unknown_finding_code_is_rejected(tmp_path: Path) -> None:
    payload = manifest_payload(CASES)
    payload[0] = {**payload[0], "expected_findings": ["NOT_A_REAL_FINDING_CODE"]}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestValidationError):
        load_manifest(path)


def test_unknown_category_is_rejected(tmp_path: Path) -> None:
    payload = manifest_payload(CASES)
    payload[0] = {**payload[0], "category": "NOT_A_CATEGORY"}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestValidationError):
        load_manifest(path)


def test_unknown_class_is_rejected(tmp_path: Path) -> None:
    payload = manifest_payload(CASES)
    payload[0] = {**payload[0], "case_class": "NOT_A_CLASS"}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestValidationError):
        load_manifest(path)


def test_unresolvable_generator_is_rejected(tmp_path: Path) -> None:
    payload = manifest_payload(CASES)
    payload[0] = {
        **payload[0],
        "generator": {
            **payload[0]["generator"],  # type: ignore[dict-item]
            "attribute": "this_function_does_not_exist",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="does not exist"):
        load_manifest(path)


def test_hard_block_finding_requires_block_only_decision(tmp_path: Path) -> None:
    payload = manifest_payload(CASES)
    payload[0] = {
        **payload[0],
        "expected_findings": ["FILE_EXECUTABLE_MASQUERADE"],
        "acceptable_decisions": ["ALLOW"],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="require acceptable_decisions"):
        load_manifest(path)


def test_malformed_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ManifestValidationError):
        load_manifest(path)


def test_non_array_root_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")

    with pytest.raises(ManifestValidationError, match="JSON array"):
        load_manifest(path)


def test_dump_manifest_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    dump_manifest(CASES, first)
    dump_manifest(CASES, second)

    assert first.read_text(encoding="utf-8") == second.read_text(encoding="utf-8")


def test_manifest_payload_is_sorted_by_case_id() -> None:
    payload = manifest_payload(CASES)
    ids = [str(entry["case_id"]) for entry in payload]

    assert ids == sorted(ids)


def test_repository_manifest_file_is_valid() -> None:
    """The checked-in evaluation/corpus_manifest.json must itself pass validation."""
    from evaluation.manifest import DEFAULT_MANIFEST_PATH

    loaded = load_manifest(DEFAULT_MANIFEST_PATH)

    assert len(loaded) == len(CASES)
