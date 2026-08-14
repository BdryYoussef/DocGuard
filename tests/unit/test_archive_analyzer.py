from __future__ import annotations

import json
import socket
import zipfile
from pathlib import Path

import pytest

from tests.fixtures.archive_factory import (
    archive_bytes,
    corrupt_crc_archive_bytes,
    data_descriptor_archive_bytes,
    encrypted_metadata_archive_bytes,
    nested_archive_bytes,
    small_zip64_archive_bytes,
    symlink_archive_bytes,
    unsupported_method_archive_bytes,
)
from worker.analyzers.archive import analyze_archive
from worker.analyzers.archive_types import (
    ArchiveAnalysis,
    ArchiveAnalysisLimits,
    ArchiveParserStatus,
    ArchiveRoutingError,
)
from worker.analyzers.file_type import FileFamily


def analyze(
    tmp_path: Path,
    payload: bytes,
    limits: ArchiveAnalysisLimits | None = None,
) -> ArchiveAnalysis:
    path = tmp_path / "archive"
    path.write_bytes(payload)
    return analyze_archive(
        path,
        detected_family=FileFamily.ZIP,
        limits=limits or ArchiveAnalysisLimits(),
    )


def codes(result: ArchiveAnalysis) -> set[str]:
    return {str(item["code"]) for item in result.findings}


def finding(result: ArchiveAnalysis, code: str) -> dict[str, object]:
    return next(item for item in result.findings if item["code"] == code)


@pytest.mark.parametrize(
    "payload",
    [
        archive_bytes([("harmless.txt", b"fixture"), ("document.pdf", b"%PDF fixture")]),
        archive_bytes([]),
        archive_bytes([("directory/", b""), ("directory/empty.txt", b"")]),
        data_descriptor_archive_bytes(),
        small_zip64_archive_bytes(),
    ],
)
def test_normal_structural_variants_complete_without_findings(
    tmp_path: Path, payload: bytes
) -> None:
    result = analyze(tmp_path, payload)

    assert result.parser_status is ArchiveParserStatus.COMPLETE
    assert result.findings == ()
    assert result.metadata["parser"] == "python-zipfile"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("../file.txt", "ARCHIVE_PATH_TRAVERSAL"),
        ("folder\\..\\..\\file.txt", "ARCHIVE_PATH_TRAVERSAL"),
        ("/etc/passwd", "ARCHIVE_ABSOLUTE_PATH"),
        ("C:\\Windows\\fixture.txt", "ARCHIVE_ABSOLUTE_PATH"),
        ("\\\\server\\share\\fixture.txt", "ARCHIVE_ABSOLUTE_PATH"),
    ],
)
def test_portable_unsafe_paths_are_detected(tmp_path: Path, name: str, expected: str) -> None:
    result = analyze(tmp_path, archive_bytes([(name, b"fixture")]))

    assert expected in codes(result)


def test_nested_traversal_is_detected_by_content_not_extension(tmp_path: Path) -> None:
    inner = archive_bytes([("../../nested.txt", b"fixture")])
    result = analyze(tmp_path, archive_bytes([("opaque-member.bin", inner)]))

    assert "ARCHIVE_PATH_TRAVERSAL" in codes(result)
    assert result.metadata["nested_archive_count"] == 1
    metadata = finding(result, "ARCHIVE_PATH_TRAVERSAL")["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["members"][0]["archive_depth"] == 1  # type: ignore[index]


def test_symlink_is_reported_and_its_target_is_never_read(tmp_path: Path) -> None:
    result = analyze(tmp_path, symlink_archive_bytes())

    assert "ARCHIVE_SYMLINK" in codes(result)
    assert result.metadata["actual_decompressed_bytes"] == 0


def test_duplicate_exact_and_portable_normalized_names_are_deterministic(
    tmp_path: Path,
) -> None:
    payload = archive_bytes(
        [
            ("same.txt", b"one"),
            ("same.txt", b"two"),
            ("folder/./item.txt", b"three"),
            ("folder/item.txt", b"four"),
        ]
    )

    first = analyze(tmp_path, payload)
    second = analyze(tmp_path, payload)

    assert "ARCHIVE_DUPLICATE_MEMBER" in codes(first)
    assert first.findings == second.findings
    metadata = finding(first, "ARCHIVE_DUPLICATE_MEMBER")["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["count"] == 2


def test_dangerous_double_extension_and_bidi_names_are_bounded_findings(
    tmp_path: Path,
) -> None:
    payload = archive_bytes(
        [
            ("invoice.pdf.exe", b"MZ inert fixture"),
            ("script.ps1", b"# harmless comment"),
            ("quarterly.report.pdf", b"fixture"),
            ("photo\u202egpj.scr", b"fixture"),
        ]
    )

    result = analyze(tmp_path, payload)
    observed = codes(result)

    assert {
        "ARCHIVE_DANGEROUS_MEMBER",
        "ARCHIVE_MEMBER_DOUBLE_EXTENSION",
        "ARCHIVE_MEMBER_BIDI_OVERRIDE",
    }.issubset(observed)
    double_metadata = finding(result, "ARCHIVE_MEMBER_DOUBLE_EXTENSION")["metadata"]
    assert isinstance(double_metadata, dict)
    assert double_metadata["count"] == 1
    serialized = json.dumps(result.findings)
    assert "\\u202e" in serialized


def test_retained_member_names_and_count_are_bounded(tmp_path: Path) -> None:
    members = [("A" * 200 + f"-{number}.exe", b"fixture") for number in range(5)]
    result = analyze(
        tmp_path,
        archive_bytes(members),
        ArchiveAnalysisLimits(
            max_member_name_length=12,
            max_metadata_string_length=12,
            max_suspicious_member_names=2,
        ),
    )

    metadata = finding(result, "ARCHIVE_DANGEROUS_MEMBER")["metadata"]
    assert isinstance(metadata, dict)
    retained = metadata["members"]
    assert isinstance(retained, list) and len(retained) == 2
    assert all(len(str(item["member_name"])) <= 12 for item in retained)
    assert result.metadata["member_names_truncated"] == 2


def test_finding_count_limit_is_fail_closed(tmp_path: Path) -> None:
    payload = archive_bytes(
        [
            ("/../invoice.pdf.exe", b"fixture"),
            ("/../invoice.pdf.exe", b"fixture-two"),
            ("photo\u202egpj.scr", b"fixture"),
        ]
    )
    result = analyze(tmp_path, payload, ArchiveAnalysisLimits(max_findings=4))

    assert len(result.findings) == 4
    assert {"ARCHIVE_RESOURCE_LIMIT", "ARCHIVE_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert "finding_limit" in result.metadata["partial_reasons"]


def test_duplicate_and_traversal_record_caps_do_not_limit_observation_counts(
    tmp_path: Path,
) -> None:
    payload = archive_bytes(
        [
            ("../same.txt", b"one"),
            ("../same.txt", b"two"),
            ("../../other.txt", b"three"),
        ]
    )
    result = analyze(
        tmp_path,
        payload,
        ArchiveAnalysisLimits(
            max_suspicious_member_names=8,
            max_duplicate_records=1,
            max_traversal_records=1,
        ),
    )

    traversal = finding(result, "ARCHIVE_PATH_TRAVERSAL")["metadata"]
    duplicates = finding(result, "ARCHIVE_DUPLICATE_MEMBER")["metadata"]
    assert isinstance(traversal, dict) and traversal["count"] == 3
    assert isinstance(duplicates, dict) and duplicates["count"] == 1
    assert len(traversal["members"]) == 1  # type: ignore[arg-type]
    assert len(duplicates["members"]) == 1  # type: ignore[arg-type]


def test_encrypted_member_is_not_decrypted_and_remains_partial(tmp_path: Path) -> None:
    result = analyze(tmp_path, encrypted_metadata_archive_bytes())

    assert result.parser_status is ArchiveParserStatus.PARTIAL
    assert {"ARCHIVE_ENCRYPTED", "ARCHIVE_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert result.metadata["actual_decompressed_bytes"] == 0


def test_allowed_nested_zip_shares_aggregate_accounting(tmp_path: Path) -> None:
    payload = nested_archive_bytes(1)
    result = analyze(tmp_path, payload)

    assert result.parser_status is ArchiveParserStatus.COMPLETE
    assert result.metadata["archive_count"] == 2
    assert result.metadata["nested_archive_count"] == 1
    assert int(result.metadata["actual_decompressed_bytes"]) > len(b"controlled nested fixture")


def test_nesting_depth_limit_is_explicit_and_partial(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        nested_archive_bytes(2),
        ArchiveAnalysisLimits(max_nesting_depth=1),
    )

    assert result.parser_status is ArchiveParserStatus.PARTIAL
    assert {"ARCHIVE_NESTING_LIMIT", "ARCHIVE_PARTIAL_ANALYSIS"}.issubset(codes(result))


def test_nested_archives_share_total_actual_byte_budget(tmp_path: Path) -> None:
    inner = archive_bytes([("leaf.txt", b"A" * 64)])
    payload = archive_bytes([("nested.bin", inner)])
    result = analyze(
        tmp_path,
        payload,
        ArchiveAnalysisLimits(max_total_decompressed_bytes=len(inner) + 16),
    )

    assert "ARCHIVE_RESOURCE_LIMIT" in codes(result)
    assert "total_actual_byte_limit" in result.metadata["partial_reasons"]
    assert result.metadata["actual_decompressed_bytes"] == len(inner) + 17


def test_malformed_nested_zip_is_controlled_and_partial(tmp_path: Path) -> None:
    result = analyze(
        tmp_path,
        archive_bytes([("nested.bin", b"PK\x03\x04controlled malformed nested fixture")]),
    )

    assert result.parser_status is ArchiveParserStatus.MALFORMED
    assert {"ARCHIVE_MALFORMED", "ARCHIVE_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert "malformed_nested_archive" in result.metadata["partial_reasons"]


@pytest.mark.parametrize(
    ("payload", "limits", "reason"),
    [
        (
            archive_bytes([("one", b"1"), ("two", b"2")]),
            ArchiveAnalysisLimits(max_zip_entries=1),
            "zip_entry_limit",
        ),
        (
            archive_bytes([("large", b"A" * 64)]),
            ArchiveAnalysisLimits(max_member_bytes=16),
            "member_actual_byte_limit",
        ),
        (
            archive_bytes([("one", b"A" * 12), ("two", b"B" * 12)]),
            ArchiveAnalysisLimits(max_total_decompressed_bytes=16),
            "total_actual_byte_limit",
        ),
        (
            archive_bytes([("nested.bin", nested_archive_bytes(1))]),
            ArchiveAnalysisLimits(max_nested_archive_bytes=16),
            "nested_materialization_limit",
        ),
        (
            archive_bytes([("tiny", b"fixture")]),
            ArchiveAnalysisLimits(max_compressed_bytes_considered=16),
            "compressed_input_limit",
        ),
        (
            archive_bytes([("one", b"1"), ("two", b"2")]),
            ArchiveAnalysisLimits(max_members_inspected=1),
            "member_inspection_limit",
        ),
    ],
)
def test_hard_resource_limits_stop_with_partial_structured_results(
    tmp_path: Path,
    payload: bytes,
    limits: ArchiveAnalysisLimits,
    reason: str,
) -> None:
    result = analyze(tmp_path, payload, limits)

    assert result.parser_status is ArchiveParserStatus.PARTIAL
    assert {"ARCHIVE_RESOURCE_LIMIT", "ARCHIVE_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert reason in result.metadata["partial_reasons"]


def test_high_compression_is_bounded_by_actual_output_not_ratio(tmp_path: Path) -> None:
    payload = archive_bytes([("compressible.txt", b"A" * 100_000)])
    result = analyze(tmp_path, payload, ArchiveAnalysisLimits(max_member_bytes=4_096))

    assert "ARCHIVE_RESOURCE_LIMIT" in codes(result)
    assert int(result.metadata["actual_decompressed_bytes"]) > 4_096


@pytest.mark.parametrize(
    ("payload", "expected_code"),
    [
        (archive_bytes([("fixture", b"data")])[:-10], "ARCHIVE_MALFORMED"),
        (corrupt_crc_archive_bytes(), "ARCHIVE_MALFORMED"),
        (unsupported_method_archive_bytes(), "ARCHIVE_PARTIAL_ANALYSIS"),
    ],
)
def test_malformed_and_unsupported_archives_are_controlled(
    tmp_path: Path, payload: bytes, expected_code: str
) -> None:
    result = analyze(tmp_path, payload)

    assert expected_code in codes(result)
    assert result.parser_status is not ArchiveParserStatus.COMPLETE
    if payload == unsupported_method_archive_bytes():
        assert result.metadata["unsupported_compression_methods"] == [99]


@pytest.mark.parametrize(
    "compression",
    [
        zipfile.ZIP_STORED,
        zipfile.ZIP_DEFLATED,
        zipfile.ZIP_BZIP2,
        zipfile.ZIP_LZMA,
        zipfile.ZIP_ZSTANDARD,
    ],
)
def test_runtime_supported_compression_methods_are_inspected(
    tmp_path: Path, compression: int
) -> None:
    result = analyze(tmp_path, archive_bytes([("fixture", b"data")], compression=compression))

    assert result.parser_status is ArchiveParserStatus.COMPLETE
    assert result.metadata["actual_decompressed_bytes"] == 4


def test_analysis_does_not_require_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_socket(*args: object, **kwargs: object) -> socket.socket:
        del args, kwargs
        raise AssertionError("archive analyzer attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden_socket)

    result = analyze(tmp_path, archive_bytes([("fixture.txt", b"fixture")]))

    assert result.parser_status is ArchiveParserStatus.COMPLETE


def test_unexpected_programming_error_is_not_converted_to_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "archive"
    path.write_bytes(archive_bytes([("fixture", b"data")]))

    def unexpected(_self: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        raise AssertionError("controlled unexpected failure")

    monkeypatch.setattr(zipfile.ZipFile, "infolist", unexpected)
    with pytest.raises(AssertionError, match="controlled unexpected failure"):
        analyze_archive(path, detected_family=FileFamily.ZIP)


def test_archive_analyzer_rejects_internal_non_zip_routing(tmp_path: Path) -> None:
    path = tmp_path / "not-zip"
    path.write_text("fixture", encoding="utf-8")

    with pytest.raises(ArchiveRoutingError):
        analyze_archive(path, detected_family=FileFamily.TEXT)
