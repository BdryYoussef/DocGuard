from __future__ import annotations

import json
import socket
import struct
import zipfile
from pathlib import Path

import pytest

from tests.fixtures.office_factory import (
    HARMLESS_AUTOEXEC_SOURCE,
    HARMLESS_EXECUTION_INDICATOR_SOURCE,
    VISIBLE_SHELL_TEXT,
    build_compound_file,
    build_vba_compound,
    write_classic_ole,
    write_encrypted_office_ole,
    write_inconsistent_ooxml,
    write_ooxml,
)
from worker.analyzers.file_type import FileFamily
from worker.analyzers.office import analyze_office
from worker.analyzers.office_types import (
    OfficeAnalysis,
    OfficeAnalysisLimits,
    OfficeApplication,
    OfficeParserStatus,
)
from worker.analyzers.vba import VbaAnalysis, analyze_vba_blob


def analyze(path: Path, limits: OfficeAnalysisLimits | None = None) -> OfficeAnalysis:
    result = analyze_office(
        path,
        detected_family=FileFamily.OOXML_CANDIDATE,
        limits=limits or OfficeAnalysisLimits(),
    )
    assert result is not None
    return result


def codes(result: OfficeAnalysis) -> set[str]:
    return {str(finding["code"]) for finding in result.findings}


def finding(result: OfficeAnalysis, code: str) -> dict[str, object]:
    return next(item for item in result.findings if item["code"] == code)


@pytest.mark.parametrize(
    ("application", "expected"),
    [
        (OfficeApplication.WORD, "OFFICE_WORD_OOXML"),
        (OfficeApplication.EXCEL, "OFFICE_EXCEL_OOXML"),
        (OfficeApplication.POWERPOINT, "OFFICE_POWERPOINT_OOXML"),
    ],
)
def test_benign_ooxml_families_are_structurally_identified(
    tmp_path: Path, application: OfficeApplication, expected: str
) -> None:
    path = write_ooxml(tmp_path / "document", application=application)

    result = analyze(path)

    assert result.detected_type == expected
    assert result.parser_status is OfficeParserStatus.COMPLETE
    assert result.findings == ()
    assert result.metadata["xml_parser_version"] == "0.7.1"


def test_macro_autoexec_and_execution_indicators_are_static_and_bounded(tmp_path: Path) -> None:
    source = HARMLESS_AUTOEXEC_SOURCE + HARMLESS_EXECUTION_INDICATOR_SOURCE
    path = write_ooxml(
        tmp_path / "macro.docm",
        application=OfficeApplication.WORD,
        macro_source=source,
    )

    result = analyze(path)

    assert {
        "OFFICE_MACRO_ENABLED",
        "OFFICE_VBA_MACRO",
        "OFFICE_VBA_AUTOEXEC",
        "OFFICE_VBA_EXECUTION_INDICATOR",
    }.issubset(codes(result))
    assert result.parser_status is OfficeParserStatus.PARTIAL
    assert "orphan_vba_stream" in result.metadata["partial_reasons"]
    autoexec = finding(result, "OFFICE_VBA_AUTOEXEC")["metadata"]
    execution = finding(result, "OFFICE_VBA_EXECUTION_INDICATOR")["metadata"]
    assert isinstance(autoexec, dict) and "AutoOpen" in autoexec["triggers"]
    assert isinstance(execution, dict)
    assert {"com_object_creation", "process_launch", "scripting_host"}.issubset(
        set(execution["indicator_classes"])  # type: ignore[arg-type]
    )
    serialized = json.dumps({"findings": result.findings, "metadata": result.metadata})
    assert "DOCGUARD_CONTROLLED_FIXTURE" not in serialized
    assert "cmd.exe /c" not in serialized


def test_macro_enabled_excel_package_is_structurally_supported(tmp_path: Path) -> None:
    result = analyze(
        write_ooxml(
            tmp_path / "macro.xlsm",
            application=OfficeApplication.EXCEL,
            macro_source=HARMLESS_AUTOEXEC_SOURCE.replace("AutoOpen", "Workbook_Open"),
        )
    )

    assert result.detected_type == "OFFICE_EXCEL_OOXML"
    assert {"OFFICE_MACRO_ENABLED", "OFFICE_VBA_MACRO", "OFFICE_VBA_AUTOEXEC"}.issubset(
        codes(result)
    )


def test_visible_document_words_do_not_trigger_vba_findings(tmp_path: Path) -> None:
    result = analyze(
        write_ooxml(
            tmp_path / "visible.docx",
            application=OfficeApplication.WORD,
            visible_text=VISIBLE_SHELL_TEXT,
        )
    )

    assert not any(code.startswith("OFFICE_VBA_") for code in codes(result))


def test_external_relationships_are_lexical_private_and_never_fetched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden_socket(*args: object, **kwargs: object) -> socket.socket:
        del args, kwargs
        raise AssertionError("Office analysis attempted network access")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    result = analyze(
        write_ooxml(
            tmp_path / "external.docx",
            application=OfficeApplication.WORD,
            external_relationship=True,
            external_template=True,
        )
    )

    assert {"OFFICE_EXTERNAL_RELATIONSHIP", "OFFICE_EXTERNAL_TEMPLATE"}.issubset(codes(result))
    serialized = json.dumps(result.findings)
    assert "links.example.invalid" in serialized
    assert "templates.example.invalid" in serialized
    assert "user" not in serialized
    assert "password" not in serialized
    assert "private=1" not in serialized


def test_embedded_and_activex_structures_are_counted_without_extraction(tmp_path: Path) -> None:
    result = analyze(
        write_ooxml(
            tmp_path / "capabilities.docx",
            application=OfficeApplication.WORD,
            embedded_object=True,
            activex=True,
        )
    )

    assert {"OFFICE_EMBEDDED_OBJECT", "OFFICE_ACTIVEX"}.issubset(codes(result))
    assert not (tmp_path / "controlled-object.bin").exists()
    assert not (tmp_path / "activeX1.bin").exists()


def test_encrypted_office_ole_is_partial_and_non_decrypted(tmp_path: Path) -> None:
    path = write_encrypted_office_ole(tmp_path / "encrypted")

    result = analyze_office(path, detected_family=FileFamily.OLE_COMPOUND)

    assert result is not None
    assert result.parser_status is OfficeParserStatus.PARTIAL
    assert {"OFFICE_ENCRYPTED", "OFFICE_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert result.metadata["application"] == "UNKNOWN"


def test_malformed_ole_parser_rejection_is_not_silently_accepted(tmp_path: Path) -> None:
    path = tmp_path / "malformed.ole"
    path.write_bytes(bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 504)

    result = analyze_office(path, detected_family=FileFamily.OLE_COMPOUND)

    assert result is not None
    assert result.parser_status is OfficeParserStatus.MALFORMED
    assert {"OFFICE_MALFORMED", "OFFICE_PARTIAL_ANALYSIS"}.issubset(codes(result))


def test_classic_ole_word_and_orphan_vba_are_conservatively_supported(tmp_path: Path) -> None:
    benign = write_classic_ole(tmp_path / "benign.doc")
    macro = write_classic_ole(tmp_path / "macro.doc", macro_source=HARMLESS_AUTOEXEC_SOURCE)

    benign_result = analyze_office(benign, detected_family=FileFamily.OLE_COMPOUND)
    macro_result = analyze_office(macro, detected_family=FileFamily.OLE_COMPOUND)

    assert benign_result is not None and benign_result.detected_type == "OFFICE_WORD_OLE"
    assert benign_result.parser_status is OfficeParserStatus.COMPLETE
    assert macro_result is not None
    assert {"OFFICE_VBA_MACRO", "OFFICE_VBA_AUTOEXEC"}.issubset(codes(macro_result))


@pytest.mark.parametrize(
    ("stream_name", "expected_type"),
    [("Workbook", "OFFICE_EXCEL_OLE"), ("PowerPoint Document", "OFFICE_POWERPOINT_OLE")],
)
def test_classic_ole_excel_and_powerpoint_families_are_classified(
    tmp_path: Path, stream_name: str, expected_type: str
) -> None:
    path = tmp_path / "classic-office"
    path.write_bytes(build_compound_file({stream_name: b"DOCGUARD_CONTROLLED_FIXTURE"}))

    result = analyze_office(path, detected_family=FileFamily.OLE_COMPOUND)

    assert result is not None
    assert result.detected_type == expected_type
    assert result.parser_status is OfficeParserStatus.COMPLETE


@pytest.mark.parametrize("malformed_relationships", [True, False])
def test_malformed_or_unsafe_relationship_xml_fails_closed(
    tmp_path: Path, malformed_relationships: bool
) -> None:
    sentinel = tmp_path / "host-sentinel"
    sentinel.write_text("PARENT_SENTINEL_MUST_NOT_LEAK", encoding="utf-8")
    hostile_xml = None
    if not malformed_relationships:
        hostile_xml = (
            '<!DOCTYPE Relationships [<!ENTITY xxe SYSTEM "file://'
            + str(sentinel)
            + '">]><Relationships '
            'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rIdX" Type="example" Target="&xxe;" '
            'TargetMode="External"/></Relationships>'
        )
    result = analyze(
        write_ooxml(
            tmp_path / "hostile.docx",
            application=OfficeApplication.WORD,
            malformed_relationships=malformed_relationships,
            hostile_relationship_xml=hostile_xml,
        )
    )

    assert result.parser_status is OfficeParserStatus.MALFORMED
    assert {"OFFICE_MALFORMED", "OFFICE_PARTIAL_ANALYSIS"}.issubset(codes(result))
    assert "PARENT_SENTINEL_MUST_NOT_LEAK" not in json.dumps(result.metadata)


def test_inconsistent_package_structure_fails_closed(tmp_path: Path) -> None:
    result = analyze(write_inconsistent_ooxml(tmp_path / "inconsistent.docx"))

    assert result.parser_status is OfficeParserStatus.MALFORMED
    assert "inconsistent_package_structure" in result.metadata["partial_reasons"]


def test_entity_expansion_is_forbidden_and_bounded(tmp_path: Path) -> None:
    entity_xml = """<!DOCTYPE Relationships [
<!ENTITY a "1234567890">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">
]><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdX" Type="example" Target="&b;" TargetMode="External"/>
</Relationships>"""
    result = analyze(
        write_ooxml(
            tmp_path / "entities.docx",
            application=OfficeApplication.WORD,
            hostile_relationship_xml=entity_xml,
        )
    )

    assert result.parser_status is OfficeParserStatus.MALFORMED
    assert "unsafe_or_malformed_xml" in result.metadata["partial_reasons"]


def test_vba_parser_limitation_produces_partial_quarantinable_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import worker.analyzers.ooxml as ooxml_module

    def limited_parser(*args: object, **kwargs: object) -> VbaAnalysis:
        del args, kwargs
        return VbaAnalysis(
            macro_detected=True,
            project_count=1,
            partial_reasons={"vba_parser_error"},
            parser_exception="ControlledFixtureError",
        )

    monkeypatch.setattr(ooxml_module, "analyze_vba_blob", limited_parser)
    result = analyze(
        write_ooxml(
            tmp_path / "parser-limited.docm",
            application=OfficeApplication.WORD,
            macro_source=HARMLESS_AUTOEXEC_SOURCE,
        )
    )

    assert result.parser_status is OfficeParserStatus.PARTIAL
    assert "OFFICE_PARTIAL_ANALYSIS" in codes(result)
    assert "vba_parser_error" in result.metadata["partial_reasons"]


@pytest.mark.parametrize(
    ("fixture_options", "limits", "reason"),
    [
        ({"extra_entries": 5}, OfficeAnalysisLimits(max_zip_entries=4), "zip_entry_limit"),
        (
            {"oversized_member_bytes": 2_048},
            OfficeAnalysisLimits(max_member_bytes=1_024),
            "member_actual_byte_limit",
        ),
        (
            {"oversized_member_bytes": 2_048},
            OfficeAnalysisLimits(max_total_bytes_read=1_000),
            "total_actual_byte_limit",
        ),
        (
            {"extra_relationships": 3},
            OfficeAnalysisLimits(max_relationships=2),
            "relationship_limit",
        ),
    ],
)
def test_ooxml_resource_budgets_preserve_controlled_partial_results(
    tmp_path: Path,
    fixture_options: dict[str, int],
    limits: OfficeAnalysisLimits,
    reason: str,
) -> None:
    result = analyze(
        write_ooxml(
            tmp_path / f"limit-{reason}.docx",
            application=OfficeApplication.WORD,
            **fixture_options,  # type: ignore[arg-type]
        ),
        limits,
    )

    assert result.parser_status is OfficeParserStatus.PARTIAL
    assert "OFFICE_PARTIAL_ANALYSIS" in codes(result)
    assert reason in result.metadata["partial_reasons"]


def test_duplicate_relevant_member_is_rejected_as_ambiguous(tmp_path: Path) -> None:
    result = analyze(
        write_ooxml(
            tmp_path / "duplicate.docx",
            application=OfficeApplication.WORD,
            duplicate_content_types=True,
        )
    )

    assert result.parser_status is OfficeParserStatus.MALFORMED
    assert "duplicate_zip_member" in result.metadata["partial_reasons"]


def test_corrupt_selected_deflate_member_fails_safely(tmp_path: Path) -> None:
    path = write_ooxml(tmp_path / "corrupt.docx", application=OfficeApplication.WORD)
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo("word/_rels/document.xml.rels")
    raw = bytearray(path.read_bytes())
    name_length, extra_length = struct.unpack_from("<HH", raw, info.header_offset + 26)
    data_offset = info.header_offset + 30 + name_length + extra_length
    raw[data_offset] ^= 0xFF
    path.write_bytes(raw)

    result = analyze(path)

    assert result.parser_status is OfficeParserStatus.MALFORMED
    assert "zip_member_read_error" in result.metadata["partial_reasons"]


def test_multiple_vba_modules_are_bounded_without_returning_source() -> None:
    blob = build_vba_compound([HARMLESS_AUTOEXEC_SOURCE, HARMLESS_EXECUTION_INDICATOR_SOURCE])

    result = analyze_vba_blob(
        blob,
        display_name="bounded-project.bin",
        application=OfficeApplication.WORD,
        limits=OfficeAnalysisLimits(max_vba_modules=1),
    )

    assert result.macro_detected
    assert result.module_count == 1
    assert "vba_module_limit" in result.partial_reasons
    assert not hasattr(result, "source")
