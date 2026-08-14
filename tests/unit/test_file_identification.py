from __future__ import annotations

import zipfile
from pathlib import Path

from tests.fixtures.office_factory import write_classic_ole, write_encrypted_office_ole, write_ooxml
from worker.analyzers.file_type import FileFamily, FileIdentification, identify_file
from worker.analyzers.filename import security_findings
from worker.analyzers.office_types import OfficeApplication


def inert_pe_fixture() -> bytes:
    return b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 128


def test_pdf_zip_executable_text_and_unknown_families(tmp_path: Path) -> None:
    pdf = tmp_path / "pdf"
    pdf.write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    archive = tmp_path / "zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("harmless.txt", "fixture")
    executable = tmp_path / "pe"
    executable.write_bytes(inert_pe_fixture())
    text = tmp_path / "text"
    text.write_text("harmless text fixture\n", encoding="utf-8")
    unknown = tmp_path / "unknown"
    unknown.write_bytes(bytes(range(1, 32)))

    assert identify_file(pdf).family is FileFamily.PDF
    assert identify_file(archive).family is FileFamily.ZIP
    assert identify_file(executable).family is FileFamily.WINDOWS_EXECUTABLE
    assert identify_file(text).family is FileFamily.TEXT
    assert identify_file(unknown).family is FileFamily.UNKNOWN


def test_real_double_extension_is_flagged_but_dotted_name_is_not() -> None:
    pdf = FileIdentification("application/pdf", FileFamily.PDF, "PDF document")

    attack_codes = {item["code"] for item in security_findings("invoice.pdf.exe", pdf, None)}
    ordinary_codes = {item["code"] for item in security_findings("quarterly.report.pdf", pdf, None)}

    assert "FILE_DOUBLE_EXTENSION" in attack_codes
    assert "FILE_DOUBLE_EXTENSION" not in ordinary_codes


def test_ooxml_classic_ole_and_encrypted_ole_are_content_identified(tmp_path: Path) -> None:
    ooxml = write_ooxml(tmp_path / "ooxml", application=OfficeApplication.WORD)
    classic = write_classic_ole(tmp_path / "classic")
    encrypted = write_encrypted_office_ole(tmp_path / "encrypted")

    assert identify_file(ooxml).family is FileFamily.OOXML_CANDIDATE
    assert identify_file(classic).family is FileFamily.OLE_COMPOUND
    assert identify_file(encrypted).family is FileFamily.OLE_COMPOUND


def test_bidi_override_is_flagged_without_normalizing_security_name() -> None:
    pdf = FileIdentification("application/pdf", FileFamily.PDF, "PDF document")

    findings = security_findings("invoice\u202efdp.exe", pdf, None)

    assert "FILE_BIDI_OVERRIDE" in {item["code"] for item in findings}


def test_executable_pdf_masquerade_emits_stable_findings() -> None:
    executable = FileIdentification(
        "application/vnd.microsoft.portable-executable",
        FileFamily.WINDOWS_EXECUTABLE,
        "PE executable",
    )

    findings = security_findings("invoice.pdf", executable, "application/pdf")
    codes = {item["code"] for item in findings}

    assert "FILE_TYPE_MISMATCH" in codes
    assert "FILE_EXECUTABLE_MASQUERADE" in codes
    assert "FILE_CLIENT_MIME_MISMATCH" in codes
