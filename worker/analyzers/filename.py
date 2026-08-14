"""Deterministic filename and claimed-metadata deception observations."""

from __future__ import annotations

from worker.analyzers.file_type import FileFamily, FileIdentification
from worker.analyzers.name_security import (
    BUSINESS_EXTENSIONS,
    bidi_codepoints,
    final_extension,
    has_dangerous_double_extension,
)
from worker.findings import finding_payload

_EXPECTED_FAMILIES: dict[str, frozenset[FileFamily]] = {
    "pdf": frozenset({FileFamily.PDF}),
    "doc": frozenset({FileFamily.OLE_COMPOUND}),
    "xls": frozenset({FileFamily.OLE_COMPOUND}),
    "ppt": frozenset({FileFamily.OLE_COMPOUND}),
    "docx": frozenset({FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}),
    "docm": frozenset({FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}),
    "xlsx": frozenset({FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}),
    "xlsm": frozenset({FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}),
    "pptx": frozenset({FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}),
    "pptm": frozenset({FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}),
    "zip": frozenset({FileFamily.ZIP}),
    "txt": frozenset({FileFamily.TEXT}),
    "csv": frozenset({FileFamily.TEXT}),
    "rtf": frozenset({FileFamily.TEXT}),
}


def security_findings(
    filename: str,
    identification: FileIdentification,
    claimed_content_type: str | None,
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    extension = claimed_extension(filename)

    if has_dangerous_double_extension(filename):
        findings.append(finding_payload("FILE_DOUBLE_EXTENSION", {"final_extension": extension}))

    observed_bidi = bidi_codepoints(filename)
    if observed_bidi:
        findings.append(finding_payload("FILE_BIDI_OVERRIDE", {"codepoints": observed_bidi}))

    expected = _EXPECTED_FAMILIES.get(extension or "")
    if expected is not None and identification.family not in expected:
        findings.append(
            finding_payload(
                "FILE_TYPE_MISMATCH",
                {
                    "claimed_extension": extension,
                    "observed_family": identification.family.value,
                },
            )
        )

    if identification.family is FileFamily.WINDOWS_EXECUTABLE and extension in BUSINESS_EXTENSIONS:
        findings.append(
            finding_payload("FILE_EXECUTABLE_MASQUERADE", {"claimed_extension": extension})
        )

    normalized_claim = _normalized_mime(claimed_content_type)
    if (
        normalized_claim is not None
        and normalized_claim != "application/octet-stream"
        and normalized_claim != identification.mime.casefold()
    ):
        findings.append(
            finding_payload(
                "FILE_CLIENT_MIME_MISMATCH",
                {
                    "claimed_content_type": normalized_claim,
                    "observed_mime": identification.mime,
                },
            )
        )
    return findings


def claimed_extension(filename: str) -> str | None:
    return final_extension(filename)


def _normalized_mime(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.partition(";")[0].strip().casefold()
    return normalized or None
