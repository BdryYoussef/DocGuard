"""Conservative classic OLE Office inspection using worker-only olefile."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

import olefile

from worker.analyzers.office_types import (
    OfficeAnalysis,
    OfficeAnalysisLimits,
    OfficeApplication,
    OfficeContainer,
    OfficeParserStatus,
)
from worker.analyzers.vba import VbaAnalysis, analyze_vba_blob
from worker.constants import OFFICE_OLE_PARSER_NAME, OFFICE_OLE_PARSER_VERSION
from worker.findings import finding_payload

_EXPECTED_ERRORS = (
    IndexError,
    KeyError,
    OSError,
    TypeError,
    ValueError,
    struct.error,
)


@dataclass(slots=True)
class _OleState:
    limits: OfficeAnalysisLimits
    application: OfficeApplication = OfficeApplication.UNKNOWN
    stream_count: int = 0
    macro_enabled: bool = False
    vba_project_count: int = 0
    embedded_object_count: int = 0
    activex_count: int = 0
    encrypted: bool = False
    malformed: bool = False
    parser_exception: str | None = None
    partial_reasons: set[str] = field(default_factory=set)
    vba: VbaAnalysis = field(default_factory=VbaAnalysis)

    def partial(self, reason: str) -> None:
        self.partial_reasons.add(reason)


def analyze_ole_office(path: Path, *, limits: OfficeAnalysisLimits) -> OfficeAnalysis | None:
    if olefile.__version__ != OFFICE_OLE_PARSER_VERSION:
        raise RuntimeError("unexpected OLE parser version")
    try:
        is_ole = olefile.isOleFile(path)
    except _EXPECTED_ERRORS:
        return None
    if not is_ole:
        return None

    state = _OleState(limits=limits)
    try:
        ole = olefile.OleFileIO(path, write_mode=False, path_encoding=None)
    except _EXPECTED_ERRORS as exc:
        state.malformed = True
        state.parser_exception = type(exc).__name__
        state.partial("ole_parser_rejected_container")
        return _result(state)

    with ole:
        try:
            entries = ole.listdir(streams=True, storages=True)
            state.stream_count = len(entries)
            if len(entries) > limits.max_zip_entries:
                state.partial("ole_entry_limit")
                entries = entries[: limits.max_zip_entries]
            normalized = {"/".join(part.casefold() for part in entry) for entry in entries}
            state.application = _classify_application(normalized)
            encrypted_names = {"encryptioninfo", "encryptedpackage"}
            leaf_names = {entry.rsplit("/", 1)[-1] for entry in normalized}
            state.encrypted = encrypted_names.issubset(leaf_names)

            embedded = {
                entry
                for entry in normalized
                if entry.rsplit("/", 1)[-1] in {"\x01ole10native", "ole10native", "package"}
                or entry.startswith("objectpool/")
            }
            state.embedded_object_count = min(len(embedded), limits.max_embedded_objects)
            if len(embedded) > limits.max_embedded_objects:
                state.partial("embedded_object_limit")
            activex = {
                entry
                for entry in normalized
                if entry.startswith(("ctls/", "activex/")) or "/activex/" in entry
            }
            state.activex_count = min(len(activex), limits.max_activex_objects)
            if len(activex) > limits.max_activex_objects:
                state.partial("activex_object_limit")

            vba_dirs = {
                entry.rsplit("/", 1)[0]
                for entry in normalized
                if entry.endswith("/dir") and (entry.startswith("vba/") or "/vba/" in entry)
            }
            state.vba_project_count = len(vba_dirs)
            if state.application is not OfficeApplication.UNKNOWN and not state.encrypted:
                data = _read_path_bounded(path, limits.max_vba_project_bytes)
                if data is None:
                    state.partial("vba_project_size_limit")
                else:
                    state.vba = analyze_vba_blob(
                        data,
                        display_name="classic-office-document.ole",
                        application=state.application,
                        limits=limits,
                    )
                    state.partial_reasons.update(state.vba.partial_reasons)
                    if state.vba.macro_detected:
                        state.vba_project_count = max(1, state.vba_project_count)
            state.macro_enabled = bool(state.vba_project_count or state.vba.macro_detected)
            if state.application is OfficeApplication.UNKNOWN and not (
                state.encrypted or state.macro_enabled
            ):
                return None
            if state.application is OfficeApplication.UNKNOWN:
                state.partial("ole_application_unclassified")
            if state.encrypted:
                state.partial("office_encryption_prevents_inspection")
        except _EXPECTED_ERRORS as exc:
            state.malformed = True
            state.parser_exception = type(exc).__name__
            state.partial("ole_parser_error")
    return _result(state)


def _classify_application(entries: set[str]) -> OfficeApplication:
    if "worddocument" in entries:
        return OfficeApplication.WORD
    if entries.intersection({"workbook", "book"}):
        return OfficeApplication.EXCEL
    if "powerpoint document" in entries:
        return OfficeApplication.POWERPOINT
    return OfficeApplication.UNKNOWN


def _read_path_bounded(path: Path, maximum_bytes: int) -> bytes | None:
    data = bytearray()
    with path.open("rb") as source:
        while True:
            chunk = source.read(min(65_536, maximum_bytes + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > maximum_bytes:
                return None


def _result(state: _OleState) -> OfficeAnalysis:
    findings: list[dict[str, object]] = []
    if state.macro_enabled:
        findings.append(
            finding_payload(
                "OFFICE_MACRO_ENABLED",
                {
                    "application": state.application.value,
                    "vba_project_count": state.vba_project_count,
                },
            )
        )
    if state.vba_project_count or state.vba.macro_detected:
        findings.append(
            finding_payload(
                "OFFICE_VBA_MACRO",
                {
                    "application": state.application.value,
                    "project_count": state.vba_project_count,
                    "module_count": state.vba.module_count,
                    "module_names": sorted(set(state.vba.module_names))[
                        : state.limits.max_metadata_entries
                    ],
                },
            )
        )
    if state.vba.autoexec_triggers:
        findings.append(
            finding_payload(
                "OFFICE_VBA_AUTOEXEC", {"triggers": sorted(state.vba.autoexec_triggers)}
            )
        )
    if state.vba.indicator_classes:
        findings.append(
            finding_payload(
                "OFFICE_VBA_EXECUTION_INDICATOR",
                {
                    "indicator_classes": sorted(state.vba.indicator_classes),
                    "indicators": sorted(state.vba.indicator_names),
                },
            )
        )
    if state.embedded_object_count:
        findings.append(
            finding_payload("OFFICE_EMBEDDED_OBJECT", {"count": state.embedded_object_count})
        )
    if state.activex_count:
        findings.append(finding_payload("OFFICE_ACTIVEX", {"count": state.activex_count}))
    if state.encrypted:
        findings.append(finding_payload("OFFICE_ENCRYPTED", {"container": "OLE"}))
    if state.malformed:
        findings.append(
            finding_payload("OFFICE_MALFORMED", {"parser_exception": state.parser_exception})
        )
    if state.partial_reasons:
        findings.append(
            finding_payload("OFFICE_PARTIAL_ANALYSIS", {"reasons": sorted(state.partial_reasons)})
        )
    if state.malformed:
        parser_status = OfficeParserStatus.MALFORMED
    elif state.partial_reasons:
        parser_status = OfficeParserStatus.PARTIAL
    else:
        parser_status = OfficeParserStatus.COMPLETE
    metadata: dict[str, object] = {
        "container": OfficeContainer.OLE.value,
        "application": state.application.value,
        "parser_status": parser_status.value,
        "ole_parser": OFFICE_OLE_PARSER_NAME,
        "ole_parser_version": olefile.__version__,
        "entry_count": state.stream_count,
        "macro_enabled": state.macro_enabled,
        "vba_project_count": state.vba_project_count,
        "vba_module_count": state.vba.module_count,
        "embedded_object_count": state.embedded_object_count,
        "activex_count": state.activex_count,
        "encrypted": state.encrypted,
        "partial_reasons": sorted(state.partial_reasons),
    }
    return OfficeAnalysis(
        OfficeContainer.OLE,
        state.application,
        parser_status,
        tuple(findings),
        metadata,
    )


__all__ = ["analyze_ole_office"]
