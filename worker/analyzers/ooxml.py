"""Bounded OOXML package inspection without extraction or active resolution."""

from __future__ import annotations

import unicodedata
import zipfile
import zlib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element, ParseError

import defusedxml
from defusedxml import ElementTree as SafeElementTree
from defusedxml.common import DefusedXmlException

from worker.analyzers.office_types import (
    OfficeAnalysis,
    OfficeAnalysisLimits,
    OfficeApplication,
    OfficeContainer,
    OfficeLimitError,
    OfficeParserStatus,
)
from worker.analyzers.vba import VbaAnalysis, analyze_vba_blob
from worker.constants import OFFICE_XML_PARSER_NAME, OFFICE_XML_PARSER_VERSION
from worker.findings import finding_payload

_CONTENT_TYPES_PART = "[Content_Types].xml"
_ROOT_RELATIONSHIPS_PART = "_rels/.rels"
_CONTENT_TYPES_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/content-types"
_RELATIONSHIPS_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/relationships"
_APPLICATION_PATHS = {
    OfficeApplication.WORD: "word/document.xml",
    OfficeApplication.EXCEL: "xl/workbook.xml",
    OfficeApplication.POWERPOINT: "ppt/presentation.xml",
}
_APPLICATION_MARKERS = {
    OfficeApplication.WORD: ("wordprocessingml", "vnd.ms-word"),
    OfficeApplication.EXCEL: ("spreadsheetml", "vnd.ms-excel"),
    OfficeApplication.POWERPOINT: ("presentationml", "vnd.ms-powerpoint"),
}
_VBA_PATHS = {
    OfficeApplication.WORD: "word/vbaProject.bin",
    OfficeApplication.EXCEL: "xl/vbaProject.bin",
    OfficeApplication.POWERPOINT: "ppt/vbaProject.bin",
}
_EMBEDDING_PREFIXES = ("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")
_ACTIVEX_PREFIXES = ("word/activeX/", "xl/activeX/", "ppt/activeX/")
_BIDI_CONTROLS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


@dataclass(slots=True)
class _State:
    limits: OfficeAnalysisLimits
    application: OfficeApplication = OfficeApplication.UNKNOWN
    entry_count: int = 0
    bytes_read: int = 0
    xml_parts_parsed: int = 0
    xml_bytes_parsed: int = 0
    relationship_count: int = 0
    external_relationship_count: int = 0
    external_summaries: list[dict[str, object]] = field(default_factory=list)
    external_summary_capped: bool = False
    external_template_count: int = 0
    external_template_summaries: list[dict[str, object]] = field(default_factory=list)
    embedded_object_count: int = 0
    activex_count: int = 0
    macro_enabled: bool = False
    vba_project_count: int = 0
    encrypted: bool = False
    malformed: bool = False
    parser_exception: str | None = None
    partial_reasons: set[str] = field(default_factory=set)
    vba: VbaAnalysis = field(default_factory=VbaAnalysis)

    def partial(self, reason: str) -> None:
        self.partial_reasons.add(reason)

    def malformed_part(self, reason: str, exc: BaseException | None = None) -> None:
        self.malformed = True
        self.partial(reason)
        if exc is not None:
            self.parser_exception = type(exc).__name__


def analyze_ooxml(path: Path, *, limits: OfficeAnalysisLimits) -> OfficeAnalysis | None:
    state = _State(limits=limits)
    try:
        archive = zipfile.ZipFile(path, mode="r")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return None

    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if _CONTENT_TYPES_PART not in names:
            return None
        state.entry_count = len(infos)
        if len(infos) > limits.max_zip_entries:
            state.partial("zip_entry_limit")
            return _result(state)
        if any(len(name) > limits.max_member_name_length for name in names):
            state.partial("zip_member_name_limit")
        duplicates = {name for name, count in Counter(names).items() if count > 1}
        if duplicates:
            state.malformed_part("duplicate_zip_member")
            return _result(state)
        members = {info.filename: info for info in infos}
        if any(info.flag_bits & 0x1 for info in infos):
            state.encrypted = True
            state.partial("encrypted_zip_member")

        try:
            content_types_root = _read_xml(
                archive, members, _CONTENT_TYPES_PART, state, required=True
            )
            if content_types_root is None:
                return _result(state)
            overrides = _content_type_overrides(content_types_root, state)
            _classify_package(overrides, members, state)
            if state.application is OfficeApplication.UNKNOWN:
                state.malformed_part("inconsistent_package_structure")
            _inspect_relationships(archive, members, state)
            _inspect_capabilities(members, overrides, archive, state)
        except OfficeLimitError as exc:
            state.partial(exc.reason)
        except (DefusedXmlException, ParseError, ValueError) as exc:
            state.malformed_part("unsafe_or_malformed_xml", exc)
        except (OSError, EOFError, zipfile.BadZipFile, zlib.error) as exc:
            state.malformed_part("zip_member_read_error", exc)
    return _result(state)


def _read_member(
    archive: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    name: str,
    state: _State,
    *,
    maximum_bytes: int | None = None,
) -> bytes:
    info = members.get(name)
    if info is None:
        raise ValueError(f"required OOXML member is absent: {name}")
    member_limit = min(
        maximum_bytes or state.limits.max_member_bytes,
        state.limits.max_member_bytes,
    )
    data = bytearray()
    try:
        with archive.open(info, mode="r") as source:
            while True:
                chunk = source.read(min(65_536, member_limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                state.bytes_read += len(chunk)
                if len(data) > member_limit:
                    raise OfficeLimitError("member_actual_byte_limit")
                if state.bytes_read > state.limits.max_total_bytes_read:
                    raise OfficeLimitError("total_actual_byte_limit")
    except RuntimeError as exc:
        if info.flag_bits & 0x1:
            state.encrypted = True
            raise OfficeLimitError("encrypted_zip_member") from exc
        raise
    return bytes(data)


def _read_xml(
    archive: zipfile.ZipFile,
    members: dict[str, zipfile.ZipInfo],
    name: str,
    state: _State,
    *,
    required: bool = False,
) -> Element | None:
    if name not in members:
        if required:
            state.malformed_part("required_xml_part_missing")
        return None
    if state.xml_parts_parsed >= state.limits.max_xml_parts:
        raise OfficeLimitError("xml_part_limit")
    remaining_xml = state.limits.max_xml_bytes - state.xml_bytes_parsed
    if remaining_xml <= 0:
        raise OfficeLimitError("xml_actual_byte_limit")
    data = _read_member(
        archive,
        members,
        name,
        state,
        maximum_bytes=min(remaining_xml, state.limits.max_member_bytes),
    )
    state.xml_parts_parsed += 1
    state.xml_bytes_parsed += len(data)
    return cast(Element, SafeElementTree.fromstring(data))


def _content_type_overrides(root: Element, state: _State) -> dict[str, str]:
    tag = getattr(root, "tag", "")
    if tag != f"{{{_CONTENT_TYPES_NAMESPACE}}}Types":
        raise ValueError("invalid content-types root")
    overrides: dict[str, str] = {}
    for element in root:
        if getattr(element, "tag", "") != f"{{{_CONTENT_TYPES_NAMESPACE}}}Override":
            continue
        part_name = str(element.attrib.get("PartName", "")).lstrip("/")
        content_type = str(element.attrib.get("ContentType", ""))
        if not part_name or not content_type:
            raise ValueError("invalid content-type override")
        if part_name in overrides and overrides[part_name] != content_type:
            state.malformed_part("ambiguous_content_type")
        overrides[part_name] = content_type
    return overrides


def _classify_package(
    overrides: dict[str, str], members: dict[str, zipfile.ZipInfo], state: _State
) -> None:
    candidates: set[OfficeApplication] = set()
    for application, expected_path in _APPLICATION_PATHS.items():
        content_type = overrides.get(expected_path, "").casefold()
        if expected_path in members and any(
            marker in content_type for marker in _APPLICATION_MARKERS[application]
        ):
            candidates.add(application)
    if len(candidates) != 1:
        return
    application = candidates.pop()
    state.application = application
    main_type = overrides[_APPLICATION_PATHS[application]].casefold()
    state.macro_enabled = "macroenabled" in main_type


def _inspect_relationships(
    archive: zipfile.ZipFile, members: dict[str, zipfile.ZipInfo], state: _State
) -> None:
    root = _read_xml(archive, members, _ROOT_RELATIONSHIPS_PART, state, required=True)
    if root is None:
        return
    root_office_targets = _relationship_targets(root, state, collect_external=False)
    expected = _APPLICATION_PATHS.get(state.application)
    if expected is not None and expected not in root_office_targets:
        state.malformed_part("office_document_relationship_missing")

    relationship_names = sorted(
        name for name in members if name.endswith(".rels") and name != _ROOT_RELATIONSHIPS_PART
    )
    for name in relationship_names:
        root = _read_xml(archive, members, name, state)
        if root is not None:
            _relationship_targets(root, state, collect_external=True)


def _relationship_targets(root: Element, state: _State, *, collect_external: bool) -> set[str]:
    if getattr(root, "tag", "") != f"{{{_RELATIONSHIPS_NAMESPACE}}}Relationships":
        raise ValueError("invalid relationships root")
    office_targets: set[str] = set()
    for element in root:
        if getattr(element, "tag", "") != f"{{{_RELATIONSHIPS_NAMESPACE}}}Relationship":
            continue
        if state.relationship_count >= state.limits.max_relationships:
            raise OfficeLimitError("relationship_limit")
        state.relationship_count += 1
        relationship_type = str(element.attrib.get("Type", ""))
        target = str(element.attrib.get("Target", ""))
        target_mode = str(element.attrib.get("TargetMode", ""))
        if relationship_type.casefold().endswith("/officedocument") and target:
            office_targets.add(str(PurePosixPath(target)))
        if not collect_external or target_mode.casefold() != "external":
            continue
        if state.external_relationship_count >= state.limits.max_external_relationships:
            raise OfficeLimitError("external_relationship_limit")
        state.external_relationship_count += 1
        summary = _external_summary(relationship_type, target, state.limits)
        if len(state.external_summaries) < state.limits.max_metadata_entries:
            state.external_summaries.append(summary)
        else:
            state.external_summary_capped = True
        if relationship_type.casefold().endswith("/attachedtemplate"):
            state.external_template_count += 1
            if len(state.external_template_summaries) < state.limits.max_metadata_entries:
                state.external_template_summaries.append(summary)
    return office_targets


def _inspect_capabilities(
    members: dict[str, zipfile.ZipInfo],
    overrides: dict[str, str],
    archive: zipfile.ZipFile,
    state: _State,
) -> None:
    names = set(members)
    embedded = sorted(name for name in names if name.startswith(_EMBEDDING_PREFIXES))
    activex = sorted(name for name in names if name.startswith(_ACTIVEX_PREFIXES))
    state.embedded_object_count = min(len(embedded), state.limits.max_embedded_objects)
    state.activex_count = min(len(activex), state.limits.max_activex_objects)
    if len(embedded) > state.limits.max_embedded_objects:
        state.partial("embedded_object_limit")
    if len(activex) > state.limits.max_activex_objects:
        state.partial("activex_object_limit")

    expected_vba_path = _VBA_PATHS.get(state.application)
    vba_members = sorted(
        name
        for name, content_type in overrides.items()
        if "vbaproject" in content_type.casefold() and name in members
    )
    if expected_vba_path in members and expected_vba_path not in vba_members:
        vba_members.append(expected_vba_path)
    state.vba_project_count = len(vba_members)
    state.macro_enabled = state.macro_enabled or bool(vba_members)
    if len(vba_members) > state.limits.max_vba_projects:
        state.partial("vba_project_count_limit")
        vba_members = vba_members[: state.limits.max_vba_projects]

    for name in vba_members:
        try:
            data = _read_member(
                archive,
                members,
                name,
                state,
                maximum_bytes=state.limits.max_vba_project_bytes,
            )
        except OfficeLimitError as exc:
            state.partial(exc.reason)
            continue
        analysis = analyze_vba_blob(
            data,
            display_name="selected-vba-project.bin",
            application=state.application,
            limits=state.limits,
        )
        _merge_vba(state.vba, analysis, state.limits)
        state.partial_reasons.update(analysis.partial_reasons)


def _merge_vba(target: VbaAnalysis, source: VbaAnalysis, limits: OfficeAnalysisLimits) -> None:
    target.macro_detected = target.macro_detected or source.macro_detected
    target.project_count = min(target.project_count + 1, limits.max_vba_projects)
    target.module_count = min(target.module_count + source.module_count, limits.max_vba_modules)
    target.source_bytes_inspected = min(
        target.source_bytes_inspected + source.source_bytes_inspected,
        limits.max_vba_source_bytes,
    )
    for name in source.module_names:
        if len(target.module_names) < limits.max_metadata_entries:
            target.module_names.append(name)
    target.autoexec_triggers.update(source.autoexec_triggers)
    target.indicator_classes.update(source.indicator_classes)
    target.indicator_names.update(source.indicator_names)
    target.partial_reasons.update(source.partial_reasons)
    target.parser_exception = target.parser_exception or source.parser_exception


def _external_summary(
    relationship_type: str, target: str, limits: OfficeAnalysisLimits
) -> dict[str, object]:
    safe_target = target[:2_048]
    summary: dict[str, object] = {
        "relationship_type": _safe_text(
            relationship_type[-2_048:].rsplit("/", 1)[-1] or "unknown",
            limits,
            hard_limit=128,
        ),
        "target_length": len(target),
        "target_truncated": len(target) > len(safe_target),
    }
    try:
        if safe_target.startswith(("\\\\", "//")):
            pieces = safe_target.replace("\\", "/").lstrip("/").split("/", 1)
            summary["scheme"] = "unc"
            if pieces and pieces[0]:
                summary["hostname"] = _safe_text(pieces[0], limits, hard_limit=128)
        else:
            parsed = urlsplit(safe_target)
            if parsed.scheme:
                summary["scheme"] = _safe_text(parsed.scheme.casefold(), limits, hard_limit=32)
            if parsed.hostname:
                summary["hostname"] = _safe_text(parsed.hostname, limits, hard_limit=128)
    except (UnicodeError, ValueError):
        summary["parse_status"] = "invalid"
    return summary


def _result(state: _State) -> OfficeAnalysis:
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
                "OFFICE_VBA_AUTOEXEC",
                {"triggers": sorted(state.vba.autoexec_triggers)},
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
    if state.external_relationship_count:
        findings.append(
            finding_payload(
                "OFFICE_EXTERNAL_RELATIONSHIP",
                {
                    "count": state.external_relationship_count,
                    "targets": state.external_summaries,
                    "targets_capped": state.external_summary_capped,
                },
            )
        )
    if state.external_template_count:
        findings.append(
            finding_payload(
                "OFFICE_EXTERNAL_TEMPLATE",
                {
                    "count": state.external_template_count,
                    "targets": state.external_template_summaries,
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
        findings.append(finding_payload("OFFICE_ENCRYPTED", {"container": "OOXML"}))
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
        "container": OfficeContainer.OOXML.value,
        "application": state.application.value,
        "parser_status": parser_status.value,
        "xml_parser": OFFICE_XML_PARSER_NAME,
        "xml_parser_version": defusedxml.__version__,
        "entry_count": state.entry_count,
        "actual_bytes_read": state.bytes_read,
        "xml_parts_parsed": state.xml_parts_parsed,
        "xml_bytes_parsed": state.xml_bytes_parsed,
        "relationship_count": state.relationship_count,
        "external_relationship_count": state.external_relationship_count,
        "embedded_object_count": state.embedded_object_count,
        "activex_count": state.activex_count,
        "macro_enabled": state.macro_enabled,
        "vba_project_count": state.vba_project_count,
        "vba_module_count": state.vba.module_count,
        "encrypted": state.encrypted,
        "partial_reasons": sorted(state.partial_reasons),
    }
    if defusedxml.__version__ != OFFICE_XML_PARSER_VERSION:
        raise RuntimeError("unexpected XML parser version")
    return OfficeAnalysis(
        OfficeContainer.OOXML,
        state.application,
        parser_status,
        tuple(findings),
        metadata,
    )


def _safe_text(value: str, limits: OfficeAnalysisLimits, *, hard_limit: int) -> str:
    normalized = unicodedata.normalize("NFC", value)
    sanitized = "".join(
        character
        for character in normalized
        if character not in _BIDI_CONTROLS and not unicodedata.category(character).startswith("C")
    )
    return sanitized[: min(hard_limit, limits.max_metadata_string_length)] or "unknown"


__all__ = ["analyze_ooxml"]
