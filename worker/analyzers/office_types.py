"""Small shared types for worker-only Office structural analysis."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum


class OfficeContainer(StrEnum):
    OOXML = "OOXML"
    OLE = "OLE"


class OfficeApplication(StrEnum):
    WORD = "WORD"
    EXCEL = "EXCEL"
    POWERPOINT = "POWERPOINT"
    UNKNOWN = "UNKNOWN"


class OfficeParserStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True, slots=True)
class OfficeAnalysisLimits:
    max_zip_entries: int = 4_096
    max_member_name_length: int = 512
    max_total_bytes_read: int = 64 * 1024 * 1024
    max_member_bytes: int = 8 * 1024 * 1024
    max_xml_parts: int = 256
    max_xml_bytes: int = 4 * 1024 * 1024
    max_relationships: int = 2_048
    max_external_relationships: int = 256
    max_embedded_objects: int = 256
    max_activex_objects: int = 256
    max_vba_projects: int = 8
    max_vba_project_bytes: int = 8 * 1024 * 1024
    max_vba_modules: int = 128
    max_vba_source_bytes: int = 4 * 1024 * 1024
    max_metadata_string_length: int = 256
    max_metadata_entries: int = 64
    max_selected_materializations: int = 8

    def __post_init__(self) -> None:
        if any(getattr(self, item.name) <= 0 for item in fields(self)):
            raise ValueError("Office analysis limits must be positive")


DEFAULT_OFFICE_LIMITS = OfficeAnalysisLimits()


@dataclass(frozen=True, slots=True)
class OfficeAnalysis:
    container: OfficeContainer
    application: OfficeApplication
    parser_status: OfficeParserStatus
    findings: tuple[dict[str, object], ...]
    metadata: dict[str, object]

    @property
    def complete(self) -> bool:
        return self.parser_status is OfficeParserStatus.COMPLETE

    @property
    def detected_type(self) -> str:
        return f"OFFICE_{self.application.value}_{self.container.value}"


class OfficeRoutingError(RuntimeError):
    """Raised when an internal caller bypasses content-family routing."""


class OfficeLimitError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


__all__ = [
    "DEFAULT_OFFICE_LIMITS",
    "OfficeAnalysis",
    "OfficeAnalysisLimits",
    "OfficeApplication",
    "OfficeContainer",
    "OfficeLimitError",
    "OfficeParserStatus",
    "OfficeRoutingError",
]
