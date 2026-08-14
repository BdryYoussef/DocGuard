"""Typed limits and result models for worker-only ZIP inspection."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum


class ArchiveParserStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MALFORMED = "MALFORMED"


@dataclass(frozen=True, slots=True)
class ArchiveAnalysisLimits:
    max_zip_entries: int = 4_096
    max_nesting_depth: int = 3
    max_members_inspected: int = 8_192
    max_compressed_bytes_considered: int = 128 * 1024 * 1024
    max_member_bytes: int = 32 * 1024 * 1024
    max_total_decompressed_bytes: int = 128 * 1024 * 1024
    max_nested_archive_bytes: int = 32 * 1024 * 1024
    max_member_name_length: int = 512
    max_findings: int = 64
    max_suspicious_member_names: int = 32
    max_duplicate_records: int = 16
    max_traversal_records: int = 16
    max_metadata_string_length: int = 256

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name == "max_nesting_depth":
                if value < 0:
                    raise ValueError("archive nesting depth must not be negative")
            elif value <= 0:
                raise ValueError("archive analysis limits must be positive")
        if self.max_findings < 4:
            raise ValueError("archive finding limit must allow fail-closed limit findings")


DEFAULT_ARCHIVE_LIMITS = ArchiveAnalysisLimits()


@dataclass(frozen=True, slots=True)
class ArchiveAnalysis:
    parser_status: ArchiveParserStatus
    findings: tuple[dict[str, object], ...]
    metadata: dict[str, object]

    @property
    def complete(self) -> bool:
        return self.parser_status is ArchiveParserStatus.COMPLETE

    @property
    def detected_type(self) -> str:
        return "ZIP"


class ArchiveRoutingError(RuntimeError):
    """Raised when an internal caller bypasses content-family routing."""


__all__ = [
    "DEFAULT_ARCHIVE_LIMITS",
    "ArchiveAnalysis",
    "ArchiveAnalysisLimits",
    "ArchiveParserStatus",
    "ArchiveRoutingError",
]
