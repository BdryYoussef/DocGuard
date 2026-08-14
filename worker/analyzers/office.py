"""Conservative content-gated routing for Microsoft Office containers."""

from __future__ import annotations

from pathlib import Path

from worker.analyzers.file_type import FileFamily
from worker.analyzers.office_types import (
    DEFAULT_OFFICE_LIMITS,
    OfficeAnalysis,
    OfficeAnalysisLimits,
    OfficeRoutingError,
)


def analyze_office(
    sample_path: Path,
    *,
    detected_family: FileFamily,
    limits: OfficeAnalysisLimits = DEFAULT_OFFICE_LIMITS,
) -> OfficeAnalysis | None:
    if detected_family in {FileFamily.ZIP, FileFamily.OOXML_CANDIDATE}:
        from worker.analyzers.ooxml import analyze_ooxml

        return analyze_ooxml(sample_path, limits=limits)
    if detected_family is FileFamily.OLE_COMPOUND:
        from worker.analyzers.ole_office import analyze_ole_office

        return analyze_ole_office(sample_path, limits=limits)
    raise OfficeRoutingError("Office analyzer requires content-identified ZIP/OOXML or OLE input")


__all__ = ["analyze_office"]
