from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import ANALYSIS_SCHEMA_VERSION, WORKER_VERSION
from app.models.domain import AnalysisResult, AnalysisStatus


@pytest.fixture
def valid_analysis_result() -> AnalysisResult:
    started = datetime.now(UTC)
    return AnalysisResult(
        schema_version=ANALYSIS_SCHEMA_VERSION,
        worker_version=WORKER_VERSION,
        status=AnalysisStatus.SUCCESS,
        detected_type="text/plain; fixture-only",
        size_bytes=10,
        findings=[],
        analyzer_metadata={"analyzer": "test"},
        started_at=started,
        completed_at=started + timedelta(milliseconds=2),
        duration_ms=2,
    )
