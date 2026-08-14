from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

import app.main as main_module
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.core.constants import ANALYSIS_SCHEMA_VERSION, WORKER_VERSION
from app.main import create_app
from app.models.database import Base
from app.models.domain import AnalysisResult, AnalysisStatus
from app.orchestrator.contract import WorkerRequest
from app.orchestrator.isolation import WorkerExecution
from tests.auth_helpers import authenticate_operator, csrf_headers


class ControlledBackend:
    def __init__(self, execution: WorkerExecution) -> None:
        self._execution = execution

    @property
    def ready(self) -> bool:
        return True

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        del request, timeout_seconds
        return self._execution


def result_json(status: AnalysisStatus) -> str:
    now = datetime.now(UTC)
    return AnalysisResult(
        schema_version=ANALYSIS_SCHEMA_VERSION,
        worker_version=WORKER_VERSION,
        status=status,
        detected_type="UNKNOWN",
        size_bytes=7,
        findings=[],
        analyzer_metadata={"detected_mime": "application/octet-stream"},
        started_at=now,
        completed_at=now,
        duration_ms=0,
    ).to_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "execution",
    [
        WorkerExecution("", "crash", 2, False),
        WorkerExecution("", "", None, True),
        WorkerExecution("not-json", "", 0, False),
        WorkerExecution(result_json(AnalysisStatus.UNSUPPORTED), "", 0, False),
        WorkerExecution(result_json(AnalysisStatus.FAILED), "", 0, False),
    ],
    ids=["crash", "timeout", "malformed", "unsupported", "identification-failed"],
)
async def test_analysis_uncertainty_never_creates_releasable_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    execution: WorkerExecution,
) -> None:
    backend = ControlledBackend(execution)
    monkeypatch.setattr(main_module, "create_isolation_backend", lambda settings: backend)
    settings = Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'failure.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.BUBBLEWRAP,
        application_origin="http://test",
    )
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans?filename=fixture.bin",
                content=b"fixture",
                headers=csrf_headers(csrf),
            )

    assert response.status_code == 201
    assert response.json()["state"] == "QUARANTINED"
    assert response.json()["analysis_status"] in {"FAILED", "UNSUPPORTED"}
