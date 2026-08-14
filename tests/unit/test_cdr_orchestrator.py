from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.cdr.models import CdrFailureCode, CdrStatus, PdfCdrResult
from app.cdr.orchestrator import PdfCdrOrchestrator
from app.cdr.registry import build_worker_cdr_config
from app.core.config import AppEnvironment, Settings
from app.orchestrator.contract import WorkerOperation, WorkerRequest
from app.orchestrator.isolation import WorkerExecution


class CdrStubBackend:
    def __init__(self, execution: WorkerExecution) -> None:
        self.execution = execution

    @property
    def ready(self) -> bool:
        return True

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        del request, timeout_seconds
        raise AssertionError("ANALYZE was not expected")

    def sanitize(
        self, request: WorkerRequest, output_path: Path, timeout_seconds: float
    ) -> WorkerExecution:
        del output_path, timeout_seconds
        assert request.operation is WorkerOperation.SANITIZE_PDF
        return self.execution


def result_json(settings: Settings, **updates: object) -> str:
    config = build_worker_cdr_config(settings)
    payload = PdfCdrResult(
        schema_version="2.1",
        operation="SANITIZE_PDF",
        status=CdrStatus.SUCCESS,
        sanitizer_version=config.sanitizer_version,
        sanitizer_fingerprint=config.sanitizer_fingerprint,
        renderer_version="1.28.2",
        engine_version="1.28.2",
        page_count=1,
        total_pixels=1,
        output_bytes=10,
        duration_ms=1,
    ).model_dump(mode="json")
    payload.update(updates)
    return json.dumps(payload)


@pytest.mark.parametrize(
    ("execution", "expected"),
    [
        (WorkerExecution("", "", None, True), CdrFailureCode.RENDER_TIMEOUT),
        (WorkerExecution("", "crash", 2, False), CdrFailureCode.RENDER_FAILED),
        (WorkerExecution("not-json", "", 0, False), CdrFailureCode.OUTPUT_INVALID),
        (
            WorkerExecution("x", "", -9, False, output_limit_exceeded=True),
            CdrFailureCode.RENDER_FAILED,
        ),
    ],
)
def test_cdr_execution_uncertainty_fails_closed(
    tmp_path: Path, execution: WorkerExecution, expected: CdrFailureCode
) -> None:
    settings = Settings(env=AppEnvironment.TEST)
    outcome = PdfCdrOrchestrator(CdrStubBackend(execution), settings).sanitize(
        tmp_path / "source", tmp_path / "output"
    )

    assert not outcome.succeeded
    assert outcome.failure_code is expected


def test_cdr_wrong_fingerprint_is_rejected(tmp_path: Path) -> None:
    settings = Settings(env=AppEnvironment.TEST)
    execution = WorkerExecution(result_json(settings, sanitizer_fingerprint="0" * 64), "", 0, False)

    outcome = PdfCdrOrchestrator(CdrStubBackend(execution), settings).sanitize(
        tmp_path / "source", tmp_path / "output"
    )

    assert outcome.failure_code is CdrFailureCode.OUTPUT_INVALID


def test_worker_operation_configuration_is_strict(tmp_path: Path) -> None:
    base = {
        "job_id": "a" * 32,
        "sample_path": str((tmp_path / "source").resolve()),
    }
    with pytest.raises(ValueError, match="requires CDR"):
        WorkerRequest(**base, operation=WorkerOperation.SANITIZE_PDF)
    with pytest.raises(ValueError, match="forbids"):
        WorkerRequest(
            **base,
            operation=WorkerOperation.ANALYZE,
            cdr=build_worker_cdr_config(Settings(env=AppEnvironment.TEST)),
        )
