from pathlib import Path

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.models.domain import AnalysisStatus
from app.orchestrator.isolation import UnsafeDevelopmentBackend
from app.orchestrator.service import AnalysisOrchestrator


def test_dummy_worker_contract_end_to_end(tmp_path: Path) -> None:
    fixture = tmp_path / "generated-fixture.txt"
    fixture.write_text("DOCGUARD_TEST_MARKER\nHarmless fixture.\n", encoding="utf-8")
    settings = Settings(
        env=AppEnvironment.TEST,
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        worker_timeout_seconds=5.0,
    )
    backend = UnsafeDevelopmentBackend(settings, project_root=Path.cwd())

    outcome = AnalysisOrchestrator(
        backend, timeout_seconds=settings.worker_timeout_seconds
    ).analyze(fixture.resolve())

    assert outcome.succeeded is True
    assert outcome.result is not None
    assert outcome.result.status is AnalysisStatus.SUCCESS
    assert outcome.result.findings == []
