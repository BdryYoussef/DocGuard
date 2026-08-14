from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from alembic.config import Config

import app.main as main_module
from alembic import command
from app.cdr.orchestrator import PdfCdrOrchestrator
from app.core.config import Settings
from app.main import create_app
from app.models.database import Base
from app.models.domain import AnalysisStatus
from app.orchestrator.isolation import BubblewrapBackend, SandboxSelfTest
from app.orchestrator.service import AnalysisOrchestrator
from tests.auth_helpers import TEST_OPERATOR_PASSWORD, authenticate_operator
from tests.fixtures.archive_factory import archive_bytes, nested_archive_bytes
from tests.fixtures.office_factory import HARMLESS_AUTOEXEC_SOURCE, write_ooxml
from tests.fixtures.pdf_factory import (
    write_benign_pdf,
    write_javascript_pdf,
    write_malformed_pdf,
    write_multiple_actions_pdf,
)
from tests.fixtures.yara_factory import EICAR_TEST_BYTES
from tests.unit.test_file_identification import inert_pe_fixture
from worker.analyzers.office_types import OfficeApplication


@pytest.fixture(scope="module")
def production_backend() -> BubblewrapBackend:
    return BubblewrapBackend(Settings(), project_root=Path.cwd())


def require_host_boundary(result: SandboxSelfTest) -> None:
    if not result.passed:
        pytest.skip(f"host isolation unavailable: {result.diagnostics}")


def test_bubblewrap_self_test_verifies_complete_boundary(
    production_backend: BubblewrapBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCGUARD_PARENT_SECRET", "must-not-enter-worker")

    result = production_backend.self_test(force=True)
    require_host_boundary(result)

    assert result.process_executes
    assert result.network_blocked
    assert result.parent_file_hidden
    assert result.parent_environment_hidden
    assert result.outside_write_blocked
    assert result.input_readable
    assert result.input_read_only
    assert result.work_writable
    assert result.trusted_paths_hidden
    assert result.capabilities_dropped
    assert result.resource_limits_applied
    assert result.worker_dependencies_load
    assert result.renderer_runtime_loads
    assert result.archive_runtime_loads
    assert result.yara_rule_pack_qualifies
    assert result.yara_rules_read_only
    assert result.timeout_enforced
    assert result.output_limit_enforced
    assert result.sanitize_output_writable
    assert result.sanitize_output_contained


def test_production_bubblewrap_raster_cdr_output_is_reanalyzed(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    require_host_boundary(production_backend.self_test())
    source = write_javascript_pdf(tmp_path / "active-source.pdf")
    source.chmod(0o400)
    output = tmp_path / "dedicated-output"
    output.touch(mode=0o600)
    settings = Settings()

    rendered = PdfCdrOrchestrator(production_backend, settings).sanitize(source, output)

    assert rendered.succeeded
    assert rendered.result is not None
    assert rendered.result.page_count == 1
    assert output.read_bytes().startswith(b"%PDF-")
    output.chmod(0o400)
    rescanned = AnalysisOrchestrator(production_backend, timeout_seconds=5.0).analyze(
        output.resolve(), original_filename="docguard-cdr.pdf"
    )
    assert rescanned.succeeded
    assert rescanned.result is not None
    assert rescanned.result.detected_type == "PDF"
    assert not any(finding.code.startswith("PDF_") for finding in rescanned.result.findings)


def test_production_bubblewrap_executes_controlled_worker(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    result = production_backend.self_test()
    require_host_boundary(result)
    fixture = tmp_path / "fixture"
    fixture.write_text("DOCGUARD_TEST_MARKER\n", encoding="utf-8")
    fixture.chmod(0o400)

    outcome = AnalysisOrchestrator(production_backend, timeout_seconds=3.0).analyze(
        fixture.resolve()
    )

    assert outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.status is AnalysisStatus.SUCCESS
    assert outcome.result.findings == []


@pytest.mark.asyncio
async def test_production_readiness_requires_passing_self_test(
    tmp_path: Path,
    production_backend: BubblewrapBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_host_boundary(production_backend.self_test())
    monkeypatch.setattr(
        main_module, "create_isolation_backend", lambda settings: production_backend
    )
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'ready.db'}",
        storage_root=tmp_path / "storage",
        application_origin="https://test",
    )
    migration_config = Config("alembic.ini")
    migration_config.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(migration_config, "head")
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://test") as client,
    ):
        app.state.authentication_service.create_operator(
            "production-operator", TEST_OPERATOR_PASSWORD
        )
        response = await client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_production_bubblewrap_runs_pdf_parser_without_network(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    require_host_boundary(production_backend.self_test())
    fixture = write_multiple_actions_pdf(tmp_path / "multiple-actions.pdf")

    outcome = AnalysisOrchestrator(production_backend, timeout_seconds=5.0).analyze(
        fixture.resolve(), original_filename="multiple-actions.pdf"
    )

    assert outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.status is AnalysisStatus.SUCCESS
    codes = {finding.code for finding in outcome.result.findings}
    assert {"PDF_JAVASCRIPT", "PDF_LAUNCH_ACTION", "PDF_EXTERNAL_URI"}.issubset(codes)
    assert len(outcome.result.to_json().encode("utf-8")) < 32_768


def test_production_bubblewrap_returns_controlled_malformed_pdf_result(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    require_host_boundary(production_backend.self_test())
    fixture = write_malformed_pdf(tmp_path / "malformed.pdf")

    outcome = AnalysisOrchestrator(production_backend, timeout_seconds=5.0).analyze(
        fixture.resolve(), original_filename="malformed.pdf"
    )

    assert not outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.status is AnalysisStatus.FAILED
    assert {finding.code for finding in outcome.result.findings} == {
        "PDF_MALFORMED",
        "PDF_PARTIAL_ANALYSIS",
    }


def test_production_bubblewrap_runs_office_parser_without_network(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    require_host_boundary(production_backend.self_test())
    fixture = write_ooxml(
        tmp_path / "macro.docm",
        application=OfficeApplication.WORD,
        macro_source=HARMLESS_AUTOEXEC_SOURCE,
        external_template=True,
    )

    outcome = AnalysisOrchestrator(production_backend, timeout_seconds=5.0).analyze(
        fixture.resolve(), original_filename="macro.docm"
    )

    assert not outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.status is AnalysisStatus.FAILED
    codes = {finding.code for finding in outcome.result.findings}
    assert {"OFFICE_VBA_MACRO", "OFFICE_VBA_AUTOEXEC", "OFFICE_EXTERNAL_TEMPLATE"}.issubset(codes)
    assert outcome.result.detected_type == "OFFICE_WORD_OOXML"


def test_production_bubblewrap_runs_archive_parser_without_network(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    require_host_boundary(production_backend.self_test())
    fixture = tmp_path / "archive.zip"
    fixture.write_bytes(
        archive_bytes(
            [
                ("../traversal.txt", b"fixture"),
                ("invoice.pdf.exe", b"MZ inert fixture"),
                ("nested.bin", nested_archive_bytes(1)),
            ]
        )
    )

    outcome = AnalysisOrchestrator(production_backend, timeout_seconds=5.0).analyze(
        fixture.resolve(), original_filename="archive.zip"
    )

    assert outcome.succeeded
    assert outcome.result is not None
    assert outcome.result.detected_type == "ZIP"
    codes = {finding.code for finding in outcome.result.findings}
    assert {
        "ARCHIVE_PATH_TRAVERSAL",
        "ARCHIVE_DANGEROUS_MEMBER",
        "ARCHIVE_MEMBER_DOUBLE_EXTENSION",
    }.issubset(codes)
    archive_metadata = outcome.result.analyzer_metadata["archive"]
    assert isinstance(archive_metadata, dict)
    assert archive_metadata["nested_archive_count"] == 2


def test_production_bubblewrap_runs_trusted_yara_pack_without_network(
    tmp_path: Path, production_backend: BubblewrapBackend
) -> None:
    require_host_boundary(production_backend.self_test())
    fixture = tmp_path / "eicar-test.txt"
    fixture.write_bytes(EICAR_TEST_BYTES)

    outcome = AnalysisOrchestrator(production_backend, timeout_seconds=5.0).analyze(
        fixture.resolve(), original_filename="eicar-test.txt"
    )

    assert outcome.succeeded
    assert outcome.result is not None
    yara_findings = [
        finding for finding in outcome.result.findings if finding.code == "YARA_TEST_SIGNATURE"
    ]
    assert len(yara_findings) == 1
    assert yara_findings[0].metadata["rule_id"] == "DOCGUARD_EICAR_TEST"
    assert EICAR_TEST_BYTES.decode("ascii") not in outcome.result.to_json()


@pytest.mark.asyncio
async def test_production_end_to_end_pdf_upload_matrix(
    tmp_path: Path,
    production_backend: BubblewrapBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_host_boundary(production_backend.self_test())
    monkeypatch.setattr(
        main_module, "create_isolation_backend", lambda settings: production_backend
    )
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'production-e2e.db'}",
        storage_root=tmp_path / "storage",
        application_origin="https://test",
    )
    app = create_app(settings)
    benign = write_benign_pdf(tmp_path / "benign.pdf").read_bytes()
    javascript = write_javascript_pdf(tmp_path / "javascript.pdf").read_bytes()
    malformed = write_malformed_pdf(tmp_path / "malformed.pdf").read_bytes()
    cases = (
        ("benign.pdf", benign),
        ("javascript.pdf", javascript),
        ("malformed.pdf", malformed),
        ("invoice.pdf", inert_pe_fixture()),
    )

    transport = httpx.ASGITransport(app=app)
    responses: dict[str, dict[str, object]] = {}
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="https://test") as client:
            client.headers["x-csrf-token"] = await authenticate_operator(app, client)
            for filename, body in cases:
                response = await client.post(
                    "/api/v1/scans",
                    params={"filename": filename},
                    content=body,
                    headers={"content-type": "application/pdf"},
                )
                assert response.status_code == 201
                payload = response.json()
                assert isinstance(payload, dict)
                responses[filename] = payload

    assert responses["benign.pdf"]["analysis_status"] == "SUCCESS"
    javascript_findings = responses["javascript.pdf"]["findings"]
    assert isinstance(javascript_findings, list)
    assert "PDF_JAVASCRIPT" in {item["code"] for item in javascript_findings}
    assert responses["malformed.pdf"]["state"] == "QUARANTINED"
    assert responses["malformed.pdf"]["analysis_status"] == "FAILED"
    assert responses["invoice.pdf"]["detected_type"] == "WINDOWS_EXECUTABLE"
    executable_findings = responses["invoice.pdf"]["findings"]
    assert isinstance(executable_findings, list)
    assert not any(str(item["code"]).startswith("PDF_") for item in executable_findings)
