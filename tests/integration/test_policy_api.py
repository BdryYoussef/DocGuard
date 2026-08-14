from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlalchemy import event, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import app.orchestrator.scan_service as scan_service_module
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base, FindingRecord, Scan
from app.policies.registry import POLICY_FINGERPRINT
from app.policies.version import POLICY_VERSION
from tests.auth_helpers import authenticate_operator, csrf_headers
from tests.fixtures.archive_factory import (
    archive_bytes,
    encrypted_metadata_archive_bytes,
    symlink_archive_bytes,
)
from tests.fixtures.office_factory import (
    HARMLESS_AUTOEXEC_SOURCE,
    HARMLESS_EXECUTION_INDICATOR_SOURCE,
    write_encrypted_office_ole,
    write_inconsistent_ooxml,
    write_ooxml,
)
from tests.fixtures.pdf_factory import (
    write_acroform_pdf,
    write_benign_pdf,
    write_encrypted_pdf,
    write_javascript_name_tree_pdf,
    write_javascript_pdf,
    write_malformed_pdf,
)
from tests.fixtures.yara_factory import EICAR_TEST_BYTES, POWERSHELL_ENCODED_PATTERN
from tests.unit.test_file_identification import inert_pe_fixture
from worker.analyzers.office_types import OfficeApplication


def policy_settings(tmp_path: Path, *, database_name: str = "policy.db") -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / database_name}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
        worker_timeout_seconds=15,
    )


@pytest.mark.asyncio
async def test_complete_policy_upload_matrix_is_deterministic_and_explainable(
    tmp_path: Path,
) -> None:
    macro_source = HARMLESS_AUTOEXEC_SOURCE + HARMLESS_EXECUTION_INDICATOR_SOURCE
    fixtures = {
        "benign.pdf": write_benign_pdf(tmp_path / "benign.pdf").read_bytes(),
        "benign.docx": write_ooxml(
            tmp_path / "benign.docx", application=OfficeApplication.WORD
        ).read_bytes(),
        "benign.xlsx": write_ooxml(
            tmp_path / "benign.xlsx", application=OfficeApplication.EXCEL
        ).read_bytes(),
        "benign.pptx": write_ooxml(
            tmp_path / "benign.pptx", application=OfficeApplication.POWERPOINT
        ).read_bytes(),
        "benign.zip": archive_bytes([("notes.txt", b"controlled benign fixture")]),
        "benign.txt": b"controlled ordinary business text fixture",
        "form.pdf": write_acroform_pdf(tmp_path / "form.pdf").read_bytes(),
        "javascript-only.pdf": write_javascript_name_tree_pdf(
            tmp_path / "javascript-only.pdf"
        ).read_bytes(),
        "javascript.pdf": write_javascript_pdf(tmp_path / "javascript.pdf").read_bytes(),
        "macro.docm": write_ooxml(
            tmp_path / "macro.docm",
            application=OfficeApplication.WORD,
            macro_source=macro_source,
        ).read_bytes(),
        "template.docx": write_ooxml(
            tmp_path / "template.docx",
            application=OfficeApplication.WORD,
            external_template=True,
        ).read_bytes(),
        "dangerous.zip": archive_bytes([("invoice.pdf.exe", b"inert fixture")]),
        "eicar.txt": EICAR_TEST_BYTES,
        "invoice.pdf": inert_pe_fixture(),
        "invoice.docx": inert_pe_fixture(),
        "traversal.zip": archive_bytes([("../outside.txt", b"fixture")]),
        "absolute.zip": archive_bytes([("/outside.txt", b"fixture")]),
        "symlink.zip": symlink_archive_bytes(),
        "encrypted.pdf": write_encrypted_pdf(tmp_path / "encrypted.pdf").read_bytes(),
        "malformed.pdf": write_malformed_pdf(tmp_path / "malformed.pdf").read_bytes(),
        "encrypted.docx": write_encrypted_office_ole(tmp_path / "encrypted.docx").read_bytes(),
        "encrypted.zip": encrypted_metadata_archive_bytes(),
        "malformed.docx": write_inconsistent_ooxml(tmp_path / "malformed.docx").read_bytes(),
        "malformed.zip": archive_bytes([("fixture", b"data")])[:-10],
        "unsupported.bin": bytes(range(1, 32)),
        "yara.txt": POWERSHELL_ENCODED_PATTERN,
    }
    expected = {
        "benign.pdf": "ALLOW",
        "benign.docx": "ALLOW",
        "benign.xlsx": "ALLOW",
        "benign.pptx": "ALLOW",
        "benign.zip": "ALLOW",
        "benign.txt": "ALLOW",
        "form.pdf": "ALLOW",
        "javascript-only.pdf": "REVIEW",
        "javascript.pdf": "QUARANTINE",
        "macro.docm": "QUARANTINE",
        "template.docx": "QUARANTINE",
        "dangerous.zip": "QUARANTINE",
        "eicar.txt": "BLOCK",
        "invoice.pdf": "BLOCK",
        "invoice.docx": "BLOCK",
        "traversal.zip": "BLOCK",
        "absolute.zip": "BLOCK",
        "symlink.zip": "BLOCK",
        "encrypted.pdf": "QUARANTINE",
        "malformed.pdf": "QUARANTINE",
        "encrypted.docx": "QUARANTINE",
        "encrypted.zip": "QUARANTINE",
        "malformed.docx": "QUARANTINE",
        "malformed.zip": "QUARANTINE",
        "unsupported.bin": "QUARANTINE",
        "yara.txt": "QUARANTINE",
    }
    app = create_app(policy_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    responses: dict[str, dict[str, object]] = {}
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            for filename, body in fixtures.items():
                response = await client.post(
                    "/api/v1/scans",
                    params={"filename": filename},
                    content=body,
                    headers=csrf_headers(csrf, **{"content-type": "application/octet-stream"}),
                )
                assert response.status_code == 201
                payload = response.json()
                assert isinstance(payload, dict)
                responses[filename] = payload
        with app.state.sessions() as session:
            persisted = list(session.execute(select(Scan)).scalars())

    for filename, decision in expected.items():
        payload = responses[filename]
        assert payload["decision"] == decision, filename
        assert payload["policy_version"] == POLICY_VERSION
        assert payload["policy_fingerprint"] == POLICY_FINGERPRINT
        assert 0 <= int(payload["risk_score"]) <= 100
        assert payload["release_eligible"] is (decision == "ALLOW")
        assert payload["disclaimer"] == (
            "DocGuard decisions describe the configured detection model. "
            "ALLOW is not proof that a document is benign."
        )
        assert "storage_key" not in payload

    assert "POLICY_COMPOUND_PDF_AUTO_JS" in responses["javascript.pdf"]["compound_rules_triggered"]
    assert (
        "POLICY_COMPOUND_OFFICE_MACRO_EXECUTION_CHAIN"
        in responses["macro.docm"]["compound_rules_triggered"]
    )
    assert (
        "POLICY_COMPOUND_ARCHIVE_MEMBER_MASQUERADE"
        in responses["dangerous.zip"]["compound_rules_triggered"]
    )
    assert responses["eicar.txt"]["hard_block_reasons"] == ["YARA_TEST_SIGNATURE"]
    assert responses["unsupported.bin"]["analysis_complete"] is False
    assert all(scan.policy_version == POLICY_VERSION for scan in persisted)
    assert all(scan.policy_fingerprint == POLICY_FINGERPRINT for scan in persisted)
    assert all(scan.release_eligible is (scan.decision == "ALLOW") for scan in persisted)


@pytest.mark.asyncio
async def test_persisted_evaluation_survives_restart_and_get_does_not_reevaluate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = policy_settings(tmp_path, database_name="restart.db")
    first_app = create_app(settings)
    first_transport = httpx.ASGITransport(app=first_app)
    body = write_benign_pdf(tmp_path / "restart.pdf").read_bytes()
    async with first_app.router.lifespan_context(first_app):
        Base.metadata.create_all(first_app.state.database_engine)
        async with httpx.AsyncClient(transport=first_transport, base_url="http://test") as client:
            csrf = await authenticate_operator(first_app, client)
            created = await client.post(
                "/api/v1/scans",
                params={"filename": "restart.pdf"},
                content=body,
                headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
            )
    assert created.status_code == 201
    created_payload = created.json()

    def forbidden_reevaluation(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("historical GET attempted policy re-evaluation")

    monkeypatch.setattr(scan_service_module, "evaluate_policy", forbidden_reevaluation)
    second_app = create_app(settings)
    second_transport = httpx.ASGITransport(app=second_app)
    async with (
        second_app.router.lifespan_context(second_app),
        httpx.AsyncClient(transport=second_transport, base_url="http://test") as client,
    ):
        await authenticate_operator(second_app, client)
        retrieved = await client.get(f"/api/v1/scans/{created_payload['scan_id']}")

    assert retrieved.status_code == 200
    retrieved_payload = retrieved.json()
    for key in (
        "decision",
        "release_eligible",
        "risk_score",
        "risk_band",
        "policy_version",
        "policy_fingerprint",
        "decision_reasons",
        "contributions",
    ):
        assert retrieved_payload[key] == created_payload[key]


@pytest.mark.asyncio
async def test_historical_pre_cleanup_policy_identity_remains_readable(tmp_path: Path) -> None:
    settings = policy_settings(tmp_path, database_name="historical-policy.db")
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    old_version = "1.0.0"
    old_fingerprint = "f53bc6a5d01fcd4f709339455033b5007447f2a7472009f789dc17c2b598c6bc"
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            created = await client.post(
                "/api/v1/scans",
                params={"filename": "historical.pdf"},
                content=write_benign_pdf(tmp_path / "historical.pdf").read_bytes(),
                headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
            )
            scan_id = created.json()["scan_id"]
            with app.state.sessions.begin() as session:
                scan = session.get(Scan, scan_id)
                assert scan is not None and scan.policy_evaluation_json is not None
                evaluation = dict(scan.policy_evaluation_json)
                evaluation["policy_version"] = old_version
                evaluation["policy_fingerprint"] = old_fingerprint
                scan.policy_version = old_version
                scan.policy_fingerprint = old_fingerprint
                scan.policy_evaluation_json = evaluation
            retrieved = await client.get(f"/api/v1/scans/{scan_id}")

    assert retrieved.status_code == 200
    assert retrieved.json()["policy_version"] == old_version
    assert retrieved.json()["policy_fingerprint"] == old_fingerprint


@pytest.mark.asyncio
async def test_policy_failure_persists_fail_closed_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def controlled_failure(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("controlled policy failure")

    monkeypatch.setattr(scan_service_module, "evaluate_policy", controlled_failure)
    app = create_app(policy_settings(tmp_path, database_name="failure.db"))
    transport = httpx.ASGITransport(app=app)
    caplog.set_level("INFO")
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans",
                params={"filename": "benign.pdf"},
                content=write_benign_pdf(tmp_path / "failure.pdf").read_bytes(),
                headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
            )
        with app.state.sessions() as session:
            scan = session.execute(select(Scan)).scalar_one()
            finding_count = len(session.execute(select(FindingRecord)).scalars().all())

    assert response.status_code == 201
    assert response.json()["decision"] == "QUARANTINE"
    assert response.json()["release_eligible"] is False
    assert response.json()["state"] == "QUARANTINED"
    assert scan.analysis_error_code == "policy_evaluation_failed"
    assert scan.release_eligible is False
    assert finding_count == 0
    assert "policy_evaluation_failed" in caplog.text


@pytest.mark.asyncio
async def test_final_database_failure_cannot_commit_release_eligibility(tmp_path: Path) -> None:
    app = create_app(policy_settings(tmp_path, database_name="database-failure.db"))
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    commit_count = 0

    def fail_final_commit(_session: Session) -> None:
        nonlocal commit_count
        commit_count += 1
        # Cookie authentication performs one read/refresh transaction before the
        # scan's registration, ANALYZING transition, and final policy transaction.
        if commit_count == 4:
            raise SQLAlchemyError("controlled final policy transaction failure")

    try:
        async with app.router.lifespan_context(app):
            Base.metadata.create_all(app.state.database_engine)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                csrf = await authenticate_operator(app, client)
                event.listen(Session, "before_commit", fail_final_commit)
                response = await client.post(
                    "/api/v1/scans",
                    params={"filename": "benign.pdf"},
                    content=write_benign_pdf(tmp_path / "database-failure.pdf").read_bytes(),
                    headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
                )
            with app.state.sessions() as session:
                scan = session.execute(select(Scan)).scalar_one()
                findings = list(session.execute(select(FindingRecord)).scalars())
    finally:
        if event.contains(Session, "before_commit", fail_final_commit):
            event.remove(Session, "before_commit", fail_final_commit)

    assert response.status_code == 500
    assert scan.state == "ANALYZING"
    assert scan.decision == "QUARANTINE"
    assert scan.release_eligible is False
    assert scan.policy_evaluation_json is None
    assert findings == []
