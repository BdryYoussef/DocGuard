from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base, FindingRecord, Scan
from tests.auth_helpers import authenticate_operator, csrf_headers
from tests.fixtures.pdf_factory import (
    HARMLESS_SCRIPT,
    write_benign_pdf,
    write_encrypted_pdf,
    write_javascript_pdf,
    write_malformed_pdf,
    write_multiple_actions_pdf,
)
from tests.unit.test_file_identification import inert_pe_fixture


def pdf_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'pdf-analysis.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


async def upload(
    tmp_path: Path, body: bytes, *, filename: str = "document.pdf"
) -> tuple[dict[str, object], Scan, list[FindingRecord]]:
    app = create_app(pdf_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans",
                params={"filename": filename},
                content=body,
                headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
            )
        with app.state.sessions() as session:
            scan = session.execute(select(Scan)).scalar_one()
            findings = list(
                session.execute(
                    select(FindingRecord).where(FindingRecord.scan_id == scan.id)
                ).scalars()
            )
            session.expunge(scan)
            for item in findings:
                session.expunge(item)
    assert response.status_code == 201
    payload = response.json()
    assert isinstance(payload, dict)
    return payload, scan, findings


@pytest.mark.asyncio
async def test_benign_pdf_completes_and_policy_allows_release_eligibility(
    tmp_path: Path,
) -> None:
    path = write_benign_pdf(tmp_path / "benign.pdf", pages=2)

    payload, scan, findings = await upload(tmp_path, path.read_bytes())

    assert payload["state"] == "COMPLETED"
    assert payload["analysis_status"] == "SUCCESS"
    assert payload["detected_type"] == "PDF"
    assert payload["decision"] == "ALLOW"
    assert payload["release_eligible"] is True
    assert payload["findings"] == []
    assert scan.decision == "ALLOW"
    assert findings == []


@pytest.mark.asyncio
async def test_javascript_pdf_findings_are_validated_persisted_and_bounded(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = write_javascript_pdf(tmp_path / "javascript.pdf")

    caplog.set_level("INFO")
    payload, _, persisted = await upload(tmp_path, path.read_bytes())
    response_codes = {str(item["code"]) for item in payload["findings"]}  # type: ignore[index]

    assert {"PDF_JAVASCRIPT", "PDF_OPEN_ACTION"}.issubset(response_codes)
    assert {item.code for item in persisted} == response_codes
    assert HARMLESS_SCRIPT not in json.dumps(payload)
    assert HARMLESS_SCRIPT not in caplog.text
    assert all(len(json.dumps(item.metadata_json)) < 16_384 for item in persisted)


@pytest.mark.asyncio
async def test_encrypted_pdf_remains_non_releasable_with_partial_findings(
    tmp_path: Path,
) -> None:
    path = write_encrypted_pdf(tmp_path / "encrypted.pdf")

    payload, scan, _ = await upload(tmp_path, path.read_bytes())
    codes = {str(item["code"]) for item in payload["findings"]}  # type: ignore[index]

    assert payload["state"] == "QUARANTINED"
    assert payload["analysis_status"] == "FAILED"
    assert payload["decision"] == "QUARANTINE"
    assert {"PDF_ENCRYPTED", "PDF_PARTIAL_ANALYSIS"}.issubset(codes)
    assert scan.analysis_error_code == "worker_failed"


@pytest.mark.asyncio
async def test_malformed_pdf_is_controlled_and_does_not_crash_fastapi(tmp_path: Path) -> None:
    path = write_malformed_pdf(tmp_path / "malformed.pdf")

    payload, _, _ = await upload(tmp_path, path.read_bytes())
    codes = {str(item["code"]) for item in payload["findings"]}  # type: ignore[index]

    assert payload["state"] == "QUARANTINED"
    assert payload["analysis_status"] == "FAILED"
    assert {"PDF_MALFORMED", "PDF_PARTIAL_ANALYSIS"}.issubset(codes)


@pytest.mark.asyncio
async def test_multiple_pdf_actions_remain_within_api_response_bounds(tmp_path: Path) -> None:
    path = write_multiple_actions_pdf(tmp_path / "multiple.pdf")

    payload, _, _ = await upload(tmp_path, path.read_bytes())

    assert len(json.dumps(payload).encode("utf-8")) < 32_768


@pytest.mark.asyncio
async def test_executable_renamed_pdf_never_produces_pdf_findings(tmp_path: Path) -> None:
    payload, _, _ = await upload(tmp_path, inert_pe_fixture(), filename="invoice.pdf")
    codes = {str(item["code"]) for item in payload["findings"]}  # type: ignore[index]

    assert payload["detected_type"] == "WINDOWS_EXECUTABLE"
    assert "FILE_EXECUTABLE_MASQUERADE" in codes
    assert not any(code.startswith("PDF_") for code in codes)
