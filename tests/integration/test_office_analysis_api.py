from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base, FindingRecord
from tests.auth_helpers import authenticate_operator, csrf_headers
from tests.fixtures.office_factory import (
    HARMLESS_AUTOEXEC_SOURCE,
    HARMLESS_EXECUTION_INDICATOR_SOURCE,
    write_encrypted_office_ole,
    write_generic_zip,
    write_inconsistent_ooxml,
    write_ooxml,
)
from tests.unit.test_file_identification import inert_pe_fixture
from worker.analyzers.office_types import OfficeApplication


def office_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'office-analysis.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@pytest.mark.asyncio
async def test_complete_office_upload_matrix_is_fail_closed_and_private(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    sources = HARMLESS_AUTOEXEC_SOURCE + HARMLESS_EXECUTION_INDICATOR_SOURCE
    fixtures = {
        "benign.docx": write_ooxml(
            tmp_path / "benign.docx", application=OfficeApplication.WORD
        ).read_bytes(),
        "macro.docm": write_ooxml(
            tmp_path / "macro.docm",
            application=OfficeApplication.WORD,
            macro_source=HARMLESS_EXECUTION_INDICATOR_SOURCE,
        ).read_bytes(),
        "autoexec.docm": write_ooxml(
            tmp_path / "autoexec.docm",
            application=OfficeApplication.WORD,
            macro_source=sources,
        ).read_bytes(),
        "template.docx": write_ooxml(
            tmp_path / "template.docx",
            application=OfficeApplication.WORD,
            external_template=True,
        ).read_bytes(),
        "embedded.docx": write_ooxml(
            tmp_path / "embedded.docx",
            application=OfficeApplication.WORD,
            embedded_object=True,
        ).read_bytes(),
        "encrypted.docx": write_encrypted_office_ole(tmp_path / "encrypted.docx").read_bytes(),
        "malformed.docx": write_inconsistent_ooxml(tmp_path / "malformed.docx").read_bytes(),
        "generic.docx": write_generic_zip(tmp_path / "generic.docx").read_bytes(),
        "executable.docx": inert_pe_fixture(),
    }
    app = create_app(office_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    responses: dict[str, dict[str, object]] = {}
    caplog.set_level("INFO")
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            for filename, body in fixtures.items():
                response = await client.post(
                    "/api/v1/scans",
                    params={"filename": filename},
                    content=body,
                    headers=csrf_headers(
                        csrf,
                        **{
                            "content-type": (
                                "application/vnd.openxmlformats-officedocument."
                                "wordprocessingml.document"
                            )
                        },
                    ),
                )
                assert response.status_code == 201
                payload = response.json()
                assert isinstance(payload, dict)
                responses[filename] = payload
        with app.state.sessions() as session:
            persisted = list(session.execute(select(FindingRecord)).scalars())

    assert responses["benign.docx"]["detected_type"] == "OFFICE_WORD_OOXML"
    assert responses["benign.docx"]["analysis_status"] == "SUCCESS"
    macro_codes = _response_codes(responses["macro.docm"])
    assert {"OFFICE_MACRO_ENABLED", "OFFICE_VBA_MACRO"}.issubset(macro_codes)
    autoexec_codes = _response_codes(responses["autoexec.docm"])
    assert {"OFFICE_VBA_AUTOEXEC", "OFFICE_VBA_EXECUTION_INDICATOR"}.issubset(autoexec_codes)
    assert "OFFICE_EXTERNAL_TEMPLATE" in _response_codes(responses["template.docx"])
    assert "OFFICE_EMBEDDED_OBJECT" in _response_codes(responses["embedded.docx"])
    assert responses["encrypted.docx"]["state"] == "QUARANTINED"
    assert responses["encrypted.docx"]["analysis_status"] == "FAILED"
    assert "OFFICE_ENCRYPTED" in _response_codes(responses["encrypted.docx"])
    assert responses["malformed.docx"]["state"] == "QUARANTINED"
    assert "OFFICE_MALFORMED" in _response_codes(responses["malformed.docx"])
    assert responses["generic.docx"]["detected_type"] == "ZIP"
    assert not any(
        code.startswith("OFFICE_") for code in _response_codes(responses["generic.docx"])
    )
    assert responses["executable.docx"]["detected_type"] == "WINDOWS_EXECUTABLE"
    assert not any(
        code.startswith("OFFICE_") for code in _response_codes(responses["executable.docx"])
    )
    public_and_database = json.dumps(
        {
            "responses": responses,
            "findings": [item.metadata_json for item in persisted],
        }
    )
    assert "DOCGUARD_CONTROLLED_FIXTURE" not in public_and_database
    assert "cmd.exe /c" not in public_and_database
    assert "DOCGUARD_CONTROLLED_FIXTURE" not in caplog.text
    assert "cmd.exe /c" not in caplog.text


def _response_codes(payload: dict[str, object]) -> set[str]:
    findings = payload["findings"]
    assert isinstance(findings, list)
    return {
        str(finding["code"])
        for finding in findings
        if isinstance(finding, dict) and "code" in finding
    }
