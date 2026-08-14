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
from tests.fixtures.archive_factory import archive_bytes
from tests.fixtures.office_factory import HARMLESS_AUTOEXEC_SOURCE, write_ooxml
from tests.fixtures.pdf_factory import write_benign_pdf
from tests.fixtures.yara_factory import (
    BENIGN_POWERSHELL_PROSE,
    EICAR_TEST_BYTES,
    POWERSHELL_ENCODED_PATTERN,
    write_pdf_with_yara_pattern,
)
from tests.unit.test_file_identification import inert_pe_fixture
from worker.analyzers.office_types import OfficeApplication


def yara_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'yara-analysis.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@pytest.mark.asyncio
async def test_complete_yara_upload_matrix_is_supplementary_private_and_fail_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fixtures = {
        "benign.pdf": write_benign_pdf(tmp_path / "benign.pdf").read_bytes(),
        "pattern.pdf": write_pdf_with_yara_pattern(tmp_path / "pattern.pdf").read_bytes(),
        "benign.docx": write_ooxml(
            tmp_path / "benign.docx",
            application=OfficeApplication.WORD,
            visible_text=(
                "PowerShell is an administration tool and WScript.Shell is discussed academically."
            ),
        ).read_bytes(),
        "macro.docm": write_ooxml(
            tmp_path / "macro.docm",
            application=OfficeApplication.WORD,
            macro_source=HARMLESS_AUTOEXEC_SOURCE,
        ).read_bytes(),
        "normal.zip": archive_bytes([("fixture.txt", b"controlled archive fixture")]),
        "eicar.txt": EICAR_TEST_BYTES,
        "powershell.txt": POWERSHELL_ENCODED_PATTERN,
        "powershell-prose.txt": BENIGN_POWERSHELL_PROSE,
        "unsupported.bin": bytes(range(1, 32)),
        "unsupported-pattern.bin": (bytes(range(1, 32)) + b"\x00" + POWERSHELL_ENCODED_PATTERN),
        "invoice.pdf": inert_pe_fixture(),
    }
    app = create_app(yara_settings(tmp_path))
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
                    headers=csrf_headers(csrf, **{"content-type": "application/octet-stream"}),
                )
                assert response.status_code == 201
                payload = response.json()
                assert isinstance(payload, dict)
                responses[filename] = payload
        with app.state.sessions() as session:
            persisted = list(session.execute(select(FindingRecord)).scalars())

    assert responses["benign.pdf"]["analysis_status"] == "SUCCESS"
    assert not _yara_codes(responses["benign.pdf"])
    assert {"PDF_JAVASCRIPT", "YARA_HEURISTIC_MATCH"}.issubset(
        _response_codes(responses["pattern.pdf"])
    )
    assert responses["benign.docx"]["detected_type"] == "OFFICE_WORD_OOXML"
    assert not _yara_codes(responses["benign.docx"])
    assert "OFFICE_VBA_AUTOEXEC" in _response_codes(responses["macro.docm"])
    assert responses["macro.docm"]["state"] == "QUARANTINED"
    assert responses["normal.zip"]["detected_type"] == "ZIP"
    assert responses["normal.zip"]["analysis_status"] == "SUCCESS"
    assert _response_codes(responses["eicar.txt"]) == {"YARA_TEST_SIGNATURE"}
    assert "YARA_HEURISTIC_MATCH" in _response_codes(responses["powershell.txt"])
    assert not _yara_codes(responses["powershell-prose.txt"])
    assert responses["unsupported.bin"]["state"] == "QUARANTINED"
    assert responses["unsupported.bin"]["analysis_status"] == "UNSUPPORTED"
    assert not _yara_codes(responses["unsupported.bin"])
    assert responses["unsupported-pattern.bin"]["state"] == "QUARANTINED"
    assert responses["unsupported-pattern.bin"]["analysis_status"] == "UNSUPPORTED"
    assert "YARA_HEURISTIC_MATCH" in _response_codes(responses["unsupported-pattern.bin"])
    assert responses["invoice.pdf"]["detected_type"] == "WINDOWS_EXECUTABLE"
    assert "FILE_EXECUTABLE_MASQUERADE" in _response_codes(responses["invoice.pdf"])

    public_and_database = json.dumps(
        {
            "responses": responses,
            "finding_metadata": [record.metadata_json for record in persisted],
        }
    )
    for private_value in (
        EICAR_TEST_BYTES.decode("ascii"),
        "QUJDREVGR0hJSktMTU5PUA==",
        "powershell.exe -EncodedCommand",
    ):
        assert private_value not in public_and_database
        assert private_value not in caplog.text
    assert "yara_scan_completed" in caplog.text


def _response_codes(payload: dict[str, object]) -> set[str]:
    findings = payload["findings"]
    assert isinstance(findings, list)
    return {str(item["code"]) for item in findings if isinstance(item, dict) and "code" in item}


def _yara_codes(payload: dict[str, object]) -> set[str]:
    return {code for code in _response_codes(payload) if code.startswith("YARA_")}
