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
from tests.fixtures.archive_factory import (
    archive_bytes,
    nested_archive_bytes,
    symlink_archive_bytes,
)
from tests.fixtures.office_factory import write_ooxml
from tests.unit.test_file_identification import inert_pe_fixture
from worker.analyzers.office_types import OfficeApplication


def archive_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'archive-analysis.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
        worker_timeout_seconds=15.0,
    )


@pytest.mark.asyncio
async def test_complete_zip_upload_matrix_is_bounded_and_fail_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    normal = archive_bytes([("notes.txt", b"fixture"), ("document.pdf", b"%PDF fixture")])
    traversal = archive_bytes([("../outside.txt", b"fixture")])
    dangerous = archive_bytes(
        [("invoice.pdf.exe", b"MZ inert fixture"), ("script.ps1", b"# harmless")]
    )
    nested = archive_bytes([("nested.bin", nested_archive_bytes(1))])
    resource_simulation = archive_bytes([("compressible.txt", b"A" * (33 * 1024 * 1024))])
    malformed = archive_bytes([("fixture.txt", b"fixture")])[:-10]
    generic_docx = archive_bytes([("ordinary.txt", b"fixture")])
    valid_docx = write_ooxml(
        tmp_path / "valid.docx", application=OfficeApplication.WORD
    ).read_bytes()
    cases = {
        "normal.zip": normal,
        "traversal.zip": traversal,
        "symlink.zip": symlink_archive_bytes(),
        "dangerous.zip": dangerous,
        "nested.zip": nested,
        "resource.zip": resource_simulation,
        "malformed.zip": malformed,
        "generic.docx": generic_docx,
        "valid.docx": valid_docx,
        "executable.zip": inert_pe_fixture(),
    }
    app = create_app(archive_settings(tmp_path))
    transport = httpx.ASGITransport(app=app)
    responses: dict[str, dict[str, object]] = {}
    caplog.set_level("INFO")
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            for filename, body in cases.items():
                response = await client.post(
                    "/api/v1/scans",
                    params={"filename": filename},
                    content=body,
                    headers=csrf_headers(csrf, **{"content-type": "application/zip"}),
                )
                assert response.status_code == 201
                payload = response.json()
                assert isinstance(payload, dict)
                responses[filename] = payload
        with app.state.sessions() as session:
            persisted = list(session.execute(select(FindingRecord)).scalars())

    assert responses["normal.zip"]["detected_type"] == "ZIP"
    assert responses["normal.zip"]["analysis_status"] == "SUCCESS"
    assert responses["normal.zip"]["decision"] == "ALLOW"
    assert responses["normal.zip"]["release_eligible"] is True
    assert "ARCHIVE_PATH_TRAVERSAL" in _response_codes(responses["traversal.zip"])
    assert "ARCHIVE_SYMLINK" in _response_codes(responses["symlink.zip"])
    assert {
        "ARCHIVE_DANGEROUS_MEMBER",
        "ARCHIVE_MEMBER_DOUBLE_EXTENSION",
    }.issubset(_response_codes(responses["dangerous.zip"]))
    assert responses["nested.zip"]["analysis_status"] == "SUCCESS"
    assert responses["resource.zip"]["state"] == "QUARANTINED"
    assert "ARCHIVE_RESOURCE_LIMIT" in _response_codes(responses["resource.zip"])
    assert responses["malformed.zip"]["state"] == "QUARANTINED"
    assert "ARCHIVE_MALFORMED" in _response_codes(responses["malformed.zip"])
    assert responses["generic.docx"]["detected_type"] == "ZIP"
    assert not any(
        code.startswith("OFFICE_") for code in _response_codes(responses["generic.docx"])
    )
    assert responses["valid.docx"]["detected_type"] == "OFFICE_WORD_OOXML"
    assert not any(code.startswith("ARCHIVE_") for code in _response_codes(responses["valid.docx"]))
    assert responses["executable.zip"]["detected_type"] == "WINDOWS_EXECUTABLE"
    assert not any(
        code.startswith("ARCHIVE_") for code in _response_codes(responses["executable.zip"])
    )
    public_and_database = json.dumps(
        {
            "responses": responses,
            "finding_metadata": [record.metadata_json for record in persisted],
        }
    )
    assert "controlled nested fixture" not in public_and_database
    assert "MZ inert fixture" not in public_and_database
    assert "controlled nested fixture" not in caplog.text
    assert "MZ inert fixture" not in caplog.text
    assert not (tmp_path / "outside.txt").exists()
    assert "archive_analysis_completed" in caplog.text
    assert "archive_analysis_partial" in caplog.text
    assert "archive_analysis_failed" in caplog.text


def _response_codes(payload: dict[str, object]) -> set[str]:
    findings = payload["findings"]
    assert isinstance(findings, list)
    return {str(item["code"]) for item in findings if isinstance(item, dict) and "code" in item}
