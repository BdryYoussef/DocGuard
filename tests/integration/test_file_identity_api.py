from __future__ import annotations

import zipfile
from io import BytesIO
from pathlib import Path

import httpx
import pytest

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import authenticate_operator, csrf_headers


def inert_pe_fixture() -> bytes:
    return b"MZ" + b"\x00" * 58 + (64).to_bytes(4, "little") + b"PE\x00\x00" + b"\x00" * 128


def settings_for_identity(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'identity.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


async def analyze(tmp_path: Path, *, filename: str, body: bytes, content_type: str) -> dict:
    app = create_app(settings_for_identity(tmp_path))
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans",
                params={"filename": filename},
                content=body,
                headers=csrf_headers(csrf, **{"content-type": content_type}),
            )
    assert response.status_code == 201
    value = response.json()
    assert isinstance(value, dict)
    return value


@pytest.mark.asyncio
async def test_pdf_is_identified_from_content(tmp_path: Path) -> None:
    result = await analyze(
        tmp_path,
        filename="document.pdf",
        body=b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n",
        content_type="application/octet-stream",
    )

    assert result["detected_type"] == "PDF"
    assert result["detected_mime"] == "application/pdf"
    assert "FILE_CLIENT_MIME_MISMATCH" not in {finding["code"] for finding in result["findings"]}


@pytest.mark.asyncio
async def test_executable_renamed_pdf_is_identified_and_flagged(tmp_path: Path) -> None:
    result = await analyze(
        tmp_path,
        filename="invoice.pdf",
        body=inert_pe_fixture(),
        content_type="application/pdf",
    )
    codes = {finding["code"] for finding in result["findings"]}

    assert result["detected_type"] == "WINDOWS_EXECUTABLE"
    assert "FILE_TYPE_MISMATCH" in codes
    assert "FILE_EXECUTABLE_MASQUERADE" in codes
    assert "FILE_CLIENT_MIME_MISMATCH" in codes


@pytest.mark.asyncio
async def test_zip_is_identified_without_deep_parsing(tmp_path: Path) -> None:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w") as stream:
        stream.writestr("harmless.txt", "fixture")

    result = await analyze(
        tmp_path,
        filename="archive.zip",
        body=buffer.getvalue(),
        content_type="application/zip",
    )

    assert result["detected_type"] == "ZIP"


@pytest.mark.asyncio
async def test_generic_data_remains_quarantined_and_unsupported(tmp_path: Path) -> None:
    result = await analyze(
        tmp_path,
        filename="sample.bin",
        body=bytes(range(1, 32)),
        content_type="application/octet-stream",
    )

    assert result["state"] == "QUARANTINED"
    assert result["analysis_status"] == "UNSUPPORTED"
    assert result["detected_type"] == "UNKNOWN"
