from __future__ import annotations

import hashlib
import stat
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base, Scan
from app.storage.ingestion import stream_document_to_quarantine
from app.storage.paths import StoragePaths
from tests.auth_helpers import authenticate_operator, csrf_headers


def ingestion_settings(tmp_path: Path, *, maximum_bytes: int = 1_024) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'ingestion.db'}",
        storage_root=tmp_path / "private-storage",
        maximum_upload_bytes=maximum_bytes,
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@pytest.mark.asyncio
async def test_small_upload_is_streamed_hashed_and_stored_opaquely(tmp_path: Path) -> None:
    settings = ingestion_settings(tmp_path)
    app = create_app(settings)
    body = b"DOCGUARD_TEST_MARKER\ncontrolled fixture\n"
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans",
                params={"filename": "../../invoice.pdf"},
                content=body,
                headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
            )

        with app.state.sessions() as session:
            scan = session.execute(select(Scan)).scalar_one()

    assert response.status_code == 201
    payload = response.json()
    assert payload["schema_version"] == "1.3"
    assert payload["sha256"] == hashlib.sha256(body).hexdigest()
    assert payload["size_bytes"] == len(body)
    assert payload["display_filename"] == ".._.._invoice.pdf"
    assert payload["claimed_content_type"] == "application/pdf"
    assert payload["state"] == "COMPLETED"
    assert payload["decision"] == "REVIEW"
    assert payload["release_eligible"] is False
    assert "storage_key" not in payload
    assert scan.original_filename == "../../invoice.pdf"
    assert scan.decision == "REVIEW"
    assert len(scan.storage_key) == 32
    assert all(character in "0123456789abcdef" for character in scan.storage_key)
    stored = list((settings.storage_root / "quarantine").iterdir())
    assert [path.name for path in stored] == [scan.storage_key]
    assert stat.S_IMODE(stored[0].stat().st_mode) == 0o400
    for directory in (
        settings.storage_root,
        settings.storage_root / "incoming",
        settings.storage_root / "quarantine",
        settings.storage_root / "sanitized",
        settings.storage_root / "work",
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert "invoice.pdf" not in str(stored[0])
    assert "static" not in stored[0].parts and "public" not in stored[0].parts


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["../escape.pdf", "/tmp/escape.pdf"])
async def test_hostile_filename_cannot_escape_storage(tmp_path: Path, filename: str) -> None:
    settings = ingestion_settings(tmp_path)
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans",
                params={"filename": filename},
                content=b"fixture",
                headers=csrf_headers(csrf),
            )

    assert response.status_code == 201
    assert not (tmp_path / "escape.pdf").exists()
    assert all(len(path.name) == 32 for path in (settings.storage_root / "quarantine").iterdir())


@pytest.mark.asyncio
async def test_actual_byte_limit_ignores_false_content_length_and_cleans_partial(
    tmp_path: Path,
) -> None:
    settings = ingestion_settings(tmp_path, maximum_bytes=8)
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans?filename=large.pdf",
                content=b"0123456789abcdef",
                headers=csrf_headers(csrf, **{"content-length": "1"}),
            )
        with app.state.sessions() as session:
            count = session.scalar(select(func.count()).select_from(Scan))

    assert response.status_code == 413
    assert count == 0
    assert list((settings.storage_root / "incoming").iterdir()) == []
    assert list((settings.storage_root / "quarantine").iterdir()) == []


@pytest.mark.asyncio
async def test_zero_byte_upload_rejected_without_artifacts(tmp_path: Path) -> None:
    settings = ingestion_settings(tmp_path)
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans?filename=empty.pdf",
                content=b"",
                headers=csrf_headers(csrf),
            )

    assert response.status_code == 400
    assert list((settings.storage_root / "incoming").iterdir()) == []
    assert list((settings.storage_root / "quarantine").iterdir()) == []


@pytest.mark.asyncio
async def test_interrupted_stream_cleans_temporary_and_final_files(tmp_path: Path) -> None:
    paths = StoragePaths(tmp_path / "storage")
    paths.initialize()

    async def interrupted() -> AsyncIterator[bytes]:
        yield b"partial"
        raise RuntimeError("simulated disconnect")

    with pytest.raises(RuntimeError, match="simulated disconnect"):
        await stream_document_to_quarantine(interrupted(), paths=paths, maximum_bytes=100)

    assert list(paths.incoming.iterdir()) == []
    assert list(paths.quarantine.iterdir()) == []


@pytest.mark.asyncio
async def test_database_failure_removes_completed_storage_object(tmp_path: Path) -> None:
    settings = ingestion_settings(tmp_path)
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        Scan.__table__.drop(app.state.database_engine)
        response = await client.post(
            "/api/v1/scans?filename=fixture.pdf",
            content=b"fixture",
            headers=csrf_headers(csrf),
        )

    assert response.status_code == 500
    assert list((settings.storage_root / "quarantine").iterdir()) == []
