"""Backend contract guards for the browser-side multi-file upload queue.

The queue itself is a client-side (app.js) orchestration layer: it fans out
independent calls to the *unmodified* single-file `/api/v1/scans` endpoint with
bounded concurrency. These tests do not exercise that browser scheduler (there
is no DOM/browser-JS test harness in this repository) — they instead prove the
server-side contract the scheduler relies on: every call is fully independent,
one call's rejection does not affect another, the same CSRF token is valid for
every call in a session, and the endpoint has not grown a batch/multipart mode.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base, Scan
from tests.auth_helpers import authenticate_operator, csrf_headers
from tests.fixtures.pdf_factory import write_benign_pdf, write_malformed_pdf


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'multi-upload.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@pytest.mark.asyncio
async def test_independent_sequential_uploads_reuse_one_csrf_token_and_isolate_failure(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    benign_a = write_benign_pdf(tmp_path / "invoice.pdf")
    malformed = write_malformed_pdf(tmp_path / "damaged.pdf")
    benign_b = write_benign_pdf(tmp_path / "report.pdf")

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)

        first = await client.post(
            "/api/v1/scans",
            params={"filename": "invoice.pdf"},
            content=benign_a.read_bytes(),
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )
        # A rejected (zero-byte) upload sits between two accepted ones, exactly
        # as a bounded-concurrency browser queue would interleave a failing item
        # with succeeding ones. It must not affect either neighbor.
        empty = await client.post(
            "/api/v1/scans",
            params={"filename": "empty.pdf"},
            content=b"",
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )
        third = await client.post(
            "/api/v1/scans",
            params={"filename": "damaged.pdf"},
            content=malformed.read_bytes(),
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )
        fourth = await client.post(
            "/api/v1/scans",
            params={"filename": "report.pdf"},
            content=benign_b.read_bytes(),
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )

        with app.state.sessions() as session:
            scans = list(session.execute(select(Scan)).scalars())

    assert first.status_code == 201
    assert empty.status_code == 400
    assert third.status_code == 201
    assert fourth.status_code == 201

    assert first.json()["decision"] == "ALLOW"
    assert third.json()["state"] == "QUARANTINED"
    assert fourth.json()["decision"] == "ALLOW"

    # The rejected empty upload created no scan; the three accepted uploads are
    # fully independent rows with distinct ids — no shared "batch" record.
    assert len(scans) == 3
    persisted_ids = {scan.id for scan in scans}
    assert len(persisted_ids) == 3
    response_ids = {first.json()["scan_id"], third.json()["scan_id"], fourth.json()["scan_id"]}
    assert response_ids == persisted_ids


@pytest.mark.asyncio
async def test_scan_creation_endpoint_still_rejects_multipart_and_requires_csrf(
    tmp_path: Path,
) -> None:
    """Guards the architectural promise the queue depends on: uploads stay a raw
    single-file stream, never a batch/multipart endpoint, and CSRF is still
    enforced on every individual call."""
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)

        no_csrf = await client.post(
            "/api/v1/scans",
            params={"filename": "x.pdf"},
            content=b"data",
            headers={"content-type": "application/pdf"},
        )
        multipart = await client.post(
            "/api/v1/scans",
            params={"filename": "x.pdf"},
            files={"document": ("x.pdf", b"data", "application/pdf")},
            headers=csrf_headers(csrf),
        )

        with app.state.sessions() as session:
            scan_count = len(list(session.execute(select(Scan)).scalars()))

    assert no_csrf.status_code == 403
    assert multipart.status_code == 415
    assert scan_count == 0
