"""Frontend-redesign contract guards.

These protect the two UX-critical distinctions the redesign introduced:

1. Bounded lexical fallback evidence (`PDF_FALLBACK_INDICATOR`) must never be
   presented as equivalent to structurally-confirmed evidence on the scan detail
   page — it carries a distinct `data-confidence="lexical"` marker and visible
   "Bounded lexical evidence" tag that no structurally-confirmed finding carries.
2. CDR lineage must visually distinguish the original source from the derived
   sanitized artifact, and a BLOCK-ineligible source must never imply a CDR
   bypass is available.

There is no DOM/browser-JS test harness in this repository; these are server-
rendered markup assertions, consistent with the rest of the suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from app.cdr.models import CdrStatus, PdfCdrResult
from app.cdr.orchestrator import CdrOutcome
from app.cdr.registry import build_worker_cdr_config
from app.cdr.service import CdrService
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import authenticate_operator
from tests.fixtures.pdf_factory import (
    write_benign_pdf,
    write_javascript_pdf,
    write_malformed_pdf_with_indicator_names,
)
from tests.unit.test_file_identification import inert_pe_fixture


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'redesign.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@dataclass
class _ControlledRenderer:
    settings: Settings
    output_bytes: bytes

    def sanitize(self, source_path: Path, output_path: Path) -> CdrOutcome:
        del source_path
        output_path.write_bytes(self.output_bytes)
        config = build_worker_cdr_config(self.settings)
        return CdrOutcome(
            PdfCdrResult(
                schema_version="2.1",
                operation="SANITIZE_PDF",
                status=CdrStatus.SUCCESS,
                sanitizer_version=config.sanitizer_version,
                sanitizer_fingerprint=config.sanitizer_fingerprint,
                renderer_version="1.28.2",
                engine_version="1.28.2",
                page_count=1,
                total_pixels=1,
                output_bytes=len(self.output_bytes),
                duration_ms=1,
                failure_code=None,
            ),
            None,
        )


async def _upload(client: httpx.AsyncClient, filename: str, body: bytes) -> dict[str, object]:
    response = await client.post(
        "/api/v1/scans",
        params={"filename": filename},
        content=body,
        headers={"content-type": "application/pdf"},
    )
    assert response.status_code == 201
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


@pytest.mark.asyncio
async def test_fallback_indicator_is_visually_distinguished_from_structural_evidence(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    malformed = write_malformed_pdf_with_indicator_names(
        tmp_path / "rejected.pdf", names=("JavaScript", "OpenAction")
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(client, "rejected.pdf", malformed.read_bytes())
        page = await client.get(f"/app/scans/{payload['scan_id']}")

    assert page.status_code == 200
    text = page.text
    assert 'data-confidence="lexical"' in text
    assert "Bounded lexical evidence" in text
    assert "PDF_FALLBACK_INDICATOR" in text
    # The parser never traversed this file, so no finding card for it can claim a
    # structurally-confirmed JavaScript/OpenAction finding.
    assert "<code>PDF_JAVASCRIPT</code>" not in text
    assert "<code>PDF_OPEN_ACTION</code>" not in text


@pytest.mark.asyncio
async def test_structurally_confirmed_finding_is_not_tagged_as_lexical_evidence(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    js_pdf = write_javascript_pdf(tmp_path / "js.pdf")
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(client, "js.pdf", js_pdf.read_bytes())
        page = await client.get(f"/app/scans/{payload['scan_id']}")

    assert page.status_code == 200
    text = page.text
    assert "PDF_JAVASCRIPT" in text
    assert 'data-confidence="lexical"' not in text
    assert "Bounded lexical evidence" not in text


@pytest.mark.asyncio
async def test_cdr_lineage_distinguishes_source_from_derived_artifact(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    app = create_app(settings)
    renderer = _ControlledRenderer(
        settings, write_benign_pdf(tmp_path / "sanitized.pdf").read_bytes()
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        source_payload = await _upload(
            client, "active.pdf", write_javascript_pdf(tmp_path / "active.pdf").read_bytes()
        )
        service = CdrService(
            app.state.sessions,
            app.state.scan_service,
            renderer,  # type: ignore[arg-type]
            app.state.audit_service,
            app.state.storage_paths,
            app.state.settings,
        )
        source_id = str(source_payload["scan_id"])
        service.sanitize_pdf(source_id)
        page = await client.get(f"/app/scans/{source_id}")

    assert page.status_code == 200
    text = page.text
    assert 'data-role="source"' in text
    assert 'data-role="derived"' in text
    assert "Original source" in text
    assert "Derived sanitized artifact" in text
    assert "Download approved sanitized PDF" in text
    # The source's own decision badge is shown on the lineage step, never silently
    # replaced by the derived ALLOW outcome.
    source_step = text.split('data-role="source"', 1)[1].split('data-role="derived"', 1)[0]
    assert (
        "badge-allow" not in source_step or "QUARANTINE" in source_step or "REVIEW" in source_step
    )


@pytest.mark.asyncio
async def test_block_ineligible_source_shows_no_cdr_bypass_language(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(client, "invoice.pdf", inert_pe_fixture())
        page = await client.get(f"/app/scans/{payload['scan_id']}")

    assert page.status_code == 200
    text = page.text
    assert "BLOCK" in text
    assert "Generate sanitized PDF" not in text
    assert "Download approved sanitized PDF" not in text
    assert 'data-role="derived"' not in text
    assert "no sanitization path" in text
