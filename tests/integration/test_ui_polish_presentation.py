"""Regression tests for the v1.1.2 UI-polish presentation pass.

This pass is presentation-only (templates, static CSS/JS, and the Jinja
`partials/format.html` humanization macros) — no worker/policy/CDR/audit
persistence semantics changed. These tests guard the specific defects the
pass fixed:

1. Format-neutral sanitization (CDR) wording — non-PDF sources (Office, ZIP)
   and PDF sources that are not CDR-eligible must never see "PDF
   sanitization" heading/body text or be told to "check sanitization below"
   when no such path exists for them.
2. Technical-metadata humanization on the scan-detail page and the evidence
   report — snake_case keys and Python-shaped values (`[]`, `['x']`, `True`/
   `False`, `None`) must render as readable text without ever discarding the
   underlying value or renaming a finding code.
3. The audit table keeps its OUTCOME column and its Details values (no raw
   Python list/tuple formatting), and BLOCK/eligible-PDF CDR affordances are
   unchanged by the wording/metadata rework.

Server-rendered markup assertions only, consistent with the rest of this
suite (no browser/DOM harness).
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import authenticate_operator
from tests.fixtures.archive_factory import archive_bytes
from tests.fixtures.office_factory import write_encrypted_office_ole
from tests.fixtures.pdf_factory import (
    write_acroform_pdf,
    write_javascript_behavior_pdf,
    write_javascript_pdf,
    write_malformed_pdf_with_indicator_names,
)
from tests.unit.test_file_identification import inert_pe_fixture


def _settings(tmp_path: Path, name: str) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / name}.db",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
        worker_timeout_seconds=15.0,
    )


async def _upload(
    client: httpx.AsyncClient, filename: str, body: bytes, *, content_type: str
) -> dict[str, object]:
    response = await client.post(
        "/api/v1/scans",
        params={"filename": filename},
        content=body,
        headers={"content-type": content_type},
    )
    assert response.status_code == 201
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


# ---------------------------------------------------------------------------
# 1. Format-neutral CDR / sanitization wording
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_office_scan_does_not_render_pdf_sanitization_wording(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "office-wording"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "encrypted.docx",
            write_encrypted_office_ole(tmp_path / "encrypted.docx").read_bytes(),
            content_type=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "PDF sanitization" not in text
    assert "PDF Sanitization" not in text
    assert "Sanitization (CDR)" in text
    assert "The original document must remain unavailable." in text
    assert "Generate sanitized PDF" not in text
    assert "check sanitization below" not in text.lower()


@pytest.mark.asyncio
async def test_zip_scan_does_not_render_pdf_sanitization_wording(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "zip-wording"))
    resource_limited_zip = archive_bytes([("compressible.txt", b"A" * (33 * 1024 * 1024))])
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "resource.zip", resource_limited_zip, content_type="application/zip"
        )
        assert payload["state"] == "QUARANTINED"
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "PDF sanitization" not in text
    assert "PDF Sanitization" not in text
    assert "Sanitization (CDR)" in text
    assert "The original document must remain unavailable." in text
    assert "Generate sanitized PDF" not in text


@pytest.mark.asyncio
async def test_non_cdr_eligible_pdf_source_does_not_point_to_sanitization_below(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path, "ineligible-pdf-wording"))
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
        payload = await _upload(
            client, "rejected.pdf", malformed.read_bytes(), content_type="application/pdf"
        )
        eligibility = app.state.cdr_service.inspect_cdr_eligibility(str(payload["scan_id"]))
        assert eligibility.eligible is False
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "Generate sanitized PDF" not in text
    assert "check whether a sanitized derivative" not in text.lower()
    assert "sanitized derivative may be available below" not in text.lower()
    assert "The original document must remain unavailable." in text


@pytest.mark.asyncio
async def test_eligible_pdf_still_exposes_the_correct_cdr_action(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "eligible-pdf-action"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "active.pdf",
            write_javascript_pdf(tmp_path / "active.pdf").read_bytes(),
            content_type="application/pdf",
        )
        eligibility = app.state.cdr_service.inspect_cdr_eligibility(str(payload["scan_id"]))
        assert eligibility.eligible is True
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "Sanitization (CDR)" in text
    assert "Generate sanitized PDF" in text
    assert 'data-scan-id="' in text


@pytest.mark.asyncio
async def test_block_still_exposes_no_override_or_cdr_bypass(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "block-no-bypass"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "invoice.pdf", inert_pe_fixture(), content_type="application/pdf"
        )
        assert payload["decision"] == "BLOCK"
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "PDF sanitization" not in text
    assert "Generate sanitized PDF" not in text
    assert "Download approved sanitized PDF" not in text
    assert "override" not in text.lower()
    assert "no sanitization path" in text.lower()


# ---------------------------------------------------------------------------
# 2. Technical-metadata humanization
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_list_metadata_reads_as_none_observed_not_python_brackets(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path, "metadata-empty-list"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "benign-js.pdf",
            write_javascript_behavior_pdf(
                tmp_path / "benign-js.pdf", script="app.alert('hi');"
            ).read_bytes(),
            content_type="application/pdf",
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "PDF_JAVASCRIPT" in text
    assert "Behavior indicators" in text
    assert "None observed" in text
    assert "[]" not in text
    assert "['" not in text
    assert "Sources" in text
    assert "OpenAction" in text
    assert "Action count" in text


@pytest.mark.asyncio
async def test_nonempty_list_metadata_joins_values_and_preserves_them(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "metadata-nonempty-list"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "url-open.pdf",
            write_javascript_behavior_pdf(
                tmp_path / "url-open.pdf",
                script="app.launchURL('https://example.invalid/y');",
            ).read_bytes(),
            content_type="application/pdf",
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "<code>PDF_JAVASCRIPT</code>" in text
    assert "Behavior indicators" in text
    assert "external_url_open_api" in text
    assert "['" not in text
    assert "']" not in text


@pytest.mark.asyncio
async def test_boolean_metadata_reads_as_yes_not_python_true(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "metadata-boolean"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "xfa.pdf",
            write_acroform_pdf(tmp_path / "xfa.pdf", xfa=True).read_bytes(),
            content_type="application/pdf",
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}")

    assert response.status_code == 200
    text = response.text
    assert "PDF_XFA" in text
    assert "Present" in text
    assert ">True<" not in text
    assert ">False<" not in text


# ---------------------------------------------------------------------------
# 3. Evidence report: humanization + preserved provenance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_report_preserves_finding_codes_and_provenance_and_print_action(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path, "report-provenance"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "url-open.pdf",
            write_javascript_behavior_pdf(
                tmp_path / "url-open.pdf",
                script="app.launchURL('https://example.invalid/y');",
            ).read_bytes(),
            content_type="application/pdf",
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    text = response.text
    # Exact technical provenance preserved: finding code, document identity.
    assert "<code>PDF_JAVASCRIPT</code>" in text
    assert "SHA-256" in text
    assert str(payload["scan_id"]) in text
    # Humanized, not raw Python formatting.
    assert "Behavior indicators" in text
    assert "external_url_open_api" in text
    assert "['" not in text
    # Print/export control is preserved.
    assert "Print / Save as PDF" in text
    assert 'data-action="print-report"' in text


# ---------------------------------------------------------------------------
# 4. Audit: OUTCOME preserved, Details preserved without raw list formatting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_table_keeps_outcome_column_and_humanizes_details(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path, "audit-outcome-details"))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client,
            "invoice.docx",
            write_encrypted_office_ole(tmp_path / "invoice.docx").read_bytes(),
            content_type=(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ),
        )
        scan_id = str(payload["scan_id"])
        # Record a real, audited eligibility check (unlike the read-only
        # `inspect_cdr_eligibility` used by the scan-detail/report pages) so
        # the audit row's Details carry a non-empty `reason_codes` list.
        eligibility = app.state.cdr_service.evaluate_cdr_eligibility(scan_id)
        assert eligibility.eligible is False
        assert "NOT_PDF" in eligibility.reason_codes
        response = await client.get("/app/audit")

    assert response.status_code == 200
    text = response.text
    assert "<th>Outcome</th>" in text
    assert "DENIED" in text
    assert "<code>reason_codes</code>" in text
    assert "NOT_PDF" in text
    # No raw Python/JSON list bracket formatting for the joined reason codes.
    assert "['" not in text
    assert "[&#39;" not in text
    assert "sanitizer_version" in text
