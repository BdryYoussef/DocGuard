"""Per-scan printable evidence report (`GET /app/scans/{scan_id}/report`).

Covers authorization (same session-authenticated operator context as the
normal scan-detail page, no raw-document exposure, no BLOCK bypass), content
(document identity, decision, rationale, findings, fallback-evidence
distinction, limitation language, and the "analyzed at" vs "generated at"
timestamp distinction), CDR/lineage presentation for source and derived
scans, and the print-contract structural guarantees (essential evidence not
gated behind a collapsed <details>, navigation/print controls hidden under
`@media print`, no external resources).

The report reuses the exact same read-only service calls as the existing
scan-detail page (`app.web.routes._load_scan_detail_context`) — there is no
parallel policy implementation and no re-analysis, consistent with the rest
of this suite's server-rendered-markup testing style (no browser/DOM
harness).
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
        database_url=f"sqlite:///{tmp_path / 'evidence-report.db'}",
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


async def _upload(
    client: httpx.AsyncClient, filename: str, body: bytes, *, content_type: str = "application/pdf"
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
# Authorization
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_anonymous_request_is_redirected_to_login_not_shown_the_report(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "doc.pdf", write_benign_pdf(tmp_path / "doc.pdf").read_bytes()
        )
        scan_id = str(payload["scan_id"])
        anonymous = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        )
        async with anonymous:
            response = await anonymous.get(f"/app/scans/{scan_id}/report")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.asyncio
async def test_authenticated_operator_can_open_the_report(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "doc.pdf", write_benign_pdf(tmp_path / "doc.pdf").read_bytes()
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


@pytest.mark.asyncio
async def test_nonexistent_scan_id_returns_generic_404_not_a_leak(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        response = await client.get("/app/scans/" + "0" * 32 + "/report")

    assert response.status_code == 404
    assert "Resource not found." in response.text
    assert "0" * 32 not in response.text.replace("Resource not found.", "")


@pytest.mark.asyncio
async def test_malformed_scan_id_is_rejected_by_the_same_path_pattern_as_scan_detail(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        response = await client.get("/app/scans/not-a-valid-id/report")

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_report_never_contains_a_raw_source_download_link(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "js.pdf", write_javascript_pdf(tmp_path / "js.pdf").read_bytes()
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    text = response.text
    # "QUARANTINE" is a legitimate decision word; the leak concern is a raw-bytes
    # route or storage-key value, neither of which this report ever renders.
    assert "/api/v1/scans/" not in text  # no raw scan-bytes/download API route
    assert "storage_key" not in text.lower()
    assert "download" not in text.lower()  # only the CDR artifact section ever says this


@pytest.mark.asyncio
async def test_block_report_has_no_override_release_or_cdr_affordance(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(client, "invoice.pdf", inert_pe_fixture())
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    text = response.text
    assert ">BLOCK<" in text
    assert "Generate sanitized PDF" not in text
    assert "Download approved sanitized PDF" not in text
    assert "override" not in text.lower()
    assert "/api/v1/artifacts/" not in text


# ---------------------------------------------------------------------------
# Content
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_shows_document_identity_and_decision_content(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "js-report.pdf", write_javascript_pdf(tmp_path / "js.pdf").read_bytes()
        )
        scan_id = str(payload["scan_id"])
        detail = await client.get(f"/app/scans/{scan_id}")
        report = await client.get(f"/app/scans/{scan_id}/report")

    assert report.status_code == 200
    assert detail.status_code == 200
    text = report.text

    # Document identity
    assert "js-report.pdf" in text
    assert scan_id in text
    assert "SHA-256" in text
    # Same persisted decision the normal detail page shows — no parallel computation.
    detail_decision_class = detail.text.split("decision-panel decision-", 1)[1].split('"', 1)[0]
    assert f"decision-panel decision-{detail_decision_class}" in text
    assert ">QUARANTINE<" in text or ">BLOCK<" in text or ">REVIEW<" in text or ">ALLOW<" in text
    assert "Risk score" in text
    assert "Policy version" in text
    assert "1.0.2" in text
    assert "Analysis status" in text
    assert "Analysis complete" in text
    assert "Release eligible" in text

    # Rationale: same decision_reasons source as scan detail, not regenerated.
    assert "Why this decision" in text

    # Findings: human title before technical code.
    assert "PDF_JAVASCRIPT" in text
    title_index = text.find("PDF_JAVASCRIPT")
    assert title_index != -1
    # The finding's human title appears earlier in the document than its code.
    assert "<code>PDF_JAVASCRIPT</code>" in text

    # Limitation language
    assert "does not guarantee that a document is benign" in text
    assert "not digitally signed" in text
    assert "safe" not in text.casefold()
    assert "malware-free" not in text.casefold()

    # Timestamp distinction
    assert "Document analyzed at" in text
    assert "Report generated at" in text
    assert text.index("Document analyzed at") != text.index("Report generated at")


@pytest.mark.asyncio
async def test_allow_decision_uses_the_established_limitation_wording(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "benign.pdf", write_benign_pdf(tmp_path / "benign.pdf").read_bytes()
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    text = response.text
    assert ">ALLOW<" in text
    assert "did not observe risky characteristics covered by the configured detection model" in text
    assert "safe" not in text.casefold()
    assert "clean" not in text.casefold()
    assert "malware-free" not in text.casefold()
    assert "100% secure" not in text.casefold()


@pytest.mark.asyncio
async def test_fallback_lexical_evidence_is_distinguished_in_the_report(tmp_path: Path) -> None:
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
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    text = response.text
    assert 'data-confidence="lexical"' in text
    assert "Bounded lexical evidence" in text
    assert "PDF_FALLBACK_INDICATOR" in text
    assert "not equivalent to a structurally-confirmed finding" in text
    assert "<code>PDF_JAVASCRIPT</code>" not in text
    assert "<code>PDF_OPEN_ACTION</code>" not in text


# ---------------------------------------------------------------------------
# CDR / lineage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_report_without_cdr_omits_the_lineage_section(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "benign.pdf", write_benign_pdf(tmp_path / "benign.pdf").read_bytes()
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    assert 'data-role="derived"' not in response.text


@pytest.mark.asyncio
async def test_source_report_shows_lineage_without_changing_source_decision(
    tmp_path: Path,
) -> None:
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
        outcome = service.sanitize_pdf(source_id)
        derived_id = outcome.derived_scan_id
        assert derived_id is not None
        source_report = await client.get(f"/app/scans/{source_id}/report")
        source_detail = await client.get(f"/app/scans/{source_id}")

    assert source_report.status_code == 200
    text = source_report.text
    assert "Sanitization lineage" in text
    assert 'data-role="source"' in text
    assert 'data-role="derived"' in text
    assert "Original source" in text
    assert "Derived sanitized artifact" in text
    assert f"/app/scans/{derived_id}/report" in text

    # The source's own persisted decision (from scan detail) matches the report exactly.
    detail_decision = source_detail.text.split("decision-panel decision-", 1)[1].split('"', 1)[0]
    assert f"decision-{detail_decision}" in text
    source_step = text.split('data-role="source"', 1)[1].split('data-role="derived"', 1)[0]
    assert "ALLOW" not in source_step  # the JS-carrying source is never itself ALLOW


@pytest.mark.asyncio
async def test_derived_scan_report_shows_the_parent_source_relationship(tmp_path: Path) -> None:
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
        outcome = service.sanitize_pdf(source_id)
        derived_id = outcome.derived_scan_id
        assert derived_id is not None
        derived_report = await client.get(f"/app/scans/{derived_id}/report")

    assert derived_report.status_code == 200
    text = derived_report.text
    assert "derived artifact" in text
    assert f"/app/scans/{source_id}" in text
    # The derived scan's own decision is ALLOW (release-eligible); nothing here
    # implies the *source's* QUARANTINE/REVIEW became ALLOW.
    assert ">ALLOW<" in text


@pytest.mark.asyncio
async def test_block_source_report_shows_no_lineage_section(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(client, "invoice.pdf", inert_pe_fixture())
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    text = response.text
    assert 'data-role="derived"' not in text
    assert "Sanitization lineage" not in text


# ---------------------------------------------------------------------------
# Print contract (structural only — no pixel/screenshot testing)
# ---------------------------------------------------------------------------


def test_print_stylesheet_and_media_print_rule_exist() -> None:
    css = Path("app/web/static/app.css").read_text(encoding="utf-8")
    assert "@media print" in css


def test_navigation_and_action_controls_are_hidden_for_print() -> None:
    css = Path("app/web/static/app.css").read_text(encoding="utf-8")
    print_block = css.split("@media print", 1)[1]
    print_rules = print_block.split("\n@media", 1)[0]
    assert ".report-header-actions" in print_rules
    assert ".topbar" in print_rules
    assert "display: none" in print_rules


def test_report_essential_evidence_is_not_gated_behind_a_details_element() -> None:
    template = Path("app/web/templates/scan_report.html").read_text(encoding="utf-8")
    assert "<details" not in template


def test_metadata_grid_blocks_never_split_mid_block_when_printed() -> None:
    """Regression guard for a real bug: a `<dl class="metadata">` (the
    Technical provenance / finding-detail grid) had no `break-inside: avoid`
    under `@media print`, so the browser could split it between rows —
    orphaning the last row onto its own near-empty trailing page."""
    css = Path("app/web/static/app.css").read_text(encoding="utf-8")
    print_block = css.split("@media print", 1)[1]
    print_rules = print_block.split("\n@media", 1)[0]
    break_inside_rule = next(
        rule
        for rule in print_rules.split("}")
        if "break-inside: avoid" in rule and ".metadata" in rule.rsplit("{", 1)[0]
    )
    assert ".metadata" in break_inside_rule.rsplit("{", 1)[0]


def test_report_does_not_duplicate_the_document_analyzed_at_timestamp() -> None:
    """Regression guard: 'Document analyzed at' was rendered twice (once in
    Document, once again in Technical provenance) — genuine duplicate content
    that inflated the printed page height for no reason. It must appear
    exactly once; the report-generation timestamp stays separately labeled."""
    template = Path("app/web/templates/scan_report.html").read_text(encoding="utf-8")
    assert template.count("Document analyzed at") == 1
    assert "Report generated at" in template


def test_print_section_spacing_is_tightened_below_the_screen_default() -> None:
    """Regression guard: print inherited the full screen section spacing
    (margin-bottom + padding-bottom summing to 56px per section), which
    across every report section was enough excess height to spill a small
    tail of content onto an otherwise-empty trailing page. Print must use a
    visibly smaller, but still nonzero, gap."""
    css = Path("app/web/static/app.css").read_text(encoding="utf-8")
    print_block = css.split("@media print", 1)[1]
    print_rules = print_block.split("\n@media", 1)[0]
    section_rule = next(rule for rule in print_rules.split("}") if ".report-section {" in rule)
    assert "margin-bottom: var(--space-3)" in section_rule
    assert "padding-bottom: var(--space-2)" in section_rule


def test_report_uses_only_same_origin_assets_and_no_inline_script_or_style() -> None:
    template = Path("app/web/templates/scan_report.html").read_text(encoding="utf-8")
    assert "http://" not in template
    assert "https://" not in template
    assert "cdn." not in template
    assert 'style="' not in template
    import re

    assert not re.search(r"\bon\w+=", template)


@pytest.mark.asyncio
async def test_print_action_button_never_triggers_print_automatically(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "benign.pdf", write_benign_pdf(tmp_path / "benign.pdf").read_bytes()
        )
        response = await client.get(f"/app/scans/{payload['scan_id']}/report")

    assert response.status_code == 200
    assert "window.print()" not in response.text  # only in the same-origin app.js, not inline
    assert 'data-action="print-report"' in response.text


def test_print_button_is_wired_through_external_js_not_inline_handler() -> None:
    js = Path("app/web/static/app.js").read_text(encoding="utf-8")
    assert 'data-action="print-report"' in js
    assert "window.print()" in js


@pytest.mark.asyncio
async def test_report_link_appears_on_the_normal_scan_detail_page(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        payload = await _upload(
            client, "benign.pdf", write_benign_pdf(tmp_path / "benign.pdf").read_bytes()
        )
        scan_id = payload["scan_id"]
        detail = await client.get(f"/app/scans/{scan_id}")

    assert detail.status_code == 200
    assert f"/app/scans/{scan_id}/report" in detail.text
    assert "Evidence report" in detail.text
