"""End-to-end proof that the PDF explainability enhancements are detection/
explanation only: the two new finding codes (PDF_FALLBACK_INDICATOR,
PDF_EXTERNAL_SUBMISSION) carry zero policy contribution, so they can never
change a risk score, risk band, decision, release eligibility, or CDR
eligibility for any sample — historical or new. GoToE recognition and
JavaScript behavior indicators are pure metadata-value corrections/additions
on already-existing findings and carry no separate policy weight at all.
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
from tests.fixtures.pdf_factory import (
    write_external_submit_form_pdf,
    write_malformed_pdf,
    write_malformed_pdf_with_indicator_names,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'pdf-explainability.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


async def _upload(
    client: httpx.AsyncClient, csrf: str, body: bytes, filename: str
) -> dict[str, object]:
    response = await client.post(
        "/api/v1/scans",
        params={"filename": filename},
        content=body,
        headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
    )
    assert response.status_code == 201
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


@pytest.mark.asyncio
async def test_fallback_indicator_finding_does_not_change_decision_or_risk_score(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    plain = write_malformed_pdf(tmp_path / "plain-malformed.pdf")
    with_indicators = write_malformed_pdf_with_indicator_names(
        tmp_path / "malformed-with-indicators.pdf",
        names=("JavaScript", "OpenAction", "AcroForm", "XFA", "Launch"),
    )

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)

        plain_result = await _upload(client, csrf, plain.read_bytes(), "plain-malformed.pdf")
        rich_result = await _upload(
            client, csrf, with_indicators.read_bytes(), "malformed-with-indicators.pdf"
        )

        rich_scan_id = rich_result["scan_id"]
        with app.state.sessions() as session:
            rich_scan = session.execute(select(Scan).where(Scan.id == rich_scan_id)).scalar_one()
            eligibility = app.state.cdr_service.inspect_cdr_eligibility(rich_scan.id)

    # Identical decision-relevant outcome regardless of how much fallback
    # lexical evidence was recovered — the same PDF_MALFORMED/PDF_PARTIAL_ANALYSIS
    # mandatory-quarantine mechanism drives both, unchanged by this feature.
    assert plain_result["decision"] == rich_result["decision"] == "QUARANTINE"
    assert plain_result["risk_score"] == rich_result["risk_score"]
    assert plain_result["release_eligible"] is False
    assert rich_result["release_eligible"] is False
    assert plain_result["analysis_complete"] is False
    assert rich_result["analysis_complete"] is False

    fallback_codes = {item["code"] for item in rich_result["contributions"]}
    assert "PDF_FALLBACK_INDICATOR" in fallback_codes
    fallback_contribution = next(
        item for item in rich_result["contributions"] if item["code"] == "PDF_FALLBACK_INDICATOR"
    )
    assert fallback_contribution["contribution"] == 0

    # A parser-rejected, fallback-evidence-bearing PDF must remain CDR-ineligible.
    assert eligibility.eligible is False
    assert "ANALYSIS_INCOMPLETE" in eligibility.reason_codes
    assert "PDF_NOT_RENDERABLE" in eligibility.reason_codes
    assert rich_scan.state == "QUARANTINED"


@pytest.mark.asyncio
async def test_external_submission_finding_carries_zero_policy_contribution(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    path = write_external_submit_form_pdf(
        tmp_path / "submit.pdf", target="https://example.invalid/submit"
    )

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        result = await _upload(client, csrf, path.read_bytes(), "submit.pdf")

    contributions = {item["code"]: item["contribution"] for item in result["contributions"]}
    assert "PDF_EXTERNAL_SUBMISSION" in contributions
    assert contributions["PDF_EXTERNAL_SUBMISSION"] == 0
