from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.routing import Mount

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import AuditEvent, Base, FindingRecord, new_database_id
from tests.auth_helpers import authenticate_operator, csrf_headers
from tests.fixtures.pdf_factory import write_javascript_name_tree_pdf
from tests.unit.test_file_identification import inert_pe_fixture


def web_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'web.db'}",
        storage_root=tmp_path / "private-storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


def test_static_mount_is_application_owned_and_rejects_parent_traversal(tmp_path: Path) -> None:
    settings = web_settings(tmp_path)
    app = create_app(settings)
    mount = next(
        route for route in app.routes if isinstance(route, Mount) and route.path == "/static"
    )
    assert isinstance(mount.app, StaticFiles)
    static_root = Path(str(mount.app.directory)).resolve()
    assert static_root == Path("app/web/static").resolve()
    assert not static_root.is_relative_to(settings.storage_root.resolve())
    assert not settings.storage_root.resolve().is_relative_to(static_root)
    asset_path, asset_stat = mount.app.lookup_path("app.css")
    assert asset_stat is not None
    assert Path(asset_path).resolve().is_relative_to(static_root)
    escaped_path, escaped_stat = mount.app.lookup_path("../../private-storage/quarantine")
    assert escaped_path == ""
    assert escaped_stat is None


@pytest.mark.asyncio
async def test_hostile_filename_finding_and_audit_values_are_escaped(
    tmp_path: Path,
) -> None:
    app = create_app(web_settings(tmp_path))
    hostile_filename = "<script>alert(1)</script><img src=x onerror=alert(2)>.pdf"
    hostile_value = '"><svg onload=alert(3)>'
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        created = await client.post(
            "/api/v1/scans",
            params={"filename": hostile_filename},
            content=write_javascript_name_tree_pdf(tmp_path / "active.pdf").read_bytes(),
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )
        assert created.status_code == 201
        scan_id = created.json()["scan_id"]
        with app.state.sessions.begin() as session:
            finding = session.scalar(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
            assert finding is not None
            finding.metadata_json = {"hostile": hostile_value}
            session.add(
                AuditEvent(
                    id=new_database_id(),
                    event_type="CONTROLLED_UI_TEST",
                    scan_id=scan_id,
                    artifact_id=None,
                    actor_type="SYSTEM",
                    actor_id=None,
                    outcome="SUCCESS",
                    reason_code=None,
                    details_json={"source_decision": hostile_value},
                )
            )

        detail = await client.get(f"/app/scans/{scan_id}")
        assert detail.status_code == 200
        assert "<script>alert(1)</script>" not in detail.text
        assert "<svg onload=alert(3)>" not in detail.text
        assert "&lt;script&gt;alert(1)" in detail.text
        assert "&lt;svg onload=alert(3)&gt;" in detail.text
        audit = await client.get("/app/audit")
        assert "<svg onload=alert(3)>" not in audit.text
        assert "&lt;svg onload=alert(3)&gt;" in audit.text


@pytest.mark.asyncio
async def test_ui_cdr_visibility_block_behavior_empty_states_and_static_boundary(
    tmp_path: Path,
) -> None:
    settings = web_settings(tmp_path)
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        empty_artifacts = await client.get("/app/artifacts")
        assert "No approved sanitized artifacts yet." in empty_artifacts.text
        empty_quarantine = await client.get("/app/quarantine")
        assert "No documents currently require review or containment." in empty_quarantine.text

        review = await client.post(
            "/api/v1/scans?filename=review.pdf",
            content=write_javascript_name_tree_pdf(tmp_path / "review.pdf").read_bytes(),
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )
        blocked = await client.post(
            "/api/v1/scans?filename=invoice.pdf",
            content=inert_pe_fixture(),
            headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
        )
        review_page = await client.get(f"/app/scans/{review.json()['scan_id']}")
        block_page = await client.get(f"/app/scans/{blocked.json()['scan_id']}")
        assert "Generate sanitized PDF" in review_page.text
        assert "Generate sanitized PDF" not in block_page.text
        assert "Download approved sanitized PDF" not in block_page.text
        assert "BLOCK cannot be overridden" in block_page.text
        assert "raw quarantine" not in block_page.text.casefold()

        static_root = Path("app/web/static").resolve()
        assert not static_root.is_relative_to(settings.storage_root.resolve())
        assert not settings.storage_root.resolve().is_relative_to(static_root)
        css = (static_root / "app.css").read_text(encoding="utf-8")
        js = (static_root / "app.js").read_text(encoding="utf-8")
        combined = css + js
        assert "https://" not in combined
        assert "innerHTML" not in js
        assert "unsafe-eval" not in review_page.headers["content-security-policy"]
        assert review_page.headers["cache-control"] == "no-store"
