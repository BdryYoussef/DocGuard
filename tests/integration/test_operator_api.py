from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.audit.service import AuditEventType
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import AuditEvent, Base
from tests.auth_helpers import TEST_OPERATOR_PASSWORD, authenticate_operator, csrf_headers


def operator_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'operator.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@pytest.mark.asyncio
async def test_scan_and_audit_apis_are_bounded_newest_first_and_never_expose_storage(
    tmp_path: Path,
) -> None:
    app = create_app(operator_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        ids = []
        for index in range(3):
            response = await client.post(
                "/api/v1/scans",
                params={"filename": f"document-{index}.txt"},
                content=f"controlled text {index}".encode(),
                headers=csrf_headers(csrf, **{"content-type": "text/plain"}),
            )
            assert response.status_code == 201
            ids.append(response.json()["scan_id"])

        first_page = await client.get("/api/v1/scans?page=1&page_size=2")
        second_page = await client.get("/api/v1/scans?page=2&page_size=2")
        assert first_page.status_code == second_page.status_code == 200
        assert first_page.json()["total"] == 3
        assert [item["scan_id"] for item in first_page.json()["items"]] == list(reversed(ids[1:]))
        assert [item["scan_id"] for item in second_page.json()["items"]] == [ids[0]]
        assert (await client.get("/api/v1/scans?page_size=101")).status_code == 422
        detail = await client.get(f"/api/v1/scans/{ids[0]}")
        public_json = first_page.text + second_page.text + detail.text
        assert "storage_key" not in public_json
        assert str(app.state.storage_paths.root) not in public_json

        audit = await client.get("/api/v1/audit-events?page=1&page_size=2")
        assert audit.status_code == 200
        assert audit.json()["page_size"] == 2
        assert audit.json()["total"] >= 4
        assert (await client.get("/api/v1/audit-events?page_size=101")).status_code == 422
        assert (
            await client.post("/api/v1/audit-events", headers=csrf_headers(csrf))
        ).status_code in {
            404,
            405,
        }
        with app.state.sessions() as session:
            upload_events = list(
                session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == AuditEventType.SCAN_UPLOAD_REQUESTED.value
                    )
                )
            )
        assert len(upload_events) == 3
        assert all(event.actor_type == "OPERATOR" and event.actor_id for event in upload_events)
        serialized = " ".join(str(event.details_json) for event in upload_events)
        assert TEST_OPERATOR_PASSWORD not in serialized
        assert "controlled text" not in serialized


def test_openapi_has_no_raw_quarantine_block_override_policy_or_rule_mutation() -> None:
    app = create_app(operator_settings(Path("/tmp/docguard-operator-route-test")))
    operations = app.openapi()["paths"]
    paths = {path.casefold() for path in operations}

    assert not any("quarantine" in path and "download" in path for path in paths)
    assert not any("source" in path and "download" in path for path in paths)
    assert not any(token in path for path in paths for token in ("override", "policy", "rules"))
    assert not any(
        method in {"put", "patch", "delete"} for path in operations.values() for method in path
    )
