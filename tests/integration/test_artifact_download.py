from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from app.audit.service import AuditEventType, AuditPersistenceError
from app.cdr.models import CdrStatus, PdfCdrResult
from app.cdr.orchestrator import CdrOutcome
from app.cdr.registry import build_worker_cdr_config
from app.cdr.service import CdrService
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Artifact, AuditEvent, Base, Scan
from tests.auth_helpers import TEST_OPERATOR_USERNAME, authenticate_operator, csrf_headers
from tests.fixtures.pdf_factory import write_benign_pdf, write_javascript_name_tree_pdf


def artifact_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'artifact.db'}",
        storage_root=tmp_path / "private-storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@dataclass
class ControlledRenderer:
    settings: Settings
    output: bytes

    def sanitize(self, source_path: Path, output_path: Path) -> CdrOutcome:
        del source_path
        output_path.write_bytes(self.output)
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
                output_bytes=len(self.output),
                duration_ms=1,
                failure_code=None,
            ),
            None,
        )


async def approved_artifact(
    app: Any, client: httpx.AsyncClient, tmp_path: Path, csrf: str
) -> tuple[dict[str, object], bytes]:
    source = await client.post(
        "/api/v1/scans?filename=active.pdf",
        content=write_javascript_name_tree_pdf(tmp_path / "active.pdf").read_bytes(),
        headers=csrf_headers(csrf, **{"content-type": "application/pdf"}),
    )
    assert source.status_code == 201 and source.json()["decision"] == "REVIEW"
    output = write_benign_pdf(tmp_path / "sanitized.pdf").read_bytes()
    app.state.cdr_service = CdrService(
        app.state.sessions,
        app.state.scan_service,
        ControlledRenderer(app.state.settings, output),  # type: ignore[arg-type]
        app.state.audit_service,
        app.state.storage_paths,
        app.state.settings,
    )
    sanitized = await client.post(
        f"/api/v1/scans/{source.json()['scan_id']}/sanitize",
        headers=csrf_headers(csrf),
    )
    assert sanitized.status_code == 200 and sanitized.json()["approved"] is True
    return sanitized.json(), output


@pytest.mark.asyncio
async def test_approved_artifact_download_rechecks_lineage_integrity_and_audits_operator(
    tmp_path: Path,
) -> None:
    app = create_app(artifact_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        result, output = await approved_artifact(app, client, tmp_path, csrf)
        artifact_id = str(result["artifact_id"])
        source_id = str(result["source_scan_id"])
        derived_id = str(result["derived_scan_id"])

        listing = await client.get("/api/v1/artifacts")
        detail = await client.get(f"/api/v1/artifacts/{artifact_id}")
        downloaded = await client.get(f"/api/v1/artifacts/{artifact_id}/download")
        assert listing.status_code == detail.status_code == downloaded.status_code == 200
        assert downloaded.content == output
        assert downloaded.headers["content-type"].startswith("application/pdf")
        assert downloaded.headers["content-disposition"].startswith("attachment;")
        assert downloaded.headers["x-content-type-options"] == "nosniff"
        assert downloaded.headers["cache-control"] == "no-store, private"
        assert "storage_key" not in listing.text + detail.text
        assert str(app.state.storage_paths.root) not in listing.text + detail.text
        assert source_id not in downloaded.headers["content-disposition"]
        reused = await client.post(
            f"/api/v1/scans/{source_id}/sanitize", headers=csrf_headers(csrf)
        )
        assert reused.status_code == 200
        assert reused.json()["artifact_id"] == artifact_id
        assert reused.json()["reused"] is True

        with app.state.sessions() as session:
            source = session.get(Scan, source_id)
            derived = session.get(Scan, derived_id)
            event = session.scalar(
                select(AuditEvent).where(
                    AuditEvent.event_type == AuditEventType.ARTIFACT_DOWNLOADED.value
                )
            )
            operator_id = session.scalar(
                select(AuditEvent.actor_id).where(
                    AuditEvent.event_type == AuditEventType.AUTH_LOGIN_SUCCESS.value
                )
            )
            operator_requests = list(
                session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == AuditEventType.CDR_REQUESTED.value
                    )
                )
            )
        assert source is not None and source.decision == "REVIEW"
        assert derived is not None and derived.decision == "ALLOW" and derived.release_eligible
        assert event is not None and event.actor_id == operator_id
        assert event.actor_type == "OPERATOR"
        assert len(operator_requests) == 2
        assert all(item.actor_id == operator_id for item in operator_requests)

        source_download = await client.get(f"/api/v1/artifacts/{source_id}/download")
        unknown = await client.get(f"/api/v1/artifacts/{'f' * 32}/download")
        assert source_download.status_code == unknown.status_code == 404


@pytest.mark.asyncio
async def test_tampered_missing_symlink_or_nonreleasable_artifact_is_denied(
    tmp_path: Path,
) -> None:
    app = create_app(artifact_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        result, output = await approved_artifact(app, client, tmp_path, csrf)
        artifact_id = str(result["artifact_id"])
        with app.state.sessions() as session:
            artifact = session.get(Artifact, artifact_id)
            assert artifact is not None
            path = app.state.storage_paths.resolve("sanitized", artifact.storage_key)

        path.chmod(0o600)
        path.write_bytes(b"tampered")
        path.chmod(0o400)
        assert (await client.get(f"/api/v1/artifacts/{artifact_id}/download")).status_code == 409

        path.chmod(0o600)
        path.write_bytes(output)
        path.chmod(0o400)
        target = tmp_path / "controlled-target.pdf"
        target.write_bytes(output)
        path.unlink()
        path.symlink_to(target)
        assert (await client.get(f"/api/v1/artifacts/{artifact_id}/download")).status_code == 409

        path.unlink()
        assert (await client.get(f"/api/v1/artifacts/{artifact_id}/download")).status_code == 409

        path.write_bytes(output)
        path.chmod(0o400)
        with app.state.sessions.begin() as session:
            artifact = session.get(Artifact, artifact_id)
            assert artifact is not None
            derived = session.get(Scan, artifact.derived_scan_id)
            assert derived is not None
            derived.release_eligible = False
        assert (await client.get(f"/api/v1/artifacts/{artifact_id}/download")).status_code == 409


@pytest.mark.asyncio
async def test_required_audit_failure_prevents_artifact_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(artifact_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        result, output = await approved_artifact(app, client, tmp_path, csrf)
        artifact_id = str(result["artifact_id"])
        original = app.state.audit_service.append

        def fail_download_audit(event_type: AuditEventType, **kwargs: object) -> None:
            if event_type is AuditEventType.ARTIFACT_DOWNLOADED:
                raise AuditPersistenceError("controlled audit outage")
            original(event_type, **kwargs)

        monkeypatch.setattr(app.state.audit_service, "append", fail_download_audit)
        response = await client.get(f"/api/v1/artifacts/{artifact_id}/download")
        assert response.status_code == 409
        assert response.content != output
        assert TEST_OPERATOR_USERNAME not in response.text
