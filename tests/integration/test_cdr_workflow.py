from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

from app.audit.service import AuditEventType, AuditService
from app.cdr.models import CdrStatus, PdfCdrResult
from app.cdr.orchestrator import CdrOutcome
from app.cdr.registry import build_worker_cdr_config
from app.cdr.service import CdrService
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Artifact, AuditEvent, Base, Scan
from app.models.domain import Decision
from tests.auth_helpers import authenticate_operator
from tests.fixtures.pdf_factory import (
    write_acroform_pdf,
    write_benign_pdf,
    write_embedded_file_pdf,
    write_encrypted_pdf,
    write_javascript_name_tree_pdf,
    write_javascript_pdf,
    write_launch_action_pdf,
    write_malformed_pdf,
    write_multiple_actions_pdf,
    write_uri_action_pdf,
)
from tests.fixtures.yara_factory import (
    EICAR_TEST_BYTES,
    POWERSHELL_ENCODED_PATTERN,
    write_pdf_with_yara_pattern,
)
from tests.unit.test_file_identification import inert_pe_fixture


def cdr_settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'cdr.db'}",
        storage_root=tmp_path / "private-storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
        worker_timeout_seconds=15,
    )


@dataclass
class ControlledRenderer:
    settings: Settings
    output_bytes: bytes
    calls: int = 0

    def sanitize(self, source_path: Path, output_path: Path) -> CdrOutcome:
        del source_path
        self.calls += 1
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


async def upload(client: httpx.AsyncClient, filename: str, body: bytes) -> dict[str, object]:
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


def controlled_service(app: object, renderer: ControlledRenderer) -> CdrService:
    return CdrService(
        app.state.sessions,
        app.state.scan_service,
        renderer,  # type: ignore[arg-type]
        app.state.audit_service,
        app.state.storage_paths,
        app.state.settings,
    )


@pytest.mark.asyncio
async def test_cdr_eligibility_matrix_and_source_integrity(tmp_path: Path) -> None:
    settings = cdr_settings(tmp_path)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.headers["x-csrf-token"] = await authenticate_operator(app, client)
            review = await upload(
                client,
                "review.pdf",
                write_javascript_name_tree_pdf(tmp_path / "review.pdf").read_bytes(),
            )
            quarantine = await upload(
                client,
                "quarantine.pdf",
                write_javascript_pdf(tmp_path / "quarantine.pdf").read_bytes(),
            )
            allowed = await upload(
                client, "allowed.pdf", write_benign_pdf(tmp_path / "allowed.pdf").read_bytes()
            )
            encrypted = await upload(
                client,
                "encrypted.pdf",
                write_encrypted_pdf(tmp_path / "encrypted.pdf").read_bytes(),
            )
            malformed = await upload(
                client,
                "malformed.pdf",
                write_malformed_pdf(tmp_path / "malformed.pdf").read_bytes(),
            )
            blocked = await upload(client, "blocked.pdf", inert_pe_fixture())

        assert app.state.cdr_service.evaluate_cdr_eligibility(str(review["scan_id"])).eligible
        assert app.state.cdr_service.evaluate_cdr_eligibility(str(quarantine["scan_id"])).eligible
        for payload in (allowed, encrypted, malformed, blocked):
            assert not app.state.cdr_service.evaluate_cdr_eligibility(
                str(payload["scan_id"])
            ).eligible

        review_scan = app.state.scan_service.get(str(review["scan_id"]))
        review_path = app.state.storage_paths.resolve("quarantine", review_scan.storage_key)
        review_path.chmod(0o600)
        review_path.write_bytes(b"changed")
        review_path.chmod(0o400)
        failed = app.state.cdr_service.evaluate_cdr_eligibility(review_scan.id)
        assert "SOURCE_INTEGRITY_FAILED" in failed.reason_codes
        review_path.unlink()
        missing = app.state.cdr_service.evaluate_cdr_eligibility(review_scan.id)
        assert "SOURCE_INTEGRITY_FAILED" in missing.reason_codes


@pytest.mark.asyncio
async def test_successful_cdr_reanalysis_lineage_audit_integrity_and_idempotency(
    tmp_path: Path,
) -> None:
    settings = cdr_settings(tmp_path)
    app = create_app(settings)
    sanitized_bytes = write_benign_pdf(tmp_path / "sanitized.pdf").read_bytes()
    renderer = ControlledRenderer(settings, sanitized_bytes)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.headers["x-csrf-token"] = await authenticate_operator(app, client)
            source_payload = await upload(
                client,
                "active.pdf",
                write_javascript_pdf(tmp_path / "active.pdf").read_bytes(),
            )
        service = controlled_service(app, renderer)
        source_id = str(source_payload["scan_id"])
        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(service.sanitize_pdf, source_id)
            second_future = executor.submit(service.sanitize_pdf, source_id)
            first, second = first_future.result(), second_future.result()

        assert first.approved and second.approved
        assert {first.reused, second.reused} == {False, True}
        assert renderer.calls == 1
        with app.state.sessions() as session:
            source = session.get(Scan, source_id)
            derived = session.get(Scan, first.derived_scan_id)
            artifacts = list(session.scalars(select(Artifact)))
            events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.created_at)))
        assert source is not None and source.decision == Decision.QUARANTINE.value
        assert source.release_eligible is False
        assert derived is not None and derived.origin == "CDR_DERIVED"
        assert derived.parent_scan_id == source_id
        assert derived.decision == Decision.ALLOW.value and derived.release_eligible
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact.derived_scan_id == derived.id
        assert artifact.sha256 == derived.sha256
        assert artifact.size_bytes == derived.size_bytes
        assert artifact.policy_version == derived.policy_version
        artifact_path = app.state.storage_paths.resolve("sanitized", artifact.storage_key)
        assert artifact_path.read_bytes() == sanitized_bytes
        assert artifact_path.stat().st_mode & 0o777 == 0o400
        event_types = [event.event_type for event in events]
        for required in (
            AuditEventType.CDR_ELIGIBILITY_CHECKED.value,
            AuditEventType.CDR_STARTED.value,
            AuditEventType.CDR_RENDER_COMPLETED.value,
            AuditEventType.CDR_DERIVED_SCAN_CREATED.value,
            AuditEventType.CDR_RESCAN_COMPLETED.value,
            AuditEventType.CDR_APPROVED.value,
        ):
            assert required in event_types
        assert all(
            "DOCGUARD_HARMLESS_SCRIPT_FIXTURE" not in str(event.details_json) for event in events
        )
        artifact_path.chmod(0o600)
        artifact_path.write_bytes(b"tampered artifact")
        artifact_path.chmod(0o400)
        integrity_retry = service.sanitize_pdf(source_id)
        assert not integrity_retry.approved
        assert not integrity_retry.reused


@pytest.mark.asyncio
async def test_service_level_cdr_source_matrix(tmp_path: Path) -> None:
    settings = cdr_settings(tmp_path)
    app = create_app(settings)
    renderer = ControlledRenderer(
        settings, write_benign_pdf(tmp_path / "matrix-output.pdf", pages=2).read_bytes()
    )
    blocked_pdf = write_benign_pdf(tmp_path / "blocked.pdf").read_bytes() + b"\n" + EICAR_TEST_BYTES
    sources = {
        "javascript.pdf": write_javascript_pdf(tmp_path / "m-js.pdf").read_bytes(),
        "launch.pdf": write_launch_action_pdf(tmp_path / "m-launch.pdf").read_bytes(),
        "form.pdf": write_acroform_pdf(tmp_path / "m-form.pdf").read_bytes(),
        "uri.pdf": write_uri_action_pdf(tmp_path / "m-uri.pdf").read_bytes(),
        "embedded.pdf": write_embedded_file_pdf(tmp_path / "m-embedded.pdf").read_bytes(),
        "mixed.pdf": write_multiple_actions_pdf(tmp_path / "m-mixed.pdf").read_bytes(),
        "yara.pdf": write_pdf_with_yara_pattern(tmp_path / "m-yara.pdf").read_bytes(),
        "encrypted.pdf": write_encrypted_pdf(tmp_path / "m-encrypted.pdf").read_bytes(),
        "malformed.pdf": write_malformed_pdf(tmp_path / "m-malformed.pdf").read_bytes(),
        "blocked.pdf": blocked_pdf,
    }
    expected_approved = {
        "javascript.pdf",
        "launch.pdf",
        "embedded.pdf",
        "mixed.pdf",
        "yara.pdf",
    }
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        service = controlled_service(app, renderer)
        results: dict[str, object] = {}
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.headers["x-csrf-token"] = await authenticate_operator(app, client)
            for filename, body in sources.items():
                source = await upload(client, filename, body)
                results[filename] = service.sanitize_pdf(str(source["scan_id"]))

        for filename, result in results.items():
            assert result.approved is (filename in expected_approved), filename
        assert renderer.calls == len(expected_approved)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "output_kind", ["non_pdf", "malformed_pdf", "active_pdf", "yara_quarantine", "yara_block"]
)
async def test_compromised_renderer_output_is_reanalyzed_and_not_approved(
    tmp_path: Path, output_kind: str
) -> None:
    settings = cdr_settings(tmp_path)
    app = create_app(settings)
    benign_output = write_benign_pdf(tmp_path / "renderer-benign.pdf").read_bytes()
    outputs = {
        "non_pdf": b"not a pdf",
        "malformed_pdf": b"%PDF-1.7\nmalformed",
        "active_pdf": write_javascript_pdf(tmp_path / "renderer-active.pdf").read_bytes(),
        "yara_quarantine": benign_output + b"\n" + POWERSHELL_ENCODED_PATTERN,
        "yara_block": benign_output + b"\n" + EICAR_TEST_BYTES,
    }
    output = outputs[output_kind]
    renderer = ControlledRenderer(settings, output)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.headers["x-csrf-token"] = await authenticate_operator(app, client)
            source = await upload(
                client,
                "active.pdf",
                write_javascript_pdf(tmp_path / "source-active.pdf").read_bytes(),
            )
        result = controlled_service(app, renderer).sanitize_pdf(str(source["scan_id"]))
        with app.state.sessions() as session:
            artifact_count = session.scalar(select(func.count()).select_from(Artifact))
            derived = session.get(Scan, result.derived_scan_id)
            persisted_source = session.get(Scan, str(source["scan_id"]))
        assert not result.approved
        assert result.failure_code is not None
        assert artifact_count == 0
        assert derived is not None and derived.origin == "CDR_DERIVED"
        assert derived.decision != Decision.ALLOW.value
        assert persisted_source is not None
        assert persisted_source.decision == Decision.QUARANTINE.value


@pytest.mark.asyncio
async def test_approval_audit_failure_removes_promoted_file_and_db_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = cdr_settings(tmp_path)
    app = create_app(settings)
    renderer = ControlledRenderer(
        settings, write_benign_pdf(tmp_path / "sanitized.pdf").read_bytes()
    )
    original = AuditService.add_to_transaction

    def fail_only_approval(*args: object, **kwargs: object) -> object:
        event_type = args[1]
        if event_type is AuditEventType.CDR_APPROVED:
            raise ValueError("controlled approval audit failure")
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(AuditService, "add_to_transaction", staticmethod(fail_only_approval))
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            client.headers["x-csrf-token"] = await authenticate_operator(app, client)
            source = await upload(
                client,
                "active.pdf",
                write_javascript_pdf(tmp_path / "source.pdf").read_bytes(),
            )
        result = controlled_service(app, renderer).sanitize_pdf(str(source["scan_id"]))
        with app.state.sessions() as session:
            artifact_count = session.scalar(select(func.count()).select_from(Artifact))
            persisted_source = session.get(Scan, str(source["scan_id"]))

        assert not result.approved
        assert artifact_count == 0
        assert list(app.state.storage_paths.sanitized.iterdir()) == []
        assert persisted_source is not None
        assert persisted_source.decision == Decision.QUARANTINE.value


def test_only_authenticated_cdr_artifact_and_audit_routes_exist() -> None:
    app = create_app(cdr_settings(Path("/tmp/docguard-route-test")))
    paths = {path.casefold() for path in app.openapi()["paths"]}

    assert "/api/v1/scans/{scan_id}/sanitize" in paths
    assert "/api/v1/artifacts/{artifact_id}/download" in paths
    assert "/api/v1/audit-events" in paths
    assert not any("release" in path for path in paths)
    assert not any("quarantine" in path and "download" in path for path in paths)
