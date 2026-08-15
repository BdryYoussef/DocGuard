from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from sqlalchemy import func, select

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.core.constants import ANALYSIS_SCHEMA_VERSION, WORKER_VERSION
from app.main import create_app
from app.models.database import Base, Scan
from app.models.domain import AnalysisResult, AnalysisStatus
from app.orchestrator.contract import WorkerRequest
from app.orchestrator.isolation import WorkerExecution
from tests.auth_helpers import TEST_OPERATOR_PASSWORD, authenticate_operator
from tests.fixtures.pdf_factory import write_javascript_pdf


def _test_settings(tmp_path: Path, **updates: object) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'http.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
        **updates,
    )


class ControlledBackend:
    ready = True

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        del timeout_seconds
        now = datetime.now(UTC)
        result = AnalysisResult(
            schema_version=ANALYSIS_SCHEMA_VERSION,
            worker_version=WORKER_VERSION,
            status=AnalysisStatus.SUCCESS,
            detected_type="TEXT",
            size_bytes=Path(request.sample_path).stat().st_size,
            findings=[],
            analyzer_metadata={"detected_mime": "text/plain"},
            started_at=now,
            completed_at=now,
            duration_ms=0,
        )
        return WorkerExecution(result.to_json(), "", 0, False)

    def sanitize(
        self, request: WorkerRequest, output_path: Path, timeout_seconds: float
    ) -> WorkerExecution:
        del request, output_path, timeout_seconds
        raise AssertionError("CDR is not part of this HTTP topology test")


@pytest.mark.asyncio
async def test_canonical_https_origin_succeeds_over_loopback_http_semantics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.main as main_module

    monkeypatch.setattr(
        main_module, "create_isolation_backend", lambda settings: ControlledBackend()
    )
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'proxy.db'}",
        storage_root=tmp_path / "storage",
        application_origin="https://docguard.example",
        trusted_proxy_ips="127.0.0.1",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        app.state.authentication_service.create_operator("operator", TEST_OPERATOR_PASSWORD)
        login = app.state.authentication_service.login(
            "operator",
            TEST_OPERATOR_PASSWORD,
            source_address="198.51.100.10",
            previous_session_token=None,
        )
        assert login.session_token is not None and login.principal is not None
        headers = {
            "host": "docguard.example",
            "origin": "https://docguard.example",
            "cookie": f"__Host-docguard_session={login.session_token}",
            "x-csrf-token": login.principal.csrf_token,
            "content-type": "text/plain",
            "x-real-ip": "198.51.100.10",
        }
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client:
            response = await client.post(
                "/api/v1/scans?filename=proxy-fixture.txt",
                content=b"DOCGUARD_TEST_MARKER\n",
                headers=headers,
            )
    assert response.status_code == 201
    assert response.headers["strict-transport-security"].startswith("max-age=")


@pytest.mark.asyncio
async def test_production_origin_host_and_request_id_negative_matrix(tmp_path: Path) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'negative.db'}",
        storage_root=tmp_path / "storage",
        application_origin="https://docguard.example",
    )
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="https://docguard.example",
            follow_redirects=False,
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        app.state.authentication_service.create_operator("operator", TEST_OPERATOR_PASSWORD)
        no_origin = await client.post(
            "/login",
            content="username=operator&password=correct+horse+battery+staple",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        foreign = await client.post(
            "/login",
            content="username=operator&password=correct+horse+battery+staple",
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://evil.example",
            },
        )
        poisoned = await client.get("/health/live", headers={"host": "evil.example"})
        duplicate_host = await client.get(
            "/health/live",
            headers=[("host", "docguard.example"), ("host", "evil.example")],
        )
        first = await client.get("/health/live", headers={"x-request-id": "caller-controlled"})
        second = await client.get("/health/live", headers={"x-request-id": "caller-controlled"})
    assert no_origin.status_code == foreign.status_code == 403
    assert poisoned.status_code == 400
    assert duplicate_host.status_code == 400
    assert re.fullmatch(r"[0-9a-f]{32}", poisoned.headers["x-request-id"])
    assert first.headers["x-request-id"] != "caller-controlled"
    assert first.headers["x-request-id"] != second.headers["x-request-id"]


@pytest.mark.asyncio
async def test_login_page_referrer_policy_is_same_origin_not_no_referrer(
    tmp_path: Path,
) -> None:
    """Regression test: ``Referrer-Policy: no-referrer`` made same-origin HTML form
    POSTs (e.g. the login form) serialize their Origin header as the literal string
    "null" per the Fetch standard's request-Origin-header algorithm, which then failed
    DocGuard's exact same-origin check with 403 "foreign origin rejected" in real
    browsers. ``same-origin`` avoids that downgrade while still sending no referrer at
    all cross-origin. Other security headers must remain unaffected."""
    app = create_app(_test_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/login")
    assert response.headers["referrer-policy"] == "same-origin"
    assert response.headers["content-security-policy"] == (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "camera=()" in response.headers["permissions-policy"]


@pytest.mark.asyncio
async def test_login_origin_enforcement_matches_browser_serialization_cases(
    tmp_path: Path,
) -> None:
    """Exercises exactly the reported interoperability scenario: explicit
    ``require_origin_header=True`` and an http:// application origin. Proves the exact
    same-origin Origin value a corrected browser now sends is accepted, that a foreign
    Origin is still rejected, that the literal string "null" (what browsers previously
    sent here) is still rejected rather than special-cased, and that a missing Origin
    is still rejected while required. CSRF enforcement is untouched by the header fix."""
    app = create_app(_test_settings(tmp_path, require_origin_header=True))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        app.state.authentication_service.create_operator("operator", TEST_OPERATOR_PASSWORD)
        login_body = "username=operator&password=correct+horse+battery+staple"
        form_headers = {"content-type": "application/x-www-form-urlencoded"}

        correct_origin = await client.post(
            "/login", content=login_body, headers={**form_headers, "origin": "http://test"}
        )
        foreign_origin = await client.post(
            "/login",
            content=login_body,
            headers={**form_headers, "origin": "https://evil.example"},
        )
        null_origin = await client.post(
            "/login", content=login_body, headers={**form_headers, "origin": "null"}
        )
        missing_origin = await client.post("/login", content=login_body, headers=form_headers)

    assert correct_origin.status_code == 303
    assert foreign_origin.status_code == 403
    assert foreign_origin.json()["detail"] == "foreign origin rejected"
    assert null_origin.status_code == 403
    assert null_origin.json()["detail"] == "foreign origin rejected"
    assert missing_origin.status_code == 403
    assert missing_origin.json()["detail"] == "origin required"


@pytest.mark.asyncio
async def test_csrf_still_enforced_after_referrer_policy_change(tmp_path: Path) -> None:
    """The Referrer-Policy fix only changes how the Origin header is populated by a
    correctly-behaving browser; it must not weaken CSRF token enforcement."""
    app = create_app(_test_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await authenticate_operator(app, client)
        missing_csrf = await client.post(
            "/api/v1/scans?filename=no-csrf.txt",
            content=b"DOCGUARD_TEST_MARKER\n",
            headers={"content-type": "text/plain"},
        )
        wrong_csrf = await client.post(
            "/api/v1/scans?filename=wrong-csrf.txt",
            content=b"DOCGUARD_TEST_MARKER\n",
            headers={"content-type": "text/plain", "x-csrf-token": "0" * 64},
        )
    assert missing_csrf.status_code == 403
    assert missing_csrf.json()["detail"] == "invalid CSRF token"
    assert wrong_csrf.status_code == 403
    assert wrong_csrf.json()["detail"] == "invalid CSRF token"


@pytest.mark.asyncio
async def test_upload_limit_rejection_creates_no_additional_scan(tmp_path: Path) -> None:
    app = create_app(_test_settings(tmp_path, uploads_per_operator_hour=1))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        first = await client.post(
            "/api/v1/scans?filename=one.txt",
            content=b"DOCGUARD_TEST_MARKER\n",
            headers={"content-type": "text/plain"},
        )
        second = await client.post(
            "/api/v1/scans?filename=two.txt",
            content=b"DOCGUARD_TEST_MARKER\n",
            headers={"content-type": "text/plain"},
        )
        with app.state.sessions() as session:
            count = session.scalar(select(func.count()).select_from(Scan))
    assert first.status_code == 201
    assert second.status_code == 429
    assert second.headers["retry-after"] == "3600"
    assert count == 1


@pytest.mark.asyncio
async def test_cdr_operator_limit_rejection_never_changes_source_policy(tmp_path: Path) -> None:
    app = create_app(_test_settings(tmp_path, cdr_requests_per_operator_hour=1))
    document = write_javascript_pdf(tmp_path / "active.pdf").read_bytes()
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await authenticate_operator(app, client)
        client.headers["x-csrf-token"] = csrf
        uploaded = await client.post(
            "/api/v1/scans?filename=active.pdf",
            content=document,
            headers={"content-type": "application/pdf"},
        )
        scan_id = uploaded.json()["scan_id"]
        before = app.state.scan_service.get(scan_id)
        first = await client.post(f"/api/v1/scans/{scan_id}/sanitize")
        second = await client.post(f"/api/v1/scans/{scan_id}/sanitize")
        after = app.state.scan_service.get(scan_id)
    assert uploaded.status_code == 201
    assert first.status_code == 409
    assert second.status_code == 429
    assert (after.state, after.decision, after.release_eligible) == (
        before.state,
        before.decision,
        before.release_eligible,
    )


@pytest.mark.asyncio
async def test_unexpected_methods_cors_and_security_headers_are_closed(tmp_path: Path) -> None:
    app = create_app(_test_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await authenticate_operator(app, client)
        responses = [
            await client.request(method, "/api/v1/scans")
            for method in ("TRACE", "CONNECT", "PUT", "PATCH", "DELETE", "OPTIONS")
        ]
        login = await client.get("/login")
    assert all(response.status_code in {405, 404} for response in responses)
    assert all(response.headers.get("access-control-allow-origin") != "*" for response in responses)
    assert login.headers["cache-control"] == "no-store"
    assert "unsafe-inline" not in login.headers["content-security-policy"]
    assert login.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_small_form_actual_size_bound_and_generic_internal_error(tmp_path: Path) -> None:
    app = create_app(_test_settings(tmp_path))
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            oversized = await client.post(
                "/login",
                content=b"username=a&password=" + b"x" * 5_000,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )

            csrf = await authenticate_operator(app, client)
            del csrf

            def fail_dashboard() -> object:
                raise RuntimeError("secret internal /path and SQL SELECT secret")

            app.state.operator_query_service.dashboard = fail_dashboard
            failed = await client.get("/app")
    assert oversized.status_code == 413
    assert failed.status_code == 500
    assert "secret" not in failed.text
    assert "/path" not in failed.text
    assert re.fullmatch(r"[0-9a-f]{32}", failed.json()["request_id"])


@pytest.mark.asyncio
async def test_request_logs_use_route_template_resolved_proxy_ip_and_no_hostile_filename(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    app = create_app(_test_settings(tmp_path, trusted_proxy_ips="127.0.0.1"))
    hostile_filename = 'report\n\r\x1b[31m"quoted"\u202e.pdf'
    with caplog.at_level("INFO"):
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://test",
                headers={"x-real-ip": "198.51.100.55", "x-forwarded-for": "203.0.113.9"},
            ) as client,
        ):
            Base.metadata.create_all(app.state.database_engine)
            csrf = await authenticate_operator(app, client)
            response = await client.post(
                "/api/v1/scans",
                params={"filename": hostile_filename},
                content=b"DOCGUARD_TEST_MARKER\n",
                headers={"x-csrf-token": csrf, "content-type": "text/plain"},
            )
    assert response.status_code == 201
    records = [
        record
        for record in caplog.records
        if record.name == "app.main" and record.getMessage() == "request_completed"
    ]
    upload_record = next(
        record
        for record in records
        if getattr(record, "structured_fields", {}).get("route") == "/api/v1/scans"
    )
    fields = upload_record.structured_fields  # type: ignore[attr-defined]
    assert fields["client_address"] == "198.51.100.55"
    assert hostile_filename not in str(fields)
    assert "filename=" not in str(fields)
