from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.audit.service import AuditEventType, AuditService
from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import AuditEvent, Base, OperatorUser, ServerSession
from tests.auth_helpers import (
    TEST_OPERATOR_PASSWORD,
    TEST_OPERATOR_USERNAME,
    authenticate_operator,
    csrf_headers,
)
from tests.fixtures.pdf_factory import write_benign_pdf


def auth_settings(tmp_path: Path, **updates: object) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'auth.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
        **updates,
    )


@pytest.mark.asyncio
async def test_anonymous_api_matrix_is_unauthorized_and_public_surface_is_bounded(
    tmp_path: Path,
) -> None:
    app = create_app(auth_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        for method, path in (
            ("GET", "/api/v1/scans"),
            ("POST", "/api/v1/scans?filename=fixture.txt"),
            ("GET", f"/api/v1/scans/{'0' * 32}"),
            ("POST", f"/api/v1/scans/{'0' * 32}/sanitize"),
            ("GET", "/api/v1/artifacts"),
            ("GET", f"/api/v1/artifacts/{'0' * 32}/download"),
            ("GET", "/api/v1/audit-events"),
        ):
            response = await client.request(
                method, path, content=b"fixture" if method == "POST" else None
            )
            assert response.status_code == 401, (method, path)
            assert response.headers["content-type"].startswith("application/json")
        app_page = await client.get("/app")
        assert app_page.status_code == 303
        assert app_page.headers["location"] == "/login"
        assert (await client.get("/login")).status_code == 200
        assert (await client.get("/health/live")).status_code == 200


@pytest.mark.asyncio
async def test_login_stores_only_hashes_rotates_session_and_logout_revokes(
    tmp_path: Path,
) -> None:
    app = create_app(auth_settings(tmp_path))
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client:
            csrf = await authenticate_operator(app, client)
            first_token = client.cookies.get("docguard_session")
            assert first_token is not None and len(first_token) == 43
            with app.state.sessions() as session:
                operator = session.execute(select(OperatorUser)).scalar_one()
                first_session = session.execute(select(ServerSession)).scalar_one()
            assert TEST_OPERATOR_PASSWORD not in operator.password_hash
            assert operator.password_hash.startswith("$argon2id$")
            assert first_session.token_hash == hashlib.sha256(first_token.encode()).hexdigest()
            assert first_session.token_hash != first_token
            assert first_session.csrf_token_hash != csrf

            second_login = await client.post(
                "/login",
                content=str(
                    httpx.QueryParams(
                        {
                            "username": TEST_OPERATOR_USERNAME,
                            "password": TEST_OPERATOR_PASSWORD,
                        }
                    )
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert second_login.status_code == 303
            second_token = client.cookies.get("docguard_session")
            assert second_token is not None and second_token != first_token
            with app.state.sessions() as session:
                sessions = list(
                    session.scalars(select(ServerSession).order_by(ServerSession.created_at))
                )
            assert len(sessions) == 2
            assert sessions[0].revoked_at is not None
            assert sessions[1].revoked_at is None

            dashboard = await client.get("/app")
            csrf = dashboard.text.split('data-csrf-token="', 1)[1].split('"', 1)[0]
            missing = await client.post("/logout")
            assert missing.status_code == 403
            logout = await client.post(
                "/logout",
                content=str(httpx.QueryParams({"csrf_token": csrf})),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert logout.status_code == 303
            with app.state.sessions() as session:
                current = session.scalar(
                    select(ServerSession).where(
                        ServerSession.token_hash
                        == hashlib.sha256(second_token.encode()).hexdigest()
                    )
                )
                logout_event = session.scalar(
                    select(AuditEvent).where(
                        AuditEvent.event_type == AuditEventType.AUTH_LOGOUT.value
                    )
                )
            assert current is not None and current.revoked_at is not None
            assert logout_event is not None and logout_event.actor_id == operator.id

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
            cookies={"docguard_session": second_token},
        ) as replay:
            assert (await replay.get("/api/v1/scans")).status_code == 401


@pytest.mark.asyncio
async def test_login_success_audit_failure_rolls_back_session_and_emits_no_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(auth_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        app.state.authentication_service.create_operator(
            TEST_OPERATOR_USERNAME, TEST_OPERATOR_PASSWORD
        )

        def fail_audit(*args: object, **kwargs: object) -> None:
            del args, kwargs
            raise RuntimeError("controlled transaction failure")

        monkeypatch.setattr(AuditService, "add_to_transaction", fail_audit)
        with pytest.raises(RuntimeError, match="controlled transaction failure"):
            await client.post(
                "/login",
                content=str(
                    httpx.QueryParams(
                        {
                            "username": TEST_OPERATOR_USERNAME,
                            "password": TEST_OPERATOR_PASSWORD,
                        }
                    )
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        with app.state.sessions() as session:
            operator = session.scalar(select(OperatorUser))
            session_count = len(list(session.scalars(select(ServerSession))))
            success_events = len(
                list(
                    session.scalars(
                        select(AuditEvent).where(
                            AuditEvent.event_type == AuditEventType.AUTH_LOGIN_SUCCESS.value
                        )
                    )
                )
            )
        assert operator is not None and operator.last_login_at is None
        assert session_count == success_events == 0
        assert "docguard_session" not in client.cookies


@pytest.mark.asyncio
async def test_login_failures_are_generic_rate_limited_and_do_not_leak_credentials(
    tmp_path: Path,
) -> None:
    settings = auth_settings(tmp_path, login_attempts_per_minute=2, login_attempts_per_hour=4)
    app = create_app(settings)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        app.state.authentication_service.create_operator(
            TEST_OPERATOR_USERNAME, TEST_OPERATOR_PASSWORD
        )
        with app.state.sessions.begin() as session:
            operator = session.scalar(
                select(OperatorUser).where(OperatorUser.username == TEST_OPERATOR_USERNAME)
            )
            assert operator is not None
            operator.is_active = False
        bodies = (
            {"username": "unknown-user", "password": "wrong password value"},
            {"username": TEST_OPERATOR_USERNAME, "password": "wrong password value"},
            {"username": TEST_OPERATOR_USERNAME, "password": TEST_OPERATOR_PASSWORD},
        )
        responses = []
        for body in bodies:
            responses.append(
                await client.post(
                    "/login",
                    content=str(httpx.QueryParams(body)),
                    headers={"content-type": "application/x-www-form-urlencoded"},
                )
            )
        assert responses[0].status_code == responses[1].status_code == 401
        assert responses[2].status_code == 429
        assert all("Invalid username or password." in response.text for response in responses)
        with app.state.sessions() as session:
            events = list(
                session.scalars(
                    select(AuditEvent).where(
                        AuditEvent.event_type == AuditEventType.AUTH_LOGIN_FAILURE.value
                    )
                )
            )
        serialized = " ".join(str(event.details_json) for event in events)
        assert "wrong password" not in serialized
        assert TEST_OPERATOR_PASSWORD not in serialized
        assert all(event.actor_id is None and event.actor_type == "ANONYMOUS" for event in events)


@pytest.mark.asyncio
async def test_csrf_session_binding_origin_and_expired_session_fail_before_upload(
    tmp_path: Path,
) -> None:
    app = create_app(auth_settings(tmp_path))
    document = write_benign_pdf(tmp_path / "fixture.pdf").read_bytes()
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        transport = httpx.ASGITransport(app=app)
        async with (
            httpx.AsyncClient(transport=transport, base_url="http://test") as first,
            httpx.AsyncClient(transport=transport, base_url="http://test") as second,
        ):
            first_csrf = await authenticate_operator(app, first, username="operator-one")
            second_csrf = await authenticate_operator(app, second, username="operator-two")
            missing = await first.post("/api/v1/scans?filename=missing.pdf", content=document)
            wrong = await first.post(
                "/api/v1/scans?filename=wrong.pdf",
                content=document,
                headers=csrf_headers("0" * 64),
            )
            cross_session = await first.post(
                "/api/v1/scans?filename=cross.pdf",
                content=document,
                headers=csrf_headers(second_csrf),
            )
            foreign = await first.post(
                "/api/v1/scans?filename=foreign.pdf",
                content=document,
                headers=csrf_headers(first_csrf, origin="https://foreign.example"),
            )
            foreign_host = await first.post(
                "/api/v1/scans?filename=foreign-host.pdf",
                content=document,
                headers=csrf_headers(first_csrf, host="foreign.example"),
            )
            valid = await first.post(
                "/api/v1/scans?filename=valid.pdf",
                content=document,
                headers=csrf_headers(first_csrf),
            )
            assert [missing.status_code, wrong.status_code, cross_session.status_code] == [
                403,
                403,
                403,
            ]
            assert foreign.status_code == 403
            assert foreign_host.status_code == 400
            assert valid.status_code == 201

            token = first.cookies.get("docguard_session")
            assert token is not None
            with app.state.sessions.begin() as session:
                server_session = session.scalar(
                    select(ServerSession).where(
                        ServerSession.token_hash == hashlib.sha256(token.encode()).hexdigest()
                    )
                )
                assert server_session is not None
                server_session.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            expired = await first.post(
                "/api/v1/scans?filename=expired.pdf",
                content=document,
                headers=csrf_headers(first_csrf),
            )
            assert expired.status_code == 401


@pytest.mark.asyncio
async def test_inactivity_and_operator_deactivation_immediately_invalidate_sessions(
    tmp_path: Path,
) -> None:
    app = create_app(
        auth_settings(
            tmp_path,
            session_inactivity_lifetime_seconds=120,
            session_refresh_interval_seconds=30,
        )
    )
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            await authenticate_operator(app, client)
            token = client.cookies.get("docguard_session")
            assert token is not None
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with app.state.sessions.begin() as session:
                server_session = session.scalar(
                    select(ServerSession).where(ServerSession.token_hash == token_hash)
                )
                assert server_session is not None
                server_session.last_seen_at = datetime.now(UTC) - timedelta(minutes=3)
            assert (await client.get("/api/v1/scans")).status_code == 401

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as active_client:
            await authenticate_operator(app, active_client)
            with app.state.sessions.begin() as session:
                operator = session.scalar(
                    select(OperatorUser).where(OperatorUser.username == TEST_OPERATOR_USERNAME)
                )
                assert operator is not None
                operator.is_active = False
            assert (await active_client.get("/api/v1/scans")).status_code == 401


@pytest.mark.asyncio
async def test_cookie_and_browser_security_headers_are_environment_specific(
    tmp_path: Path,
) -> None:
    test_app = create_app(auth_settings(tmp_path))
    async with (
        test_app.router.lifespan_context(test_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=test_app),
            base_url="http://test",
            follow_redirects=False,
        ) as client,
    ):
        Base.metadata.create_all(test_app.state.database_engine)
        test_app.state.authentication_service.create_operator(
            TEST_OPERATOR_USERNAME, TEST_OPERATOR_PASSWORD
        )
        response = await client.post(
            "/login",
            content=str(
                httpx.QueryParams(
                    {
                        "username": TEST_OPERATOR_USERNAME,
                        "password": TEST_OPERATOR_PASSWORD,
                    }
                )
            ),
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": "http://test",
            },
        )
        cookie = response.headers["set-cookie"]
        assert "HttpOnly" in cookie and "SameSite=lax" in cookie
        assert "Secure" not in cookie
        login_page = await client.get("/login")
        assert login_page.headers["cache-control"] == "no-store"
        assert "default-src 'self'" in login_page.headers["content-security-policy"]
        assert "unsafe-inline" not in login_page.headers["content-security-policy"]
        assert login_page.headers["x-content-type-options"] == "nosniff"
        assert login_page.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in login_page.headers["content-security-policy"]

    production_settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'production-auth.db'}",
        storage_root=tmp_path / "production-storage",
        application_origin="https://test",
    )
    production_app = create_app(production_settings)
    async with (
        production_app.router.lifespan_context(production_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=production_app),
            base_url="https://test",
            follow_redirects=False,
        ) as client,
    ):
        Base.metadata.create_all(production_app.state.database_engine)
        production_app.state.authentication_service.create_operator(
            TEST_OPERATOR_USERNAME, TEST_OPERATOR_PASSWORD
        )
        response = await client.post(
            "/login",
            content=str(
                httpx.QueryParams(
                    {
                        "username": TEST_OPERATOR_USERNAME,
                        "password": TEST_OPERATOR_PASSWORD,
                    }
                )
            ),
            headers={
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://test",
            },
        )
        cookie = response.headers["set-cookie"]
        assert cookie.startswith("__Host-docguard_session=")
        assert "Secure" in cookie and "Path=/" in cookie
        assert "Domain=" not in cookie
        assert response.headers["strict-transport-security"].startswith("max-age=")
        assert (await client.get("/docs")).status_code == 404
        assert (await client.get("/redoc")).status_code == 404
        assert (await client.get("/openapi.json")).status_code == 404


@pytest.mark.asyncio
async def test_session_cleanup_is_bounded_dry_run_then_explicit_apply(tmp_path: Path) -> None:
    app = create_app(auth_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await authenticate_operator(app, client)
        with app.state.sessions.begin() as session:
            server_session = session.scalar(select(ServerSession))
            assert server_session is not None
            session_id = server_session.id
            server_session.revoked_at = datetime.now(UTC)
        candidates = app.state.authentication_service.cleanup_sessions(limit=1)
        with app.state.sessions() as session:
            assert session.get(ServerSession, session_id) is not None
        removed = app.state.authentication_service.cleanup_sessions(limit=1, apply=True)
        with app.state.sessions() as session:
            assert session.get(ServerSession, session_id) is None
    assert candidates == removed == 1
