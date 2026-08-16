from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import authenticate_operator


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'landing.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://test",
    )


@pytest.mark.asyncio
async def test_anonymous_root_serves_landing_page(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/")

    assert response.status_code == 200
    assert "Inspect suspicious business documents before anyone opens them." in response.text
    assert (
        "DocGuard analyzes untrusted PDFs, Office documents and archives in an isolated"
        in response.text
    )
    assert 'href="/login"' in response.text
    # The four decisions are explained in plain language, and ALLOW is never overstated.
    assert "Significant risk or incomplete analysis requires containment." in response.text
    assert "Operators cannot override BLOCK in" in response.text
    assert "did not observe risky characteristics" in response.text
    assert "safe" not in response.text.casefold()
    assert "malware-free" not in response.text.casefold()


@pytest.mark.asyncio
async def test_landing_page_explains_the_trust_boundary_and_never_offers_registration(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/")

    assert response.status_code == 200
    text = response.text
    # Trusted-zone and untrusted-worker components from the architecture diagram.
    assert "Security trust boundary" in text
    assert "versioned JSON only" in text
    assert "FastAPI" in text
    assert "Authentication &amp; CSRF" in text
    assert "No network" in text
    assert "Bounded CPU" in text
    # Sign-in only — no registration flow of any kind.
    assert "Sign in" in text
    for forbidden in ("Sign up", "Register", "Create account", "Create an account"):
        assert forbidden not in text


@pytest.mark.asyncio
async def test_landing_page_carries_no_authenticated_content_or_session_state(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/")

    # No operator nav, no CSRF token, no logout affordance — this is the public shell.
    assert "data-csrf-token" not in response.text
    assert '/app/quarantine"' not in response.text
    assert '/app/audit"' not in response.text
    assert "Logout" not in response.text
    assert "set-cookie" not in response.headers


@pytest.mark.asyncio
async def test_authenticated_root_redirects_to_dashboard(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", follow_redirects=False
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await authenticate_operator(app, client)

        response = await client.get("/")

    assert response.status_code == 303
    assert response.headers["location"] == "/app"


@pytest.mark.asyncio
async def test_root_route_carries_existing_security_headers_and_csp(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/")

    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert "unsafe-eval" not in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


@pytest.mark.asyncio
async def test_unexpected_host_still_rejected_on_root(tmp_path: Path) -> None:
    """The new public route must not accidentally bypass canonical Host validation."""
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/", headers={"host": "evil.example"})

    assert response.status_code == 400


@pytest.mark.asyncio
async def test_authenticated_shell_navigation_labels_and_routes(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await authenticate_operator(app, client)

        dashboard = await client.get("/app")

    assert dashboard.status_code == 200
    text = dashboard.text
    for href, label in (
        ('/app"', "Dashboard"),
        ('/app/scans"', "Documents"),
        ('/app/quarantine"', "Quarantine"),
        ('/app/artifacts"', "Sanitized"),
        ('/app/audit"', "Audit"),
    ):
        assert href in text
        assert label in text
    # Routes are unchanged even though "Documents" is the new visible label for /app/scans.
    assert "Scans" not in text.split("<nav", 1)[1].split("</nav>", 1)[0]


@pytest.mark.asyncio
async def test_login_page_still_posts_to_login_with_required_fields(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.get("/login")

    assert response.status_code == 200
    assert 'method="post" action="/login"' in response.text
    assert 'name="username"' in response.text
    assert 'name="password"' in response.text
    assert "Authorized operators only." in response.text
