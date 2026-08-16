"""Regression guards for the "queue reports authentication required immediately
after a fresh login" bug.

Root cause (see README's Quick development setup section): `application_origin`
defaults to `https://127.0.0.1:8000`. A developer who runs the documented dev
server over plain HTTP without also exporting `DOCGUARD_APPLICATION_ORIGIN` ends
up with every *fetch-based* authenticated request rejected with 403 "foreign
origin rejected" by the existing (correct, unmodified) same-origin check — while
a classic top-level form POST (`/login`) and page navigations (`GET /app`) are
unaffected, because only "unsafe" fetch/XHR requests carry a browser-set Origin
header for a same-origin request. That asymmetry is what makes a fresh, working
login look like it "didn't prevent" an immediate upload failure: the session is
completely valid, but a *different* independent check (Origin, not authentication)
is rejecting the request.

These tests prove:
  1. The queue's frontend-compatible request contract succeeds end-to-end when
     `application_origin` is configured correctly (the actual fix).
  2. A genuinely missing/invalid session still produces 401, never 403.
  3. A mismatched Origin still produces 403, never 401 — the two failure modes
     must never be collapsed into each other, in either direction.
  4. An invalid CSRF token still produces 403, never 401.
  5. Per-file isolation and login/dashboard behavior are unaffected by any of
     the above — one file's rejection never touches another.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from tests.auth_helpers import TEST_OPERATOR_PASSWORD, TEST_OPERATOR_USERNAME
from tests.fixtures.pdf_factory import write_benign_pdf


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{tmp_path / 'origin-regression.db'}",
        storage_root=tmp_path / "storage",
        isolation_backend=IsolationBackendName.UNSAFE_DEVELOPMENT,
        allow_unsafe_development_backend=True,
        application_origin="http://127.0.0.1:8000",
    )


async def _login(app: object, client: httpx.AsyncClient) -> str:
    from contextlib import suppress

    from app.auth.service import DuplicateOperatorError

    with suppress(DuplicateOperatorError):
        app.state.authentication_service.create_operator(  # type: ignore[attr-defined]
            TEST_OPERATOR_USERNAME, TEST_OPERATOR_PASSWORD
        )
    response = await client.post(
        "/login",
        content=str(
            httpx.QueryParams(
                {"username": TEST_OPERATOR_USERNAME, "password": TEST_OPERATOR_PASSWORD}
            )
        ).encode(),
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 303
    dashboard = await client.get("/app")
    assert dashboard.status_code == 200
    match = re.search(r'data-csrf-token="([0-9a-f]{64})"', dashboard.text)
    assert match is not None
    return match.group(1)


@pytest.mark.asyncio
async def test_frontend_compatible_upload_succeeds_with_matching_origin(tmp_path: Path) -> None:
    """This is the actual fix, proven end-to-end: a fresh login followed by the
    exact request shape app.js sends (same-origin fetch, credentials, CSRF
    header, an Origin header the browser adds automatically) must succeed when
    `application_origin` matches how the server is actually being served."""
    app = create_app(_settings(tmp_path))
    body = write_benign_pdf(tmp_path / "invoice.pdf").read_bytes()

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        # Deliberately do NOT set an Origin header for the login navigation — a
        # real same-origin top-level form POST typically does not carry one.
        csrf = await _login(app, client)

        response = await client.post(
            "/api/v1/scans",
            params={"filename": "invoice.pdf"},
            content=body,
            headers={
                "content-type": "application/pdf",
                "x-csrf-token": csrf,
                # A real fetch() always sets Origin for this "unsafe" method,
                # even same-origin.
                "origin": "http://127.0.0.1:8000",
            },
        )

    assert response.status_code == 201
    assert response.json()["decision"] == "ALLOW"


@pytest.mark.asyncio
async def test_missing_session_yields_401_never_403(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        response = await client.post(
            "/api/v1/scans",
            params={"filename": "invoice.pdf"},
            content=b"irrelevant",
            headers={
                "content-type": "application/pdf",
                "origin": "http://127.0.0.1:8000",
            },
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "authentication required"


@pytest.mark.asyncio
async def test_mismatched_origin_yields_403_never_401(tmp_path: Path) -> None:
    """A valid, freshly-logged-in session with a foreign Origin must be rejected
    as a CSRF/Origin failure (403) — never surfaced as an authentication failure
    (401). Collapsing these would be exactly the bug this suite guards against:
    the frontend's `authBlocked` halt must stay reserved for real 401s."""
    app = create_app(_settings(tmp_path))
    body = write_benign_pdf(tmp_path / "invoice.pdf").read_bytes()

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await _login(app, client)

        response = await client.post(
            "/api/v1/scans",
            params={"filename": "invoice.pdf"},
            content=body,
            headers={
                "content-type": "application/pdf",
                "x-csrf-token": csrf,
                "origin": "https://attacker.example",
            },
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "foreign origin rejected"


@pytest.mark.asyncio
async def test_invalid_csrf_token_yields_403_never_401(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path))
    body = write_benign_pdf(tmp_path / "invoice.pdf").read_bytes()

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        await _login(app, client)

        response = await client.post(
            "/api/v1/scans",
            params={"filename": "invoice.pdf"},
            content=body,
            headers={
                "content-type": "application/pdf",
                "x-csrf-token": "0" * 64,
                "origin": "http://127.0.0.1:8000",
            },
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "invalid CSRF token"


@pytest.mark.asyncio
async def test_one_rejected_origin_request_does_not_affect_a_sibling_request(
    tmp_path: Path,
) -> None:
    """Mirrors the queue's failure-isolation promise at the transport level: an
    Origin-rejected call and a legitimate call, made with the same session and
    CSRF token, are fully independent."""
    app = create_app(_settings(tmp_path))
    body = write_benign_pdf(tmp_path / "invoice.pdf").read_bytes()

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000"
        ) as client,
    ):
        Base.metadata.create_all(app.state.database_engine)
        csrf = await _login(app, client)

        rejected = await client.post(
            "/api/v1/scans",
            params={"filename": "bad-origin.pdf"},
            content=body,
            headers={
                "content-type": "application/pdf",
                "x-csrf-token": csrf,
                "origin": "https://attacker.example",
            },
        )
        accepted = await client.post(
            "/api/v1/scans",
            params={"filename": "invoice.pdf"},
            content=body,
            headers={
                "content-type": "application/pdf",
                "x-csrf-token": csrf,
                "origin": "http://127.0.0.1:8000",
            },
        )

    assert rejected.status_code == 403
    assert accepted.status_code == 201
    assert accepted.json()["decision"] == "ALLOW"


_JS_PATH = Path("app/web/static/app.js")


def test_frontend_never_treats_403_as_authentication_expiry() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    run_item = re.search(r"async function runItem\(item\) \{.*?\n    \}\n", js, re.DOTALL)
    assert run_item is not None
    body = run_item.group(0)
    # 403 (CSRF/Origin rejection) must fall through to the generic per-item
    # error branch and must never set authBlocked.
    assert "response.status === 403" not in body
    assert body.count("authBlocked = true") == 1
    branch_401 = body.split("response.status === 401", 1)[1].split("} else if", 1)[0]
    assert "authBlocked = true;" in branch_401


def test_frontend_never_treats_429_as_authentication_expiry() -> None:
    js = _JS_PATH.read_text(encoding="utf-8")
    run_item = re.search(r"async function runItem\(item\) \{.*?\n    \}\n", js, re.DOTALL)
    assert run_item is not None
    body = run_item.group(0)
    branch_429 = body.split("response.status === 429", 1)[1].split("} else {", 1)[0]
    assert "authBlocked" not in branch_429
