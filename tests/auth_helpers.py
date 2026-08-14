"""Real test operators and sessions; deliberately no authentication bypass."""

from __future__ import annotations

import re
from contextlib import suppress
from typing import Any

import httpx

from app.auth.service import DuplicateOperatorError

TEST_OPERATOR_USERNAME = "test-operator"
TEST_OPERATOR_PASSWORD = "correct horse battery staple"  # noqa: S105 - isolated test database
_CSRF_RE = re.compile(r'data-csrf-token="([0-9a-f]{64})"')


async def authenticate_operator(
    app: Any,
    client: httpx.AsyncClient,
    *,
    username: str = TEST_OPERATOR_USERNAME,
    password: str = TEST_OPERATOR_PASSWORD,
) -> str:
    with suppress(DuplicateOperatorError):
        app.state.authentication_service.create_operator(username, password)
    response = await client.post(
        "/login",
        content=str(httpx.QueryParams({"username": username, "password": password})).encode(),
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "origin": app.state.settings.application_origin,
        },
    )
    assert response.status_code == 303
    client.headers["origin"] = app.state.settings.application_origin
    dashboard = await client.get("/app")
    assert dashboard.status_code == 200
    match = _CSRF_RE.search(dashboard.text)
    assert match is not None
    return match.group(1)


def csrf_headers(csrf_token: str, **headers: str) -> dict[str, str]:
    return {**headers, "x-csrf-token": csrf_token}


__all__ = [
    "TEST_OPERATOR_PASSWORD",
    "TEST_OPERATOR_USERNAME",
    "authenticate_operator",
    "csrf_headers",
]
