"""HTTP authentication, authorization, origin, CSRF, and cookie primitives."""

from __future__ import annotations

import hmac
from collections.abc import Awaitable, Callable
from typing import Literal, cast
from urllib.parse import parse_qs

from fastapi import HTTPException, Request, Response, status

from app.auth.models import AuthenticatedPrincipal, Capability
from app.core.config import Settings
from app.core.proxy import resolve_client_address

SESSION_COOKIE_MAX_AGE_BUFFER_SECONDS = 60
MAX_FORM_BYTES = 4_096
MAX_CSRF_TOKEN_LENGTH = 128


def principal_from_request(request: Request) -> AuthenticatedPrincipal | None:
    value = getattr(request.state, "principal", None)
    return value if isinstance(value, AuthenticatedPrincipal) else None


def require_capability(
    capability: Capability,
) -> Callable[[Request], Awaitable[AuthenticatedPrincipal]]:
    async def dependency(request: Request) -> AuthenticatedPrincipal:
        principal = principal_from_request(request)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
            )
        if not principal.has_capability(capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="not authorized",
            )
        return principal

    return dependency


async def require_html_authenticated(request: Request) -> AuthenticatedPrincipal:
    principal = principal_from_request(request)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/login"},
            detail="authentication required",
        )
    return principal


async def enforce_csrf(request: Request) -> None:
    settings = cast(Settings, request.app.state.settings)
    if not settings.csrf_required:
        return
    principal = principal_from_request(request)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required"
        )
    _enforce_origin(request, settings)
    supplied = request.headers.get("x-csrf-token")
    if supplied is None and request.headers.get("content-type", "").casefold().startswith(
        "application/x-www-form-urlencoded"
    ):
        fields = await parse_urlencoded_form(request)
        supplied = fields.get("csrf_token")
    if (
        supplied is None
        or len(supplied) > MAX_CSRF_TOKEN_LENGTH
        or not hmac.compare_digest(supplied, principal.csrf_token)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid CSRF token")


async def parse_urlencoded_form(request: Request) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").partition(";")[0].strip().casefold()
    if content_type != "application/x-www-form-urlencoded":
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="invalid form"
        )
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            if int(declared_length) > MAX_FORM_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="form too large"
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="invalid content length"
            ) from None
    collected = bytearray()
    async for chunk in request.stream():
        if len(collected) + len(chunk) > MAX_FORM_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="form too large"
            )
        collected.extend(chunk)
    body = bytes(collected)
    try:
        parsed = parse_qs(
            body.decode("utf-8"),
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=10,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid form") from exc
    if any(len(values) != 1 for values in parsed.values()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid form")
    return {key: values[0] for key, values in parsed.items()}


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=settings.effective_session_cookie_name,
        value=token,
        max_age=settings.session_absolute_lifetime_seconds,
        httponly=True,
        secure=settings.effective_session_cookie_secure,
        samesite=_cookie_samesite(settings),
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=settings.effective_session_cookie_name,
        httponly=True,
        secure=settings.effective_session_cookie_secure,
        samesite=_cookie_samesite(settings),
        path="/",
    )


def source_address(request: Request) -> str:
    resolved = getattr(request.state, "client_address", None)
    if isinstance(resolved, str):
        return resolved
    return resolve_client_address(request, cast(Settings, request.app.state.settings))


def enforce_request_origin(request: Request) -> None:
    _enforce_origin(request, cast(Settings, request.app.state.settings))


def _enforce_origin(request: Request, settings: Settings) -> None:
    configured_origin = settings.application_origin.rstrip("/")
    origin = request.headers.get("origin")
    if origin is None and settings.effective_require_origin_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="origin required")
    if origin is not None and not hmac.compare_digest(origin.rstrip("/"), configured_origin):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="foreign origin rejected")


def _cookie_samesite(settings: Settings) -> Literal["lax", "strict"]:
    return "strict" if settings.session_cookie_samesite.casefold() == "strict" else "lax"


__all__ = [
    "clear_session_cookie",
    "enforce_csrf",
    "enforce_request_origin",
    "parse_urlencoded_form",
    "principal_from_request",
    "require_capability",
    "require_html_authenticated",
    "set_session_cookie",
    "source_address",
]
