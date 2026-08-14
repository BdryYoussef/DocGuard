"""Public login and CSRF-protected logout browser routes."""

from __future__ import annotations

from typing import Annotated, cast

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth.http import (
    clear_session_cookie,
    enforce_csrf,
    enforce_request_origin,
    parse_urlencoded_form,
    principal_from_request,
    require_html_authenticated,
    set_session_cookie,
    source_address,
)
from app.auth.models import AuthenticatedPrincipal

router = APIRouter(tags=["authentication"])
_GENERIC_LOGIN_ERROR = "Invalid username or password."


@router.get("/login", response_class=HTMLResponse, response_model=None)
async def login_page(request: Request) -> HTMLResponse | RedirectResponse:
    if principal_from_request(request) is not None:
        return RedirectResponse("/app", status_code=status.HTTP_303_SEE_OTHER)
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None},
            status_code=status.HTTP_200_OK,
        ),
    )


@router.post("/login", response_class=HTMLResponse, response_model=None)
async def login(request: Request) -> HTMLResponse | RedirectResponse:
    enforce_request_origin(request)
    fields = await parse_urlencoded_form(request)
    username = fields.get("username", "")
    password = fields.get("password", "")
    settings = request.app.state.settings
    previous = request.cookies.get(settings.effective_session_cookie_name)
    result = request.app.state.authentication_service.login(
        username,
        password,
        source_address=source_address(request),
        previous_session_token=previous,
    )
    if not result.authenticated or result.session_token is None:
        code = (
            status.HTTP_429_TOO_MANY_REQUESTS
            if result.rate_limited
            else status.HTTP_401_UNAUTHORIZED
        )
        return cast(
            HTMLResponse,
            request.app.state.templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": _GENERIC_LOGIN_ERROR},
                status_code=code,
            ),
        )
    response = RedirectResponse("/app", status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, result.session_token, settings)
    return response


@router.post("/logout")
async def logout(
    request: Request,
    principal: Annotated[AuthenticatedPrincipal, Depends(require_html_authenticated)],
    _csrf: Annotated[None, Depends(enforce_csrf)],
) -> RedirectResponse:
    settings = request.app.state.settings
    raw_token = request.cookies.get(settings.effective_session_cookie_name)
    request.app.state.authentication_service.logout(raw_token, principal)
    response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response, settings)
    return response


__all__ = ["router"]
