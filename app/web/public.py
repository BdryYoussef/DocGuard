"""Public, unauthenticated landing page at the application root."""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.auth.http import principal_from_request

router = APIRouter(tags=["public"])


@router.get("/", response_class=HTMLResponse, response_model=None)
async def landing(request: Request) -> HTMLResponse | RedirectResponse:
    if principal_from_request(request) is not None:
        return RedirectResponse("/app", status_code=status.HTTP_303_SEE_OTHER)
    return cast(
        HTMLResponse,
        request.app.state.templates.TemplateResponse(
            request=request,
            name="landing.html",
            context={},
            status_code=status.HTTP_200_OK,
        ),
    )


__all__ = ["router"]
