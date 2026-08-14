"""Browser security headers for application-owned pages and APIs."""

from __future__ import annotations

from fastapi import Request, Response

from app.core.config import AppEnvironment, Settings

CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
    )
)


def apply_security_headers(request: Request, response: Response, settings: Settings) -> None:
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
    )
    if request.url.path.startswith(("/app", "/api/", "/login", "/logout")):
        response.headers.setdefault("Cache-Control", "no-store")
    if settings.env is AppEnvironment.PRODUCTION and settings.effective_session_cookie_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


__all__ = ["CONTENT_SECURITY_POLICY", "apply_security_headers"]
