"""Application-level abuse-control enforcement for authenticated operations."""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from app.auth.models import AuthenticatedPrincipal
from app.core.logging import log_event

logger = logging.getLogger(__name__)


def enforce_operator_limit(
    request: Request,
    principal: AuthenticatedPrincipal,
    *,
    action: str,
    limit: int,
    window_seconds: int,
) -> None:
    allowed = request.app.state.abuse_rate_limiter.consume(
        action=action,
        actor_id=principal.user_id,
        limit=limit,
        window_seconds=window_seconds,
    )
    if allowed:
        return
    log_event(
        logger,
        logging.WARNING,
        "operator_rate_limit_rejected",
        request_id=getattr(request.state, "request_id", "unavailable"),
        actor_id=principal.user_id,
        action=action,
    )
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="request rate limit exceeded",
        headers={"Retry-After": str(window_seconds)},
    )


__all__ = ["enforce_operator_limit"]
