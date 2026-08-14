"""Bounded removal of expired and revoked server-side sessions."""

from __future__ import annotations

import argparse

from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditService
from app.auth.passwords import PasswordService
from app.auth.rate_limit import LoginRateLimiter
from app.auth.service import AuthenticationPersistenceError, AuthenticationService
from app.core.config import Settings
from app.core.database import create_database_engine


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove a bounded batch of inactive sessions")
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument(
        "--apply", action="store_true", help="delete the reported expired/revoked sessions"
    )
    arguments = parser.parse_args()
    if not 1 <= arguments.limit <= 10_000:
        parser.error("--limit must be between 1 and 10000")
    settings = Settings()
    engine = create_database_engine(settings.database_url)
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    service = AuthenticationService(
        sessions,
        settings,
        PasswordService(),
        AuditService(sessions),
        LoginRateLimiter(
            per_minute=settings.login_attempts_per_minute,
            per_hour=settings.login_attempts_per_hour,
        ),
    )
    try:
        candidates = service.cleanup_sessions(limit=arguments.limit, apply=arguments.apply)
    except AuthenticationPersistenceError:
        print("Session cleanup failed; verify database availability and migration state.")
        return 1
    finally:
        engine.dispose()
    action = "Removed" if arguments.apply else "Would remove"
    print(f"{action} {candidates} expired or revoked sessions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
