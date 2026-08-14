"""Securely bootstrap one local DocGuard operator."""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditService
from app.auth.passwords import CredentialValidationError, PasswordService
from app.auth.rate_limit import LoginRateLimiter
from app.auth.service import (
    AuthenticationPersistenceError,
    AuthenticationService,
    DuplicateOperatorError,
)
from app.core.config import Settings
from app.core.database import create_database_engine


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a local DocGuard OPERATOR account")
    parser.add_argument("--username", help="canonical operator username; prompted when omitted")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one password line from standard input for controlled deployment automation",
    )
    arguments = parser.parse_args()
    username = arguments.username or input("Username: ").strip()
    if arguments.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            print("No password was provided on standard input.", file=sys.stderr)
            return 2
    else:
        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            print("Passwords do not match.", file=sys.stderr)
            return 2

    settings = Settings()
    engine = create_database_engine(settings.database_url)
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    passwords = PasswordService()
    audit = AuditService(sessions)
    service = AuthenticationService(
        sessions,
        settings,
        passwords,
        audit,
        LoginRateLimiter(
            per_minute=settings.login_attempts_per_minute,
            per_hour=settings.login_attempts_per_hour,
        ),
    )
    try:
        operator = service.create_operator(username, password)
    except (CredentialValidationError, DuplicateOperatorError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except AuthenticationPersistenceError:
        print("Operator creation failed. Verify that migration 0005 is applied.", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print(f"Created active OPERATOR {operator.username} ({operator.id}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
