"""Database-backed local login and opaque server-side session lifecycle."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditEventType, AuditPersistenceError, AuditService
from app.auth.models import AuthenticatedPrincipal, Role
from app.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    CredentialValidationError,
    PasswordService,
    normalize_username,
)
from app.auth.rate_limit import LoginRateLimiter
from app.core.config import Settings
from app.core.constants import CSRF_CONTEXT, SESSION_TOKEN_BYTES
from app.core.errors import DocGuardError
from app.models.database import OperatorUser, ServerSession, new_database_id
from app.models.domain import AuditActorType, AuditOutcome

logger = logging.getLogger(__name__)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class AuthenticationPersistenceError(DocGuardError):
    pass


class DuplicateOperatorError(DocGuardError):
    pass


@dataclass(frozen=True, slots=True)
class LoginResult:
    authenticated: bool
    principal: AuthenticatedPrincipal | None = None
    session_token: str | None = None
    rate_limited: bool = False


class AuthenticationService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        settings: Settings,
        password_service: PasswordService,
        audit_service: AuditService,
        rate_limiter: LoginRateLimiter,
    ) -> None:
        self._sessions = sessions
        self._settings = settings
        self._passwords = password_service
        self._audit = audit_service
        self._rate_limiter = rate_limiter

    def create_operator(self, username: str, password: str) -> OperatorUser:
        canonical = normalize_username(username)
        password_hash = self._passwords.hash_password(password)
        operator = OperatorUser(
            id=new_database_id(),
            username=canonical,
            password_hash=password_hash,
            role=Role.OPERATOR.value,
            is_active=True,
        )
        try:
            with self._sessions.begin() as session:
                session.add(operator)
        except IntegrityError as exc:
            raise DuplicateOperatorError("operator username already exists") from exc
        except SQLAlchemyError as exc:
            raise AuthenticationPersistenceError("operator creation failed") from exc
        return operator

    def login(
        self,
        username: str,
        password: str,
        *,
        source_address: str,
        previous_session_token: str | None,
    ) -> LoginResult:
        try:
            canonical = normalize_username(username)
        except CredentialValidationError:
            canonical = "invalid-username"
            valid_username = False
        else:
            valid_username = True

        if not self._rate_limiter.check(source_address, canonical).allowed:
            self._record_failed_login("RATE_LIMITED")
            return LoginResult(authenticated=False, rate_limited=True)

        operator: OperatorUser | None = None
        if valid_username:
            try:
                with self._sessions() as session:
                    operator = session.execute(
                        select(OperatorUser).where(OperatorUser.username == canonical)
                    ).scalar_one_or_none()
                    if operator is not None:
                        session.expunge(operator)
            except SQLAlchemyError as exc:
                raise AuthenticationPersistenceError("authentication lookup failed") from exc

        password_in_policy = len(password) <= MAX_PASSWORD_LENGTH
        if operator is None or not password_in_policy:
            self._passwords.verify_dummy(password if password_in_policy else "invalid-bounded")
            verified = False
        else:
            verified = self._passwords.verify_password(operator.password_hash, password)
        if operator is None or not verified or not operator.is_active:
            self._rate_limiter.record_failure(source_address, canonical)
            self._record_failed_login("INVALID_CREDENTIALS")
            return LoginResult(authenticated=False)

        raw_token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        token_hash = _sha256_text(raw_token)
        csrf_token = _derive_csrf_token(raw_token)
        csrf_hash = _sha256_text(csrf_token)
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self._settings.session_absolute_lifetime_seconds)
        session_id = new_database_id()
        try:
            with self._sessions.begin() as session:
                persisted = session.execute(
                    select(OperatorUser).where(OperatorUser.id == operator.id).with_for_update()
                ).scalar_one()
                if not persisted.is_active or persisted.role != Role.OPERATOR.value:
                    raise AuthenticationPersistenceError("operator is not active")
                if self._passwords.needs_rehash(persisted.password_hash):
                    persisted.password_hash = self._passwords.hash_password(password)
                if previous_session_token is not None and _valid_token(previous_session_token):
                    previous = session.execute(
                        select(ServerSession).where(
                            ServerSession.token_hash == _sha256_text(previous_session_token)
                        )
                    ).scalar_one_or_none()
                    if previous is not None and previous.revoked_at is None:
                        previous.revoked_at = now
                persisted.last_login_at = now
                server_session = ServerSession(
                    id=session_id,
                    user_id=persisted.id,
                    token_hash=token_hash,
                    csrf_token_hash=csrf_hash,
                    expires_at=expires_at,
                    last_seen_at=now,
                    revoked_at=None,
                )
                session.add(server_session)
                AuditService.add_to_transaction(
                    session,
                    AuditEventType.AUTH_LOGIN_SUCCESS,
                    scan_id=None,
                    outcome=AuditOutcome.SUCCESS,
                    actor_type=AuditActorType.OPERATOR,
                    actor_id=persisted.id,
                    details={"role": Role.OPERATOR.value},
                )
        except AuthenticationPersistenceError:
            raise
        except SQLAlchemyError as exc:
            raise AuthenticationPersistenceError("session creation failed") from exc
        self._rate_limiter.clear_username(canonical)
        principal = AuthenticatedPrincipal(
            user_id=operator.id,
            username=canonical,
            role=Role.OPERATOR,
            session_id=session_id,
            csrf_token=csrf_token,
        )
        return LoginResult(True, principal, raw_token)

    def authenticate(self, raw_token: str | None) -> AuthenticatedPrincipal | None:
        if raw_token is None or not _valid_token(raw_token):
            return None
        token_hash = _sha256_text(raw_token)
        csrf_token = _derive_csrf_token(raw_token)
        now = datetime.now(UTC)
        try:
            with self._sessions.begin() as session:
                row = session.execute(
                    select(ServerSession, OperatorUser)
                    .join(OperatorUser, OperatorUser.id == ServerSession.user_id)
                    .where(ServerSession.token_hash == token_hash)
                ).one_or_none()
                if row is None:
                    return None
                server_session, operator = row
                expires_at = _aware_utc(server_session.expires_at)
                last_seen_at = _aware_utc(server_session.last_seen_at)
                invalid = any(
                    (
                        server_session.revoked_at is not None,
                        now >= expires_at,
                        now - last_seen_at
                        >= timedelta(seconds=self._settings.session_inactivity_lifetime_seconds),
                        not operator.is_active,
                        operator.role != Role.OPERATOR.value,
                        not hmac.compare_digest(
                            server_session.csrf_token_hash, _sha256_text(csrf_token)
                        ),
                    )
                )
                if invalid:
                    if server_session.revoked_at is None:
                        server_session.revoked_at = now
                    return None
                if now - last_seen_at >= timedelta(
                    seconds=self._settings.session_refresh_interval_seconds
                ):
                    server_session.last_seen_at = now
                return AuthenticatedPrincipal(
                    user_id=operator.id,
                    username=operator.username,
                    role=Role(operator.role),
                    session_id=server_session.id,
                    csrf_token=csrf_token,
                )
        except (SQLAlchemyError, ValueError) as exc:
            raise AuthenticationPersistenceError("session validation failed") from exc

    def logout(self, raw_token: str | None, principal: AuthenticatedPrincipal | None) -> None:
        if raw_token is None or not _valid_token(raw_token):
            return
        now = datetime.now(UTC)
        actor_id: str | None = principal.user_id if principal is not None else None
        try:
            with self._sessions.begin() as session:
                server_session = session.execute(
                    select(ServerSession).where(ServerSession.token_hash == _sha256_text(raw_token))
                ).scalar_one_or_none()
                if server_session is not None and server_session.revoked_at is None:
                    server_session.revoked_at = now
                    actor_id = server_session.user_id
        except SQLAlchemyError as exc:
            raise AuthenticationPersistenceError("session revocation failed") from exc
        if actor_id is not None:
            try:
                self._audit.append(
                    AuditEventType.AUTH_LOGOUT,
                    scan_id=None,
                    outcome=AuditOutcome.SUCCESS,
                    actor_type=AuditActorType.OPERATOR,
                    actor_id=actor_id,
                )
            except AuditPersistenceError:
                logger.exception("logout_audit_unavailable")

    def cleanup_sessions(self, *, limit: int = 500, apply: bool = False) -> int:
        now = datetime.now(UTC)
        try:
            with self._sessions.begin() as session:
                ids = list(
                    session.scalars(
                        select(ServerSession.id)
                        .where(
                            or_(
                                ServerSession.expires_at <= now,
                                ServerSession.revoked_at.is_not(None),
                            )
                        )
                        .order_by(ServerSession.expires_at, ServerSession.id)
                        .limit(limit)
                    )
                )
                if ids and apply:
                    session.execute(delete(ServerSession).where(ServerSession.id.in_(ids)))
                return len(ids)
        except SQLAlchemyError as exc:
            raise AuthenticationPersistenceError("session cleanup failed") from exc

    def readiness(self, *, require_active_operator: bool) -> dict[str, bool]:
        checks = {"password_hasher": self._passwords.ready}
        try:
            with self._sessions() as session:
                session.scalar(select(func.count()).select_from(ServerSession))
                active = session.scalar(
                    select(func.count())
                    .select_from(OperatorUser)
                    .where(
                        OperatorUser.is_active.is_(True),
                        OperatorUser.role == Role.OPERATOR.value,
                    )
                )
            checks["auth_schema"] = True
            checks["session_store"] = True
            checks["active_operator"] = bool(active) if require_active_operator else True
        except SQLAlchemyError:
            checks["auth_schema"] = False
            checks["session_store"] = False
            checks["active_operator"] = not require_active_operator
        return checks

    def _record_failed_login(self, reason_code: str) -> None:
        try:
            self._audit.append(
                AuditEventType.AUTH_LOGIN_FAILURE,
                scan_id=None,
                outcome=AuditOutcome.DENIED,
                reason_code=reason_code,
                actor_type=AuditActorType.ANONYMOUS,
                actor_id=None,
            )
        except AuditPersistenceError:
            logger.warning("login_failure_audit_unavailable")


def _derive_csrf_token(raw_token: str) -> str:
    return hmac.new(raw_token.encode("ascii"), CSRF_CONTEXT, hashlib.sha256).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_token(value: str) -> bool:
    return bool(_TOKEN_RE.fullmatch(value))


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


__all__ = [
    "AuthenticationPersistenceError",
    "AuthenticationService",
    "DuplicateOperatorError",
    "LoginResult",
]
