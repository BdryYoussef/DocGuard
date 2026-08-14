"""Pinned Argon2id password hashing and bounded credential policy."""

from __future__ import annotations

import re
from contextlib import suppress

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from argon2.low_level import Type

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65_536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_LENGTH = 16
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MIN_USERNAME_LENGTH = 1
MAX_USERNAME_LENGTH = 64
_USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")
_DUMMY_ARGON2_VERIFIER = (
    "$argon2id$v=19$m=65536,t=3,p=4$RG9jR3VhcmREdW1teVYxIQ$"
    "PCFP6cnslqG1JtYpq8aP2xdii927ASHZFbMr1kE4k70"
)


class CredentialValidationError(ValueError):
    pass


class PasswordService:
    def __init__(self) -> None:
        self._hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LENGTH,
            salt_len=ARGON2_SALT_LENGTH,
            type=Type.ID,
        )

    @property
    def ready(self) -> bool:
        try:
            return self._hasher.verify(_DUMMY_ARGON2_VERIFIER, "docguard-unknown-user-verification")
        except VerificationError:
            return False

    def hash_password(self, password: str) -> str:
        validate_password(password)
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False

    def verify_dummy(self, password: str) -> None:
        with suppress(InvalidHashError, VerificationError, VerifyMismatchError):
            self._hasher.verify(_DUMMY_ARGON2_VERIFIER, password)

    def needs_rehash(self, password_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(password_hash)
        except InvalidHashError:
            return True


def normalize_username(username: str) -> str:
    canonical = username.strip().casefold()
    if not _USERNAME_RE.fullmatch(canonical):
        raise CredentialValidationError(
            "username must contain only ASCII letters, digits, period, underscore, or hyphen"
        )
    return canonical


def validate_password(password: str) -> None:
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        raise CredentialValidationError(
            f"password must be {MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH} characters"
        )
    if not password.strip():
        raise CredentialValidationError("password must not be whitespace only")


__all__ = [
    "ARGON2_HASH_LENGTH",
    "ARGON2_MEMORY_COST_KIB",
    "ARGON2_PARALLELISM",
    "ARGON2_SALT_LENGTH",
    "ARGON2_TIME_COST",
    "MAX_PASSWORD_LENGTH",
    "MAX_USERNAME_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "CredentialValidationError",
    "PasswordService",
    "normalize_username",
    "validate_password",
]
