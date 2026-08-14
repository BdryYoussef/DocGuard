from __future__ import annotations

from importlib.metadata import version

import pytest

from app.auth.models import ROLE_CAPABILITIES, Capability, Role
from app.auth.passwords import (
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    CredentialValidationError,
    PasswordService,
    normalize_username,
    validate_password,
)
from app.core.config import AppEnvironment, Settings


def test_pinned_argon2id_hashing_policy_and_rehash_behavior() -> None:
    passwords = PasswordService()
    plaintext = "correct horse battery staple"
    encoded = passwords.hash_password(plaintext)

    assert version("argon2-cffi") == "25.1.0"
    assert encoded.startswith("$argon2id$v=19$")
    assert f"m={ARGON2_MEMORY_COST_KIB},t={ARGON2_TIME_COST},p={ARGON2_PARALLELISM}" in encoded
    assert plaintext not in encoded
    assert passwords.verify_password(encoded, plaintext)
    assert not passwords.verify_password(encoded, "wrong password value")
    assert not passwords.needs_rehash(encoded)
    assert passwords.ready


@pytest.mark.parametrize(
    "password",
    ["", " " * 12, "short", "x" * 129],
)
def test_password_policy_rejects_empty_short_whitespace_and_overlong(password: str) -> None:
    with pytest.raises(CredentialValidationError):
        validate_password(password)


def test_username_policy_is_canonical_bounded_and_path_independent() -> None:
    assert normalize_username("  Operator.Name_1-2  ") == "operator.name_1-2"
    for invalid in ("../operator", "/operator", "operator name", "opérator", "x" * 65):
        with pytest.raises(CredentialValidationError):
            normalize_username(invalid)


def test_capability_registry_has_only_v1_operator_actions() -> None:
    assert set(ROLE_CAPABILITIES) == {Role.OPERATOR}
    assert ROLE_CAPABILITIES[Role.OPERATOR] == {
        Capability.SCAN_UPLOAD,
        Capability.SCAN_READ,
        Capability.CDR_REQUEST,
        Capability.ARTIFACT_READ,
        Capability.AUDIT_READ,
    }
    forbidden = {"RAW_QUARANTINE_DOWNLOAD", "BLOCK_OVERRIDE", "POLICY_EDIT", "RULE_UPLOAD"}
    assert forbidden.isdisjoint(Capability.__members__)


def test_production_auth_configuration_rejects_unsafe_combinations() -> None:
    with pytest.raises(ValueError, match="Secure"):
        Settings(env=AppEnvironment.PRODUCTION, session_cookie_secure=False)
    with pytest.raises(ValueError, match="CSRF"):
        Settings(env=AppEnvironment.PRODUCTION, csrf_required=False)
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(env=AppEnvironment.PRODUCTION, application_origin="http://docguard.example")
    with pytest.raises(ValueError, match="__Host"):
        Settings(env=AppEnvironment.PRODUCTION, session_cookie_name="docguard_session")


def test_development_cookie_defaults_do_not_weaken_production_defaults() -> None:
    development = Settings(env=AppEnvironment.DEVELOPMENT)
    production = Settings()

    assert development.effective_session_cookie_name == "docguard_session"
    assert development.effective_session_cookie_secure is False
    assert production.effective_session_cookie_name == "__Host-docguard_session"
    assert production.effective_session_cookie_secure is True
