"""Small, centralized operator role and capability model."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    OPERATOR = "OPERATOR"


class Capability(StrEnum):
    SCAN_UPLOAD = "SCAN_UPLOAD"
    SCAN_READ = "SCAN_READ"
    CDR_REQUEST = "CDR_REQUEST"
    ARTIFACT_READ = "ARTIFACT_READ"
    AUDIT_READ = "AUDIT_READ"


ROLE_CAPABILITIES: dict[Role, frozenset[Capability]] = {
    Role.OPERATOR: frozenset(Capability),
}


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    user_id: str
    username: str
    role: Role
    session_id: str
    csrf_token: str

    def has_capability(self, capability: Capability) -> bool:
        return capability in ROLE_CAPABILITIES[self.role]


__all__ = [
    "ROLE_CAPABILITIES",
    "AuthenticatedPrincipal",
    "Capability",
    "Role",
]
