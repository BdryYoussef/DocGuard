"""Read-only bounded verification of persisted private objects."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.database import Artifact, Scan
from app.storage.paths import StoragePaths, validate_storage_key

_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class StorageIntegrityIssue:
    code: str


@dataclass(slots=True)
class StorageIntegrityReport:
    inspected: int = 0
    issues: list[StorageIntegrityIssue] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.issues


class StorageIntegrityService:
    def __init__(self, sessions: sessionmaker[Session], paths: StoragePaths) -> None:
        self._sessions = sessions
        self._paths = paths

    def check(self, *, batch_size: int, include_quarantine: bool = False) -> StorageIntegrityReport:
        if not 1 <= batch_size <= 10_000:
            raise ValueError("batch size must be between 1 and 10000")
        report = StorageIntegrityReport()
        with self._sessions() as session:
            artifacts = list(
                session.scalars(select(Artifact).order_by(Artifact.id).limit(batch_size))
            )
            scans = (
                list(session.scalars(select(Scan).order_by(Scan.id).limit(batch_size)))
                if include_quarantine
                else []
            )
        for artifact in artifacts:
            report.inspected += 1
            path = self._paths.resolve("sanitized", validate_storage_key(artifact.storage_key))
            if not _verify(path, artifact.sha256, artifact.size_bytes):
                report.issues.append(StorageIntegrityIssue("ARTIFACT_INTEGRITY_FAILURE"))
        for scan in scans:
            report.inspected += 1
            path = self._paths.resolve("quarantine", validate_storage_key(scan.storage_key))
            if not _verify(path, scan.sha256, scan.size_bytes):
                report.issues.append(StorageIntegrityIssue("SCAN_OBJECT_INTEGRITY_FAILURE"))
        return report


def _verify(path: Path, expected_sha256: str, expected_size: int) -> bool:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_size != expected_size
        ):
            return False
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, _CHUNK_BYTES):
            digest.update(chunk)
        return digest.hexdigest() == expected_sha256
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


__all__ = ["StorageIntegrityIssue", "StorageIntegrityReport", "StorageIntegrityService"]
