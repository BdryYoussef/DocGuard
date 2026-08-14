"""Download-time authorization, lineage, and byte-integrity enforcement."""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import AsyncIterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, aliased, sessionmaker

from app.audit.service import AuditEventType, AuditPersistenceError, AuditService
from app.auth.models import AuthenticatedPrincipal
from app.core.config import Settings
from app.core.errors import DocGuardError
from app.models.database import Artifact, Scan
from app.models.domain import (
    ArtifactType,
    AuditActorType,
    AuditOutcome,
    Decision,
    ScanOrigin,
    ScanState,
)
from app.storage.paths import StoragePaths

_READ_CHUNK_BYTES = 64 * 1024


class ArtifactNotFound(DocGuardError):
    pass


class ArtifactUnavailable(DocGuardError):
    pass


class ArtifactAuditUnavailable(DocGuardError):
    pass


@dataclass(slots=True)
class PreparedArtifactDownload:
    artifact_id: str
    descriptor: int
    size_bytes: int
    download_filename: str

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class ArtifactDownloadService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        paths: StoragePaths,
        settings: Settings,
        audit: AuditService,
    ) -> None:
        self._sessions = sessions
        self._paths = paths
        self._settings = settings
        self._audit = audit

    def prepare(
        self, artifact_id: str, principal: AuthenticatedPrincipal
    ) -> PreparedArtifactDownload:
        source = aliased(Scan)
        derived = aliased(Scan)
        try:
            with self._sessions() as session:
                row = session.execute(
                    select(Artifact, source, derived)
                    .join(source, source.id == Artifact.scan_id)
                    .join(derived, derived.id == Artifact.derived_scan_id)
                    .where(Artifact.id == artifact_id)
                ).one_or_none()
                if row is None:
                    raise ArtifactNotFound("artifact does not exist")
                artifact, source_scan, derived_scan = row
                valid = _valid_lineage(artifact, source_scan, derived_scan)
                session.expunge(artifact)
        except ArtifactNotFound:
            raise
        except SQLAlchemyError as exc:
            raise ArtifactUnavailable("artifact lookup failed") from exc
        if not valid:
            self._deny(artifact_id, principal, "LINEAGE_INVALID")
            raise ArtifactUnavailable("artifact is not approved for download")
        try:
            path = self._paths.resolve("sanitized", artifact.storage_key)
            descriptor = _open_verified_artifact(
                path,
                expected_size=artifact.size_bytes,
                expected_sha256=artifact.sha256,
                maximum_bytes=self._settings.cdr_max_output_bytes,
            )
        except (OSError, ValueError, ArtifactUnavailable):
            self._deny(artifact_id, principal, "INTEGRITY_FAILED")
            raise ArtifactUnavailable("artifact integrity verification failed") from None
        try:
            self._audit.append(
                AuditEventType.ARTIFACT_DOWNLOADED,
                scan_id=artifact.scan_id,
                artifact_id=artifact.id,
                outcome=AuditOutcome.SUCCESS,
                actor_type=AuditActorType.OPERATOR,
                actor_id=principal.user_id,
                details={"derived_scan_id": artifact.derived_scan_id},
            )
        except AuditPersistenceError as exc:
            os.close(descriptor)
            raise ArtifactAuditUnavailable("artifact download audit failed") from exc
        return PreparedArtifactDownload(
            artifact_id=artifact.id,
            descriptor=descriptor,
            size_bytes=artifact.size_bytes,
            download_filename=f"docguard-sanitized-{artifact.id[:12]}.pdf",
        )

    def _deny(self, artifact_id: str, principal: AuthenticatedPrincipal, reason_code: str) -> None:
        with suppress(AuditPersistenceError):
            self._audit.append(
                AuditEventType.ARTIFACT_DOWNLOAD_DENIED,
                scan_id=None,
                artifact_id=None,
                outcome=AuditOutcome.DENIED,
                reason_code=reason_code,
                actor_type=AuditActorType.OPERATOR,
                actor_id=principal.user_id,
                details={"requested_artifact_id": artifact_id},
            )


async def iter_download(download: PreparedArtifactDownload) -> AsyncIterator[bytes]:
    try:
        while chunk := os.read(download.descriptor, _READ_CHUNK_BYTES):
            yield chunk
    finally:
        download.close()


def _valid_lineage(artifact: Artifact, source: Scan, derived: Scan) -> bool:
    evaluation = derived.policy_evaluation_json
    return all(
        (
            artifact.artifact_type == ArtifactType.PDF_CDR.value,
            artifact.scan_id == source.id,
            artifact.derived_scan_id == derived.id,
            derived.origin == ScanOrigin.CDR_DERIVED.value,
            derived.parent_scan_id == source.id,
            derived.detected_type == "PDF",
            derived.worker_status == "SUCCESS",
            derived.state == ScanState.COMPLETED.value,
            derived.decision == Decision.ALLOW.value,
            derived.release_eligible is True,
            artifact.sha256 == derived.sha256,
            artifact.size_bytes == derived.size_bytes,
            artifact.policy_version == derived.policy_version,
            artifact.policy_fingerprint == derived.policy_fingerprint,
            isinstance(evaluation, dict),
            evaluation.get("decision") == Decision.ALLOW.value
            if isinstance(evaluation, dict)
            else False,
            evaluation.get("release_eligible") is True if isinstance(evaluation, dict) else False,
            evaluation.get("policy_version") == artifact.policy_version
            if isinstance(evaluation, dict)
            else False,
            evaluation.get("policy_fingerprint") == artifact.policy_fingerprint
            if isinstance(evaluation, dict)
            else False,
        )
    )


def _open_verified_artifact(
    path: Path, *, expected_size: int, expected_sha256: str, maximum_bytes: int
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size != expected_size
        ):
            raise ArtifactUnavailable("artifact filesystem metadata is invalid")
        digest = hashlib.sha256()
        observed_size = 0
        while chunk := os.read(descriptor, _READ_CHUNK_BYTES):
            observed_size += len(chunk)
            if observed_size > maximum_bytes:
                raise ArtifactUnavailable("artifact exceeds configured maximum")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            observed_size != expected_size
            or digest.hexdigest() != expected_sha256
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ArtifactUnavailable("artifact bytes changed or do not match persistence")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


__all__ = [
    "ArtifactAuditUnavailable",
    "ArtifactDownloadService",
    "ArtifactNotFound",
    "ArtifactUnavailable",
    "PreparedArtifactDownload",
    "iter_download",
]
