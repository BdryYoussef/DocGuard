"""Bounded crash reconciliation with conservative fail-closed apply actions."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditEventType, AuditService
from app.models.database import Artifact, Scan
from app.models.domain import AuditActorType, AuditOutcome, Decision, ScanState
from app.storage.paths import StoragePaths, validate_storage_key

_UPLOAD_TEMP_RE = re.compile(r"^\.[0-9a-f]{32}\.[0-9a-f]{16}\.part$")
_CDR_TEMP_RE = re.compile(r"^\.cdr-[0-9a-f]{32}\.part$")
_HASH_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class ReconciliationIssue:
    code: str
    object_id: str | None = None


@dataclass(slots=True)
class ReconciliationReport:
    inspected_scans: int = 0
    inspected_artifacts: int = 0
    inspected_files: int = 0
    issues: list[ReconciliationIssue] = field(default_factory=list)
    stale_scans_quarantined: int = 0
    temporary_files_cleaned: int = 0
    truncated: bool = False

    @property
    def passed(self) -> bool:
        return not self.issues


class ReconciliationLocked(RuntimeError):
    pass


class ReconciliationLock(AbstractContextManager["ReconciliationLock"]):
    def __init__(self, storage_root: Path) -> None:
        self._path = storage_root / ".reconcile.lock"
        self._descriptor: int | None = None

    def __enter__(self) -> ReconciliationLock:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags, 0o600)
        except OSError as exc:
            raise ReconciliationLocked("trusted reconciliation lock is unavailable") from exc
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
            ):
                raise ReconciliationLocked("reconciliation lock is not a trusted regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise ReconciliationLocked("another reconciliation process holds the lock") from exc
        except (OSError, ReconciliationLocked):
            os.close(descriptor)
            raise
        self._descriptor = descriptor
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self._descriptor is not None:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)
            self._descriptor = None


class ReconciliationService:
    def __init__(self, sessions: sessionmaker[Session], paths: StoragePaths) -> None:
        self._sessions = sessions
        self._paths = paths

    def inspect(
        self,
        *,
        stale_seconds: int,
        batch_size: int,
        apply: bool = False,
        cleanup_temporary: bool = False,
        now: datetime | None = None,
    ) -> ReconciliationReport:
        if not 1 <= batch_size <= 10_000:
            raise ValueError("batch size must be between 1 and 10000")
        current = now or datetime.now(UTC)
        with ReconciliationLock(self._paths.root):
            return self._inspect_locked(
                stale_seconds=stale_seconds,
                batch_size=batch_size,
                apply=apply,
                cleanup_temporary=cleanup_temporary,
                now=current,
            )

    def _inspect_locked(
        self,
        *,
        stale_seconds: int,
        batch_size: int,
        apply: bool,
        cleanup_temporary: bool,
        now: datetime,
    ) -> ReconciliationReport:
        report = ReconciliationReport()
        cutoff = now - timedelta(seconds=stale_seconds)
        with self._sessions() as session:
            scans = list(session.scalars(select(Scan).order_by(Scan.id).limit(batch_size)))
            artifacts = list(
                session.scalars(select(Artifact).order_by(Artifact.id).limit(batch_size))
            )
        report.inspected_scans = len(scans)
        report.inspected_artifacts = len(artifacts)
        for scan in scans:
            updated = _aware_utc(scan.updated_at)
            if scan.state == ScanState.ANALYZING.value and updated <= cutoff:
                report.issues.append(ReconciliationIssue("STALE_ANALYZING_SCAN", scan.id))
                if apply and self._quarantine_stale_scan(scan.id, cutoff, now):
                    report.stale_scans_quarantined += 1
            path = self._paths.resolve("quarantine", validate_storage_key(scan.storage_key))
            if not _private_file_matches(path, scan.sha256, scan.size_bytes):
                report.issues.append(ReconciliationIssue("SCAN_OBJECT_MISSING_OR_INVALID", scan.id))
            if scan.parent_scan_id is not None and not self._row_exists(Scan, scan.parent_scan_id):
                report.issues.append(ReconciliationIssue("DERIVED_PARENT_LINEAGE_BROKEN", scan.id))

        for artifact in artifacts:
            path = self._paths.resolve("sanitized", validate_storage_key(artifact.storage_key))
            if not _private_file_matches(path, artifact.sha256, artifact.size_bytes):
                report.issues.append(ReconciliationIssue("ARTIFACT_INTEGRITY_FAILURE", artifact.id))

        self._inspect_orphans(
            self._paths.quarantine,
            Scan,
            "QUARANTINE_ORPHAN",
            report,
            batch_size,
        )
        self._inspect_orphans(
            self._paths.sanitized,
            Artifact,
            "SANITIZED_ORPHAN",
            report,
            batch_size,
        )
        self._inspect_temporary(
            report,
            cutoff=cutoff,
            batch_size=batch_size,
            delete=apply and cleanup_temporary,
        )
        return report

    def _quarantine_stale_scan(self, scan_id: str, cutoff: datetime, now: datetime) -> bool:
        with self._sessions.begin() as session:
            scan = session.execute(
                select(Scan).where(Scan.id == scan_id).with_for_update()
            ).scalar_one_or_none()
            if (
                scan is None
                or scan.state != ScanState.ANALYZING.value
                or _aware_utc(scan.updated_at) > cutoff
            ):
                return False
            scan.state = ScanState.QUARANTINED.value
            scan.worker_status = "FAILED"
            scan.analysis_error_code = "recovery_stale_analysis"
            scan.analysis_completed_at = now
            scan.release_eligible = False
            scan.decision = Decision.QUARANTINE.value
            AuditService.add_to_transaction(
                session,
                AuditEventType.RECOVERY_STALE_SCAN_QUARANTINED,
                scan_id=scan.id,
                outcome=AuditOutcome.SUCCESS,
                actor_type=AuditActorType.SYSTEM,
                reason_code="RECOVERY_STALE_ANALYSIS",
            )
        return True

    def _inspect_orphans(
        self,
        directory: Path,
        model: type[Scan] | type[Artifact],
        code: str,
        report: ReconciliationReport,
        batch_size: int,
    ) -> None:
        count = 0
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                count += 1
                if count > batch_size:
                    report.truncated = True
                    break
                report.inspected_files += 1
                if not self._storage_key_is_referenced(model, entry.name):
                    report.issues.append(ReconciliationIssue(code, entry.name))

    def _row_exists(self, model: type[Scan], object_id: str) -> bool:
        with self._sessions() as session:
            return session.get(model, object_id) is not None

    def _storage_key_is_referenced(
        self, model: type[Scan] | type[Artifact], storage_key: str
    ) -> bool:
        with self._sessions() as session:
            value = session.scalar(select(model.id).where(model.storage_key == storage_key))
            return value is not None

    def _inspect_temporary(
        self,
        report: ReconciliationReport,
        *,
        cutoff: datetime,
        batch_size: int,
        delete: bool,
    ) -> None:
        count = 0
        for directory in (self._paths.incoming, self._paths.work):
            with os.scandir(directory) as entries:
                for entry in entries:
                    recognized_name = _UPLOAD_TEMP_RE.fullmatch(
                        entry.name
                    ) or _CDR_TEMP_RE.fullmatch(entry.name)
                    if not recognized_name:
                        continue
                    count += 1
                    if count > batch_size:
                        report.truncated = True
                        return
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    modified = datetime.fromtimestamp(metadata.st_mtime, UTC)
                    trusted = (
                        stat.S_ISREG(metadata.st_mode)
                        and metadata.st_uid == os.geteuid()
                        and metadata.st_nlink == 1
                        and stat.S_IMODE(metadata.st_mode) in {0o400, 0o600}
                        and modified <= cutoff
                    )
                    if not trusted:
                        continue
                    report.issues.append(ReconciliationIssue("STALE_TEMP_OBJECT", entry.name))
                    if delete and _unlink_qualified_temp(directory, entry.name, cutoff):
                        report.temporary_files_cleaned += 1
                        AuditService(self._sessions).append(
                            AuditEventType.TEMP_OBJECT_CLEANED,
                            scan_id=None,
                            outcome=AuditOutcome.SUCCESS,
                            actor_type=AuditActorType.SYSTEM,
                            details={"area": directory.name},
                        )


def _private_file_matches(path: Path, expected_hash: str, expected_size: int) -> bool:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
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
        while chunk := os.read(descriptor, _HASH_CHUNK_BYTES):
            digest.update(chunk)
        return digest.hexdigest() == expected_hash
    except OSError:
        return False
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _unlink_qualified_temp(directory: Path, name: str, cutoff: datetime) -> bool:
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    file_fd: int | None = None
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
        opened = os.fstat(file_fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        trusted = (
            stat.S_ISREG(opened.st_mode)
            and opened.st_uid == os.geteuid()
            and opened.st_nlink == 1
            and stat.S_IMODE(opened.st_mode) in {0o400, 0o600}
            and datetime.fromtimestamp(opened.st_mtime, UTC) <= cutoff
            and (opened.st_dev, opened.st_ino) == (current.st_dev, current.st_ino)
        )
        if not trusted:
            return False
        os.unlink(name, dir_fd=directory_fd)
        return True
    except OSError:
        return False
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


__all__ = [
    "ReconciliationIssue",
    "ReconciliationLock",
    "ReconciliationLocked",
    "ReconciliationReport",
    "ReconciliationService",
]
