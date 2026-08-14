from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditEventType
from app.core.database import create_database_engine
from app.models.database import Artifact, AuditEvent, Base, Scan
from app.models.domain import Decision, ScanState
from app.operations.reconciliation import (
    ReconciliationLock,
    ReconciliationLocked,
    ReconciliationService,
)
from app.operations.storage_integrity import StorageIntegrityService
from app.storage.paths import StoragePaths, generate_storage_key


def _service(tmp_path: Path) -> tuple[ReconciliationService, sessionmaker[Session], StoragePaths]:
    paths = StoragePaths(tmp_path / "state")
    paths.initialize()
    engine = create_database_engine(f"sqlite:///{tmp_path / 'state.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    return ReconciliationService(sessions, paths), sessions, paths


def _stale_scan(
    sessions: sessionmaker[Session], paths: StoragePaths, *, stale: bool = True
) -> Scan:
    content = b"stored opaque fixture"
    key = generate_storage_key()
    path = paths.resolve("quarantine", key)
    path.write_bytes(content)
    path.chmod(0o400)
    scan = Scan(
        id=generate_storage_key(),
        original_filename="fixture.pdf",
        display_filename="fixture.pdf",
        storage_key=key,
        origin="UPLOAD",
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        state=ScanState.ANALYZING.value,
        decision=Decision.QUARANTINE.value,
        release_eligible=False,
        worker_status="RUNNING",
        updated_at=datetime.now(UTC) - timedelta(hours=1) if stale else datetime.now(UTC),
    )
    with sessions.begin() as session:
        session.add(scan)
    return scan


def test_reconciliation_dry_run_reports_without_mutating_or_deleting(tmp_path: Path) -> None:
    service, sessions, paths = _service(tmp_path)
    scan = _stale_scan(sessions, paths)
    orphan = paths.quarantine / generate_storage_key()
    orphan.write_bytes(b"unknown business object")
    orphan.chmod(0o400)

    report = service.inspect(stale_seconds=60, batch_size=100)

    assert {issue.code for issue in report.issues} >= {
        "STALE_ANALYZING_SCAN",
        "QUARANTINE_ORPHAN",
    }
    assert orphan.exists()
    with sessions() as session:
        persisted = session.get(Scan, scan.id)
        assert persisted is not None and persisted.state == ScanState.ANALYZING.value
        assert list(session.scalars(select(AuditEvent))) == []


def test_apply_only_quarantines_stale_scan_and_appends_system_audit(tmp_path: Path) -> None:
    service, sessions, paths = _service(tmp_path)
    scan = _stale_scan(sessions, paths)

    report = service.inspect(stale_seconds=60, batch_size=100, apply=True)

    assert report.stale_scans_quarantined == 1
    with sessions() as session:
        persisted = session.get(Scan, scan.id)
        assert persisted is not None
        assert persisted.state == ScanState.QUARANTINED.value
        assert persisted.worker_status == "FAILED"
        assert persisted.analysis_error_code == "recovery_stale_analysis"
        assert persisted.release_eligible is False
        assert persisted.decision == Decision.QUARANTINE.value
        events = list(session.scalars(select(AuditEvent)))
    assert [event.event_type for event in events] == [
        AuditEventType.RECOVERY_STALE_SCAN_QUARANTINED.value
    ]
    assert events[0].actor_type == "SYSTEM"


def test_temp_cleanup_is_exact_old_owned_regular_and_never_business_orphan(
    tmp_path: Path,
) -> None:
    service, sessions, paths = _service(tmp_path)
    _stale_scan(sessions, paths)
    eligible = paths.work / f".cdr-{generate_storage_key()}.part"
    eligible.write_bytes(b"temporary")
    eligible.chmod(0o600)
    old = datetime.now(UTC).timestamp() - 3_600
    os.utime(eligible, (old, old), follow_symlinks=False)
    unknown = paths.work / "unknown.part"
    unknown.write_bytes(b"must remain")
    unknown.chmod(0o600)
    symlink_target = tmp_path / "outside-temp"
    symlink_target.write_bytes(b"outside")
    symlink = paths.work / f".cdr-{generate_storage_key()}.part"
    symlink.symlink_to(symlink_target)
    orphan = paths.quarantine / generate_storage_key()
    orphan.write_bytes(b"business object")
    orphan.chmod(0o400)

    report = service.inspect(
        stale_seconds=60,
        batch_size=100,
        apply=True,
        cleanup_temporary=True,
    )

    assert report.temporary_files_cleaned == 1
    assert not eligible.exists()
    assert unknown.exists()
    assert symlink.is_symlink()
    assert symlink_target.read_bytes() == b"outside"
    assert orphan.exists()


def test_reconciliation_lock_prevents_concurrent_apply_and_recovers_on_exit(
    tmp_path: Path,
) -> None:
    paths = StoragePaths(tmp_path / "state")
    paths.initialize()
    with (
        ReconciliationLock(paths.root),
        pytest.raises(ReconciliationLocked),
        ReconciliationLock(paths.root),
    ):
        pass
    with ReconciliationLock(paths.root):
        pass
    assert (paths.root / ".reconcile.lock").stat().st_mode & 0o777 == 0o600


def test_storage_integrity_is_read_only_and_detects_tampering(tmp_path: Path) -> None:
    _, sessions, paths = _service(tmp_path)
    scan = _stale_scan(sessions, paths)
    service = StorageIntegrityService(sessions, paths)
    assert service.check(batch_size=100, include_quarantine=True).passed
    path = paths.resolve("quarantine", scan.storage_key)
    hardlink = tmp_path / "hardlink"
    os.link(path, hardlink)
    assert not service.check(batch_size=100, include_quarantine=True).passed
    hardlink.unlink()
    path.chmod(0o600)
    path.write_bytes(b"tampered")
    path.chmod(0o400)
    report = service.check(batch_size=100, include_quarantine=True)
    assert not report.passed
    assert [issue.code for issue in report.issues] == ["SCAN_OBJECT_INTEGRITY_FAILURE"]


def test_current_analysis_artifact_failures_and_sanitized_orphan_are_reported(
    tmp_path: Path,
) -> None:
    service, sessions, paths = _service(tmp_path)
    current = _stale_scan(sessions, paths, stale=False)
    artifact_key = generate_storage_key()
    with sessions.begin() as session:
        session.add(
            Artifact(
                id=generate_storage_key(),
                scan_id=current.id,
                artifact_type="PDF_CDR",
                storage_key=artifact_key,
                sha256="0" * 64,
                derived_scan_id=current.id,
                size_bytes=10,
                sanitizer_version="1.0.0",
                sanitizer_fingerprint="1" * 64,
                policy_version="1.0.0",
                policy_fingerprint="2" * 64,
            )
        )
    orphan = paths.sanitized / generate_storage_key()
    orphan.write_bytes(b"unreferenced sanitized")
    orphan.chmod(0o400)

    report = service.inspect(stale_seconds=60, batch_size=100, apply=True)

    codes = {issue.code for issue in report.issues}
    assert "STALE_ANALYZING_SCAN" not in codes
    assert "ARTIFACT_INTEGRITY_FAILURE" in codes
    assert "SANITIZED_ORPHAN" in codes
    assert orphan.exists()
    with sessions() as session:
        persisted = session.get(Scan, current.id)
        assert persisted is not None and persisted.state == ScanState.ANALYZING.value


def test_reconciliation_batch_is_bounded_and_truncation_is_explicit(tmp_path: Path) -> None:
    service, sessions, paths = _service(tmp_path)
    _stale_scan(sessions, paths)
    for _ in range(3):
        orphan = paths.quarantine / generate_storage_key()
        orphan.write_bytes(b"bounded orphan")
        orphan.chmod(0o400)
    report = service.inspect(stale_seconds=60, batch_size=1)
    assert report.inspected_scans == 1
    assert report.truncated
