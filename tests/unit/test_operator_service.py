from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from app.core.database import create_database_engine
from app.models.database import Artifact, Base, Scan, new_database_id
from app.models.domain import ArtifactType, Decision
from app.operator.service import OperatorQueryService


def _service(tmp_path: Path) -> tuple[OperatorQueryService, sessionmaker[Session]]:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'operator.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, class_=Session, expire_on_commit=False)
    return OperatorQueryService(sessions), sessions


def _scan(*, decision: str, origin: str = "UPLOAD", parent_scan_id: str | None = None) -> Scan:
    content = f"fixture-{new_database_id()}".encode()
    return Scan(
        id=new_database_id(),
        original_filename="fixture.pdf",
        display_filename="fixture.pdf",
        storage_key=new_database_id(),
        origin=origin,
        parent_scan_id=parent_scan_id,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        state="COMPLETED",
        detected_type="PDF",
        decision=decision,
        release_eligible=decision == Decision.ALLOW.value,
        worker_status="SUCCESS",
    )


def test_dashboard_with_only_ordinary_allow_scans(tmp_path: Path) -> None:
    """No REVIEW/QUARANTINE/BLOCK scan exists, so the recent and contained result
    sets cannot overlap; this is the baseline dashboard call that already worked."""
    service, sessions = _service(tmp_path)
    first = _scan(decision=Decision.ALLOW.value)
    second = _scan(decision=Decision.ALLOW.value)
    with sessions.begin() as session:
        session.add_all([first, second])

    data = service.dashboard()

    assert data.decision_counts == {"ALLOW": 2}
    assert {scan.id for scan in data.recent_scans} == {first.id, second.id}
    assert data.contained_scans == []
    assert data.approved_artifact_count == 0


def test_dashboard_after_source_and_cdr_derived_scan_does_not_double_expunge(
    tmp_path: Path,
) -> None:
    """Reproduces the reported golden-route sequence: a QUARANTINE source scan and its
    CDR-derived ALLOW/release-eligible scan plus approved artifact both exist. With
    only two scans total, the QUARANTINE source is necessarily present in both the
    5-most-recent-overall query and the 5-most-recent-contained query, so the same
    SQLAlchemy identity-mapped Scan instance is returned by both queries in the same
    session. Before the fix, ``dashboard()`` expunged that instance twice and raised
    ``sqlalchemy.exc.InvalidRequestError``; this must now succeed."""
    service, sessions = _service(tmp_path)
    source = _scan(decision=Decision.QUARANTINE.value)
    derived = _scan(decision=Decision.ALLOW.value, origin="CDR_DERIVED")
    with sessions.begin() as session:
        session.add_all([source, derived])
    with sessions.begin() as session:
        derived_row = session.get(Scan, derived.id)
        assert derived_row is not None
        derived_row.parent_scan_id = source.id
        session.add(
            Artifact(
                id=new_database_id(),
                scan_id=source.id,
                artifact_type=ArtifactType.PDF_CDR.value,
                storage_key=new_database_id(),
                sha256="0" * 64,
                derived_scan_id=derived.id,
                size_bytes=1_024,
                sanitizer_version="1.0.0",
                sanitizer_fingerprint="0" * 64,
                policy_version="1.0.1",
                policy_fingerprint="0" * 64,
            )
        )

    data = service.dashboard()

    assert data.decision_counts == {"QUARANTINE": 1, "ALLOW": 1}
    assert {scan.id for scan in data.recent_scans} == {source.id, derived.id}
    assert [scan.id for scan in data.contained_scans] == [source.id]
    assert data.approved_artifact_count == 1


def test_dashboard_returned_scans_are_usable_after_session_closes(tmp_path: Path) -> None:
    """The dashboard call's internal session is closed before ``dashboard()`` returns;
    every scalar attribute the UI reads must remain accessible without triggering a
    lazy load against the now-closed session."""
    service, sessions = _service(tmp_path)
    scan = _scan(decision=Decision.BLOCK.value)
    with sessions.begin() as session:
        session.add(scan)

    data = service.dashboard()

    (returned,) = data.recent_scans
    assert returned.id == scan.id
    assert returned.display_filename == "fixture.pdf"
    assert returned.detected_type == "PDF"
    assert returned.decision == "BLOCK"
    assert returned.created_at is not None


def test_dashboard_overlap_does_not_corrupt_counts_or_ordering(tmp_path: Path) -> None:
    """A larger, more realistic mixed dataset: multiple ALLOW scans plus a QUARANTINE
    and a REVIEW scan among the most recent, forcing overlap between the recent-5 and
    contained-5 queries at more than one row, while still asserting exact counts and
    newest-first ordering are unaffected by the fix."""
    service, sessions = _service(tmp_path)
    base_time = datetime.now(UTC)
    scans = [
        _scan(decision=Decision.ALLOW.value),
        _scan(decision=Decision.QUARANTINE.value),
        _scan(decision=Decision.REVIEW.value),
        _scan(decision=Decision.ALLOW.value),
        _scan(decision=Decision.BLOCK.value),
    ]
    with sessions.begin() as session:
        for offset, scan in enumerate(scans):
            scan.created_at = base_time + timedelta(seconds=offset)
        session.add_all(scans)

    data = service.dashboard()

    assert data.decision_counts == {"ALLOW": 2, "QUARANTINE": 1, "REVIEW": 1, "BLOCK": 1}
    assert [scan.id for scan in data.recent_scans] == [scan.id for scan in reversed(scans)]
    contained_expected = [scan.id for scan in scans if scan.decision != Decision.ALLOW.value]
    assert [scan.id for scan in data.contained_scans] == list(reversed(contained_expected))
