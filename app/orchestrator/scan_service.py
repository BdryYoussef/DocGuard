"""Persisted non-release scan lifecycle around synchronous worker orchestration."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import PurePath

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload, sessionmaker

from app.core.errors import DocGuardError
from app.core.logging import log_event
from app.models.database import FindingRecord, Scan, new_database_id
from app.models.domain import AnalysisStatus, Decision, ScanOrigin, ScanState
from app.orchestrator.service import AnalysisOrchestrator
from app.policies.engine import evaluate_policy, fail_closed_policy_evaluation
from app.policies.models import PolicyEvaluation
from app.policies.registry import FINDING_POLICIES
from app.storage.ingestion import StoredDocument, remove_stored_document


class DatabasePersistenceError(DocGuardError):
    pass


class ScanNotFound(DocGuardError):
    pass


logger = logging.getLogger(__name__)


class ScanService:
    def __init__(
        self,
        sessions: sessionmaker[Session],
        orchestrator: AnalysisOrchestrator,
    ) -> None:
        self._sessions = sessions
        self._orchestrator = orchestrator

    def register_and_analyze(
        self,
        document: StoredDocument,
        *,
        original_filename: str,
        display_filename: str,
        claimed_content_type: str | None,
        origin: ScanOrigin = ScanOrigin.UPLOAD,
        parent_scan_id: str | None = None,
    ) -> Scan:
        scan = Scan(
            id=new_database_id(),
            original_filename=original_filename,
            display_filename=display_filename,
            storage_key=document.storage_key,
            origin=origin.value,
            parent_scan_id=parent_scan_id,
            sha256=document.sha256,
            size_bytes=document.size_bytes,
            claimed_extension=_claimed_extension(original_filename),
            claimed_content_type=claimed_content_type,
            state=ScanState.STORED.value,
            detected_type=None,
            detected_mime=None,
            analysis_error_code=None,
            risk_score=None,
            severity=None,
            decision=Decision.QUARANTINE.value,
            worker_status="PENDING",
            analysis_duration_ms=None,
            analysis_started_at=None,
            analysis_completed_at=None,
            policy_version=None,
            policy_fingerprint=None,
            release_eligible=False,
            policy_evaluation_json=None,
            analysis_metadata_json=None,
        )
        try:
            with self._sessions.begin() as session:
                session.add(scan)
        except SQLAlchemyError as exc:
            remove_stored_document(document)
            raise DatabasePersistenceError("scan registration failed") from exc

        self._mark_analyzing(scan.id)
        outcome = self._orchestrator.analyze(
            document.path,
            original_filename=original_filename,
            claimed_content_type=claimed_content_type,
        )
        evaluation: PolicyEvaluation | None = None
        try:
            with self._sessions.begin() as session:
                persisted = session.execute(
                    select(Scan).where(Scan.id == scan.id).with_for_update()
                ).scalar_one()
                policy_input_state = ScanState(persisted.state)
                persisted.analysis_completed_at = datetime.now(UTC)
                persisted.decision = Decision.QUARANTINE.value
                if outcome.result is None:
                    persisted.state = ScanState.QUARANTINED.value
                    persisted.worker_status = "FAILED"
                    persisted.analysis_error_code = (
                        outcome.failure_code.value
                        if outcome.failure_code is not None
                        else "unknown"
                    )
                else:
                    result = outcome.result
                    persisted.worker_status = result.status.value
                    persisted.analysis_duration_ms = result.duration_ms
                    persisted.detected_type = result.detected_type
                    persisted.analysis_metadata_json = result.analyzer_metadata
                    detected_mime = result.analyzer_metadata.get("detected_mime")
                    persisted.detected_mime = (
                        detected_mime if isinstance(detected_mime, str) else None
                    )
                    if result.status is AnalysisStatus.SUCCESS:
                        persisted.state = ScanState.COMPLETED.value
                        persisted.analysis_error_code = None
                    else:
                        persisted.state = ScanState.QUARANTINED.value
                        persisted.analysis_error_code = (
                            outcome.failure_code.value
                            if outcome.failure_code is not None
                            else result.status.value.casefold()
                        )
                    for finding in result.findings:
                        persisted.findings.append(
                            FindingRecord(
                                code=finding.code,
                                category=finding.category,
                                severity=finding.severity.value,
                                score_delta=FINDING_POLICIES[finding.code].contribution,
                                title=finding.title,
                                description=finding.description,
                                mitre_techniques=list(finding.mitre_techniques),
                                metadata_json=finding.metadata,
                            )
                        )
                log_event(
                    logger,
                    logging.INFO,
                    "policy_evaluation_started",
                    scan_id=persisted.id,
                )
                try:
                    evaluation = evaluate_policy(
                        outcome.result,
                        failure_code=(
                            outcome.failure_code.value if outcome.failure_code is not None else None
                        ),
                        scan_state=policy_input_state,
                    )
                except Exception:
                    logger.exception(
                        "policy_evaluation_failed",
                        extra={"structured_fields": {"scan_id": persisted.id}},
                    )
                    evaluation = fail_closed_policy_evaluation()
                    persisted.analysis_error_code = "policy_evaluation_failed"
                persisted.risk_score = evaluation.risk_score
                persisted.severity = evaluation.risk_band.value
                persisted.decision = evaluation.decision.value
                persisted.policy_version = evaluation.policy_version
                persisted.policy_fingerprint = evaluation.policy_fingerprint
                persisted.release_eligible = evaluation.release_eligible
                persisted.policy_evaluation_json = evaluation.model_dump(mode="json")
                if evaluation.decision in {Decision.QUARANTINE, Decision.BLOCK}:
                    persisted.state = ScanState.QUARANTINED.value
        except SQLAlchemyError as exc:
            raise DatabasePersistenceError("analysis result persistence failed") from exc
        if evaluation is None:
            raise AssertionError("policy evaluation was not produced")
        log_event(
            logger,
            logging.INFO,
            "policy_evaluation_completed",
            scan_id=scan.id,
            policy_version=evaluation.policy_version,
            risk_score=evaluation.risk_score,
            risk_band=evaluation.risk_band.value,
            decision=evaluation.decision.value,
            release_eligible=evaluation.release_eligible,
            hard_block_reason_count=len(evaluation.hard_block_reasons),
            compound_rule_count=len(evaluation.compound_rules_triggered),
        )
        return self.get(scan.id)

    def get(self, scan_id: str) -> Scan:
        try:
            with self._sessions() as session:
                scan = session.execute(
                    select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings))
                ).scalar_one_or_none()
                if scan is None:
                    raise ScanNotFound("scan does not exist")
                session.expunge(scan)
                return scan
        except SQLAlchemyError as exc:
            raise DatabasePersistenceError("scan lookup failed") from exc

    def _mark_analyzing(self, scan_id: str) -> None:
        try:
            with self._sessions.begin() as session:
                scan = session.execute(
                    select(Scan).where(Scan.id == scan_id).with_for_update()
                ).scalar_one()
                scan.state = ScanState.ANALYZING.value
                scan.worker_status = "RUNNING"
                scan.analysis_started_at = datetime.now(UTC)
        except SQLAlchemyError as exc:
            raise DatabasePersistenceError("could not begin analysis") from exc


def _claimed_extension(filename: str) -> str | None:
    basename = PurePath(filename.replace("\\", "/")).name
    suffix = PurePath(basename).suffix.casefold()
    if not suffix or len(suffix) > 32:
        return None
    return suffix.lstrip(".")
