"""Trusted, fail-closed PDF CDR workflow with re-analysis and immutable lineage."""

from __future__ import annotations

import json
import logging
import threading

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.audit.service import AuditEventType, AuditPersistenceError, AuditService
from app.cdr.models import CdrEligibility, CdrFailureCode, CdrServiceResult
from app.cdr.orchestrator import PdfCdrOrchestrator
from app.cdr.registry import build_worker_cdr_config
from app.core.config import Settings
from app.models.database import Artifact, Scan, new_database_id
from app.models.domain import (
    ArtifactType,
    AuditOutcome,
    Decision,
    ScanOrigin,
    ScanState,
)
from app.orchestrator.scan_service import DatabasePersistenceError, ScanNotFound, ScanService
from app.policies.models import PolicyEvaluation
from app.storage.ingestion import (
    StorageFailure,
    create_cdr_output,
    finalize_cdr_output,
    remove_cdr_output,
    remove_stored_document,
    store_private_copy,
    verify_private_document,
)
from app.storage.paths import StoragePaths

logger = logging.getLogger(__name__)


class CdrService:
    """Synchronous Phase-8 service; callers receive IDs, never filesystem paths."""

    def __init__(
        self,
        sessions: sessionmaker[Session],
        scan_service: ScanService,
        orchestrator: PdfCdrOrchestrator,
        audit: AuditService,
        paths: StoragePaths,
        settings: Settings,
    ) -> None:
        self._sessions = sessions
        self._scan_service = scan_service
        self._orchestrator = orchestrator
        self._audit = audit
        self._paths = paths
        self._settings = settings
        self._serialization_lock = threading.Lock()

    def get_existing_cdr_artifact(self, scan_id: str) -> Artifact | None:
        fingerprint = build_worker_cdr_config(self._settings).sanitizer_fingerprint
        with self._sessions() as session:
            artifact = session.execute(
                select(Artifact).where(
                    Artifact.scan_id == scan_id,
                    Artifact.artifact_type == ArtifactType.PDF_CDR.value,
                    Artifact.sanitizer_fingerprint == fingerprint,
                )
            ).scalar_one_or_none()
            if artifact is not None:
                try:
                    artifact_path = self._paths.resolve("sanitized", artifact.storage_key)
                except ValueError:
                    return None
                if not verify_private_document(
                    artifact_path,
                    expected_sha256=artifact.sha256,
                    expected_size=artifact.size_bytes,
                    maximum_bytes=self._settings.cdr_max_output_bytes,
                ):
                    return None
                session.expunge(artifact)
            return artifact

    def evaluate_cdr_eligibility(self, scan_id: str) -> CdrEligibility:
        return self._evaluate_cdr_eligibility(scan_id, record_audit=True)

    def inspect_cdr_eligibility(self, scan_id: str) -> CdrEligibility:
        """Read-only eligibility for UI/API presentation; never appends an event on GET."""

        return self._evaluate_cdr_eligibility(scan_id, record_audit=False)

    def _evaluate_cdr_eligibility(self, scan_id: str, *, record_audit: bool) -> CdrEligibility:
        config = build_worker_cdr_config(self._settings)
        reasons: set[str] = set()
        try:
            scan = self._scan_service.get(scan_id)
        except ScanNotFound:
            reasons.add("SCAN_NOT_FOUND")
            eligibility = CdrEligibility(
                eligible=False,
                scan_id=scan_id,
                reason_codes=tuple(sorted(reasons)),
                sanitizer_version=config.sanitizer_version,
                sanitizer_fingerprint=config.sanitizer_fingerprint,
            )
            if record_audit:
                self._append_eligibility(eligibility, source_decision=None, persisted_scan=False)
            return eligibility

        codes = {finding.code for finding in scan.findings}
        evaluation = _policy_evaluation(scan)
        if scan.detected_type != "PDF":
            reasons.add("NOT_PDF")
        if scan.worker_status != "SUCCESS" or scan.state not in {
            ScanState.COMPLETED.value,
            ScanState.QUARANTINED.value,
        }:
            reasons.add("ANALYSIS_NOT_SUCCESSFUL")
        if evaluation is None or not evaluation.analysis_complete:
            reasons.add("ANALYSIS_INCOMPLETE")
        if codes & {"PDF_PARTIAL_ANALYSIS", "PDF_MALFORMED", "PDF_ENCRYPTED"}:
            reasons.add("PDF_NOT_RENDERABLE")
        if scan.decision not in {Decision.REVIEW.value, Decision.QUARANTINE.value}:
            reasons.add("DECISION_NOT_REMEDIABLE")
        if scan.decision == Decision.BLOCK.value or (
            evaluation is not None and evaluation.hard_block_reasons
        ):
            reasons.add("SOURCE_BLOCKED")
        page_count = _pdf_page_count(scan.analysis_metadata_json)
        if page_count is None or not 1 <= page_count <= config.max_pages:
            reasons.add("PAGE_COUNT_OUT_OF_RANGE")
        try:
            source_path = self._paths.resolve("quarantine", scan.storage_key)
        except ValueError:
            reasons.add("SOURCE_STORAGE_INVALID")
        else:
            if not verify_private_document(
                source_path,
                expected_sha256=scan.sha256,
                expected_size=scan.size_bytes,
                maximum_bytes=self._settings.maximum_upload_bytes,
            ):
                reasons.add("SOURCE_INTEGRITY_FAILED")
        eligibility = CdrEligibility(
            eligible=not reasons,
            scan_id=scan.id,
            reason_codes=tuple(sorted(reasons)),
            sanitizer_version=config.sanitizer_version,
            sanitizer_fingerprint=config.sanitizer_fingerprint,
        )
        if record_audit:
            self._append_eligibility(eligibility, source_decision=scan.decision)
        return eligibility

    def sanitize_pdf(self, scan_id: str) -> CdrServiceResult:
        with self._serialization_lock:
            try:
                eligibility = self.evaluate_cdr_eligibility(scan_id)
            except AuditPersistenceError:
                return _failed(scan_id, CdrFailureCode.AUDIT_FAILURE)
            if not eligibility.eligible:
                return _failed(scan_id, CdrFailureCode.INELIGIBLE)
            existing = self.get_existing_cdr_artifact(scan_id)
            if existing is not None:
                return CdrServiceResult(
                    source_scan_id=scan_id,
                    derived_scan_id=existing.derived_scan_id,
                    artifact_id=existing.id,
                    approved=True,
                    reused=True,
                )
            source = self._scan_service.get(scan_id)
            source_path = self._paths.resolve("quarantine", source.storage_key)
            try:
                self._audit.append(
                    AuditEventType.CDR_STARTED,
                    scan_id=source.id,
                    outcome=AuditOutcome.SUCCESS,
                    details=_identity_details(eligibility),
                )
            except AuditPersistenceError:
                return _failed(scan_id, CdrFailureCode.AUDIT_FAILURE)

            try:
                output = create_cdr_output(self._paths)
            except StorageFailure:
                self._safe_audit_failure(source.id, CdrFailureCode.STORAGE_FAILURE)
                return _failed(scan_id, CdrFailureCode.STORAGE_FAILURE)
            try:
                render = self._orchestrator.sanitize(source_path, output.path)
                if not render.succeeded or render.result is None:
                    failure = render.failure_code or CdrFailureCode.RENDER_FAILED
                    self._audit.append(
                        AuditEventType.CDR_RENDER_FAILED,
                        scan_id=source.id,
                        outcome=AuditOutcome.FAILURE,
                        reason_code=failure.value,
                        details=_identity_details(eligibility),
                    )
                    self._audit.append(
                        AuditEventType.CDR_REJECTED,
                        scan_id=source.id,
                        outcome=AuditOutcome.DENIED,
                        reason_code=failure.value,
                    )
                    return _failed(scan_id, failure)
                candidate_sha256, candidate_size = finalize_cdr_output(
                    output, maximum_bytes=self._settings.cdr_max_output_bytes
                )
                if render.result.output_bytes != candidate_size:
                    self._safe_audit_failure(source.id, CdrFailureCode.HASH_MISMATCH)
                    return _failed(scan_id, CdrFailureCode.HASH_MISMATCH)
                self._audit.append(
                    AuditEventType.CDR_RENDER_COMPLETED,
                    scan_id=source.id,
                    outcome=AuditOutcome.SUCCESS,
                    details={
                        **_identity_details(eligibility),
                        "duration_ms": render.result.duration_ms,
                        "page_count": render.result.page_count,
                        "output_bytes": candidate_size,
                    },
                )
                derived_document = store_private_copy(
                    output.path,
                    paths=self._paths,
                    area="quarantine",
                    maximum_bytes=self._settings.cdr_max_output_bytes,
                    expected_sha256=candidate_sha256,
                )
                try:
                    derived = self._scan_service.register_and_analyze(
                        derived_document,
                        original_filename="docguard-cdr.pdf",
                        display_filename="docguard-cdr.pdf",
                        claimed_content_type="application/pdf",
                        origin=ScanOrigin.CDR_DERIVED,
                        parent_scan_id=source.id,
                    )
                except DatabasePersistenceError:
                    remove_stored_document(derived_document)
                    self._safe_audit_failure(source.id, CdrFailureCode.DATABASE_FAILURE)
                    return _failed(scan_id, CdrFailureCode.DATABASE_FAILURE)
                self._audit.append(
                    AuditEventType.CDR_DERIVED_SCAN_CREATED,
                    scan_id=derived.id,
                    outcome=AuditOutcome.SUCCESS,
                    details={"source_scan_id": source.id},
                )
                self._audit.append(
                    AuditEventType.CDR_RESCAN_COMPLETED,
                    scan_id=derived.id,
                    outcome=AuditOutcome.SUCCESS,
                    details={"decision": derived.decision or Decision.QUARANTINE.value},
                )
                if not _derived_is_approvable(
                    derived,
                    source_id=source.id,
                    expected_sha256=candidate_sha256,
                ):
                    self._audit.append(
                        AuditEventType.CDR_REJECTED,
                        scan_id=derived.id,
                        outcome=AuditOutcome.DENIED,
                        reason_code=CdrFailureCode.DERIVED_ANALYSIS_REJECTED.value,
                        details={"source_scan_id": source.id, "derived_decision": derived.decision},
                    )
                    return CdrServiceResult(
                        source_scan_id=source.id,
                        derived_scan_id=derived.id,
                        artifact_id=None,
                        approved=False,
                        failure_code=CdrFailureCode.DERIVED_ANALYSIS_REJECTED,
                    )
                return self._promote(
                    source,
                    derived,
                    eligibility,
                    candidate_sha256=candidate_sha256,
                    candidate_size=candidate_size,
                )
            except AuditPersistenceError:
                return _failed(scan_id, CdrFailureCode.AUDIT_FAILURE)
            except StorageFailure:
                self._safe_audit_failure(source.id, CdrFailureCode.STORAGE_FAILURE)
                return _failed(scan_id, CdrFailureCode.STORAGE_FAILURE)
            finally:
                try:
                    remove_cdr_output(output)
                except StorageFailure:
                    logger.exception("cdr_temporary_cleanup_failed")

    def _promote(
        self,
        source: Scan,
        derived: Scan,
        eligibility: CdrEligibility,
        *,
        candidate_sha256: str,
        candidate_size: int,
    ) -> CdrServiceResult:
        derived_path = self._paths.resolve("quarantine", derived.storage_key)
        try:
            promoted = store_private_copy(
                derived_path,
                paths=self._paths,
                area="sanitized",
                maximum_bytes=self._settings.cdr_max_output_bytes,
                expected_sha256=candidate_sha256,
            )
        except StorageFailure:
            self._safe_audit_failure(source.id, CdrFailureCode.PROMOTION_FAILURE)
            return _failed(source.id, CdrFailureCode.PROMOTION_FAILURE, derived.id)
        if promoted.sha256 != derived.sha256 or promoted.size_bytes != candidate_size:
            remove_stored_document(promoted)
            self._safe_audit_failure(source.id, CdrFailureCode.HASH_MISMATCH)
            return _failed(source.id, CdrFailureCode.HASH_MISMATCH, derived.id)

        artifact = Artifact(
            id=new_database_id(),
            scan_id=source.id,
            derived_scan_id=derived.id,
            artifact_type=ArtifactType.PDF_CDR.value,
            storage_key=promoted.storage_key,
            sha256=promoted.sha256,
            size_bytes=promoted.size_bytes,
            sanitizer_version=eligibility.sanitizer_version,
            sanitizer_fingerprint=eligibility.sanitizer_fingerprint,
            policy_version=derived.policy_version or "",
            policy_fingerprint=derived.policy_fingerprint or "",
        )
        try:
            with self._sessions.begin() as session:
                session.add(artifact)
                session.flush()
                AuditService.add_to_transaction(
                    session,
                    AuditEventType.CDR_APPROVED,
                    scan_id=source.id,
                    artifact_id=artifact.id,
                    outcome=AuditOutcome.SUCCESS,
                    details={
                        **_identity_details(eligibility),
                        "derived_scan_id": derived.id,
                        "derived_decision": derived.decision,
                        "policy_version": derived.policy_version,
                    },
                )
        except IntegrityError:
            remove_stored_document(promoted)
            existing = self.get_existing_cdr_artifact(source.id)
            if existing is not None:
                return CdrServiceResult(
                    source_scan_id=source.id,
                    derived_scan_id=existing.derived_scan_id,
                    artifact_id=existing.id,
                    approved=True,
                    reused=True,
                )
            return _failed(source.id, CdrFailureCode.DATABASE_FAILURE, derived.id)
        except ValueError:
            remove_stored_document(promoted)
            self._safe_audit_failure(source.id, CdrFailureCode.AUDIT_FAILURE)
            return _failed(source.id, CdrFailureCode.AUDIT_FAILURE, derived.id)
        except SQLAlchemyError:
            remove_stored_document(promoted)
            self._safe_audit_failure(source.id, CdrFailureCode.DATABASE_FAILURE)
            return _failed(source.id, CdrFailureCode.DATABASE_FAILURE, derived.id)
        return CdrServiceResult(
            source_scan_id=source.id,
            derived_scan_id=derived.id,
            artifact_id=artifact.id,
            approved=True,
        )

    def _append_eligibility(
        self,
        eligibility: CdrEligibility,
        *,
        source_decision: str | None,
        persisted_scan: bool = True,
    ) -> None:
        self._audit.append(
            AuditEventType.CDR_ELIGIBILITY_CHECKED,
            scan_id=eligibility.scan_id if persisted_scan else None,
            outcome=AuditOutcome.SUCCESS if eligibility.eligible else AuditOutcome.DENIED,
            reason_code=eligibility.reason_codes[0] if eligibility.reason_codes else None,
            details={
                **_identity_details(eligibility),
                "source_decision": source_decision,
                "requested_scan_id": eligibility.scan_id,
                "reason_codes": list(eligibility.reason_codes),
            },
        )

    def _safe_audit_failure(self, scan_id: str, failure: CdrFailureCode) -> None:
        try:
            self._audit.append(
                AuditEventType.CDR_PROMOTION_FAILED,
                scan_id=scan_id,
                outcome=AuditOutcome.FAILURE,
                reason_code=failure.value,
            )
        except AuditPersistenceError:
            logger.exception("cdr_failure_audit_unavailable")


def _policy_evaluation(scan: Scan) -> PolicyEvaluation | None:
    if scan.policy_evaluation_json is None:
        return None
    try:
        return PolicyEvaluation.model_validate_json(
            json.dumps(scan.policy_evaluation_json, separators=(",", ":"), sort_keys=True)
        )
    except ValueError:
        return None


def _pdf_page_count(metadata: dict[str, object] | None) -> int | None:
    if not isinstance(metadata, dict):
        return None
    pdf = metadata.get("pdf")
    if not isinstance(pdf, dict):
        return None
    value = pdf.get("page_count")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _derived_is_approvable(scan: Scan, *, source_id: str, expected_sha256: str) -> bool:
    evaluation = _policy_evaluation(scan)
    codes = {finding.code for finding in scan.findings}
    return all(
        (
            scan.origin == ScanOrigin.CDR_DERIVED.value,
            scan.parent_scan_id == source_id,
            scan.sha256 == expected_sha256,
            scan.detected_type == "PDF",
            scan.worker_status == "SUCCESS",
            scan.state == ScanState.COMPLETED.value,
            scan.decision == Decision.ALLOW.value,
            scan.release_eligible is True,
            evaluation is not None,
            evaluation.analysis_complete if evaluation is not None else False,
            not evaluation.hard_block_reasons if evaluation is not None else False,
            not evaluation.mandatory_quarantine_reasons if evaluation is not None else False,
            not any(
                code.endswith("_PARTIAL_ANALYSIS") or code.endswith("_MALFORMED") for code in codes
            ),
        )
    )


def _identity_details(eligibility: CdrEligibility) -> dict[str, object]:
    return {
        "sanitizer_version": eligibility.sanitizer_version,
        "sanitizer_fingerprint": eligibility.sanitizer_fingerprint,
    }


def _failed(
    source_scan_id: str,
    code: CdrFailureCode,
    derived_scan_id: str | None = None,
) -> CdrServiceResult:
    return CdrServiceResult(
        source_scan_id=source_scan_id,
        derived_scan_id=derived_scan_id,
        artifact_id=None,
        approved=False,
        failure_code=code,
    )


__all__ = ["CdrService"]
