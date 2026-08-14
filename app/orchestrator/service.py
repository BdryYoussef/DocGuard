"""Trusted orchestration that validates worker output and fails closed."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from pydantic import ValidationError

from app.core.logging import log_event
from app.models.domain import AnalysisResult, AnalysisStatus, Decision
from app.orchestrator.contract import WorkerRequest
from app.orchestrator.isolation import IsolationBackend, IsolationError

logger = logging.getLogger(__name__)


class FailureCode(StrEnum):
    ISOLATION_UNAVAILABLE = "isolation_unavailable"
    TIMEOUT = "timeout"
    NON_ZERO_EXIT = "non_zero_exit"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    MALFORMED_OUTPUT = "malformed_output"
    WORKER_FAILED = "worker_failed"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class AnalysisOutcome:
    job_id: str
    result: AnalysisResult | None
    decision: Decision | None
    failure_code: FailureCode | None

    @property
    def succeeded(self) -> bool:
        return self.result is not None and self.result.status is AnalysisStatus.SUCCESS


class AnalysisOrchestrator:
    def __init__(self, backend: IsolationBackend, *, timeout_seconds: float) -> None:
        self._backend = backend
        self._timeout_seconds = timeout_seconds

    def prepare_job(
        self,
        sample_path: Path,
        *,
        original_filename: str = "unnamed-document",
        claimed_content_type: str | None = None,
    ) -> WorkerRequest:
        if not sample_path.is_absolute():
            raise ValueError("sample path must be absolute")
        return WorkerRequest(
            job_id=secrets.token_hex(16),
            sample_path=str(sample_path),
            original_filename=original_filename,
            claimed_content_type=claimed_content_type,
        )

    def analyze(
        self,
        sample_path: Path,
        *,
        original_filename: str = "unnamed-document",
        claimed_content_type: str | None = None,
    ) -> AnalysisOutcome:
        request = self.prepare_job(
            sample_path,
            original_filename=original_filename,
            claimed_content_type=claimed_content_type,
        )
        try:
            execution = self._backend.execute(request, self._timeout_seconds)
        except IsolationError:
            logger.exception(
                "worker_isolation_unavailable",
                extra={"structured_fields": {"job_id": request.job_id}},
            )
            return self._quarantined(request.job_id, FailureCode.ISOLATION_UNAVAILABLE)

        if execution.timed_out:
            return self._quarantined(request.job_id, FailureCode.TIMEOUT)
        if execution.output_limit_exceeded:
            return self._quarantined(request.job_id, FailureCode.OUTPUT_LIMIT_EXCEEDED)
        if execution.exit_code != 0:
            return self._quarantined(request.job_id, FailureCode.NON_ZERO_EXIT)

        try:
            result = AnalysisResult.model_validate_json(execution.stdout)
        except (ValidationError, ValueError):
            log_event(
                logger,
                logging.ERROR,
                "worker_output_rejected",
                job_id=request.job_id,
                reason=FailureCode.MALFORMED_OUTPUT.value,
            )
            return self._quarantined(request.job_id, FailureCode.MALFORMED_OUTPUT)

        self._log_pdf_analysis(request.job_id, result)
        self._log_office_analysis(request.job_id, result)
        self._log_archive_analysis(request.job_id, result)
        self._log_yara_analysis(request.job_id, result)

        if result.status is AnalysisStatus.UNSUPPORTED:
            return AnalysisOutcome(
                request.job_id, result, Decision.QUARANTINE, FailureCode.UNSUPPORTED
            )
        if result.status is not AnalysisStatus.SUCCESS:
            return AnalysisOutcome(
                request.job_id, result, Decision.QUARANTINE, FailureCode.WORKER_FAILED
            )
        return AnalysisOutcome(request.job_id, result, None, None)

    @staticmethod
    def _log_pdf_analysis(job_id: str, result: AnalysisResult) -> None:
        if result.detected_type != "PDF":
            return
        pdf_metadata = result.analyzer_metadata.get("pdf")
        if not isinstance(pdf_metadata, dict):
            return
        parser_status = pdf_metadata.get("parser_status")
        if parser_status == "COMPLETE":
            event = "pdf_analysis_completed"
            level = logging.INFO
        elif parser_status == "PARTIAL":
            event = "pdf_analysis_partial"
            level = logging.WARNING
        else:
            event = "pdf_analysis_failed"
            level = logging.ERROR
        page_count = pdf_metadata.get("page_count")
        log_event(
            logger,
            level,
            event,
            job_id=job_id,
            duration_ms=result.duration_ms,
            page_count=page_count if isinstance(page_count, int) else None,
            finding_count=len(result.findings),
            parser_status=parser_status if isinstance(parser_status, str) else "UNKNOWN",
        )

    @staticmethod
    def _log_office_analysis(job_id: str, result: AnalysisResult) -> None:
        office_metadata = result.analyzer_metadata.get("office")
        if not isinstance(office_metadata, dict):
            return
        parser_status = office_metadata.get("parser_status")
        if parser_status == "COMPLETE":
            event = "office_analysis_completed"
            level = logging.INFO
        elif parser_status == "PARTIAL":
            event = "office_analysis_partial"
            level = logging.WARNING
        else:
            event = "office_analysis_failed"
            level = logging.ERROR
        integer_fields = {
            key: value if isinstance(value, int) else None
            for key, value in {
                "vba_project_count": office_metadata.get("vba_project_count"),
                "external_relationship_count": office_metadata.get("external_relationship_count"),
                "embedded_object_count": office_metadata.get("embedded_object_count"),
            }.items()
        }
        log_event(
            logger,
            level,
            event,
            job_id=job_id,
            duration_ms=result.duration_ms,
            document_family=office_metadata.get("application"),
            finding_count=len(result.findings),
            parser_status=parser_status if isinstance(parser_status, str) else "UNKNOWN",
            **integer_fields,
        )

    @staticmethod
    def _log_archive_analysis(job_id: str, result: AnalysisResult) -> None:
        archive_metadata = result.analyzer_metadata.get("archive")
        if not isinstance(archive_metadata, dict):
            return
        parser_status = archive_metadata.get("parser_status")
        if parser_status == "COMPLETE":
            event = "archive_analysis_completed"
            level = logging.INFO
        elif parser_status == "PARTIAL":
            event = "archive_analysis_partial"
            level = logging.WARNING
        else:
            event = "archive_analysis_failed"
            level = logging.ERROR
        integer_fields = {
            key: value if isinstance(value, int) else None
            for key, value in {
                "entry_count": archive_metadata.get("entry_count"),
                "nested_archive_count": archive_metadata.get("nested_archive_count"),
                "actual_decompressed_bytes": archive_metadata.get("actual_decompressed_bytes"),
            }.items()
        }
        log_event(
            logger,
            level,
            event,
            job_id=job_id,
            duration_ms=result.duration_ms,
            finding_count=len(result.findings),
            parser_status=parser_status if isinstance(parser_status, str) else "UNKNOWN",
            **integer_fields,
        )

    @staticmethod
    def _log_yara_analysis(job_id: str, result: AnalysisResult) -> None:
        yara_metadata = result.analyzer_metadata.get("yara")
        if not isinstance(yara_metadata, dict):
            return
        parser_status = yara_metadata.get("parser_status")
        if parser_status == "COMPLETE":
            event = "yara_scan_completed"
            level = logging.INFO
        elif parser_status == "PARTIAL":
            event = "yara_scan_partial"
            level = logging.WARNING
        else:
            event = "yara_scan_failed"
            level = logging.ERROR
        matched_rule_count = yara_metadata.get("matched_rule_count")
        duration_ms = yara_metadata.get("duration_ms")
        log_event(
            logger,
            level,
            event,
            job_id=job_id,
            rule_pack_version=yara_metadata.get("rule_pack_version"),
            matched_rule_count=(
                matched_rule_count if isinstance(matched_rule_count, int) else None
            ),
            duration_ms=duration_ms if isinstance(duration_ms, int) else result.duration_ms,
            parser_status=parser_status if isinstance(parser_status, str) else "UNKNOWN",
        )

    @staticmethod
    def _quarantined(job_id: str, failure_code: FailureCode) -> AnalysisOutcome:
        return AnalysisOutcome(job_id, None, Decision.QUARANTINE, failure_code)
