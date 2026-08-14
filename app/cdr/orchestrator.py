"""Trusted validation of one isolated PDF sanitization operation."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from app.cdr.models import CdrFailureCode, CdrStatus, PdfCdrResult
from app.cdr.registry import build_worker_cdr_config
from app.core.config import Settings
from app.orchestrator.contract import WorkerOperation, WorkerRequest
from app.orchestrator.isolation import IsolationBackend, IsolationError


@dataclass(frozen=True, slots=True)
class CdrOutcome:
    result: PdfCdrResult | None
    failure_code: CdrFailureCode | None

    @property
    def succeeded(self) -> bool:
        return self.result is not None and self.result.status is CdrStatus.SUCCESS


class PdfCdrOrchestrator:
    def __init__(self, backend: IsolationBackend, settings: Settings) -> None:
        self._backend = backend
        self._settings = settings

    def sanitize(self, source_path: Path, output_path: Path) -> CdrOutcome:
        request = WorkerRequest(
            job_id=secrets.token_hex(16),
            sample_path=str(source_path.resolve()),
            original_filename="source.pdf",
            operation=WorkerOperation.SANITIZE_PDF,
            cdr=build_worker_cdr_config(self._settings),
        )
        try:
            execution = self._backend.sanitize(
                request, output_path, self._settings.cdr_timeout_seconds
            )
        except IsolationError:
            return CdrOutcome(None, CdrFailureCode.RENDERER_UNAVAILABLE)
        if execution.timed_out:
            return CdrOutcome(None, CdrFailureCode.RENDER_TIMEOUT)
        if execution.output_limit_exceeded or execution.exit_code != 0:
            return CdrOutcome(None, CdrFailureCode.RENDER_FAILED)
        try:
            result = PdfCdrResult.model_validate_json(execution.stdout)
        except (ValidationError, ValueError):
            return CdrOutcome(None, CdrFailureCode.OUTPUT_INVALID)
        expected = build_worker_cdr_config(self._settings)
        if (
            result.sanitizer_version != expected.sanitizer_version
            or result.sanitizer_fingerprint != expected.sanitizer_fingerprint
        ):
            return CdrOutcome(None, CdrFailureCode.OUTPUT_INVALID)
        if result.status is CdrStatus.FAILED:
            return CdrOutcome(result, result.failure_code or CdrFailureCode.RENDER_FAILED)
        return CdrOutcome(result, None)


__all__ = ["CdrOutcome", "PdfCdrOrchestrator"]
