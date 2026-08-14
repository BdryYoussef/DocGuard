from __future__ import annotations

import json
from pathlib import Path

from app.models.domain import AnalysisResult, Decision
from app.orchestrator.contract import WorkerRequest
from app.orchestrator.isolation import IsolationError, WorkerExecution
from app.orchestrator.service import AnalysisOrchestrator, FailureCode
from docguard_contract.findings import FINDING_DEFINITIONS


class StubBackend:
    def __init__(
        self,
        execution: WorkerExecution | None = None,
        error: IsolationError | None = None,
    ) -> None:
        self.execution = execution
        self.error = error

    @property
    def ready(self) -> bool:
        return self.error is None

    def execute(self, request: WorkerRequest, timeout_seconds: float) -> WorkerExecution:
        del request, timeout_seconds
        if self.error is not None:
            raise self.error
        assert self.execution is not None
        return self.execution


def run_with_execution(tmp_path: Path, execution: WorkerExecution):
    sample = tmp_path / "sample.txt"
    sample.write_text("fixture", encoding="utf-8")
    return AnalysisOrchestrator(StubBackend(execution), timeout_seconds=0.1).analyze(
        sample.resolve()
    )


def test_valid_worker_response_accepted(
    tmp_path: Path, valid_analysis_result: AnalysisResult
) -> None:
    outcome = run_with_execution(
        tmp_path,
        WorkerExecution(valid_analysis_result.to_json(), "", 0, False),
    )

    assert outcome.succeeded is True
    assert outcome.decision is None
    assert outcome.failure_code is None


def test_malformed_worker_json_fails_closed(tmp_path: Path) -> None:
    outcome = run_with_execution(tmp_path, WorkerExecution("not-json", "", 0, False))

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.MALFORMED_OUTPUT


def test_wrong_schema_version_fails_closed(
    tmp_path: Path, valid_analysis_result: AnalysisResult
) -> None:
    payload = json.loads(valid_analysis_result.to_json())
    payload["schema_version"] = "999.0"
    outcome = run_with_execution(
        tmp_path,
        WorkerExecution(json.dumps(payload), "", 0, False),
    )

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.MALFORMED_OUTPUT


def test_unknown_yara_rule_id_in_worker_output_fails_closed(
    tmp_path: Path, valid_analysis_result: AnalysisResult
) -> None:
    payload = json.loads(valid_analysis_result.to_json())
    definition = FINDING_DEFINITIONS["YARA_HEURISTIC_MATCH"]
    payload["findings"] = [
        {
            "code": definition.code,
            "title": definition.title,
            "description": definition.description,
            "category": definition.category,
            "severity": definition.default_severity,
            "score_delta": 0,
            "mitre_techniques": [],
            "metadata": {
                "rule_id": "DOCGUARD_UNTRUSTED_USER_RULE",
                "rule_title": "Untrusted",
                "rule_explanation": "Untrusted",
                "rule_category": "untrusted",
                "confidence_class": "HEURISTIC",
                "rule_pack_version": "untrusted",
                "rule_pack_sha256": "0" * 64,
                "scope": "TOP_LEVEL",
                "match_count": 1,
                "string_ids": ["$untrusted"],
                "offsets": [0],
            },
        }
    ]
    outcome = run_with_execution(
        tmp_path,
        WorkerExecution(json.dumps(payload), "", 0, False),
    )

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.MALFORMED_OUTPUT


def test_worker_non_zero_exit_fails_closed(tmp_path: Path) -> None:
    outcome = run_with_execution(tmp_path, WorkerExecution("", "failure", 2, False))

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.NON_ZERO_EXIT


def test_worker_timeout_fails_closed(tmp_path: Path) -> None:
    outcome = run_with_execution(tmp_path, WorkerExecution("", "", None, True))

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.TIMEOUT


def test_worker_output_limit_fails_closed(tmp_path: Path) -> None:
    outcome = run_with_execution(
        tmp_path,
        WorkerExecution("x" * 10, "", -9, False, output_limit_exceeded=True),
    )

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.OUTPUT_LIMIT_EXCEEDED


def test_isolation_failure_fails_closed(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("fixture", encoding="utf-8")
    backend = StubBackend(error=IsolationError("unavailable"))

    outcome = AnalysisOrchestrator(backend, timeout_seconds=0.1).analyze(sample.resolve())

    assert outcome.decision is Decision.QUARANTINE
    assert outcome.failure_code is FailureCode.ISOLATION_UNAVAILABLE
