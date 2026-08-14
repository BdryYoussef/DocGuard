"""Phase 11 evaluation runner: manifest validation, listing, dry-run, and execution.

Phase 11A ships every mode, but only ``--validate-manifest``, ``--list-cases``, and
``--dry-run`` are meant to be used routinely: they never invoke the DocGuard scan
pipeline. ``--execute`` invokes the real, production-shaped pipeline (the same
``create_app`` + ASGI-transport path the integration test suite uses) but Phase 11A
requires callers to name specific case IDs — there is no "run everything" shortcut here,
so the full 45-60 case benchmark cannot be triggered accidentally. Running the full
corpus is Phase 11B's job.
"""

from __future__ import annotations

import importlib.metadata
import platform
import subprocess
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from app.core.config import AppEnvironment, IsolationBackendName, Settings
from app.main import create_app
from app.models.database import Base
from app.models.domain import Decision
from app.policies.registry import POLICY_FINGERPRINT
from app.policies.version import POLICY_VERSION
from docguard_contract.cdr import PDF_CDR_FINGERPRINT, PDF_CDR_VERSION
from docguard_contract.yara_rules import YARA_RULE_PACK_SHA256, YARA_RULE_PACK_VERSION
from evaluation.corpus import CORPUS_VERSION, materialize_case
from evaluation.manifest import ManifestValidationError, load_manifest
from evaluation.models import (
    AnalysisCompletenessClass,
    EvaluationCase,
    EvaluationResult,
    EvaluationRun,
    ReproducibilityMetadata,
)

_WORKER_DEPENDENCIES = ("pikepdf", "PyMuPDF", "yara-python", "oletools", "olefile", "defusedxml")


def gather_reproducibility_metadata(cases: Sequence[EvaluationCase]) -> ReproducibilityMetadata:
    """Best-effort, privacy-safe identity of the current build and host tools.

    Never includes username, home path, or any environment secret; host-tool lookups
    that fail (missing binary, missing package) degrade to ``None``/omission rather
    than raising, so this always succeeds even on a minimal host.
    """
    return ReproducibilityMetadata(
        timestamp=datetime.now(UTC),
        git_commit=_git_commit(),
        corpus_version=CORPUS_VERSION,
        corpus_case_count=len(cases),
        policy_version=POLICY_VERSION,
        policy_fingerprint=POLICY_FINGERPRINT,
        yara_rule_pack_version=YARA_RULE_PACK_VERSION,
        yara_rule_pack_sha256=YARA_RULE_PACK_SHA256,
        sanitizer_version=PDF_CDR_VERSION,
        sanitizer_fingerprint=PDF_CDR_FINGERPRINT,
        python_version=platform.python_version(),
        platform=f"{platform.system()}-{platform.machine()}",
        bubblewrap_version=_tool_version(["bwrap", "--version"]),
        qpdf_version=_tool_version(["qpdf", "--version"]),
        worker_dependency_versions=_worker_dependency_versions(),
    )


def _git_commit() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - fixed local dev-tool launcher
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = completed.stdout.strip()
    return commit if completed.returncode == 0 and commit else None


def _tool_version(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed local dev-tool launcher, caller-controlled
            command, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    first_line = completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else None
    return first_line[:64] if first_line else None


def _worker_dependency_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in _WORKER_DEPENDENCIES:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return versions


def validate_manifest_mode() -> tuple[bool, str]:
    """Returns ``(ok, message)``; touches no files besides reading the manifest."""
    try:
        cases = load_manifest()
    except ManifestValidationError as exc:
        return False, f"FAIL manifest validation: {exc}"
    return True, f"PASS manifest validation: {len(cases)} cases"


def list_cases_mode() -> str:
    """A deterministic, sorted, human-readable case listing. Touches no files."""
    cases = load_manifest()
    lines = []
    for case in cases:
        decisions = "|".join(d.value for d in case.acceptable_decisions)
        flags = "".join(
            flag
            for flag, active in (
                ("F", case.fail_secure),
                ("C", case.cdr_case),
            )
            if active
        )
        lines.append(
            f"{case.case_id:16s} {case.category.value:16s} {case.case_class.value:7s} "
            f"decisions={decisions:20s} flags={flags or '-'}"
        )
    return "\n".join(lines)


def dry_run_mode() -> tuple[bool, str]:
    """Materializes every manifest fixture into a throwaway temp directory to prove the
    corpus is generatable, then deletes it. Never touches ``var/`` and never invokes the
    scan pipeline."""
    cases = load_manifest()
    failures: list[str] = []
    with TemporaryDirectory(prefix="docguard-eval-dry-run-") as workspace:
        directory = Path(workspace)
        for case in cases:
            try:
                path = materialize_case(case, directory)
                if not path.exists() or path.stat().st_size == 0:
                    failures.append(f"{case.case_id}: fixture missing or empty")
            except Exception as exc:
                failures.append(f"{case.case_id}: {type(exc).__name__}: {exc}")
    if failures:
        return False, "FAIL dry-run: " + "; ".join(failures)
    return True, f"PASS dry-run: {len(cases)} fixtures materialized"


def _build_settings(workspace: Path, *, isolation_backend: IsolationBackendName) -> Settings:
    return Settings(
        env=AppEnvironment.TEST,
        database_url=f"sqlite:///{workspace / 'evaluation.db'}",
        storage_root=workspace / "storage",
        isolation_backend=isolation_backend,
        allow_unsafe_development_backend=(
            isolation_backend is IsolationBackendName.UNSAFE_DEVELOPMENT
        ),
        application_origin="http://test",
    )


async def _execute_cases(
    cases: Sequence[EvaluationCase], workspace: Path, settings: Settings
) -> list[EvaluationResult]:
    from tests.auth_helpers import authenticate_operator, csrf_headers

    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)
    results: list[EvaluationResult] = []
    async with app.router.lifespan_context(app):
        Base.metadata.create_all(app.state.database_engine)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            csrf = await authenticate_operator(app, client)
            for case in cases:
                fixture_dir = workspace / "fixtures" / case.case_id
                fixture_dir.mkdir(parents=True, exist_ok=True)
                fixture_path = materialize_case(case, fixture_dir)
                body = fixture_path.read_bytes()
                content_type = case.claimed_content_type or "application/octet-stream"
                started = time.monotonic()
                try:
                    response = await client.post(
                        "/api/v1/scans",
                        params={"filename": case.filename},
                        content=body,
                        headers=csrf_headers(csrf, **{"content-type": content_type}),
                    )
                except httpx.HTTPError as exc:
                    results.append(_error_result(case, f"transport error: {type(exc).__name__}"))
                    continue
                latency_ms = int((time.monotonic() - started) * 1_000)
                if response.status_code != 201:
                    results.append(
                        _error_result(case, f"unexpected status {response.status_code}", latency_ms)
                    )
                    continue
                results.append(_result_from_payload(case, response.json(), latency_ms))
    return results


def _error_result(
    case: EvaluationCase, error: str, latency_ms: int | None = None
) -> EvaluationResult:
    return EvaluationResult(
        case_id=case.case_id,
        category=case.category,
        case_class=case.case_class,
        expected_findings=case.expected_findings,
        acceptable_decisions=case.acceptable_decisions,
        latency_ms=latency_ms,
        error=error[:500],
    )


def _result_from_payload(
    case: EvaluationCase, payload: dict[str, object], latency_ms: int
) -> EvaluationResult:
    findings = payload.get("findings")
    actual_codes = (
        tuple(sorted(str(item["code"]) for item in findings)) if isinstance(findings, list) else ()
    )
    expected = set(case.expected_findings)
    actual = set(actual_codes)
    missing = tuple(sorted(expected - actual))
    if case.allow_any_additional_findings:
        unexpected: tuple[str, ...] = ()
    else:
        acceptable = expected | set(case.acceptable_additional_findings)
        unexpected = tuple(sorted(actual - acceptable))

    decision_raw = payload.get("decision")
    actual_decision = Decision(decision_raw) if isinstance(decision_raw, str) else None
    analysis_complete = payload.get("analysis_complete")
    analysis_status = payload.get("analysis_status")
    worker_status = str(analysis_status) if analysis_status is not None else None

    return EvaluationResult(
        case_id=case.case_id,
        category=case.category,
        case_class=case.case_class,
        expected_findings=case.expected_findings,
        actual_findings=actual_codes,
        missing_expected_findings=missing,
        unexpected_findings=unexpected,
        acceptable_decisions=case.acceptable_decisions,
        actual_decision=actual_decision,
        release_eligible=(
            bool(payload.get("release_eligible"))
            if isinstance(payload.get("release_eligible"), bool)
            else None
        ),
        analysis_complete=(
            bool(analysis_complete) if isinstance(analysis_complete, bool) else None
        ),
        worker_status=worker_status,
        completeness_class=_infer_completeness_class(
            analysis_complete, worker_status, actual_codes
        ),
        latency_ms=latency_ms,
        decision_compliant=(
            actual_decision in case.acceptable_decisions if actual_decision is not None else None
        ),
        findings_recall_pass=not missing,
    )


def _infer_completeness_class(
    analysis_complete: object, worker_status: str | None, codes: Sequence[str]
) -> AnalysisCompletenessClass | None:
    if analysis_complete is True:
        return AnalysisCompletenessClass.COMPLETE
    if analysis_complete is not False:
        return None
    if worker_status == "TIMEOUT":
        return AnalysisCompletenessClass.TIMEOUT
    if any(code.endswith("_MALFORMED") for code in codes):
        return AnalysisCompletenessClass.PARSER_FAILURE
    if any(code.endswith("_RESOURCE_LIMIT") for code in codes):
        return AnalysisCompletenessClass.RESOURCE_LIMIT_FAILURE
    if any(code.endswith(("_ENCRYPTED", "_PARTIAL_ANALYSIS", "_NESTING_LIMIT")) for code in codes):
        return AnalysisCompletenessClass.INTENTIONAL_PARTIAL
    return AnalysisCompletenessClass.OTHER_FAIL_CLOSED


def execute_mode(
    case_ids: Sequence[str],
    *,
    isolation_backend: IsolationBackendName = IsolationBackendName.BUBBLEWRAP,
) -> EvaluationRun:
    """Run only the named cases through the real DocGuard pipeline.

    Phase 11A callers (and this module's own smoke coverage) must pass explicit case
    IDs; there is deliberately no "run all" argument here so the full corpus cannot be
    executed until Phase 11B decides to.
    """
    import asyncio

    if not case_ids:
        raise ValueError("execute_mode requires at least one explicit case_id")
    all_cases = {case.case_id: case for case in load_manifest()}
    unknown = sorted(set(case_ids) - set(all_cases))
    if unknown:
        raise ValueError(f"unknown case_id(s): {unknown}")
    selected = [all_cases[case_id] for case_id in case_ids]

    with TemporaryDirectory(prefix="docguard-eval-execute-") as workspace_str:
        workspace = Path(workspace_str)
        settings = _build_settings(workspace, isolation_backend=isolation_backend)
        results = asyncio.run(_execute_cases(selected, workspace, settings))

    metadata = gather_reproducibility_metadata(list(all_cases.values()))
    return EvaluationRun(metadata=metadata, results=tuple(results))


__all__ = [
    "dry_run_mode",
    "execute_mode",
    "gather_reproducibility_metadata",
    "list_cases_mode",
    "validate_manifest_mode",
]
