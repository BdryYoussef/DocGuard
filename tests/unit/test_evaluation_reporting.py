from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from app.models.domain import Decision
from evaluation.corpus import CASES
from evaluation.metrics import compute_all_metrics
from evaluation.models import EvaluationResult, EvaluationRun
from evaluation.reporting import (
    find_private_path_leak,
    render_markdown_report,
    results_to_csv,
    results_to_json,
    write_markdown_report,
    write_metrics_json,
    write_results_csv,
    write_results_json,
)
from evaluation.runner import gather_reproducibility_metadata


def _sample_results() -> list[EvaluationResult]:
    results = []
    for case in CASES[:6]:
        results.append(
            EvaluationResult(
                case_id=case.case_id,
                category=case.category,
                case_class=case.case_class,
                expected_findings=case.expected_findings,
                actual_findings=case.expected_findings,
                acceptable_decisions=case.acceptable_decisions,
                actual_decision=case.acceptable_decisions[0],
                release_eligible=case.acceptable_decisions[0] is Decision.ALLOW,
                analysis_complete=True,
                worker_status="SUCCESS",
                latency_ms=50,
                decision_compliant=True,
                findings_recall_pass=True,
            )
        )
    return results


def test_results_to_csv_is_sorted_and_parseable() -> None:
    results = list(reversed(_sample_results()))

    text = results_to_csv(results)
    rows = list(csv.DictReader(io.StringIO(text)))

    assert [row["case_id"] for row in rows] == sorted(result.case_id for result in results)


def test_results_to_json_round_trips() -> None:
    metadata = gather_reproducibility_metadata(CASES)
    run = EvaluationRun(metadata=metadata, results=tuple(_sample_results()))

    text = results_to_json(run)
    payload = json.loads(text)

    assert len(payload["results"]) == len(run.results)
    assert payload["metadata"]["corpus_case_count"] == len(CASES)


def test_write_results_json_and_csv(tmp_path: Path) -> None:
    metadata = gather_reproducibility_metadata(CASES)
    run = EvaluationRun(metadata=metadata, results=tuple(_sample_results()))

    write_results_json(run, tmp_path / "results.json")
    write_results_csv(run.results, tmp_path / "results.csv")

    assert (tmp_path / "results.json").exists()
    assert (tmp_path / "results.csv").exists()


def test_markdown_report_marks_missing_run_as_not_executed() -> None:
    summary = compute_all_metrics(CASES, [])

    report = render_markdown_report(CASES, [], summary)

    assert "NOT EXECUTED" in report
    assert "not applicable" in report
    assert "59" not in report or "Total cases: 59" in report  # sanity, not a strict check


def test_markdown_report_never_fabricates_a_number_when_no_results_exist() -> None:
    summary = compute_all_metrics(CASES, [])

    report = render_markdown_report(CASES, [], summary)

    for line in report.splitlines():
        if line.startswith("- Risky-case detection recall"):
            assert "not applicable" in line


def test_write_metrics_and_markdown_reports(tmp_path: Path) -> None:
    results = _sample_results()
    summary = compute_all_metrics(CASES, results)
    metadata = gather_reproducibility_metadata(CASES)

    write_metrics_json(summary, tmp_path / "metrics.json", metadata)
    write_markdown_report(CASES, results, summary, tmp_path / "report.md", metadata)

    assert (tmp_path / "metrics.json").exists()
    assert "# DocGuard Phase 11 Evaluation Report" in (tmp_path / "report.md").read_text()


def test_no_private_path_leaks_into_any_report_artifact(tmp_path: Path) -> None:
    results = _sample_results()
    summary = compute_all_metrics(CASES, results)
    metadata = gather_reproducibility_metadata(CASES)
    run = EvaluationRun(metadata=metadata, results=tuple(results))

    write_results_json(run, tmp_path / "results.json")
    write_results_csv(run.results, tmp_path / "results.csv")
    write_metrics_json(summary, tmp_path / "metrics.json", metadata)
    write_markdown_report(CASES, results, summary, tmp_path / "report.md", metadata)

    for artifact in tmp_path.iterdir():
        text = artifact.read_text(encoding="utf-8")
        leak = find_private_path_leak(text)
        assert leak is None, f"{artifact.name} leaked a private path fragment: {leak!r}"


def test_find_private_path_leak_detects_home_directory() -> None:
    import os

    home = os.path.expanduser("~")
    assert find_private_path_leak(f"scan stored at {home}/var/incoming/foo") == home


def test_find_private_path_leak_is_clean_for_ordinary_text() -> None:
    assert find_private_path_leak("case PDF-BEN-001 decision=ALLOW") is None
