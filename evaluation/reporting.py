"""Report-generation primitives: JSON results, CSV case table, metrics JSON, Markdown.

All writers here are pure formatting over already-computed :class:`EvaluationResult` /
:class:`MetricsSummary` objects — they never run analysis and never fabricate a metric
value. Ordering is always deterministic (sorted by ``case_id``/category) so repeated
runs over the same results produce byte-identical output.
"""

from __future__ import annotations

import csv
import io
import json
import os
from collections.abc import Sequence
from pathlib import Path

from evaluation.metrics import MetricsSummary, Rate
from evaluation.models import (
    EvaluationCase,
    EvaluationResult,
    EvaluationRun,
    ReproducibilityMetadata,
)

_CSV_FIELDS = (
    "case_id",
    "category",
    "case_class",
    "actual_decision",
    "acceptable_decisions",
    "decision_compliant",
    "release_eligible",
    "analysis_complete",
    "completeness_class",
    "worker_status",
    "findings_recall_pass",
    "missing_expected_findings",
    "unexpected_findings",
    "latency_ms",
    "error",
)


def sorted_results(results: Sequence[EvaluationResult]) -> list[EvaluationResult]:
    return sorted(results, key=lambda result: result.case_id)


def results_to_json(run: EvaluationRun) -> str:
    """Canonical, sorted-key JSON text for the full run (metadata + all results)."""
    payload = {
        "metadata": run.metadata.model_dump(mode="json"),
        "results": [result.model_dump(mode="json") for result in sorted_results(run.results)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_results_json(run: EvaluationRun, path: Path) -> None:
    path.write_text(results_to_json(run), encoding="utf-8")


def results_to_csv(results: Sequence[EvaluationResult]) -> str:
    """A flat, deterministic case-level CSV table for spreadsheet review."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS, lineterminator="\n")
    writer.writeheader()
    for result in sorted_results(results):
        writer.writerow(
            {
                "case_id": result.case_id,
                "category": result.category.value,
                "case_class": result.case_class.value,
                "actual_decision": result.actual_decision.value if result.actual_decision else "",
                "acceptable_decisions": "|".join(d.value for d in result.acceptable_decisions),
                "decision_compliant": _bool_cell(result.decision_compliant),
                "release_eligible": _bool_cell(result.release_eligible),
                "analysis_complete": _bool_cell(result.analysis_complete),
                "completeness_class": (
                    result.completeness_class.value if result.completeness_class else ""
                ),
                "worker_status": result.worker_status or "",
                "findings_recall_pass": _bool_cell(result.findings_recall_pass),
                "missing_expected_findings": "|".join(result.missing_expected_findings),
                "unexpected_findings": "|".join(result.unexpected_findings),
                "latency_ms": result.latency_ms if result.latency_ms is not None else "",
                "error": result.error or "",
            }
        )
    return buffer.getvalue()


def write_results_csv(results: Sequence[EvaluationResult], path: Path) -> None:
    path.write_text(results_to_csv(results), encoding="utf-8")


def _bool_cell(value: bool | None) -> str:
    if value is None:
        return ""
    return "true" if value else "false"


def metrics_to_json(
    summary: MetricsSummary, metadata: ReproducibilityMetadata | None = None
) -> str:
    payload: dict[str, object] = {"metrics": summary.to_json()}
    if metadata is not None:
        payload["metadata"] = metadata.model_dump(mode="json")
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_metrics_json(
    summary: MetricsSummary, path: Path, metadata: ReproducibilityMetadata | None = None
) -> None:
    path.write_text(metrics_to_json(summary, metadata), encoding="utf-8")


def _format_rate(rate: Rate, *, as_percent: bool = True) -> str:
    if rate.value is None:
        return "not applicable (0 evaluable cases)"
    if as_percent:
        return f"{rate.value * 100:.1f}% ({rate.numerator}/{rate.denominator})"
    return f"{rate.value:.3f} ({rate.numerator}/{rate.denominator})"


def render_markdown_report(
    cases: Sequence[EvaluationCase],
    results: Sequence[EvaluationResult],
    summary: MetricsSummary,
    metadata: ReproducibilityMetadata | None = None,
) -> str:
    """Deterministic Markdown evaluation report.

    When ``results`` is empty (Phase 11A has not executed the benchmark), every metric
    line explicitly reads "not applicable" / "pending Phase 11B" rather than a fabricated
    number — see docs/EVALUATION.md.
    """
    lines: list[str] = ["# DocGuard Phase 11 Evaluation Report", ""]
    pending = not results
    if pending:
        lines.append(
            "**Status: NOT EXECUTED.** This report was generated from the manifest only; "
            "no case has been run through the real pipeline yet. All metrics below are "
            "placeholders pending Phase 11B."
        )
        lines.append("")

    lines.append("## Corpus")
    lines.append("")
    lines.append(f"- Total cases: {len(cases)}")
    lines.append(f"- Matched results: {summary.matched_case_count}")
    category_counts = _category_counts(cases)
    lines.append("")
    lines.append("| Category | Cases |")
    lines.append("| --- | ---: |")
    for category, count in category_counts:
        lines.append(f"| {category} | {count} |")
    lines.append("")

    if metadata is not None:
        lines.append("## Reproducibility")
        lines.append("")
        lines.append(f"- Timestamp: {metadata.timestamp.isoformat()}")
        lines.append(f"- Git commit: {metadata.git_commit or 'unknown'}")
        lines.append(
            f"- Corpus version: {metadata.corpus_version} ({metadata.corpus_case_count} cases)"
        )
        lines.append(
            f"- Policy version / fingerprint: {metadata.policy_version} / "
            f"{metadata.policy_fingerprint}"
        )
        lines.append(
            f"- YARA rule pack: {metadata.yara_rule_pack_version} / "
            f"{metadata.yara_rule_pack_sha256}"
        )
        lines.append(
            f"- Sanitizer: {metadata.sanitizer_version} / {metadata.sanitizer_fingerprint}"
        )
        lines.append(f"- Python: {metadata.python_version}; platform: {metadata.platform}")
        lines.append("")

    lines.append("## Metrics")
    lines.append("")
    lines.append(
        f"- Risky-case detection recall (A): {_format_rate(summary.risky_case_detection_recall)}"
    )
    lines.append(f"- Finding-level recall (B): {_format_rate(summary.finding_level_recall)}")
    lines.append(f"- Benign escalation rate (C): {_format_rate(summary.benign_escalation_rate)}")
    lines.append(f"- Benign ALLOW rate (D): {_format_rate(summary.benign_allow_rate)}")
    lines.append(f"- Decision compliance (E): {_format_rate(summary.decision_compliance_rate)}")
    lines.append(f"- Fail-secure rate (G): {_format_rate(summary.fail_secure_rate)}")
    lines.append(
        f"- CDR recovery rate (I, Phase 11B only): {_format_rate(summary.cdr_recovery_rate)}"
    )
    lines.append("")

    lines.append("### Finding-level recall by category (B)")
    lines.append("")
    lines.append("| Category | Recall |")
    lines.append("| --- | --- |")
    for category, rate in summary.finding_level_recall_by_category.items():
        lines.append(f"| {category.value} | {_format_rate(rate)} |")
    lines.append("")

    lines.append("### Analysis completeness counts (F)")
    lines.append("")
    if summary.completeness_counts:
        lines.append("| Class | Count |")
        lines.append("| --- | ---: |")
        for name, count in sorted(summary.completeness_counts.items()):
            lines.append(f"| {name} | {count} |")
    else:
        lines.append("Pending Phase 11B.")
    lines.append("")

    lines.append("### Latency (H)")
    lines.append("")
    latency = summary.latency
    if latency.count == 0:
        lines.append("Pending Phase 11B (no timed results).")
    else:
        lines.append(f"- count: {latency.count}")
        lines.append(
            f"- mean: {latency.mean_ms:.1f} ms" if latency.mean_ms is not None else "- mean: n/a"
        )
        lines.append(
            f"- median: {latency.median_ms:.1f} ms"
            if latency.median_ms is not None
            else "- median: n/a"
        )
        lines.append(f"- min / max: {latency.min_ms} / {latency.max_ms} ms")
        lines.append(f"- p95: {latency.p95_ms} ms")
    lines.append("")

    lines.append(
        "Real benchmark values are pending Phase 11B execution against the isolated "
        "Bubblewrap worker and trusted policy engine; nothing above was fabricated."
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(
    cases: Sequence[EvaluationCase],
    results: Sequence[EvaluationResult],
    summary: MetricsSummary,
    path: Path,
    metadata: ReproducibilityMetadata | None = None,
) -> None:
    path.write_text(render_markdown_report(cases, results, summary, metadata), encoding="utf-8")


def _category_counts(cases: Sequence[EvaluationCase]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for case in cases:
        counts[case.category.value] = counts.get(case.category.value, 0) + 1
    return sorted(counts.items())


def find_private_path_leak(text: str) -> str | None:
    """Return an offending substring if ``text`` contains the current user's home
    directory path or an obvious host-specific temp path; ``None`` if it looks clean.

    Used defensively by tests and by the runner before writing any report artifact.
    """
    home = os.path.expanduser("~")
    if home and home != "~" and home in text:
        return home
    for marker in ("/tmp/", "/var/folders/", "\\Users\\", "\\Temp\\"):  # noqa: S108
        if marker in text:
            return marker
    return None


__all__ = [
    "find_private_path_leak",
    "metrics_to_json",
    "render_markdown_report",
    "results_to_csv",
    "results_to_json",
    "sorted_results",
    "write_markdown_report",
    "write_metrics_json",
    "write_results_csv",
    "write_results_json",
]
