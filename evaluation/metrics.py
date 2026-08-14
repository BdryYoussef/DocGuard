"""Deterministic metric calculations over evaluation cases and results.

Every metric here is a pure function of ``(cases, results)`` (or ``results`` alone for
latency). None of them fabricate a value: a metric whose denominator is zero returns a
:class:`Rate` with ``value=None`` rather than silently reporting 0% or 100% (see
docs/EVALUATION.md, "Zero-denominator handling"). Nothing in this module executes a
scan; it only summarizes results Phase 11B will have already produced.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.models.domain import Decision
from evaluation.models import (
    CaseCategory,
    CaseClass,
    EvaluationCase,
    EvaluationResult,
)

_ESCALATED_DECISIONS = frozenset({Decision.REVIEW, Decision.QUARANTINE, Decision.BLOCK})


@dataclass(frozen=True, slots=True)
class Rate:
    """A numerator/denominator ratio that is explicitly ``None`` (not 0.0 or 1.0) when
    the denominator is zero, i.e. the metric is not applicable to this corpus/run."""

    numerator: int
    denominator: int
    value: float | None

    def to_json(self) -> dict[str, object]:
        return {"numerator": self.numerator, "denominator": self.denominator, "value": self.value}


def _rate(numerator: int, denominator: int) -> Rate:
    if denominator < 0 or numerator < 0 or numerator > denominator:
        raise ValueError("invalid rate: numerator/denominator out of range")
    if denominator == 0:
        return Rate(numerator=0, denominator=0, value=None)
    return Rate(numerator=numerator, denominator=denominator, value=numerator / denominator)


@dataclass(frozen=True, slots=True)
class LatencyStats:
    """Deterministic latency statistics; ``None`` fields mean no timed results existed.

    ``p95`` uses the nearest-rank method (ceil(0.95 * n), 1-indexed). This is a simple
    descriptive statistic over the observed sample, not a claim of statistical
    significance — Phase 11B should not present it as one.
    """

    count: int
    mean_ms: float | None
    median_ms: float | None
    min_ms: int | None
    max_ms: int | None
    p95_ms: int | None

    def to_json(self) -> dict[str, object]:
        return {
            "count": self.count,
            "mean_ms": self.mean_ms,
            "median_ms": self.median_ms,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "p95_ms": self.p95_ms,
        }


def _results_by_case_id(results: Sequence[EvaluationResult]) -> dict[str, EvaluationResult]:
    return {result.case_id: result for result in results}


def _matched(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> list[tuple[EvaluationCase, EvaluationResult]]:
    by_id = _results_by_case_id(results)
    return [(case, by_id[case.case_id]) for case in cases if case.case_id in by_id]


def risky_case_detection_recall(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> Rate:
    """Metric A: risky cases where every mandatory expected finding was observed,
    divided by the number of evaluable risky cases (risky cases that both have at
    least one expected finding and have a result)."""
    evaluable = [
        (case, result)
        for case, result in _matched(cases, results)
        if case.case_class is CaseClass.RISKY and case.expected_findings
    ]
    detected = sum(
        1
        for case, result in evaluable
        if set(case.expected_findings) <= set(result.actual_findings)
    )
    return _rate(detected, len(evaluable))


def finding_level_recall(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> Rate:
    """Metric B: expected findings detected / total expected findings, across all
    matched cases (any class)."""
    total = 0
    detected = 0
    for case, result in _matched(cases, results):
        expected = set(case.expected_findings)
        total += len(expected)
        detected += len(expected & set(result.actual_findings))
    return _rate(detected, total)


def finding_level_recall_by_category(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> dict[CaseCategory, Rate]:
    """Metric B, broken down per :class:`CaseCategory`."""
    by_category: dict[CaseCategory, list[EvaluationCase]] = {}
    for case in cases:
        by_category.setdefault(case.category, []).append(case)
    return {
        category: finding_level_recall(category_cases, results)
        for category, category_cases in sorted(by_category.items(), key=lambda item: item[0].value)
    }


def benign_escalation_rate(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> Rate:
    """Metric C: benign cases receiving REVIEW/QUARANTINE/BLOCK / total benign cases."""
    benign = [
        (case, result)
        for case, result in _matched(cases, results)
        if case.case_class is CaseClass.BENIGN
    ]
    escalated = sum(1 for _, result in benign if result.actual_decision in _ESCALATED_DECISIONS)
    return _rate(escalated, len(benign))


def benign_allow_rate(cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]) -> Rate:
    """Metric D: benign cases receiving ALLOW / total benign cases."""
    benign = [
        (case, result)
        for case, result in _matched(cases, results)
        if case.case_class is CaseClass.BENIGN
    ]
    allowed = sum(1 for _, result in benign if result.actual_decision is Decision.ALLOW)
    return _rate(allowed, len(benign))


def decision_compliance_rate(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> Rate:
    """Metric E: cases whose actual decision is a member of their case-specific
    ``acceptable_decisions`` set / total matched cases. No numeric ordering is imposed;
    compliance is judged solely against each case's explicit acceptable-decision set."""
    matched = _matched(cases, results)
    compliant = sum(
        1
        for case, result in matched
        if result.actual_decision is not None
        and result.actual_decision in case.acceptable_decisions
    )
    return _rate(compliant, len(matched))


def fail_secure_rate(cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]) -> Rate:
    """Metric G: fail-secure cases ending non-release-eligible / total fail-secure
    cases. ``release_eligible`` must be explicitly ``False``; ``None`` (unknown/never
    ran) does not count as a pass."""
    fail_secure = [(case, result) for case, result in _matched(cases, results) if case.fail_secure]
    contained = sum(1 for _, result in fail_secure if result.release_eligible is False)
    return _rate(contained, len(fail_secure))


def completeness_counts(results: Sequence[EvaluationResult]) -> Counter[str]:
    """Metric F: counts per :class:`AnalysisCompletenessClass`, plus an ``UNKNOWN``
    bucket for results that never recorded a completeness class."""
    counter: Counter[str] = Counter()
    for result in results:
        counter[
            result.completeness_class.value if result.completeness_class is not None else "UNKNOWN"
        ] += 1
    return counter


def cdr_recovery_rate(results: Sequence[EvaluationResult]) -> Rate:
    """Metric I: eligible CDR-attempted cases with a release-eligible derived artifact,
    divided by eligible CDR-attempted cases. Phase 11A never populates ``cdr_outcome``
    from a real run; this is data-model support for Phase 11B."""
    attempted = [
        result.cdr_outcome
        for result in results
        if result.cdr_outcome is not None and result.cdr_outcome.cdr_eligible
    ]
    recovered = sum(1 for outcome in attempted if outcome.derived_release_eligible is True)
    return _rate(recovered, len(attempted))


def latency_stats(results: Sequence[EvaluationResult]) -> LatencyStats:
    """Metric H: descriptive latency statistics over results that recorded a latency."""
    values = sorted(result.latency_ms for result in results if result.latency_ms is not None)
    if not values:
        return LatencyStats(
            count=0, mean_ms=None, median_ms=None, min_ms=None, max_ms=None, p95_ms=None
        )
    count = len(values)
    mean_ms = sum(values) / count
    mid = count // 2
    median_ms = float(values[mid]) if count % 2 else (values[mid - 1] + values[mid]) / 2
    p95_index = min(count - 1, math.ceil(0.95 * count) - 1)
    return LatencyStats(
        count=count,
        mean_ms=mean_ms,
        median_ms=median_ms,
        min_ms=values[0],
        max_ms=values[-1],
        p95_ms=values[p95_index],
    )


@dataclass(frozen=True, slots=True)
class MetricsSummary:
    """The complete Phase 11 metric set for one evaluation run."""

    risky_case_detection_recall: Rate
    finding_level_recall: Rate
    finding_level_recall_by_category: dict[CaseCategory, Rate]
    benign_escalation_rate: Rate
    benign_allow_rate: Rate
    decision_compliance_rate: Rate
    fail_secure_rate: Rate
    completeness_counts: Counter[str]
    cdr_recovery_rate: Rate
    latency: LatencyStats
    matched_case_count: int = field(default=0)
    total_case_count: int = field(default=0)

    def to_json(self) -> dict[str, object]:
        return {
            "risky_case_detection_recall": self.risky_case_detection_recall.to_json(),
            "finding_level_recall": self.finding_level_recall.to_json(),
            "finding_level_recall_by_category": {
                category.value: rate.to_json()
                for category, rate in self.finding_level_recall_by_category.items()
            },
            "benign_escalation_rate": self.benign_escalation_rate.to_json(),
            "benign_allow_rate": self.benign_allow_rate.to_json(),
            "decision_compliance_rate": self.decision_compliance_rate.to_json(),
            "fail_secure_rate": self.fail_secure_rate.to_json(),
            "completeness_counts": dict(sorted(self.completeness_counts.items())),
            "cdr_recovery_rate": self.cdr_recovery_rate.to_json(),
            "latency": self.latency.to_json(),
            "matched_case_count": self.matched_case_count,
            "total_case_count": self.total_case_count,
        }


def compute_all_metrics(
    cases: Sequence[EvaluationCase], results: Sequence[EvaluationResult]
) -> MetricsSummary:
    """Compute every Phase 11 metric in one deterministic pass."""
    return MetricsSummary(
        risky_case_detection_recall=risky_case_detection_recall(cases, results),
        finding_level_recall=finding_level_recall(cases, results),
        finding_level_recall_by_category=finding_level_recall_by_category(cases, results),
        benign_escalation_rate=benign_escalation_rate(cases, results),
        benign_allow_rate=benign_allow_rate(cases, results),
        decision_compliance_rate=decision_compliance_rate(cases, results),
        fail_secure_rate=fail_secure_rate(cases, results),
        completeness_counts=completeness_counts(results),
        cdr_recovery_rate=cdr_recovery_rate(results),
        latency=latency_stats(results),
        matched_case_count=len(_matched(cases, results)),
        total_case_count=len(cases),
    )


__all__ = [
    "LatencyStats",
    "MetricsSummary",
    "Rate",
    "benign_allow_rate",
    "benign_escalation_rate",
    "cdr_recovery_rate",
    "completeness_counts",
    "compute_all_metrics",
    "decision_compliance_rate",
    "fail_secure_rate",
    "finding_level_recall",
    "finding_level_recall_by_category",
    "latency_stats",
    "risky_case_detection_recall",
]
