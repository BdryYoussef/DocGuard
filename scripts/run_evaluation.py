"""Phase 11 evaluation CLI: ``python -m scripts.run_evaluation``.

Safe, no-execution modes (no scan pipeline invoked, no ``var/`` writes):

    python -m scripts.run_evaluation --validate-manifest
    python -m scripts.run_evaluation --list-cases
    python -m scripts.run_evaluation --dry-run

Execution mode (invokes the real DocGuard pipeline; requires explicit case IDs so the
full 45-60 case corpus is never run by accident during Phase 11A):

    python -m scripts.run_evaluation --execute --case-id PDF-BEN-001 --case-id PDF-RISK-003

See docs/EVALUATION.md for the full methodology and current limitations.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.core.config import IsolationBackendName
from evaluation.manifest import ManifestValidationError
from evaluation.metrics import compute_all_metrics
from evaluation.reporting import (
    write_markdown_report,
    write_metrics_json,
    write_results_csv,
    write_results_json,
)
from evaluation.runner import dry_run_mode, execute_mode, list_cases_mode, validate_manifest_mode


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-manifest", action="store_true")
    mode.add_argument("--list-cases", action="store_true")
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument(
        "--case-id",
        action="append",
        default=[],
        help="case_id to run under --execute; repeatable. Required for --execute.",
    )
    parser.add_argument(
        "--isolation-backend",
        choices=[member.value for member in IsolationBackendName],
        default=IsolationBackendName.BUBBLEWRAP.value,
        help="worker isolation backend for --execute (default: bubblewrap, the production path)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="directory to write results.json/results.csv/metrics.json/report.md under --execute",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if args.validate_manifest:
        ok, message = validate_manifest_mode()
        print(message)
        return 0 if ok else 1

    if args.list_cases:
        try:
            print(list_cases_mode())
        except ManifestValidationError as exc:
            print(f"FAIL manifest validation: {exc}")
            return 1
        return 0

    if args.dry_run:
        ok, message = dry_run_mode()
        print(message)
        return 0 if ok else 1

    # --execute
    if not args.case_id:
        print(
            "FAIL: --execute requires at least one --case-id. Phase 11A does not run the "
            "full corpus; use --list-cases to see available IDs. Full-corpus execution is "
            "Phase 11B."
        )
        return 1
    backend = IsolationBackendName(args.isolation_backend)
    if backend is IsolationBackendName.UNSAFE_DEVELOPMENT:
        print(
            "WARNING: running with the unsafe-development isolation backend. This backend "
            "is forbidden in production and must never be used to draw conclusions about "
            "real detection behavior; it exists only for interface smoke-testing.",
            file=sys.stderr,
        )
    try:
        run = execute_mode(args.case_id, isolation_backend=backend)
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1

    cases_by_id = {case_id: None for case_id in args.case_id}
    from evaluation.manifest import load_manifest

    manifest_cases = [case for case in load_manifest() if case.case_id in cases_by_id]
    summary = compute_all_metrics(manifest_cases, run.results)

    for result in run.results:
        status = "OK" if result.decision_compliant else "NON-COMPLIANT"
        print(
            f"{result.case_id:16s} decision={result.actual_decision} "
            f"missing={list(result.missing_expected_findings)} "
            f"unexpected={list(result.unexpected_findings)} [{status}]"
        )

    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_results_json(run, args.output_dir / "results.json")
        write_results_csv(run.results, args.output_dir / "results.csv")
        write_metrics_json(summary, args.output_dir / "metrics.json", run.metadata)
        write_markdown_report(
            manifest_cases, run.results, summary, args.output_dir / "report.md", run.metadata
        )
        print(f"wrote reports to {args.output_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
