"""Supplementary non-PDF end-to-end operator-workflow validation for DocGuard v1.1.1.

This is post-release validation tooling only. It does not modify DocGuard's
application code, security controls, policy, or analyzers. It authenticates as a
real operator and drives the real, unmodified `POST /api/v1/scans` and
`GET /api/v1/scans/{id}` endpoints against a real running instance (real Bubblewrap
isolation backend), using fixture bytes materialized byte-for-byte identically to
the frozen Phase 11 corpus via `evaluation.corpus.materialize_case` (imported, not
modified). It selects a subset of already-existing Office/archive/file-identity
cases from `evaluation/corpus_manifest.json` and compares observed findings/decision
/completeness against that manifest's own ground truth, using the same pass/fail
semantics as `evaluation/runner.py::_result_from_payload` (missing-expected-findings,
unexpected-findings vs. acceptable_additional_findings/allow_any_additional_findings,
and decision membership in acceptable_decisions).

This script does NOT re-run or extend the frozen Phase 11D benchmark. It is a
smaller, separate, supplementary E2E pass — see docs/validation/NON_PDF_E2E_VALIDATION.md.

Reads credentials only from environment variables (never hardcoded, never printed):

    DOCGUARD_VALIDATION_BASE_URL
    DOCGUARD_VALIDATION_USERNAME
    DOCGUARD_VALIDATION_PASSWORD

Writes `.report-venv/instance/nonpdf_validation_results.json`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from evaluation.corpus import CASES, materialize_case  # noqa: E402
from evaluation.models import Decision as EvalDecision  # noqa: E402

FIXTURES_DIR = REPO_ROOT / ".report-venv" / "instance" / "nonpdf-fixtures"
RESULTS_PATH = REPO_ROOT / ".report-venv" / "instance" / "nonpdf_validation_results.json"

# Selected supplementary non-PDF cases, pulled by case_id from the existing frozen
# Phase 11 corpus manifest (evaluation/corpus_manifest.json). Selection rationale is
# recorded in docs/validation/NON_PDF_E2E_VALIDATION.md.
SELECTED_CASE_IDS: list[str] = [
    "OFF-BEN-001",
    "OFF-RISK-002",
    "OFF-RISK-006",
    "OFF-RISK-009",
    "ARC-BEN-001",
    "ARC-RISK-001",
    "ARC-RISK-002",
    "ARC-RISK-004",
    "ARC-RISK-009",
    "FID-004",
]


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def _login(client: httpx.Client, username: str, password: str, base_url: str) -> str:
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        headers={"origin": base_url},
    )
    if response.status_code != 303:
        raise SystemExit(f"login failed: {response.status_code} {response.text[:300]}")
    dashboard = client.get("/app")
    if dashboard.status_code != 200:
        raise SystemExit("login did not yield an authenticated session")
    csrf_start = dashboard.text.find('name="csrf_token" value="')
    if csrf_start == -1:
        raise SystemExit("could not locate a csrf token on the dashboard page")
    csrf_start += len('name="csrf_token" value="')
    csrf_end = dashboard.text.find('"', csrf_start)
    return dashboard.text[csrf_start:csrf_end]


def _upload(
    client: httpx.Client, csrf: str, filename: str, body: bytes, content_type: str
) -> dict[str, object]:
    response = client.post(
        "/api/v1/scans",
        params={"filename": filename},
        content=body,
        headers={"content-type": content_type, "x-csrf-token": csrf},
    )
    if response.status_code != 201:
        raise SystemExit(
            f"upload of {filename} failed: {response.status_code} {response.text[:300]}"
        )
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def _compare(case, payload: dict[str, object]) -> dict[str, object]:
    """Mirror evaluation/runner.py::_result_from_payload's pass/fail semantics exactly."""
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
    actual_decision = EvalDecision(decision_raw) if isinstance(decision_raw, str) else None
    decision_compliant = (
        actual_decision in case.acceptable_decisions if actual_decision is not None else False
    )
    findings_recall_pass = not missing
    analysis_complete = payload.get("analysis_complete")

    passed = decision_compliant and findings_recall_pass and not unexpected

    return {
        "case_id": case.case_id,
        "category": case.category.value,
        "filename": case.filename,
        "expected_findings": sorted(expected),
        "observed_findings": list(actual_codes),
        "missing_expected_findings": list(missing),
        "unexpected_findings": list(unexpected),
        "acceptable_decisions": [d.value for d in case.acceptable_decisions],
        "observed_decision": decision_raw,
        "decision_compliant": decision_compliant,
        "expected_analysis_complete": case.expected_analysis_complete,
        "observed_analysis_complete": analysis_complete,
        "observed_analysis_status": payload.get("analysis_status"),
        "observed_release_eligible": payload.get("release_eligible"),
        "observed_risk_score": payload.get("risk_score"),
        "observed_risk_band": payload.get("risk_band"),
        "fail_secure": case.fail_secure,
        "scan_id": payload.get("scan_id"),
        "PASS": passed,
    }


def main() -> int:
    base_url = _env("DOCGUARD_VALIDATION_BASE_URL")
    username = _env("DOCGUARD_VALIDATION_USERNAME")
    password = _env("DOCGUARD_VALIDATION_PASSWORD")

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    cases_by_id = {case.case_id: case for case in CASES}
    missing_ids = [cid for cid in SELECTED_CASE_IDS if cid not in cases_by_id]
    if missing_ids:
        raise SystemExit(f"selected case_id(s) not found in frozen corpus: {missing_ids}")

    results: list[dict[str, object]] = []
    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        csrf = _login(client, username, password, base_url)
        client.headers["origin"] = base_url

        for case_id in SELECTED_CASE_IDS:
            case = cases_by_id[case_id]
            fixture_dir = FIXTURES_DIR / case_id
            fixture_path = materialize_case(case, fixture_dir)
            body = fixture_path.read_bytes()
            content_type = case.claimed_content_type or "application/octet-stream"
            payload = _upload(client, csrf, case.filename, body, content_type)
            result = _compare(case, payload)
            results.append(result)
            status = "PASS" if result["PASS"] else "**FAIL**"
            print(f"[{status}] {case_id}: {case.filename} -> decision={result['observed_decision']}")

        # Audit trail check: confirm SCAN_UPLOAD_REQUESTED events exist for this run.
        audit_response = client.get("/api/v1/audit-events", params={"page_size": 100})
        audit_ok = audit_response.status_code == 200
        audit_event_count = 0
        if audit_ok:
            audit_payload = audit_response.json()
            items = audit_payload.get("items", [])
            scan_ids = {r["scan_id"] for r in results}
            audit_event_count = sum(
                1
                for item in items
                if item.get("event_type") == "SCAN_UPLOAD_REQUESTED"
                and item.get("scan_id") in scan_ids
            )

    output = {
        "base_url": base_url,
        "selected_case_ids": SELECTED_CASE_IDS,
        "results": results,
        "audit_check": {
            "status_code": audit_response.status_code,
            "matched_upload_events": audit_event_count,
            "expected_matched_upload_events": len(results),
        },
        "all_passed": all(r["PASS"] for r in results),
    }
    RESULTS_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nwrote {RESULTS_PATH}")
    print(f"audit check: {audit_event_count}/{len(results)} matched SCAN_UPLOAD_REQUESTED events found")
    print(f"all_passed: {output['all_passed']}")
    return 0 if output["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
