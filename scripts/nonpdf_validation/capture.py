"""Capture at most two supplementary Office/ZIP scan-detail screenshots for the
non-PDF E2E validation pass. Post-release validation tooling only — does not modify
application code, security controls, policy, or analyzers. Drives a real, running,
unmodified DocGuard instance through Playwright/Chromium.

Reads credentials only from environment variables, never hardcoded or printed:

    DOCGUARD_VALIDATION_BASE_URL
    DOCGUARD_VALIDATION_USERNAME
    DOCGUARD_VALIDATION_PASSWORD

Reads scan ids from .report-venv/instance/nonpdf_validation_results.json (written by
seed_and_validate.py).

Run with:

    .report-venv/bin/python scripts/nonpdf_validation/capture.py
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "docs" / "screenshots" / "report"
RESULTS_PATH = REPO_ROOT / ".report-venv" / "instance" / "nonpdf_validation_results.json"

DESKTOP_VIEWPORT = {"width": 1440, "height": 900}
DEVICE_SCALE_FACTOR = 2

OFFICE_CASE_ID = "OFF-RISK-002"
ARCHIVE_CASE_ID = "ARC-RISK-001"


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def main() -> int:
    base_url = _env("DOCGUARD_VALIDATION_BASE_URL")
    username = _env("DOCGUARD_VALIDATION_USERNAME")
    password = _env("DOCGUARD_VALIDATION_PASSWORD")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))["results"]
    by_case = {r["case_id"]: r for r in results}
    office_scan_id = by_case[OFFICE_CASE_ID]["scan_id"]
    archive_scan_id = by_case[ARCHIVE_CASE_ID]["scan_id"]

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(
            viewport=DESKTOP_VIEWPORT,
            device_scale_factor=DEVICE_SCALE_FACTOR,
            reduced_motion="reduce",
            base_url=base_url,
        )
        page = context.new_page()
        page.goto("/login")
        page.fill('input[name="username"]', username)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_url("**/app")

        page.goto(f"/app/scans/{office_scan_id}")
        page.wait_for_selector(".decision-panel")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(OUTPUT_DIR / "15_office_analysis.png"))
        print(f"captured 15_office_analysis.png (scan {office_scan_id}, case {OFFICE_CASE_ID})")

        page.goto(f"/app/scans/{archive_scan_id}")
        page.wait_for_selector(".decision-panel")
        page.wait_for_load_state("networkidle")
        page.screenshot(path=str(OUTPUT_DIR / "16_archive_analysis.png"))
        print(f"captured 16_archive_analysis.png (scan {archive_scan_id}, case {ARCHIVE_CASE_ID})")

        context.close()
        browser.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
