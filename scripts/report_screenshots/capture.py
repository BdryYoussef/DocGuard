"""Capture the curated DocGuard v1.1.1 report/defense screenshot set.

Post-release tooling only. Does not modify DocGuard's application code, security
controls, policy, or analyzers. Drives a real, running, unmodified DocGuard instance
through Playwright/Chromium using only synthetic/controlled data (see
`seed_data.py`). Read `docs/screenshots/SCREENSHOT_MANIFEST.md` for what each image is
for and its recommended report caption.

Credentials are read only from environment variables, never hardcoded or printed:

    DOCGUARD_SCREENSHOT_BASE_URL
    DOCGUARD_SCREENSHOT_USERNAME
    DOCGUARD_SCREENSHOT_PASSWORD

Run with:

    .report-venv/bin/python scripts/report_screenshots/capture.py

Exits nonzero if DocGuard is unreachable, authentication fails, the reported
application version does not match the expected release, a required seeded
scan/state is missing, or any required screenshot fails to be produced.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = REPO_ROOT / "docs" / "screenshots" / "report"
MANIFEST_PATH = REPO_ROOT / ".report-venv" / "instance" / "seed_manifest.json"

EXPECTED_APPLICATION_VERSION = "1.1.1"

DESKTOP_VIEWPORT = {"width": 1440, "height": 900}
MOBILE_VIEWPORT = {"width": 375, "height": 812}
EVIDENCE_REPORT_VIEWPORT = {"width": 1440, "height": 1650}
DEVICE_SCALE_FACTOR = 2

REQUIRED_SCREENSHOTS = [
    "01_landing_hero.png",
    "02_security_architecture.png",
    "03_operator_login.png",
    "04_dashboard.png",
    "05_multi_file_queue.png",
    "06_documents_list.png",
    "07_allow_decision.png",
    "08_quarantine_decision.png",
    "09_fallback_evidence.png",
    "10_block_decision.png",
    "11_cdr_lineage.png",
    "12_evidence_report.png",
    "13_audit_trail.png",
]
OPTIONAL_SCREENSHOTS = ["14_mobile_dashboard.png"]

TERMINAL_QUEUE_STATES = {"allow", "review", "quarantine", "block", "error", "skipped"}


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def _verify_reachable(base_url: str) -> None:
    response = httpx.get(f"{base_url}/health/live", timeout=10.0)
    if response.status_code != 200:
        raise SystemExit(f"DocGuard is not reachable at {base_url}: {response.status_code}")
    print(f"[1/8] DocGuard reachable at {base_url}")


def _verify_release_identity(base_url: str) -> None:
    try:
        response = httpx.get(f"{base_url}/openapi.json", timeout=10.0)
    except httpx.HTTPError as exc:
        print(f"[2/8] release-identity check skipped (openapi.json unreachable: {exc})")
        return
    if response.status_code != 200:
        print(
            f"[2/8] release-identity check skipped (openapi.json returned "
            f"{response.status_code} — expected in a production-mode instance)"
        )
        return
    version = response.json().get("info", {}).get("version")
    if version != EXPECTED_APPLICATION_VERSION:
        raise SystemExit(
            f"DocGuard reports application version {version!r}, expected "
            f"{EXPECTED_APPLICATION_VERSION!r}. The screenshot instance is likely "
            f"running stale code (e.g. a uvicorn process started before the "
            f"current release) — restart it against current HEAD before capturing."
        )
    print(f"[2/8] DocGuard application version confirmed: {version}")


def _load_seed_manifest() -> dict[str, object]:
    if not MANIFEST_PATH.exists():
        raise SystemExit(f"seed manifest not found at {MANIFEST_PATH} — run seed_data.py first")
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"seed manifest at {MANIFEST_PATH} must contain a JSON object")
    return data


def _manifest_scan_ids(source: dict[str, object], key: str) -> dict[str, str]:
    """Narrow one already-trusted manifest field (written by seed_data.py in the
    same tooling family) to the `dict[str, str]` shape every caller here assumes."""
    value = source[key]
    if not isinstance(value, dict):
        raise SystemExit(f"seed manifest field {key!r} must be an object, got {type(value)!r}")
    return value


def _manifest_str_list(source: dict[str, object], key: str) -> list[str]:
    """Narrow one already-trusted manifest field to the `list[str]` shape every
    caller here assumes."""
    value = source[key]
    if not isinstance(value, list):
        raise SystemExit(f"seed manifest field {key!r} must be a list, got {type(value)!r}")
    return value


def _authenticated_context(
    browser: Browser, base_url: str, username: str, password: str
) -> tuple[BrowserContext, Page]:
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
    return context, page


def capture_public(browser: Browser, base_url: str) -> None:
    context = browser.new_context(
        viewport=DESKTOP_VIEWPORT,
        device_scale_factor=DEVICE_SCALE_FACTOR,
        reduced_motion="reduce",
        base_url=base_url,
    )
    page = context.new_page()

    page.goto("/")
    page.wait_for_selector(".hero")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUTPUT_DIR / "01_landing_hero.png"))

    architecture = page.locator("#architecture")
    architecture.scroll_into_view_if_needed()
    page.wait_for_timeout(150)  # let the scroll-reveal transition settle
    architecture.screenshot(path=str(OUTPUT_DIR / "02_security_architecture.png"))

    page.goto("/login")
    page.wait_for_selector('input[name="username"]')
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUTPUT_DIR / "03_operator_login.png"))

    context.close()


def capture_dashboard(page: Page) -> None:
    page.goto("/app")
    page.wait_for_selector(".panel")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUTPUT_DIR / "04_dashboard.png"))


def capture_multi_file_queue(page: Page, queue_files: list[str]) -> None:
    if not queue_files:
        raise SystemExit("no queue fixture files were provided by the seed manifest")
    page.goto("/app")
    page.wait_for_selector("#document")
    page.set_input_files("#document", queue_files)
    page.click("#upload-start")

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        items = page.locator(".upload-queue-item").all()
        if len(items) == len(queue_files):
            states = [item.get_attribute("data-state") for item in items]
            if all(state in TERMINAL_QUEUE_STATES for state in states):
                break
        page.wait_for_timeout(250)
    else:
        raise SystemExit("multi-file queue did not reach a terminal state within 30s")

    page.wait_for_timeout(200)  # let the last item's terminal-state transition settle
    page.locator("#upload-form").screenshot(path=str(OUTPUT_DIR / "05_multi_file_queue.png"))


def capture_documents_list(page: Page) -> None:
    page.goto("/app/scans")
    page.wait_for_selector(".table-wrap")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUTPUT_DIR / "06_documents_list.png"))


def capture_scan_detail(page: Page, scan_id: str, filename: str) -> None:
    page.goto(f"/app/scans/{scan_id}")
    page.wait_for_selector(".decision-panel")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUTPUT_DIR / filename))


def capture_fallback_evidence(page: Page, scan_id: str) -> None:
    """Screenshot the whole findings list, not just the lexical row alone — this
    is what actually shows the required contrast between the bounded lexical
    finding and its structurally-confirmed siblings on the same scan."""
    page.goto(f"/app/scans/{scan_id}")
    page.locator('.finding-row[data-confidence="lexical"]').first.wait_for(state="visible")
    page.wait_for_load_state("networkidle")
    page.locator(".finding-rows").screenshot(path=str(OUTPUT_DIR / "09_fallback_evidence.png"))


def capture_cdr_lineage(page: Page, source_scan_id: str) -> None:
    page.goto(f"/app/scans/{source_scan_id}")
    lineage = page.locator(".lineage")
    lineage.wait_for(state="visible")
    page.wait_for_load_state("networkidle")
    lineage.scroll_into_view_if_needed()
    lineage.screenshot(path=str(OUTPUT_DIR / "11_cdr_lineage.png"))


def capture_evidence_report(page: Page, scan_id: str) -> None:
    """A full `full_page` screenshot of this route is disproportionately tall
    (~2600px) and unreadable once scaled to fit an A4 report page width. Resize
    the viewport to a height that comfortably covers Document identity, the
    Decision (including policy version/fingerprint), the decision rationale, and
    real findings, then take one normal (non-full-page) screenshot of exactly
    that — a properly-proportioned, readable figure instead of the entire
    scrollable document compressed into one image."""
    page.set_viewport_size(EVIDENCE_REPORT_VIEWPORT)
    page.goto(f"/app/scans/{scan_id}/report")
    page.wait_for_selector(".report-section")
    page.wait_for_load_state("networkidle")
    page.screenshot(
        path=str(OUTPUT_DIR / "12_evidence_report.png"),
        clip={
            "x": 0,
            "y": 0,
            "width": EVIDENCE_REPORT_VIEWPORT["width"],
            "height": EVIDENCE_REPORT_VIEWPORT["height"],
        },
    )
    page.set_viewport_size(DESKTOP_VIEWPORT)


def capture_audit_trail(page: Page) -> None:
    page.goto("/app/audit")
    page.wait_for_selector(".table-wrap")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUTPUT_DIR / "13_audit_trail.png"))


def capture_mobile_dashboard(browser: Browser, base_url: str, username: str, password: str) -> None:
    context = browser.new_context(
        viewport=MOBILE_VIEWPORT,
        device_scale_factor=DEVICE_SCALE_FACTOR,
        reduced_motion="reduce",
        base_url=base_url,
        is_mobile=True,
    )
    page = context.new_page()
    page.goto("/login")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_url("**/app")
    page.wait_for_selector(".panel")
    page.screenshot(path=str(OUTPUT_DIR / "14_mobile_dashboard.png"))
    context.close()


def main() -> int:
    base_url = _env("DOCGUARD_SCREENSHOT_BASE_URL")
    username = _env("DOCGUARD_SCREENSHOT_USERNAME")
    password = _env("DOCGUARD_SCREENSHOT_PASSWORD")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    _verify_reachable(base_url)
    _verify_release_identity(base_url)

    manifest = _load_seed_manifest()
    scans = _manifest_scan_ids(manifest, "scans")
    queue_files = _manifest_str_list(manifest, "queue_fixture_files")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()

        print("[3/8] capturing public screenshots")
        capture_public(browser, base_url)

        print("[4/8] authenticating")
        context, page = _authenticated_context(browser, base_url, username, password)

        print("[5/8] capturing authenticated screenshots")
        capture_dashboard(page)
        capture_multi_file_queue(page, queue_files)
        capture_documents_list(page)
        capture_scan_detail(page, scans["allow"], "07_allow_decision.png")
        # Prefer the malformed/incomplete fail-closed example for the QUARANTINE
        # figure over the structural-JS one — more useful for a jury: it shows
        # QUARANTINE triggered by incomplete analysis, not just a risky finding.
        capture_scan_detail(page, scans["quarantine_fallback"], "08_quarantine_decision.png")
        capture_fallback_evidence(page, scans["quarantine_fallback"])
        capture_scan_detail(page, scans["block"], "10_block_decision.png")
        capture_cdr_lineage(page, scans["cdr_source"])
        capture_evidence_report(page, scans["quarantine_risky"])
        capture_audit_trail(page)
        context.close()

        print("[6/8] capturing optional mobile screenshot")
        capture_mobile_dashboard(browser, base_url, username, password)

        browser.close()

    print("[7/8] verifying required screenshots exist")
    missing = [name for name in REQUIRED_SCREENSHOTS if not (OUTPUT_DIR / name).is_file()]
    present_optional = [name for name in OPTIONAL_SCREENSHOTS if (OUTPUT_DIR / name).is_file()]

    print("[8/8] summary")
    for name in REQUIRED_SCREENSHOTS:
        path = OUTPUT_DIR / name
        status = "OK" if path.is_file() else "MISSING"
        size = f"{path.stat().st_size:,} bytes" if path.is_file() else "-"
        print(f"  {status:8s} {name:32s} {size}")
    for name in present_optional:
        path = OUTPUT_DIR / name
        print(f"  OK       {name:32s} {path.stat().st_size:,} bytes (optional)")

    if missing:
        print(f"\nFAILED: {len(missing)} required screenshot(s) missing: {missing}")
        return 1

    print(f"\nSUCCESS: all {len(REQUIRED_SCREENSHOTS)} required screenshots captured.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
