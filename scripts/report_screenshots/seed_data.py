"""Seed a running DocGuard instance with curated, synthetic, controlled scans for
the report/defense screenshot set.

This is post-release tooling only. It does not modify DocGuard's application code,
security controls, policy, or analyzers — it authenticates as a real operator and
drives the real, unmodified `POST /api/v1/scans` and `POST /api/v1/scans/{id}/sanitize`
endpoints with locally-generated, inert, synthetic PDF fixtures (the same factories
used by the test suite and the Phase 11 evaluation corpus). No real client data of any
kind is used.

Reads credentials only from environment variables (never hardcoded, never printed):

    DOCGUARD_SCREENSHOT_BASE_URL
    DOCGUARD_SCREENSHOT_USERNAME
    DOCGUARD_SCREENSHOT_PASSWORD

Writes `.report-venv/instance/seed_manifest.json` — logical scan/artifact identity
(scan_id, decision, etc.) for `capture.py` to navigate to directly, and the paths of
a separate, NOT-yet-uploaded set of fixture files for the live multi-file-queue
screenshot. Nothing under this output path is committed (`.report-venv/` is
gitignored).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tests.fixtures.pdf_factory import (  # noqa: E402
    write_benign_pdf,
    write_javascript_pdf,
    write_malformed_pdf_with_indicator_names,
)
from tests.unit.test_file_identification import inert_pe_fixture  # noqa: E402

FIXTURES_DIR = REPO_ROOT / ".report-venv" / "instance" / "fixtures"
QUEUE_FIXTURES_DIR = REPO_ROOT / ".report-venv" / "instance" / "queue-fixtures"
MANIFEST_PATH = REPO_ROOT / ".report-venv" / "instance" / "seed_manifest.json"


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


def _upload(client: httpx.Client, csrf: str, filename: str, body: bytes) -> dict[str, object]:
    response = client.post(
        "/api/v1/scans",
        params={"filename": filename},
        content=body,
        headers={"content-type": "application/pdf", "x-csrf-token": csrf},
    )
    if response.status_code != 201:
        raise SystemExit(
            f"upload of {filename} failed: {response.status_code} {response.text[:300]}"
        )
    payload = response.json()
    assert isinstance(payload, dict)
    return payload


def main() -> int:
    base_url = _env("DOCGUARD_SCREENSHOT_BASE_URL")
    username = _env("DOCGUARD_SCREENSHOT_USERNAME")
    password = _env("DOCGUARD_SCREENSHOT_PASSWORD")

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    QUEUE_FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    with httpx.Client(base_url=base_url, timeout=30.0) as client:
        csrf = _login(client, username, password, base_url)
        client.headers["origin"] = base_url

        allow_bytes = write_benign_pdf(FIXTURES_DIR / "rapport-annuel-2026.pdf").read_bytes()
        risky_bytes = write_javascript_pdf(FIXTURES_DIR / "facture-fournisseur.pdf").read_bytes()
        fallback_bytes = write_malformed_pdf_with_indicator_names(
            FIXTURES_DIR / "document-partiel-endommage.pdf", names=("JavaScript", "OpenAction")
        ).read_bytes()
        block_bytes = inert_pe_fixture()

        allow_scan = _upload(client, csrf, "rapport-annuel-2026.pdf", allow_bytes)
        quarantine_risky_scan = _upload(client, csrf, "facture-fournisseur.pdf", risky_bytes)
        quarantine_fallback_scan = _upload(
            client, csrf, "document-partiel-endommage.pdf", fallback_bytes
        )
        block_scan = _upload(client, csrf, "piece-jointe-executable.pdf", block_bytes)

        sanitize_response = client.post(
            f"/api/v1/scans/{quarantine_risky_scan['scan_id']}/sanitize",
            headers={"x-csrf-token": csrf},
        )
        if sanitize_response.status_code != 200:
            raise SystemExit(
                f"CDR sanitize request failed: {sanitize_response.status_code} "
                f"{sanitize_response.text[:300]}"
            )
        cdr_result = sanitize_response.json()
        if not cdr_result.get("approved"):
            raise SystemExit(f"CDR sanitize did not approve a derived artifact: {cdr_result}")

        # Exercise the real approved-artifact download endpoint once, so the
        # audit trail includes a genuine ARTIFACT_DOWNLOADED event alongside
        # upload/CDR activity, not just repeated logins.
        download_response = client.get(f"/api/v1/artifacts/{cdr_result['artifact_id']}/download")
        if download_response.status_code != 200:
            raise SystemExit(
                f"approved-artifact download failed: {download_response.status_code} "
                f"{download_response.text[:300]}"
            )

        # A second, distinct BLOCK example for multi-file queue variety — same
        # fixture bytes, a different filename so it reads as an independent item.
        write_benign_pdf(QUEUE_FIXTURES_DIR / "bulletin-de-paie.pdf")
        write_benign_pdf(QUEUE_FIXTURES_DIR / "note-de-service.pdf", keyword_text=True)
        write_javascript_pdf(QUEUE_FIXTURES_DIR / "contrat-partenariat.pdf")
        (QUEUE_FIXTURES_DIR / "piece-jointe-suspecte.pdf").write_bytes(block_bytes)

    scans: dict[str, object] = {
        "allow": allow_scan["scan_id"],
        "quarantine_risky": quarantine_risky_scan["scan_id"],
        "quarantine_fallback": quarantine_fallback_scan["scan_id"],
        "block": block_scan["scan_id"],
        "cdr_source": quarantine_risky_scan["scan_id"],
        "cdr_derived": cdr_result["derived_scan_id"],
        "cdr_artifact_id": cdr_result["artifact_id"],
    }
    manifest: dict[str, object] = {
        "base_url": base_url,
        "scans": scans,
        "queue_fixture_files": sorted(str(p) for p in QUEUE_FIXTURES_DIR.glob("*.pdf")),
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"seed complete: {MANIFEST_PATH}")
    for key, value in scans.items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
