# Supplementary Non-PDF End-to-End Validation

- **Release:** DocGuard v1.1.1 (commit `72ad95dc812c65220bd14d5a301c2d7b75009396`,
  1 docs/tooling-only commit ahead of tag `v1.1.1`; `git diff v1.1.1..HEAD --stat --
  app/ worker/ docguard_contract/ evaluation/` is empty)
- **Policy:** 1.0.2 (`app/policies/version.py`)
- **Date:** 2026-08-18
- **Backend:** Bubblewrap (`DOCGUARD_ISOLATION_BACKEND=bubblewrap`, the same real
  sandboxing backend the production topology uses — not `unsafe-development`)
- **Corpus source:** the frozen Phase 11 controlled corpus
  (`evaluation/corpus_manifest.json`, 59 cases, unmodified). This document reuses 10
  of those 59 cases; it adds no new cases to the corpus.

> **This supplementary pass validates representative end-to-end operator workflows
> for Office and archive formats. It does not extend or alter the frozen Phase 11D
> benchmark.**

Do not combine the pass/fail counts below with Phase 11D's recall percentages. They
are a separate, smaller, non-benchmark validation of the real operator-facing
workflow (upload → real Bubblewrap worker → real analyzer → real policy → persisted
scan → operator scan-detail page → audit trail) for formats that prior manual/E2E
screenshot validation (`docs/screenshots/report/`) had covered mostly with PDF
examples.

## Motivation

Phase 11D (`evaluation/results/phase11d/`) already includes Office, archive, file-
identity, and YARA cases and is the authoritative detection-rate benchmark — 59/59
cases, 100% decision compliance, 100% finding-level recall, run through the real
Bubblewrap production path. That benchmark is not reproduced, re-run, or altered
here. What was missing was **operator-facing E2E and UI verification** for non-PDF
formats specifically: confirming the real upload API, real worker, real persistence,
real scan-detail page, and real audit trail behave correctly end-to-end for Office
and ZIP documents, and that the UI presents them correctly (not with PDF-specific
wording, not offering unsupported controls). This document is that check.

## Method

- New, uncommitted-style validation tooling only, added under
  `scripts/nonpdf_validation/` (`seed_and_validate.py`, `capture.py`), following the
  exact pattern already used for the PDF report screenshot tooling
  (`scripts/report_screenshots/`). No application, worker, contract, or evaluation
  code was modified.
- Fixture bytes for each selected case were materialized **byte-for-byte identically**
  to the frozen corpus by importing and calling `evaluation.corpus.materialize_case`
  (read-only import; the module and `evaluation/corpus_manifest.json` were not
  edited) — the same function `scripts.run_evaluation` uses internally. No new
  payloads were invented.
- A dedicated local operator account (`nonpdf-validation-operator`) was created via
  the existing `scripts/create_operator.py` against the same local dev database
  (`var/docguard.db`, gitignored) already used for prior Phase 11C/11D revalidation
  runs.
- A real `uvicorn` process served `app.main:create_app` with the project's existing
  `.env` configuration (`DOCGUARD_ISOLATION_BACKEND=bubblewrap`,
  `DOCGUARD_DATABASE_URL=sqlite:///./var/docguard.db`,
  `DOCGUARD_STORAGE_ROOT=./var/storage`), on `127.0.0.1:8010` (only
  `DOCGUARD_APPLICATION_ORIGIN` was overridden to match the port; all security,
  isolation, and storage settings were the project's real configured values).
  `GET /openapi.json` confirmed `"version": "1.1.1"` before any upload.
- Each case was uploaded through the real, unmodified `POST /api/v1/scans` endpoint
  (raw body, `filename` query parameter, `content-type` header — the exact contract
  `app/api/scans.py::create_scan` implements), authenticated with a real logged-in
  session and real CSRF token (no direct analyzer/service calls).
- Each scan's persisted result was retrieved via the real
  `GET /api/v1/scans/{scan_id}` endpoint and compared against
  `evaluation/corpus_manifest.json`'s own recorded ground truth for that `case_id`,
  using the same pass/fail semantics as `evaluation/runner.py::_result_from_payload`
  (missing-expected-findings, unexpected-findings vs.
  `acceptable_additional_findings`/`allow_any_additional_findings`, and decision
  membership in `acceptable_decisions`).
- The real audit trail was checked via `GET /api/v1/audit-events`.
- Two scan-detail pages were opened through a real authenticated browser session
  (Playwright/Chromium) at `/app/scans/{scan_id}` and visually verified.

## Case selection

Selected directly from `evaluation/corpus_manifest.json` by `case_id` (ground truth
quoted from that file, not from memory):

| # | case_id | Rationale |
|---|---|---|
| 1 | `OFF-BEN-001` | Benign Office document |
| 2 | `OFF-RISK-002` | Macro-enabled/VBA (AutoOpen autoexec) |
| 3 | `OFF-RISK-006` | External relationship / external template |
| 4 | `OFF-RISK-009` | Encrypted Office container — fail-closed, incomplete analysis |
| 5 | `ARC-BEN-001` | Benign ZIP |
| 6 | `ARC-RISK-001` | Path traversal member — hard-block |
| 7 | `ARC-RISK-002` | Absolute-path member |
| 8 | `ARC-RISK-004` | Dangerous executable member (`.scr`) |
| 9 | `ARC-RISK-009` | Nested-ZIP recursion limit — fail-closed, incomplete analysis |
| 10 | `FID-004` (optional masquerade case) | Inert PE content under a `.pdf` filename/claimed content-type — proves DocGuard does not trust the extension or claimed MIME type alone |

## Results

All values below are read directly from each scan's real, persisted
`GET /api/v1/scans/{id}` response.

| case_id | filename | file type | expected finding(s) | observed finding(s) | expected decision | observed decision | analysis status / complete | PASS |
|---|---|---|---|---|---|---|---|---|
| OFF-BEN-001 | memo.docx | OFFICE_WORD_OOXML | (none) | (none) | ALLOW | ALLOW | SUCCESS / true | PASS |
| OFF-RISK-002 | macro-autoexec.docm | OFFICE_WORD_OOXML | OFFICE_MACRO_ENABLED, OFFICE_PARTIAL_ANALYSIS, OFFICE_VBA_AUTOEXEC, OFFICE_VBA_MACRO | identical | QUARANTINE | QUARANTINE | FAILED / false (fail-closed by design) | PASS |
| OFF-RISK-006 | external-template.docx | OFFICE_WORD_OOXML | OFFICE_EXTERNAL_RELATIONSHIP, OFFICE_EXTERNAL_TEMPLATE | identical | QUARANTINE | QUARANTINE | SUCCESS / true | PASS |
| OFF-RISK-009 | encrypted.doc | OFFICE_WORD legacy OLE | OFFICE_ENCRYPTED, OFFICE_PARTIAL_ANALYSIS | identical | QUARANTINE | QUARANTINE | FAILED / false (fail-closed) | PASS |
| ARC-BEN-001 | documents.zip | ZIP | (none) | (none) | ALLOW | ALLOW | SUCCESS / true | PASS |
| ARC-RISK-001 | traversal.zip | ZIP | ARCHIVE_PATH_TRAVERSAL | identical | BLOCK | BLOCK | SUCCESS / true | PASS |
| ARC-RISK-002 | absolute.zip | ZIP | ARCHIVE_ABSOLUTE_PATH | identical | BLOCK | BLOCK | SUCCESS / true | PASS |
| ARC-RISK-004 | dangerous-member.zip | ZIP | ARCHIVE_DANGEROUS_MEMBER | identical | QUARANTINE | QUARANTINE | SUCCESS / true | PASS |
| ARC-RISK-009 | deep-nesting.zip | ZIP | ARCHIVE_NESTING_LIMIT, ARCHIVE_PARTIAL_ANALYSIS | identical | QUARANTINE | QUARANTINE | FAILED / false (fail-closed) | PASS |
| FID-004 | invoice.pdf (inert PE bytes) | claimed application/pdf, actual PE | FILE_CLIENT_MIME_MISMATCH, FILE_EXECUTABLE_MASQUERADE, FILE_TYPE_MISMATCH | identical | BLOCK | BLOCK | SUCCESS / **false** (see note) | PASS |

**10/10 supplementary cases passed** (decision compliant, zero missing findings, zero
unexpected findings), matching `evaluation/corpus_manifest.json` ground truth exactly.

**Note on FID-004 completeness:** the manifest's `expected_analysis_complete` field
for `FID-004` is `true`, but the real persisted result is `analysis_complete: false`
(`analysis_status: SUCCESS`). This is **not a discrepancy** — it is exactly what the
official, already-accepted Phase 11D benchmark run itself recorded for this same
case (`evaluation/results/phase11d/results.json`, `case_id: "FID-004"` →
`"analysis_complete": false`, `"completeness_class": "OTHER_FAIL_CLOSED"`,
`"decision_compliant": true`, `"findings_recall_pass": true`). `expected_analysis_complete`
is descriptive metadata in the manifest, not part of the pass/fail gate in
`evaluation/runner.py::_result_from_payload` — the worker completes structurally
(`SUCCESS`) but the hard-block short-circuit correctly prevents claiming complete
downstream analysis. No further investigation was needed; this matches known,
previously-validated behavior.

No other discrepancies were found. No case required stopping under rule 10 (observed
decision/findings never differed from `evaluation/corpus_manifest.json`).

## Real Bubblewrap confirmation

- `.env`/runtime configuration used: `DOCGUARD_ISOLATION_BACKEND=bubblewrap` (not
  `unsafe-development`).
- `bwrap --version` on the host: `bubblewrap 0.11.1` (the exact version
  `app/core/preflight.py` qualifies against).
- Server startup log and per-scan log lines
  (`.report-venv/instance/nonpdf-server.log`) show real `worker_status` values
  (`SUCCESS`/`FAILED`) returned from the isolated worker for every case, consistent
  with genuine sandboxed execution, not a stub/mock backend.

## End-to-end path confirmation

Real path exercised for all 10 cases, with no shortcuts:

`POST /api/v1/scans` (real authenticated upload, real CSRF) → real Bubblewrap worker
(`DOCGUARD_ISOLATION_BACKEND=bubblewrap`) → real analyzer → real policy evaluation
(policy `1.0.2`) → persisted `Scan` row in `var/docguard.db` → real
`GET /api/v1/scans/{id}` → real `/app/scans/{id}` operator UI page (Playwright,
authenticated session) → real `GET /api/v1/audit-events`.

No analyzer function, policy function, or fixture generator was called directly as a
substitute for this path.

## Audit trail verification

`GET /api/v1/audit-events?page_size=100` (real, authenticated) returned
`SCAN_UPLOAD_REQUESTED` events for all 10 uploaded scan IDs — **10/10 matched**,
attributed to the `nonpdf-validation-operator` actor.

## UI visual verification

Two scan-detail pages were opened live through Playwright at `/app/scans/{id}`:

- `OFF-RISK-002` (macro-autoexec.docm, QUARANTINE) —
  `docs/screenshots/report/15_office_analysis.png`
- `ARC-RISK-001` (traversal.zip, BLOCK) —
  `docs/screenshots/report/16_archive_analysis.png`

Verified correct:
- Filename renders correctly (`macro-autoexec.docm`, `traversal.zip`).
- Document type is correct and not mislabeled (`OFFICE_WORD_OOXML`, `ZIP` — never
  shown as a PDF type).
- Findings have human-readable titles ("Office VBA auto-execution entry point
  detected", "Archive path traversal observed", etc.) with technical codes and MITRE
  ATT&CK IDs visible under "Technical details" (e.g. `T1059.005`, `T1204.002`).
- Decision hierarchy is correct: QUARANTINE renders in the amber/orange treatment
  with "Check whether a sanitized derivative is possible below"; BLOCK renders in
  red with "Policy prohibits release. BLOCK cannot be overridden by an operator."
- Metadata (Analysis summary: detected type, analysis status, risk score, release
  eligible, policy version, uploaded timestamp) renders cleanly with no overflow.
- No sanitize/CDR action control is offered on either page — consistent with CDR
  being PDF-only (README: "CDR currently covers PDF only").
- BLOCK/QUARANTINE controls and copy are otherwise correct for both formats.

### PDF-specific UI wording bug found on non-PDF scans

**A genuine, reproducible UI wording bug was found** — not a security/policy bug,
purely a presentation-layer wording issue, and **left unfixed** per the feature
freeze:

Both the Office (`.docm`) and archive (`.zip`) scan-detail pages render a section
literally headed **"PDF sanitization"**, with body copy "This document is not
eligible for PDF sanitization[...]", even though the scanned document is not a PDF.
Source: `app/web/templates/scan_detail.html:69`
(`<h2 class="text-section-title">PDF sanitization</h2>`, rendered unconditionally
regardless of `detected_type`) and `:82` ("This document is not eligible for PDF
sanitization..."). The equivalent client-side string exists at
`app/web/static/app.js:406`.

This does not affect security behavior — no sanitize control is actually offered,
the ineligibility is correctly reported, and BLOCK/QUARANTINE enforcement is
unaffected — but it is misleading terminology on non-PDF scan-detail pages and
should be corrected in a future release (e.g. a format-neutral heading like
"Sanitization (CDR)" with the existing PDF-only-scope note already present
elsewhere). **No code was changed to fix this**, consistent with the active feature
freeze and the instruction not to modify `app/`, `worker/`, `docguard_contract/`, or
`evaluation/` during this validation pass.

## Known limitations

During the supplementary non-PDF UI review, the scan-detail template was observed
to retain PDF-specific sanitization wording for Office and archive files. This is
a presentation-layer limitation only: unsupported formats are not offered a CDR
action, and authorization/policy behavior is unaffected. Not fixed here, per the
active feature freeze — tracked as a candidate for a future cosmetic-only release.

## Pass/fail summary

| Metric | Result |
|---|---|
| Cases run | 10 |
| Decision-compliant | 10/10 |
| Findings recall (no missing expected findings) | 10/10 |
| No unexpected findings | 10/10 |
| Audit events matched | 10/10 |
| UI visual checks | 2/2 pages verified, all items correct except the wording bug noted above |
| **Overall** | **10/10 PASS** (supplementary, non-benchmark) |

These figures are **separate from and not additive to** Phase 11D's 59-case, 100%
decision-compliance / 100% finding-level-recall results.

## Release/corpus integrity confirmation

- `git diff v1.1.1..HEAD --stat -- app/ worker/ docguard_contract/ evaluation/` —
  empty (runtime product files unchanged since the tagged release).
- `git diff --stat -- evaluation/corpus_manifest.json evaluation/results/phase11d/`
  — empty (frozen corpus and Phase 11D artifacts untouched).
- No new application version or tag was created.
- New files added by this validation pass (all outside the protected paths):
  `scripts/nonpdf_validation/seed_and_validate.py`,
  `scripts/nonpdf_validation/capture.py`,
  `docs/screenshots/report/15_office_analysis.png`,
  `docs/screenshots/report/16_archive_analysis.png`,
  `docs/validation/NON_PDF_E2E_VALIDATION.md` (this file).
