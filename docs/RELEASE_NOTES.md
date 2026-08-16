# DocGuard Release Notes

This file is cumulative release history. Earlier sections are preserved exactly as
originally written — read each as a record of that release, not the current one.
Current release: **1.1.1** (this section).

---

# DocGuard 1.1.1 Release Notes

Patch release: session-lifecycle / authentication reliability hotfix. Policy stays
`1.0.2`, unchanged by this release.

## Release identity

- Application release version: **1.1.1** (`pyproject.toml`, FastAPI app metadata) —
  bumped from `1.1.0`.
- Policy version: **1.0.2**, fingerprint
  `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` — unchanged.
- Hotfix commit: `0b06cd6d2beb95eb35cf23a6ddc6712962544fae`.

## The defect

An authenticated request for a static asset (`/static/app.css`, `/static/app.js`, the
wordmark, the font) could clear an otherwise valid session cookie. The session
middleware intentionally skips authentication for `/static/*` requests — static assets
don't need it — but the invalid-session cleanup path that runs afterward read that
intentional skip (`principal is None`) as a failed authentication attempt, and deleted
the session cookie in response. A real browser normally serves cached static assets
from disk after the first page load, which is why this went unnoticed in ordinary use;
a fresh session (first login, a cleared cache, or an automated browser) hit it almost
immediately.

## The correction

Invalid-session cookie cleanup now occurs only when authentication was actually
attempted for that request. Static asset requests still never perform session
database/authentication work in either direction — this is a reliability fix to
cleanup semantics, not a change to what gets authenticated.

## What did not change

Static assets remain unauthenticated by design. CSRF, Origin enforcement, session
cookie flags, and session idle/absolute expiry semantics are all unchanged. Policy,
detection behavior, and CDR semantics are unchanged — see the Phase 11D revalidation
in `docs/EVALUATION.md`.

## Classification

This is framed as a **session-lifecycle / authentication-reliability hotfix**, not a
security vulnerability disclosure: no route ever became reachable without a valid
session, no capability was bypassed, and no document/policy data was exposed — the
defect only caused a valid, already-authenticated session to be discarded prematurely.

---

# DocGuard 1.1.0 Release Notes

Feature-freeze release. This document is factual and deliberately conservative — see
`docs/DEFENSE_GUIDE.md` §J/§K/§M for the exact required wording around decisions and
evaluation results.

## Release identity

- Application release version: **1.1.0** (`pyproject.toml`, FastAPI app metadata) —
  bumped from `1.0.0`.
- Policy version: **1.0.2** (bumped from `1.0.1`), fingerprint
  `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b`.
- YARA rule pack (`2026.08.1`) and PDF CDR sanitizer (`1.0.0`) are unchanged from the
  `1.0.0` release. These four identities are independent — see `docs/RELEASE_MANIFEST.md`.

## Why 1.1.0, not a patch release

Since `1.0.0`, DocGuard gained backward-compatible operator-facing functionality and a
policy addition — new capability, not merely bug fixes — which is a minor-version-level
change under the versioning convention this project follows.

## Highlights

- Bounded multi-file upload queue on the operator dashboard: up to 20 queued files,
  concurrency limit 2, each file submitted as an independent scan through the
  unmodified single-file upload endpoint.
- Printable per-scan evidence report (`GET /app/scans/{scan_id}/report`): a read-only,
  authenticated, print-optimized page an operator can save as PDF via the browser's
  native print dialog. It never re-analyzes the document or re-evaluates policy.
- Policy `1.0.2` explainability additions and a public architecture/trust-boundary page
  explaining the isolation model.

## Security analysis improvements

- Policy `1.0.2` adds two zero-contribution, no-hard-block, no-decision-floor
  explainability finding codes: `PDF_FALLBACK_INDICATOR` (bounded lexical evidence
  recovered from an incomplete PDF, including GoToE and external SubmitForm target
  recognition) and `PDF_EXTERNAL_SUBMISSION` (names an external form-submission
  destination on an already-scored action). Neither changes any score or decision on
  its own — see `docs/POLICY_ENGINE.md` §"Phase 11 comparability."
- Bounded JavaScript behavior indicators and GoToE (go-to-embedded) action recognition
  in the PDF analyzer, and bounded parser-failure lexical fallback evidence when
  structural analysis cannot complete — still explicitly distinguished from
  structurally-confirmed findings in the UI and in every report.

## Operator workflow

- Multi-file upload queue: bounded (20 files, 2 concurrent), each file an independent
  scan, one failure never blocks the rest of the batch, single CSRF token reused across
  the batch.
- Evidence report action on the scan detail page ("Evidence report"), producing a
  standalone printable document with document identity, decision, rationale, findings,
  fallback-evidence distinction, CDR lineage where applicable, and limitations —
  without gating essential evidence behind a collapsed disclosure.
- Redesigned operator UI and public marketing/landing page: the DocGuard wordmark
  replaces the prior icon+text lockup as the sole brand identity, a locally-sourced
  same-origin Manrope typeface replaces the prior font stack (no remote font/CDN), and
  the public landing page gained a trust-boundary architecture diagram (trusted
  application vs. disposable worker) and a rebalanced decision-explanation grid.

## Evidence/reporting

- The evidence report is explicitly **not digitally signed or cryptographically
  tamper-evident** in this release — it is an authenticated presentation of persisted
  evidence, not a certificate. See `docs/OPERATOR_WORKFLOW.md` §7.
- Report generation performs no analysis, re-evaluation, or worker invocation, and
  creates no new database records; "Report generated at" is clearly distinct
  presentation metadata from the document's own "Document analyzed at" timestamp.

## Validation

- **Phase 11C current-release revalidation**: the identical frozen 59-case Phase 11
  corpus (`11A.1`) re-executed once through the real Bubblewrap-isolated production
  path against the current release (application code evaluated at commit `f18961c`,
  policy `1.0.2`). Within that frozen 59-case controlled synthetic corpus and
  documented detection model, DocGuard policy `1.0.2` reproduced all pre-registered
  decision expectations and covered all pre-registered risky characteristics —
  identical decision compliance (59/59), risky-case recall (41/41), finding recall
  (72/72), benign-ALLOW (18/18), benign-escalation (0/18), fail-secure (9/9), and CDR
  outcomes to the original Phase 11B (policy `1.0.1`) evaluation.
- This is a controlled, self-constructed synthetic corpus, not an independent
  adversarial benchmark, and it does not establish that `ALLOW` means a document is
  benign. Full methodology, comparison tables, and result-artifact hashes:
  `docs/EVALUATION.md` Part B; retained artifacts: `evaluation/results/phase11c/`.
  The original Phase 11B evidence (`evaluation/results/phase11b/`) is untouched and
  remains the historical record of the `1.0.0` release.

## Security invariants preserved

No change to the trust boundary, authentication, session/CSRF handling, CSP, worker
isolation, Bubblewrap sandbox profile, CDR semantics (source decision immutability,
BLOCK CDR-ineligibility, mandatory re-analysis of derived artifacts), or audit
semantics. The evidence report introduces no raw-document exposure, no source-download
capability, and no BLOCK override/release affordance — verified in
`tests/integration/test_scan_evidence_report.py`.

## Known limitations

Everything documented for `1.0.0` below still applies. In addition:

- The evidence report is not digitally signed or tamper-evident (see "Evidence/reporting"
  above); a hash-chained audit log remains unimplemented and separately optional.
- No seccomp-bpf syscall-filtering layer under Bubblewrap; isolation relies on
  namespaces, dropped capabilities, and resource limits.
- Analysis remains synchronous within the request lifecycle (no background scheduler);
  the multi-file queue is a client-side fan-out over that same synchronous endpoint.
- Phase 11C validates the *current release* against the *same* synthetic, self-
  constructed corpus as Phase 11B — it is not a larger or independent corpus, and any
  external malicious-PDF validation work remains deliberately separate from these
  percentages.

## Upgrade / operational notes

- No database migration is required beyond the existing `alembic upgrade head` (no new
  tables or columns were introduced by this release).
- No configuration, environment variable, or CSP change is required.
- Operators printing an evidence report in Firefox should disable "Print headers and
  footers" in the print dialog for a clean exported PDF — a browser-level setting
  outside DocGuard's control (see `docs/OPERATOR_WORKFLOW.md` §7).

---

# DocGuard 1.0.0 Release Notes

Final academic release. This document is factual and deliberately conservative — see
`docs/DEFENSE_GUIDE.md` §J/§K/§M for the exact required wording around decisions and
evaluation results.

## Release identity

- Application release version: **1.0.0** (`pyproject.toml`, FastAPI app metadata).
- This is a separate identity from the policy version (`1.0.1`), the YARA rule pack
  version (`2026.08.1`), and the PDF CDR sanitizer version (`1.0.0`). Bumping the
  application release version never implies, and did not trigger, any change to those
  three detection/integrity identities — see `docs/RELEASE_MANIFEST.md`.

## Summary

DocGuard is an isolated and explainable security gateway for untrusted business
documents. It streams an uploaded document to private storage without interpreting it
in the trusted application process, identifies and structurally analyzes it inside a
disposable, network-isolated Bubblewrap sandbox, and applies a deterministic, versioned
policy to reach one of four decisions: ALLOW, REVIEW, QUARANTINE, or BLOCK. Eligible
suspicious PDFs can be reconstructed via raster Content Disarm and Reconstruction
(CDR), whose output is independently re-analyzed before any artifact is approved for
download.

## Major implemented capabilities

- **Ingestion and storage**: streamed, size-bounded upload with incremental SHA-256,
  atomic opaque quarantine storage; original filenames are metadata only.
- **Worker-side content identification and structural analysis**: libmagic-driven
  routing (never filename/client-MIME-driven) to a PDF analyzer (pikepdf/qpdf), an
  Office analyzer (OOXML + classic OLE, static VBA via oletools), and a generic ZIP
  archive analyzer, each with bounded traversal, resource limits, and explicit
  partial/malformed handling.
- **YARA**: a fixed, fingerprinted six-rule local pack (one EICAR test signature, five
  command/execution heuristics) scanning only the top-level submitted file inside the
  worker.
- **Trusted policy engine**: version `1.0.1`, exact coverage of all 43 production
  finding codes, deterministic 0-100 scoring, five transparent compound rules,
  semantic hard blocks, and a normalized fingerprint validated at readiness.
- **PDF CDR**: explicit raster reconstruction operation, mandatory re-ingestion of the
  derived output as an independent scan, and immutable source lineage — CDR can never
  change a source decision or release a BLOCK source.
- **Authentication and authorization**: local Argon2id operator accounts, opaque
  hashed sessions, session-bound CSRF, centralized capabilities (no raw-download,
  policy-edit, or BLOCK-override capability exists in V1).
- **Audit**: append-only, actor-attributed events for login, upload, analysis, CDR, and
  artifact download, with bounded metadata and no document content.
- **Production hardening**: canonical Host/Origin validation, exact-proxy-IP trust,
  structured request-ID logging, operator abuse rate limits, filesystem/runtime
  qualification, and a fail-closed production preflight gate.
- **Operational tooling**: database/storage integrity checks and bounded, dry-run-by-
  default crash-state reconciliation.
- **Controlled evaluation framework**: a 59-case, pre-registered, synthetic corpus
  executed once through the real production Bubblewrap path, with retained
  machine-readable results (`evaluation/results/phase11b/`) and full methodology
  (`docs/EVALUATION.md`).

## Security architecture

Raw untrusted document bytes are never parsed by the trusted FastAPI/database/policy
process. All hostile-format parsing, YARA scanning, and PDF rendering run inside a
disposable Bubblewrap sandbox: new user/PID/network/IPC/UTS/mount namespaces, dropped
capabilities, no network route, a cleared environment, and cgroup/`prlimit` resource
limits. See `docs/ARCHITECTURE.md` and `docs/THREAT_MODEL.md`.

## Supported formats

PDF; Office OOXML (Word/Excel/PowerPoint) and classic OLE variants; generic ZIP
archives. Nested/nested-format nested content (archive members, OOXML parts, PDF
attachments) is not recursively parsed or YARA-scanned — see `docs/ARCHIVE_ANALYSIS.md`,
`docs/OFFICE_ANALYSIS.md`, `docs/PDF_ANALYSIS.md`.

## Policy decisions

Four outcomes: `ALLOW`, `REVIEW`, `QUARANTINE`, `BLOCK`. Only `ALLOW` is release
eligible for an original upload. **ALLOW means DocGuard did not observe risky
characteristics covered by the configured detection model — it does not mean the
document is safe, clean, or malware-free.** See `docs/POLICY_ENGINE.md`.

## CDR

PDF-only raster reconstruction, gated by explicit eligibility rules (excludes ALLOW,
BLOCK, incomplete, encrypted, malformed, non-PDF, over-limit sources). The derived
output is copied to quarantine as an independent scan, fully re-analyzed, and only
becomes an approved, downloadable artifact if that re-analysis also reaches ALLOW. The
original source's decision and quarantine status never change. See `docs/PDF_CDR.md`.

## Authentication and audit

Local operator accounts only (no MFA/SSO in this release); Argon2id password hashing;
opaque, hash-only server sessions; append-only audit events. See
`docs/AUTHENTICATION.md` and `docs/AUDIT_LOG.md`.

## Production hardening

Qualified for one browser-facing HTTPS origin (Nginx) → one loopback Uvicorn worker →
local SQLite/private storage → disposable Bubblewrap workers. See
`docs/PRODUCTION_HARDENING.md` and `docs/OPERATIONS.md`.

## Controlled evaluation results

Within the 59-case controlled, synthetic, pre-registered corpus, executed once through
the real Bubblewrap production path:

- 41/41 risky-case detection recall.
- 72/72 expected findings detected.
- 0/18 benign cases escalated.
- 9/9 fail-secure cases remained non-release-eligible.
- CDR recovery: 2/2 eligible cases; the 1 BLOCK case was correctly CDR-ineligible.
- Median latency 317 ms, p95 386 ms (one development host).

These results describe behavior on this specific corpus and detection model, not a
general malware-detection rate. Full methodology, pre-registration hashes, and
reproduction instructions: `docs/EVALUATION.md`.

## Deployment target

Single-node, small-office-scale deployment: one Nginx + one Uvicorn worker + local
SQLite + disposable Bubblewrap workers. Not qualified for multi-node/multi-worker
deployment. See `docs/RELEASE_MANIFEST.md` for the exact qualification results
recorded for this release.

## Known limitations

- Static structural analysis only; no dynamic/behavioral execution.
- ALLOW is not proof of benignity; no zero-day guarantee.
- Evaluation corpus is synthetic, controlled, and sized at 59 cases, built around
  DocGuard's own documented detection coverage.
- Benchmarked on a single development host; latency is host-specific.
- No MFA/SSO; local operator authentication only.
- Process-local rate limiting; single-worker/single-node qualified topology.
- SQLite is the qualified single-node target, not a multi-node database.
- TLS/reverse-proxy configuration is an administrator responsibility.
- The systemd reference unit was syntactically verified but not installed as a running
  production service during this project.
- No external antivirus/cloud reputation integration (by design, for confidentiality).
- CDR currently covers PDF only.
- File-format coverage is intentionally narrow (PDF, Office, ZIP).

See `docs/DEFENSE_GUIDE.md` §N and `docs/EVALUATION.md` §25/26 for full detail.
