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
