# DocGuard Agent Rules

## Phase 10 frozen production envelope

- V1 production is trusted Nginx TLS, loopback Uvicorn, and exactly one Uvicorn worker. Never enable
  generic proxy-header trust or use forwarded chains for security decisions.
- Host and mutation Origin derive from the canonical HTTPS origin. Only an explicitly trusted direct
  peer may provide one valid `X-Real-IP`.
- Production filesystem, dependency, migration, auth, registry, and Bubblewrap qualification fail
  closed. Startup never auto-migrates, creates users, reconciles, or deletes data.
- Reconciliation is dry-run by default. Apply only forces stale analysis to non-release and may
  delete strictly qualified temp objects; never delete orphan business documents or create ALLOW.
- Process-local rate limits are not distributed. Never log query strings, bodies, raw filenames,
  credentials/tokens, storage keys, document/parser content, or environment values.

These rules are non-negotiable for every change in this repository.

## Frozen architecture

- Treat every submitted document and every filename as hostile.
- Never parse, render, inspect, or otherwise interpret document bytes in the trusted FastAPI, database, storage-metadata, policy, or orchestration process.
- Put all PDF, Office, archive, YARA, rendering, and future CDR work behind the versioned worker contract and an `IsolationBackend`.
- Keep pikepdf/qpdf and every future hostile-document parser in the dedicated worker dependency artifact; the trusted dependency set must remain parser-free.
- Route PDF parsing only from worker-side libmagic family identification, never from filename or client MIME claims.
- Route Office parsing only from worker-side libmagic ZIP/OOXML/OLE families, then validate OOXML package structure before assigning an Office application family. Generic ZIPs and renamed executables are never Office-routed by filename.
- Never bulk-extract OOXML, resolve XML entities, fetch relationships, return VBA source, instantiate ActiveX, or recursively parse embedded Office objects.
- Route generic ZIP inspection only after worker-side content identification and the OOXML gate. Never call archive extraction APIs or turn a member name into a filesystem path.
- Bound archive inspection by actual produced bytes, shared nested budgets, entry/member counts, metadata caps, and external timeout. Encrypted, malformed, unsupported, or limited coverage stays quarantined.
- Run YARA only in the disposable worker against the top-level submitted file. Compile only the fixed reviewed local rule pack; never accept user rules, download feeds, or scan extracted child content implicitly.
- Treat YARA rule IDs, confidence, severity, descriptions, and ATT&CK mappings as trusted manifest data. Reject unknown/spoofed rule metadata and never retain matched bytes.
- Keep final scoring and decisions exclusively in the trusted immutable policy registry. Worker score fields must remain zero and can never influence policy.
- Require exact policy coverage for every finding code. Missing, unknown, inconsistent, or fingerprint-mismatched policy definitions make readiness false and evaluation fail closed.
- Persist policy identity and evaluation transactionally before any scan becomes release eligible. Historical reads return persisted policy results and never silently re-evaluate.
- Treat every renderer and CDR output as untrusted. CDR must use the explicit sandbox operation, and exact output bytes must become a derived quarantine scan that passes identification, PDF analysis, YARA, and trusted policy before promotion.
- Never permit CDR to override `BLOCK`, rewrite a source decision, or write directly to final sanitized storage. Artifact approval and its audit event commit together.
- Keep security audit events append-only through application services and never include document content in audit details.
- Keep authentication local and database-backed unless a later phase explicitly changes it. Never add
  default credentials, public registration, a debug bypass, universal password, query/header login,
  or implicit localhost trust.
- Store only Argon2id password hashes and SHA-256 session/CSRF digests. Never persist or log raw
  passwords, session bearer tokens, or CSRF tokens.
- Centralize authorization through `AuthenticatedPrincipal` and the V1 capability registry. Do not
  invent raw quarantine, source download, policy/rule edit, decision override, or BLOCK override
  capabilities.
- Require session-bound CSRF on every cookie-authenticated mutation. Production must retain Secure
  `__Host-` cookies, HTTPS origin validation, and no trust of forwarded proxy headers.
- Autoescape all hostile metadata in the UI, keep assets local under `app/web/static`, retain the
  restrictive CSP/security headers, and never mount any runtime/document storage as static.
- Approved artifact download must revalidate lineage, policy, path containment, immutable file
  metadata, size, and digest from a trusted artifact ID. Required audit persistence occurs before
  bytes; raw/quarantine bytes are never downloadable.
- Never silently fall back to an unisolated worker. The unsafe development backend is opt-in, emits a prominent warning, and is forbidden in production.
- Fail closed: crash, timeout, non-zero exit, malformed output, schema mismatch, or unsupported input leaves the document quarantined.
- Never execute uploaded files, fetch document URLs, or send samples to third parties.
- Use server-generated opaque storage keys. Original filenames are metadata only. Raw and quarantined files never belong under a public/static path.
- Keep findings observational and explainable. Never claim a document is safe, clean, benign, or malware-free because no modeled finding was observed.
- Reject feature creep beyond the phase explicitly requested. Do not add parsers, source-release
  workflows, identity providers, account-management UI, integrations, or infrastructure
  speculatively.

## Security review responsibility

For changes involving trust boundaries, parsing, filesystems, subprocesses, archives, uploads, downloads, quarantine, or configuration:

1. Trace all untrusted inputs to their sinks.
2. Check for fail-open paths, traversal, absolute paths, symlink following, command injection, SSRF, parser exposure, secret leakage, unsafe logging, and privilege mistakes.
3. Confirm resource and timeout failures remain externally terminable and quarantined.
4. Record implemented and planned mitigations accurately.

## Verification gate responsibility

Before declaring a phase complete, run the exact applicable commands for:

1. formatting check;
2. linting;
3. static typing;
4. the full unit and integration test suite;
5. migration application;
6. application import/startup sanity.

Report exact commands and results. Never claim a check passed if it was not executed. Do not weaken tests to obtain a green run.

## Engineering rules

- Use typed, small modules and explicit error types.
- Keep security-sensitive constants and validation centralized.
- Use `pathlib`, timezone-aware UTC timestamps, and cryptographically strong random identifiers.
- Preserve the trusted/untrusted separation in tests: generated benign fixtures only; never download malware.
