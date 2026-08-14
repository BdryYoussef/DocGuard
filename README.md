# DocGuard

Phase 10 qualifies a narrow single-node production topology: HTTPS Nginx, loopback-only one-worker
Uvicorn, private SQLite/storage, and disposable Bubblewrap workers. It adds exact Host/origin and
one-hop proxy trust, operator abuse controls, request IDs, filesystem/runtime/database preflight,
SQLite WAL durability, integrity tooling, and conservative crash reconciliation. See
`docs/PRODUCTION_HARDENING.md` and `docs/OPERATIONS.md`; no later analyzer or product features are
included.

DocGuard is an isolated and explainable security gateway for untrusted business documents. It
stores an untrusted document without interpreting it in the trusted API process, identifies content
inside a disposable Linux sandbox, records deterministic findings, and applies a versioned trusted
policy to decide whether it may be eligible for a future release workflow.

DocGuard is not an antivirus replacement, dynamic malware sandbox, AI malware classifier, SIEM,
full DLP platform, or proof that a file is benign. The accurate absence-of-findings statement is:

> DocGuard did not observe risky characteristics covered by the configured detection model.

## Phase 9 status

Implemented:

- production Bubblewrap backend with per-job namespaces, user-systemd cgroups, `prlimit`, scrubbed
  environment, bounded output capture, external timeout, and a cached boundary self-test;
- raw-body streaming ingestion at `POST /api/v1/scans` with actual-byte limits, incremental SHA-256,
  atomic opaque quarantine storage, and failure cleanup;
- persisted `STORED` → `ANALYZING` → `COMPLETED`/`QUARANTINED` lifecycle, initially non-release and
  made release eligible only by a complete trusted `ALLOW` evaluation;
- worker-side libmagic identification through `/usr/bin/file` for PDF, ZIP/OOXML candidates, classic
  OLE, Windows executables, text, and unknown data;
- stable findings for dangerous double extensions, bidirectional controls, type mismatches,
  executable masquerading, and meaningful client-MIME discrepancies.
- worker-only pikepdf 10.11.0/qpdf 12.3.2 structural PDF inspection for actions, JavaScript
  capability, attachments, forms, URI actions, encryption, and malformed PDFs;
- bounded PDF page, object, action, recursion, URI, attachment-name, and metadata traversal with
  explicit partial-analysis findings when a budget is exhausted;
- a shared stable finding registry whose presentation metadata is revalidated by the trusted side.
- worker-only Office analysis for structurally validated Word, Excel, and PowerPoint OOXML packages
  plus conservative classic OLE Word/Excel/PowerPoint identification;
- bounded static VBA detection for macro presence, auto-execution entry points, and a curated set
  of execution-capable indicators, without retaining macro source;
- passive external-relationship and remote-template inspection, embedded-object and ActiveX
  presence detection, explicit encryption handling, hardened XML, and actual decompressed-byte
  budgets for selected OOXML members.
- worker-only generic ZIP inspection with no extraction, portable traversal/rooted-path checks,
  symlink and duplicate detection, dangerous member-name findings, encrypted-member handling, and
  bounded content-signature recursion for nested ZIPs;
- per-member and aggregate actual decompressed-byte enforcement, bounded nested materialization,
  entry/member/container/finding budgets, and controlled partial or malformed results.
- worker-only yara-python 4.5.4/YARA 4.5.4 top-level scanning with a six-rule curated local pack,
  an internal timeout, bounded match metadata, and no raw matched bytes;
- strict trusted rule-ID/presentation/ATT&CK validation, a fingerprinted rule manifest, read-only
  Bubblewrap rule access, and production EICAR/benign compilation self-tests.
- trusted policy version `1.0.1` with exact coverage for all 43 production finding codes, deterministic
  fingerprinting, deduplicated 0–100 scoring, five transparent compound rules, and semantic hard
  blocks;
- transactionally persisted decision, release eligibility, score, band, policy identity, bounded
  reasons, and a historical `GET /api/v1/scans/{scan_id}` that never silently re-evaluates policy.
- worker-only PyMuPDF/MuPDF 1.28.2 raster CDR through an explicit Bubblewrap operation and one
  descriptor-bound output object;
- trusted eligibility that excludes ALLOW, BLOCK, incomplete, encrypted, malformed, non-PDF,
  over-limit, missing, mutable, and hash-mismatched sources;
- mandatory re-ingestion as a distinct `CDR_DERIVED` scan through libmagic, PDF analysis, YARA,
  and current trusted policy before artifact promotion;
- immutable source/derived/artifact lineage, sanitizer version/fingerprint, three-way SHA-256
  integrity, artifact idempotency, and append-only application audit events.
- database-backed local OPERATOR authentication with pinned Argon2id password hashing, opaque
  hash-only server sessions, absolute/inactivity expiry, rotation, deactivation, and bounded cleanup;
- centralized capabilities for scan upload/read, PDF CDR request, approved-artifact read, and audit
  read, with no V1 raw-download, policy/rule-edit, or BLOCK-override capability;
- session-bound CSRF, exact configured-origin checks, generic login errors, dummy-hash verification,
  bounded in-process login throttling, secure production cookies, and operator-attributed audit;
- authenticated paginated scan/artifact/audit APIs plus a server-rendered operator UI with autoescape,
  local assets, restrictive CSP, security headers, no-store caching, and no remote dependencies;
- download-time lineage, policy, filesystem-metadata, size, and SHA-256 revalidation for approved CDR
  artifacts, with required audit persistence before bytes and no raw quarantine endpoint;
- production readiness for migration `0005`, authentication configuration/runtime, session store,
  and an active bootstrapped operator, with detailed check names hidden publicly in production.

Not implemented: Office/archive CDR, OCR, structural PDF rewriting, archive extraction, RAR/7z/TAR,
recursive child analysis/YARA, community rule feeds, entropy, MFA/SSO, account-management UI,
policy editing/re-evaluation, raw quarantine download, source release, or non-PDF sanitization.

## Trust boundary

The trusted `app/` package may stream bytes to storage and hash them, but never identifies or parses
document content. The dependency-free `worker/` package performs libmagic identification. The
worker is launched once per operation and exchanges strict schema-version `2.1` JSON with the trusted
orchestrator.

The sandbox does not mount the repository, `app/`, `.git`, `.env`, `.python-deps`, the database,
incoming/quarantine directories, or a home directory. It receives only read-only runtime paths,
read-only worker/contract code, a dedicated read-only `.worker-deps` artifact, and one read-only
input at `/input/document`; `/work` and `/tmp` are ephemeral tmpfs mounts.

Only content identified as PDF by libmagic is routed to pikepdf. Eligible CDR uses a separate
PyMuPDF raster operation, but its output returns through libmagic, pikepdf, YARA, and trusted policy
before approval. ZIP/OOXML and OLE content may enter
the Office gate, but a ZIP becomes Word, Excel, or PowerPoint only after internal OPC structures are
validated. A ZIP rejected by the Office gate is routed to the generic archive analyzer; an
executable named `.zip` never reaches it. A filename or client MIME claim can never cause parser
routing. Encrypted, malformed, parser-limited, timed-out, or otherwise incomplete analysis remains
quarantined. See [PDF analysis](docs/PDF_ANALYSIS.md),
[Office analysis](docs/OFFICE_ANALYSIS.md), and [Archive analysis](docs/ARCHIVE_ANALYSIS.md) for
structural coverage. The fixed local YARA pack scans only the top-level submitted file after those
analyzers and never overrides their status. See [YARA analysis](docs/YARA_ANALYSIS.md).

See [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md), and
[Security policy](SECURITY.md). Exact decision and score semantics are in the
[Policy engine](docs/POLICY_ENGINE.md).
See [PDF CDR](docs/PDF_CDR.md) and [Audit log](docs/AUDIT_LOG.md) for reconstruction and event
semantics.
Authentication and browser boundaries are described in [Authentication](docs/AUTHENTICATION.md),
[Operator workflow](docs/OPERATOR_WORKFLOW.md), and [Web security](docs/WEB_SECURITY.md).

## Host prerequisites

- Python 3.12 or newer for the trusted application
- Bubblewrap 0.11.1 or a compatible reviewed version
- util-linux `prlimit`
- cgroup v2 with a usable user systemd manager and `systemd-run --user --scope`
- libmagic and `/usr/bin/file` available read-only to the worker
- the pinned `requirements-worker.lock` artifact installed at the configured worker dependency root

The Office stack is pinned to oletools 0.60.2, olefile 0.47, defusedxml 0.7.1, and pyparsing 3.2.5.
It is qualified by import and behavior tests on Python 3.14.4; oletools package metadata itself only
advertises compatibility through Python 3.12.

Yara-python 4.5.4 embeds YARA 4.5.4. PyPI supplies no CPython 3.14 Linux wheel for this release on
the inspected host, so the worker artifact is built from the pinned source distribution. The local
source build, import, rule compilation, behavior fixtures, Bubblewrap self-test, and full suite
qualify it on Python 3.14.4; deployments must provide a compiler toolchain when no compatible wheel
exists.

Readiness fails closed if the sandbox self-test cannot establish these properties. Binary presence
alone is insufficient.

## Local development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -r requirements-worker.lock --target .worker-deps
```

On this inspected Ubuntu host, only Python 3.14.4 exists and `ensurepip` is unavailable. Install the
distribution-provided `python3.14-venv` package manually before using a conventional environment.
The repository-local `.python-deps` directory is only a Codex-run workaround and is not the intended
production setup.

## First production startup

There are no default credentials and no web registration route. Configure the production database,
private storage root, HTTPS application origin, worker artifact, and qualified Bubblewrap backend,
then run:

```bash
alembic upgrade head
python -m scripts.create_operator --username operator-name
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Visit `/login`. Production readiness remains false until an active OPERATOR exists. The authenticated
UI submits the raw upload body with a session-bound CSRF token; the UTF-8 filename and HTTP
Content-Type remain bounded claims only. API responses contain no storage paths or raw download link.

For generated fixture development only:

```bash
DOCGUARD_ENV=development \
DOCGUARD_ISOLATION_BACKEND=unsafe-development \
DOCGUARD_ALLOW_UNSAFE_DEVELOPMENT_BACKEND=true \
.venv/bin/uvicorn app.main:create_app --factory
```

## Verification commands

```bash
ruff format --check .
ruff check .
PYTHONPATH=.worker-deps mypy app worker docguard_contract
PYTHONPATH=.worker-deps pytest
alembic upgrade head
```

The Bubblewrap integration tests require permission to create user namespaces and transient user
systemd scopes. They skip with an explicit reason when the host cannot supply that boundary; a
production qualification run must execute them without skips.

## Security language

- ALLOW is not proof that a document is benign.
- DocGuard's risk score is a deterministic policy score, not a probability that a file is malicious.
- CDR reduces active document functionality by reconstructing visual content. It does not prove the
  output is benign.
- The CDR output is re-analyzed before approval.
- BLOCK represents an explicit security-policy violation and cannot be overridden by an operator in
  V1.
