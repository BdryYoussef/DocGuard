<p align="center">
  <img src="docs/assets/docguard-wordmark.png" alt="DocGuard" width="360">
</p># DocGuard

**An isolated and explainable security gateway for untrusted business documents.**

Release `1.1.2`. See `docs/RELEASE_NOTES.md` for the full release summary and
`docs/DEFENSE_GUIDE.md` for a jury-oriented explanation of the project.

## Problem

Small offices that handle sensitive paperwork — accounting, fiduciary, or notarial-style
work — routinely receive PDFs, Office documents, and ZIP attachments by email,
messaging, USB, or client upload, with no dedicated security staff. Opening an
attacker-controlled attachment directly is a real, recurring risk, and the documents
themselves (identity papers, tax records, bank statements) are too confidential to hand
to an external cloud scanner.

## What DocGuard does

DocGuard stores an uploaded document without interpreting it in the trusted
application, identifies and structurally analyzes it inside a disposable, isolated
sandbox, and applies a deterministic, versioned policy to decide **ALLOW, REVIEW,
QUARANTINE, or BLOCK**. Eligible suspicious PDFs can be reconstructed through raster
Content Disarm and Reconstruction (CDR); the reconstructed output is independently
re-analyzed and only becomes downloadable if that re-analysis also reaches ALLOW.

DocGuard is **not** an antivirus replacement, a dynamic malware sandbox, an AI malware
classifier, a SIEM, a full DLP platform, or proof that a file is benign. The accurate
absence-of-findings statement is:

> **DocGuard did not observe risky characteristics covered by the configured detection
> model.**

## Trust boundary

The trusted `app/` package (FastAPI, database, policy engine, audit, operator UI) may
stream document bytes to storage and hash them, but **never** identifies or parses
document content. All hostile-format work — libmagic identification, PDF/Office/ZIP
parsing, YARA scanning, and PDF raster CDR — runs once per document inside a brand-new,
disposable Bubblewrap sandbox: new user/PID/network/IPC/UTS/mount namespaces, dropped
capabilities, no network route, a cleared environment, and cgroup/`prlimit` resource
limits. The worker exchanges a strict, versioned JSON contract with the trusted side
and can never set a score or a final decision — only a separate, immutable, fingerprinted
policy registry in the trusted process does that. See `docs/ARCHITECTURE.md` and
`docs/THREAT_MODEL.md`.

## Supported document families

PDF; Office OOXML (Word/Excel/PowerPoint) and classic OLE variants; generic ZIP
archives. Routing is always based on worker-side libmagic content identification, never
on filename or client-claimed MIME type. See `docs/PDF_ANALYSIS.md`,
`docs/OFFICE_ANALYSIS.md`, `docs/ARCHIVE_ANALYSIS.md`, and `docs/YARA_ANALYSIS.md`.

## High-level workflow

```
upload (authenticated, CSRF-protected)
  -> private quarantine storage (opaque key; original filename is metadata only)
  -> disposable Bubblewrap worker
       -> libmagic identification -> PDF / Office / archive analyzer -> YARA
  -> strictly validated worker JSON contract
  -> trusted, versioned, fingerprinted policy engine
  -> ALLOW / REVIEW / QUARANTINE / BLOCK (persisted transactionally)
       -> (QUARANTINE/REVIEW PDF only) optional CDR: rasterize, re-analyze as a
          new scan, approve only if that new scan also reaches ALLOW
```

## Decision semantics

| Decision | Meaning |
| --- | --- |
| `ALLOW` | No finding required containment under the active policy; the scan is release eligible. |
| `REVIEW` | Low/moderate accumulated risk score; not release eligible. |
| `QUARANTINE` | A finding or accumulated score requires containment; not release eligible. |
| `BLOCK` | A semantic hard-block finding fired (e.g. executable masquerade, archive traversal, a trusted YARA signature match); not release eligible and **cannot be overridden by an operator** in this release. |

The risk score is a **deterministic, policy-derived, explainable** number — not a
malware probability, not a confidence score, not an ML prediction. See
`docs/POLICY_ENGINE.md`.

## Security model

- Local Argon2id operator authentication; opaque, hash-only server sessions;
  session-bound CSRF; exact configured-Origin checks; no MFA/SSO, registration, or
  default credentials.
- Append-only, actor-attributed audit events with bounded metadata (never document
  content, matched YARA bytes, or VBA source).
- Fail-closed throughout: encrypted, malformed, resource-limited, or timed-out analysis
  stays non-release-eligible rather than defaulting to ALLOW.
- Production topology: one TLS-terminating Nginx origin → one loopback Uvicorn worker
  → local SQLite/private storage → disposable Bubblewrap workers. Canonical Host/Origin
  validation never trusts forwarded headers except one exact configured proxy IP.

See `SECURITY.md`, `docs/AUTHENTICATION.md`, `docs/WEB_SECURITY.md`,
`docs/PRODUCTION_HARDENING.md`, and `docs/OPERATIONS.md`.

## CDR (Content Disarm and Reconstruction)

For eligible `QUARANTINE`/`REVIEW` PDFs, an operator may request raster CDR: pages are
rendered to flat RGB images inside a fresh sandboxed worker and reassembled into a new
PDF with no active content. That output is copied to quarantine as an **independent
scan** and run through the full analysis pipeline again — it is never trusted merely
for having come from the CDR renderer. The **source scan's decision never changes**,
a **BLOCK source is never CDR-eligible**, and only a fully re-analyzed, `ALLOW`,
release-eligible derived scan produces a downloadable artifact. See `docs/PDF_CDR.md`.

## Evaluation summary

A 59-case controlled, synthetic, **pre-registered** corpus was executed once through
the real Bubblewrap production path (Phase 11B):

- 41/41 risky-case detection recall.
- 72/72 expected findings detected.
- 0/18 benign cases escalated.
- 9/9 fail-secure cases remained non-release-eligible.
- CDR recovery: 2/2 eligible cases; the 1 BLOCK case was correctly CDR-ineligible.
- Median latency 317 ms, p95 386 ms (one development host).

These results describe behavior on this specific controlled corpus and documented
detection model — **not** a general malware-detection rate. Full methodology,
pre-registration hashes, and every retained artifact: `docs/EVALUATION.md` and
`evaluation/results/phase11b/`.

The current release (policy `1.0.2`) was separately revalidated against the identical
frozen corpus (Phase 11C) with identical results — decision compliance, recall,
benign-escalation, fail-secure, and CDR outcomes all reproduced exactly. See
`docs/EVALUATION.md` Part B and `evaluation/results/phase11c/`.

## Quick development setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install -r requirements-worker.lock --target .worker-deps
```

For generated-fixture development only (never for production or for evaluating real
detection behavior):

```bash
DOCGUARD_ENV=development \
DOCGUARD_ISOLATION_BACKEND=unsafe-development \
DOCGUARD_ALLOW_UNSAFE_DEVELOPMENT_BACKEND=true \
DOCGUARD_APPLICATION_ORIGIN=http://127.0.0.1:8000 \
.venv/bin/uvicorn app.main:create_app --factory
```

`DOCGUARD_APPLICATION_ORIGIN` must exactly match the scheme, host, and port the
browser actually uses. `application_origin` otherwise defaults to
`https://127.0.0.1:8000` — a mismatched scheme against this plain-HTTP dev server
causes the existing (correct, and not to be weakened) same-origin check to reject
every authenticated fetch-based request — CSRF-protected form submissions and page
navigations are unaffected, so login still succeeds and the dashboard still loads,
which makes the failure easy to mistake for a session/authentication problem.

## Test commands

```bash
ruff format --check .
ruff check .
PYTHONPATH=.worker-deps mypy --strict app worker docguard_contract evaluation scripts
PYTHONPATH=.worker-deps pytest
alembic upgrade head
```

The Bubblewrap integration tests require permission to create user namespaces and
transient user systemd scopes. They skip with an explicit reason when the host cannot
supply that boundary; a production qualification run must execute them without skips.

## Evaluation reproduction

```bash
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --list-cases
python -m scripts.run_evaluation --dry-run
python -m scripts.run_evaluation --execute --case-id PDF-BEN-001 --case-id PDF-RISK-003 \
    --output-dir /tmp/docguard-eval-out
```

See `docs/EVALUATION.md` for the full official-benchmark reproduction procedure and
pre-registration hashes to verify against.

## Production deployment summary

There are no default credentials and no web registration route. Configure the
production database, private storage root, HTTPS application origin, worker artifact,
and qualified Bubblewrap backend, then:

```bash
alembic upgrade head
python -m scripts.create_operator --username operator-name
python -m scripts.production_preflight
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Production readiness remains false until `production_preflight` passes and an active
operator exists. See `docs/OPERATIONS.md`, `docs/PRODUCTION_HARDENING.md`, and
`docs/RELEASE_CHECKLIST.md` for the complete deployment procedure and qualification
gate.

### Host prerequisites

- Python 3.12 or newer for the trusted application.
- Bubblewrap 0.11.1 or a compatible reviewed version.
- util-linux `prlimit`.
- cgroup v2 with a usable user systemd manager and `systemd-run --user --scope`.
- libmagic and `/usr/bin/file` available read-only to the worker.
- The pinned `requirements-worker.lock` artifact installed at the configured worker
  dependency root.

Readiness fails closed if the sandbox self-test cannot establish these properties;
binary presence alone is insufficient.

## Architecture and documentation

- [Architecture](docs/ARCHITECTURE.md) — trust boundary and end-to-end data flow.
- [Threat model](docs/THREAT_MODEL.md) — assets, threats, controls, residual risk.
- [Security policy](SECURITY.md) — assumptions and prohibitions.
- [Policy engine](docs/POLICY_ENGINE.md) — exact decision/score semantics.
- [PDF CDR](docs/PDF_CDR.md), [Audit log](docs/AUDIT_LOG.md).
- [Authentication](docs/AUTHENTICATION.md), [Operator workflow](docs/OPERATOR_WORKFLOW.md),
  [Web security](docs/WEB_SECURITY.md).
- [Production hardening](docs/PRODUCTION_HARDENING.md), [Operations](docs/OPERATIONS.md),
  [Reconciliation](docs/RECONCILIATION.md).
- [Evaluation](docs/EVALUATION.md) — Phase 11 controlled benchmark methodology and results.
- [Release notes](docs/RELEASE_NOTES.md), [Release checklist](docs/RELEASE_CHECKLIST.md),
  [Release manifest](docs/RELEASE_MANIFEST.md).
- [Demo script](docs/DEMO.md), [Defense guide](docs/DEFENSE_GUIDE.md),
  [Presentation outline](docs/PRESENTATION_OUTLINE.md).

## Known limitations

- Static structural analysis only; no dynamic/behavioral execution sandbox.
- ALLOW is not proof of benignity; no zero-day guarantee.
- The evaluation corpus is synthetic, controlled, and sized at 59 cases, built around
  DocGuard's own documented detection coverage — not an independent adversarial
  benchmark.
- Benchmarked on a single development host; latency figures are host-specific.
- No MFA/SSO; local operator authentication only.
- Process-local rate limiting; the qualified topology is a single Uvicorn
  worker/single node.
- SQLite is the qualified single-node target, not a multi-node database.
- TLS termination and reverse-proxy configuration are administrator responsibilities.
- No external antivirus/cloud reputation integration (by design, for confidentiality).
- CDR currently covers PDF only; file-format coverage is intentionally narrow.

Full detail: `docs/DEFENSE_GUIDE.md` §N and `docs/EVALUATION.md` §25/26.

## Security language

- **ALLOW is not proof that a document is benign.**
- DocGuard's risk score is a deterministic policy score, not a probability that a file
  is malicious.
- CDR reduces active document functionality by reconstructing visual content; it does
  not prove the output is benign, and its output is always re-analyzed before approval.
- BLOCK represents an explicit security-policy violation and cannot be overridden by an
  operator in this release.
