# PDF Content Disarm and Reconstruction

## Security model

DocGuard PDF CDR is destructive raster reconstruction for complete, non-blocked PDF scans that
require review or quarantine. The source, PyMuPDF renderer, and renderer output are all untrusted.

> CDR reduces active document functionality by reconstructing visual content. It does not prove the
> output is benign.

> The CDR output is re-analyzed before approval.

## Renderer and sanitizer identity

The worker-only renderer is PyMuPDF 1.28.2 backed by MuPDF 1.28.2. Sanitizer version `1.0.0` uses
150 DPI RGB raster pages, raster-images-only construction, and an empty/minimal metadata policy. A
deterministic SHA-256 fingerprint covers those values, renderer/engine versions, and every page,
geometry, pixel, raster, and output bound. Tests may inject lower bounds, producing a different
fingerprint.

PyMuPDF has a maintained local API, a pinned CPython stable-ABI wheel compatible with Python 3.14,
and needs no browser, Office suite, shell pipeline, network, or cloud service. MuPDF remains a large
native hostile-input attack surface. The outer Bubblewrap/cgroup/rlimit boundary is essential
because native allocation may occur before Python rejects a document.

## Eligibility and BLOCK exclusion

Trusted code alone decides eligibility. A source must be identified as PDF; have successful,
complete structural analysis; have no partial, malformed, or encryption limitation; retain REVIEW
or QUARANTINE; have no hard-block reason; and remain within the page limit. Its private quarantine
object must be a regular mode-`0400` file whose size and SHA-256 match persistence. ALLOW does not
need remediation. BLOCK never enters CDR: rasterization cannot override executable masquerading,
EICAR, or another semantic hard block.

## Raster limits and reconstruction

Defaults are 100 pages, 2,000 by 2,000 PDF points, 4,200 by 4,200 pixels, 16 million pixels per
page, 80 million total pixels, 240 million RGB raster bytes, 64 MiB generated PDF, and a 30-second
parent wall clock. Existing 512 MiB memory/address-space, process, CPU, file, tmpfs, stdout, and
stderr bounds also apply. DPI is fixed at 150 and cannot be supplied by a document or public caller.

Every page is rendered without annotations into opaque RGB pixels. A brand-new page with the same
visual proportions receives only that image. No source actions, JavaScript, annotations,
hyperlinks, forms, XFA, files, names, bookmarks, metadata, attachments, encryption, or object
dictionaries are copied. There is no OCR. Selectable text, semantics, accessibility structure,
forms, links, signatures, and exact fidelity are intentionally lost. Output may vary by platform;
structural passivity, not byte identity, is the goal.

## Isolated output handoff

`SANITIZE_PDF` is a trusted-selected operation with bounded configuration and no arbitrary flag,
command, DPI, page expression, or path. Bubblewrap retains the normal namespace, network,
environment, capability, dependency, input, `/work`, and `/tmp` profile. It adds one empty
parent-opened mode-`0600` file at `/output/document` using `--bind-fd`. The renderer cannot see its
parent directory, quarantine, sanitized storage, database, repository, trusted app, home, or other
jobs.

PyMuPDF saves to bounded ephemeral `/work/reconstructed.pdf` because its save operation uses path
replacement, then the worker copies it within the configured limit to the bound object. The parent
enforces wall time and bounded JSON output, fsyncs the exact PDF, checks non-zero/maximum size,
hashes it without parsing, and changes it to `0400`.

## Untrusted re-analysis and promotion

The handoff is atomically copied under a new opaque quarantine key and registered as a distinct
`CDR_DERIVED` scan linked by `parent_scan_id`. The normal worker runs libmagic identification, PDF
structural analysis, and top-level YARA. Current trusted policy is persisted. Only observed PDF,
SUCCESS, complete analysis, ALLOW, release eligibility, no containment reason, and matching hashes
can promote.

Promotion copies exact derived bytes through a temporary private object into mode-`0400` sanitized
storage, verifies candidate/derived/promoted SHA-256 and size, then commits the artifact and
`CDR_APPROVED` event together. REVIEW, QUARANTINE, BLOCK, unsupported, malformed, partial, failed,
timed-out, non-PDF, or YARA-flagged output is rejected. The renderer handoff is destroyed; rejected
derived scans remain quarantined for lineage.

## Lineage, idempotency, and limitations

The source decision never changes. History reads “original quarantined; derived allowed; sanitized
artifact approved.” Artifacts persist source and derived IDs, hash, size, sanitizer identity,
derived policy identity, and an opaque key. `(source_scan_id, sanitizer_fingerprint)` is unique;
an in-process lock avoids duplicate local work and the database arbitrates separate processes.

Every failure remains non-approved and cannot alter the source. A database/audit failure after
filesystem promotion removes the promoted file when possible. A host crash can still leave an
opaque temporary/orphan or derived scan without an artifact. Lineage supports future
reconciliation; Phase 9 adds no daemon.

## Operator request and controlled download

Authenticated OPERATORs may invoke `POST /api/v1/scans/{scan_id}/sanitize` with a session-bound CSRF
token. The request records operator identity and then repeats all trusted eligibility checks; UI
button visibility grants nothing. BLOCK represents an explicit security-policy violation and cannot
be overridden by an operator in V1.

Only an approved artifact whose derived scan still passes exact lineage, ALLOW, release eligibility,
policy identity, filesystem metadata, size, and SHA-256 checks can be downloaded. The server opens
the private mode-`0400` object without following symlinks, commits the operator-attributed download
audit before sending bytes, and streams the verified descriptor under a generated attachment name.
Audit failure, tampering, missing data, or policy/lineage inconsistency denies the download. Source
and raw quarantine bytes have no browser or API download route.
