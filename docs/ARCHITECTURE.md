# DocGuard Architecture

## Phase 10 deployment envelope

The frozen production path is browser HTTPS → trusted Nginx → loopback HTTP → one trusted Uvicorn
process → SQLite/private storage → one disposable Bubblewrap worker per hostile operation. Nginx
owns TLS and overwrites the sole trusted client-IP header. Uvicorn proxy-header interpretation is
disabled; the application owns canonical Host/Origin, authentication, policy, persistence,
qualification, and recovery. The parser boundary and worker JSON contract are unchanged.

Trusted maintenance may hash bytes only for transport/storage integrity; it never identifies or
interprets content. Recovery can only make state failed/non-releasable. See
`PRODUCTION_HARDENING.md`, `OPERATIONS.md`, and `RECONCILIATION.md`.

## End-to-end flow

1. `POST /api/v1/scans` receives one raw request body.
2. The trusted API writes bounded slices to an exclusive temporary file while counting bytes and
   computing SHA-256.
3. After fsync, the object becomes a read-only opaque quarantine object through atomic rename.
4. A `STORED` database row is committed with decision `QUARANTINE`.
5. The row transitions to `ANALYZING`; the orchestrator sends schema-version `2.1` JSON through the
   `IsolationBackend` interface.
6. A new isolated worker identifies the fixed `/input/document` with local libmagic. PDF routes to
   pikepdf; ZIP/OOXML/OLE may enter the Office gate. Filenames never route parsers.
7. The PDF analyzer performs bounded semantic structure inspection. The Office gate validates OOXML
   package metadata before application classification, or conservatively inspects classic OLE, then
   reports bounded structural and static-VBA metadata.
8. A ZIP that is not a validated Office package enters the generic archive analyzer. Members are
   streamed without extraction; bounded content signatures may recurse only into nested ZIPs.
9. The fixed local YARA pack scans only the top-level mounted input and supplements any structural
   findings with bounded rule-ID/string-ID/offset metadata. Matched bytes are discarded.
10. The trusted side validates every result field, including YARA rule identity and product-owned
    metadata. Worker score claims must be zero.
11. Policy version `1.0.1` deduplicates validated finding codes, applies immutable finding and
    compound definitions, checks completeness, and produces score, band, decision, reasons, and
    explicit release eligibility.
12. One transaction persists findings plus the complete policy evaluation before a scan can become
    release eligible. Historical reads return that persisted evaluation without re-running policy.

## Bubblewrap launcher chain

The production backend opens the selected sample with `O_NOFOLLOW`, verifies it is a regular file,
and passes that descriptor to Bubblewrap with `--ro-bind-fd`. This prevents a path-replacement race
between selection and mounting.

The parent launches:

```text
systemd-run --user --scope
  -> prlimit
    -> bwrap
      -> one Python worker
```

No Python `preexec_fn` is used.

### Namespaces and identity

Bubblewrap 0.11.1 uses `--unshare-all` plus explicit user namespace creation. This isolates user,
PID, network, IPC, UTS, cgroup, and mount views. Nested user namespaces are disabled and asserted
disabled. The host process runs as the unprivileged DocGuard service user; capabilities are dropped
inside the namespace. `--new-session` and `--die-with-parent` strengthen lifecycle containment.

### Filesystem view

Read-only:

- `/usr`
- `/lib` and `/lib64` when present
- `/etc/ld.so.cache` when present
- `/opt/docguard-runtime/worker`
- `/opt/docguard-runtime/docguard_contract`
- `/opt/docguard-runtime/dependencies`, the pinned worker-only parser artifact
- `/input/document`, bound from one already-open descriptor

Ephemeral writable:

- `/work`, size-bounded tmpfs, mode `0700`
- `/tmp`, size-bounded tmpfs

Special minimal mounts are a new `/proc` and synthetic `/dev`. The root is remounted read-only. The
repository, trusted `app/`, trusted `.python-deps`, databases, all storage directories, `.git`,
`.env`, `/home`, `/run`, and `/sys` are absent.

### Environment and network

The outer launcher receives only `PATH`, locale, and the user-systemd bus address required to create
the cgroup. Bubblewrap uses `--clearenv` and constructs a smaller worker environment containing only
runtime path/locale values and the read-only runtime/dependency roots. No database URL, application
secret,
credential, or home variable is forwarded. The network namespace has no usable route.

### Resource and output controls

The transient cgroup sets aggregate `MemoryMax`, `MemorySwapMax=0`, `TasksMax`, and `CPUQuota`.
`prlimit` sets address-space, per-process CPU-time, open-file, created-file-size, and core limits.
Tmpfs mounts have explicit size ceilings. The trusted parent concurrently drains stdout/stderr only
up to configured byte limits and kills the process group on overflow or wall-clock expiry.

The readiness probe directly checks empty Linux capability sets and the effective address-space,
CPU-time, open-file, created-file-size, and core rlimits. It also imports the exact pinned pikepdf,
oletools, olefile, defusedxml, and pyparsing versions from the read-only dependency artifact and
checks the standard ZIP compression runtime. It imports yara-python/libyara, compiles the exact
fingerprinted rule pack, compares declarations to the strict manifest, verifies EICAR and benign
behavior with an internal timeout, and proves the rules are read-only. Successful `systemd-run`
scope creation is required for the aggregate cgroup controls.

These controls depend on a functioning cgroup-v2 user systemd manager with delegation. If it is not
available, the self-test fails and production readiness remains false.

## Worker contract and detector

`docguard_contract/` contains version constants plus immutable finding and YARA rule registries. The worker uses
the standard library, `/usr/bin/file`, and parser packages only after content-family routing. It does
not import FastAPI, Pydantic, SQLAlchemy, or `app`. The trusted Pydantic
`AnalysisResult` remains authoritative for result validation and enforces registry metadata and
JSON-size limits.

Normalized families are PDF, ZIP, OOXML candidate, OLE compound, Windows executable, text, and
unknown. A ZIP signature is not treated as proof of Office content. The filename, HTTP MIME claim,
libmagic MIME, and signature description remain separate metadata lanes.

For PDFs, action traversal follows semantic `/A`, `/AA`, `/OpenAction`, JavaScript name-tree, page,
annotation, form-field, and indirect action structures. Only `/Next` action chains and known form
field trees are recursively followed. Object numbers and hard depth/node budgets stop cycles and
pathological graphs. `PARTIAL` or `MALFORMED` parser status maps to worker `FAILED` and persisted
`QUARANTINED`; `COMPLETE` becomes eligible for trusted policy evaluation but is not automatically
allowed.

For OOXML, `zipfile` reads the central directory but never extracts members. Exact selected member
reads are chunked and counted; defusedxml parses only content types and relationships. Valid packages
must identify exactly one Word, Excel, or PowerPoint main part and a matching root relationship.
VBA project bytes are read under an actual-byte cap and passed in memory to worker-only oletools.
External targets are reduced to relationship type, scheme, hostname, and length. Query strings,
credentials, raw XML, VBA source, and embedded bytes never cross the contract.

Classic OLE uses olefile directory/stream metadata to identify Word, Excel, PowerPoint, encrypted
OOXML wrappers, embedded/package structures, and ActiveX presence. Static VBA extraction is bounded
by input/project caps and the outer worker controls. No Office application is invoked.

For a generic ZIP, the worker uses Python's standard `zipfile` parser after the Office gate returns
no package. It never extracts. Portable member-name checks operate on raw forward/backslash forms;
symlink metadata is recognized and skipped. Normal members are streamed to enforce actual output
limits and to identify a nested ZIP only from its leading signature. Nested bytes remain in bounded
memory, are keyed by SHA-256 for repeated-content suppression, and share all aggregate budgets.
There is no recursive PDF or Office dispatch for archive children. Expected encryption,
unsupported-compression, structural, CRC, and resource failures become bounded partial/malformed
results; unexpected exceptions still terminate the worker.

YARA runs after the format-specific analyzer and scans only `/input/document`. The engine compiles
one source file from the read-only worker mount after checking its SHA-256, rejecting import/include
directives, and comparing all declarations to the shared trusted manifest. YARA's internal timeout,
match-data configuration, rule/match/identifier/offset/metadata limits, and existing outer sandbox
controls bound scanning. Only trusted rule identity plus counts and offsets cross the JSON contract;
matched bytes, tags, rule metadata, scripts, and excerpts do not. The trusted Pydantic model derives
expected severity and ATT&CK context from the rule registry and rejects unknown or spoofed IDs.

Archive members, Office parts, PDF attachments, and nested objects are not recursively YARA-scanned.
YARA results cannot change the structural parser status from unsupported/failed to successful.

## Trusted policy boundary

`app/policies/` is trusted and parser-free. Its immutable registry exactly covers the shared finding
registry and contains fixed contributions, decision floors, hard-block flags, compound presence
rules, explanations, version, and fingerprint. The worker never receives policy configuration and
cannot set a final score or decision.

Evaluation occurs while the scan is in the trusted `ANALYZING` lifecycle and after strict worker
validation. Finding persistence and evaluation persistence share the final database transaction.
`ALLOW` is the only release-eligible decision; no endpoint serves a source scan. An approved CDR
artifact may be downloaded only after independent lineage/integrity authorization. Policy or database
failure cannot leave a release-eligible partial record.

The authenticated `GET /api/v1/scans/{scan_id}` reads stored policy JSON. It does not compute from stored
findings, so later policy releases do not silently rewrite historical meaning.

## PDF CDR and audit boundary

Trusted CDR eligibility reads persisted metadata and hashes only. It authorizes explicit
`SANITIZE_PDF` after checking source decision, completeness, page count, mode, existence, size, and
SHA-256. Bubblewrap retains the normal namespace/network/environment/resource profile and adds one
parent-opened read-write file at `/output/document`; final sanitized storage is never mounted.

The worker renders fixed 150 DPI RGB pages into ephemeral `/work`, reconstructs a raster-image-only
PDF, and copies it to the bound object. JSON carries bounded status/version/count metadata, not PDF
or image bytes. The parent fsyncs and hashes without parsing, atomically copies into quarantine,
and creates a distinct `CDR_DERIVED` scan linked to the source.

The exact derived bytes follow libmagic → PDF structural analysis → top-level YARA → trusted policy.
Only complete persisted ALLOW is copied into private sanitized storage and referenced by an
artifact. Candidate, derived, and promoted hashes match; source history stays unchanged. Artifact
creation and `CDR_APPROVED` share one transaction. Audit application code is append-only and stores
bounded trusted metadata only. See [PDF CDR](PDF_CDR.md) and [Audit log](AUDIT_LOG.md).

## Authentication, authorization, and web boundary

The trusted API owns local OPERATOR authentication. Argon2id password hashes, active state, and role
are in `operators`; opaque server-side sessions store only token/CSRF digests, absolute expiry,
last-seen time, and revocation. Successful session creation, last-login update, token rotation, and
`AUTH_LOGIN_SUCCESS` audit commit together. Every request resolves a session and active operator from
the database. The browser receives one HttpOnly `__Host-` cookie in production.

Routes depend on centralized capabilities rather than content or UI state. V1 defines only scan
upload/read, CDR request, approved-artifact read, and audit read. There is no raw quarantine, policy
override, rule upload, or BLOCK override capability. Cookie-authenticated mutations also require a
constant-time session-bound CSRF token and reject foreign supplied Origin headers.

The Jinja UI is a trusted presentation layer over bounded query services and typed response models;
it never parses document bytes. Templates autoescape hostile metadata. Only local CSS/JavaScript is
mounted from `app/web/static`, which is disjoint from all document storage. A restrictive CSP and
security headers apply centrally. Production disables interactive API documentation. See
[Authentication](AUTHENTICATION.md), [Operator workflow](OPERATOR_WORKFLOW.md), and
[Web security](WEB_SECURITY.md).

## Approved artifact download boundary

`GET /api/v1/artifacts/{artifact_id}/download` is the only byte-serving route. It accepts an opaque
artifact ID, re-queries source and derived scans, and requires exact CDR lineage, a complete derived
ALLOW, release eligibility, and persisted policy identity. The persisted opaque storage key is
resolved under private sanitized storage and opened with `O_NOFOLLOW`; the descriptor must be a
single-link, owner-only mode-`0400` regular file with matching size and SHA-256 before and after
verification.

The required operator audit append succeeds before `StreamingResponse` is created, so audit failure
sends no bytes. Streaming uses the verified open descriptor and closes it in `finally`; a later path
replacement cannot redirect the descriptor. Source/quarantine storage is never addressable through
this route or static files.

## Readiness and bootstrap

Production readiness combines the existing database, migration, storage, policy, sanitizer, and
qualified isolation checks with authentication configuration, Argon2 runtime, auth tables, session
store, and existence of at least one active OPERATOR. Production returns only `ready`/`not_ready`
while details remain in structured logs. Bootstrap is migration followed by the local
`scripts.create_operator` CLI; no browser registration exists.

## Asynchronous evolution

Uploaded scans and operator-requested CDR still analyze synchronously within the request lifecycle.
Storage
registration, `AnalysisOrchestrator`, and persisted states are separate. A later internal scheduler
can invoke the same orchestrator without changing the worker contract. Redis and Celery are
intentionally absent.
