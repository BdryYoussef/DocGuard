# Security Policy and Assumptions

## Production operations boundary

The qualified V1 edge is trusted TLS-terminating Nginx forwarding to loopback Uvicorn. Forwarded
headers are ignored unless the direct peer is an explicitly configured exact proxy IP, and only one
valid `X-Real-IP` is accepted. Canonical Host/Origin checks never trust backend transport or chains.
Readiness fails on unsafe storage/static layout, schema/runtime qualification, missing operator, or a
failed sandbox self-test. Recovery is dry-run by default and cannot create ALLOW or automatically
delete orphan business data. No telemetry, automatic migration/account, or retention workflow is
introduced.

## Hostile-input assumption

Every submitted byte, claimed MIME, extension, URL, filename, and future embedded object is
attacker-controlled. A lack of findings does not establish benignity.

## Trusted and untrusted sides

The FastAPI/database side may only perform bounded transport operations: streaming raw bytes to an
opaque storage object and incrementally hashing them. It must not use libmagic, parsers, renderers,
archive readers, or content heuristics.

Content identification plus PDF, Office, ZIP, YARA, and PDF rendering run in a separate worker. The
dedicated parser artifact contains pinned pikepdf/qpdf, PyMuPDF/MuPDF, oletools/olefile, defusedxml,
and transitive dependencies plus pinned yara-python/libyara; generic ZIP inspection uses the worker Python
runtime's standard `zipfile` module. None are part of the trusted application dependency set.
Parsers and the PyMuPDF/MuPDF renderer remain hostile-input attack surface.

## PDF CDR and derived output

Raster CDR is not a trust shortcut. Trusted eligibility excludes BLOCK, ALLOW, incomplete,
encrypted, malformed, non-PDF, over-limit, missing, mutable, and hash-mismatched sources. The
renderer receives one read-only input and one descriptor-bound output object; final sanitized
storage is invisible. Output is copied to quarantine as a `CDR_DERIVED` scan, content identified,
structurally analyzed, top-level YARA scanned, and evaluated by normal trusted policy. Only a
complete persisted ALLOW can become an approved private artifact.

The original decision never changes. Candidate, derived, and promoted hashes must match. Artifact
persistence and `CDR_APPROVED` audit persistence share one transaction. Bounded audit details
exclude contents, scripts, URLs, matched bytes, filenames, and pixels. There is no public sanitize,
source-release, or raw-quarantine endpoint. Authenticated operators may request eligible CDR, read
bounded audit metadata, and download only an approved re-analyzed CDR artifact.

## Isolation boundary

Each document receives a new process chain:

1. a transient user-systemd scope bounds aggregate memory, swap, tasks, and CPU bandwidth;
2. `prlimit` bounds address space, CPU seconds, open files, created-file size, and core dumps;
3. Bubblewrap creates user, PID, network, IPC, UTS, cgroup, and mount namespaces;
4. the worker runs with all capabilities dropped, nested user namespaces disabled, no network, a
   cleared environment, a read-only root, and no normal home.

Only `/usr`, runtime libraries, a minimal loader cache, `worker/`, `docguard_contract/`, the
worker-only dependency artifact, `/proc`, a synthetic `/dev`, and the single read-only input are
visible. `/work` and `/tmp` are size-bounded tmpfs mounts. The trusted parent enforces wall time and
bounded stdout/stderr while draining pipes.

Production readiness executes controlled probes for execution, network denial, environment/file
secrecy, trusted-path hiding, write containment, input immutability, work access, timeout, and output
limits. It also verifies that capability sets are empty, configured process rlimits are active, and
the exact pinned PDF, Office, and YARA runtimes import from the isolated dependency mount. The YARA
probe also compiles the fingerprinted rule pack, verifies its manifest, checks EICAR and benign
behavior, and proves the rule source is read-only. Failure of any probe keeps readiness false. There
is no unsafe fallback.

## PDF structural analysis

Libmagic content classification is the only route into the PDF analyzer. Pikepdf never executes
JavaScript, launches actions, extracts attachments, renders XFA, or fetches URI actions. The analyzer
retains counts, action classes, sanitized attachment display names, and URI scheme/hostname only;
scripts, full URLs, embedded contents, and parser warning text never cross the JSON boundary.

Page, indirect-object, custom-object, action-node, action-depth, URI, attachment, trigger, and
metadata limits are enforced inside the worker. Indirect action cycles are broken using PDF object
numbers. Hitting a limit emits `PDF_PARTIAL_ANALYSIS` and makes the worker result `FAILED`, so the
scan remains quarantined. Password-required and malformed PDFs follow the same non-release rule.

The trusted Finding model bounds JSON metadata and verifies every product code's title,
description, category, severity, and related ATT&CK metadata against the shared registry. Unknown or
spoofed definitions invalidate the complete worker result.

## Ingestion and quarantine

- The upload endpoint processes the raw ASGI body in bounded slices.
- `Content-Length` is only an early optimization; the actual byte count is authoritative.
- SHA-256 is computed while writing, not in a second trusted content-processing pass.
- Temporary objects use exclusive creation and mode `0600`.
- Non-empty, bounded content is fsynced, changed to `0400`, and atomically renamed to a random
  128-bit quarantine key.
- Temporary and finalized files are removed on handled overflow, interruption, storage error, or
  initial database failure.
- Original filenames never form paths and are not logged at INFO.
- Raw storage is rejected when configured under a `public` or `static` path.

A host crash between atomic rename and database commit can leave an opaque orphan in quarantine.
It is not releasable or publicly addressable. A crash after `ANALYZING` can leave that persisted
non-release state for later operational reconciliation.

## Identification trust model

HTTP `Content-Type` and filename extensions are claims only. `/usr/bin/file`, backed by local
libmagic, identifies the mounted content inside the sandbox. Filename and claim mismatches create
explainable findings but never change the observed type. Generic octet-stream claims are excluded
from noisy discrepancy findings.

## Data handling prohibitions

- Never execute a submitted file.
- Never expose quarantine through static/public routes.
- Never upload samples to VirusTotal or another third party.
- Never fetch document URLs; future URL analysis is lexical only.
- Never log raw contents, binary blobs, secrets, or untrusted filenames at INFO.
- Never claim that a document is safe, clean, malware-free, or benign based on this model.

Absence of PDF findings is not proof that the document is benign.

## Office structural analysis

Libmagic ZIP/OOXML/OLE classification is the only route into the Office gate. OOXML classification
then requires `[Content_Types].xml`, root relationships, one expected application main part, and a
matching office-document relationship. A generic ZIP remains a generic ZIP.

OOXML is never bulk-extracted. Only content types, relationship XML, and selected VBA project
members are opened. Actual bytes read are counted independently of ZIP size claims; entry, member,
aggregate, XML, relationship, external-target, embedded-object, ActiveX, project, module, source,
and metadata limits stop traversal. Defusedxml rejects DTD/entity constructs and no relationship is
resolved or fetched.

Oletools performs static VBA extraction inside the worker with P-code analysis, XLM analysis, and
deobfuscation disabled. DocGuard retains bounded module names, counts, auto-exec trigger names, and
curated execution-indicator classes—not source, decoded strings, full URLs, or parser objects.
Selected OOXML VBA members are bounded before oletools sees them. Classic OLE inspection is more
conservative and remains subject to the sandbox memory and wall-clock controls during parser-internal
decompression.

Encryption, malformed components, parser limits, or resource limits produce partial/failed analysis
and preserve quarantine. Embedded objects and ActiveX are counted but neither extracted, recursively
analyzed, instantiated, nor executed.

Absence of Office findings is not proof that the document is benign.

## Generic ZIP analysis

Libmagic ZIP/OOXML classification is the only route into archive handling. The existing Office gate
has precedence: a structurally valid OOXML package stays Office, while a generic ZIP is inspected by
the archive analyzer. Extensions and client MIME claims never route the parser.

The analyzer never calls `extract` or `extractall`, never follows symlinks, and never turns a member
name into a filesystem path. It detects forward- and backslash parent components, POSIX/Windows/UNC
rooted paths, Unix symlink metadata, conservative duplicate-name collisions, dangerous final and
double extensions, and bidirectional controls. Retained attacker-controlled names and record counts
are bounded and control characters are visibly escaped.

Every readable regular member is consumed through bounded reads. Actual output, not declared ZIP
sizes or compression ratio, governs the 32 MiB per-member and 128 MiB aggregate decompression
budgets. Nested ZIPs are detected from leading content signatures, materialized only in bounded
memory, recursively inspected to depth three, and share container, member, decompression, and
materialization budgets. Archive children are not passed to PDF or Office analyzers.

Encrypted members are not opened. Unsupported compression, nesting/resource limits, malformed
central directories, CRC/decompression failures, and malformed nested containers produce partial or
malformed results and preserve quarantine. Central-directory allocation occurs inside the existing
cgroup/rlimit/Bubblewrap boundary before Python exposes an entry list; the outer memory and timeout
controls remain essential.

Absence of archive findings is not proof that the archive or its contents are benign.

## YARA analysis

Yara-python 4.5.4 and its statically linked YARA 4.5.4 runtime execute only in the disposable
worker. The trusted dependency set does not contain or import `yara`. Uploaded users cannot provide
rules: the worker compiles exactly `worker/rules/docguard_v1.yar`, whose SHA-256 and six expected rule
IDs are fixed in the trusted contract registry.

YARA scans only the descriptor-bound top-level submitted file after structural analysis. It does not
scan archive children, OOXML members, VBA projects, PDF attachments, embedded objects, or nested
documents, and it does not decompress content for signature matching. Structural status remains
authoritative; a YARA success or absence of matches never turns unsupported, malformed, encrypted,
or otherwise incomplete analysis into a release decision.

The scan uses YARA's internal timeout plus the external worker wall-clock timeout. Matched rules,
instances, retained string identifiers, offsets, metadata bytes, and total findings are bounded.
Matched bytes, scripts, commands, document excerpts, YARA tags, and arbitrary rule metadata are
discarded. The trusted Pydantic model revalidates each rule ID, finding class, rule title and
explanation, confidence, pack version/fingerprint, severity, and ATT&CK mapping before persistence.

The bundled pack contains one controlled EICAR test signature and five narrowly combined command or
execution heuristics. EICAR is a safe anti-malware test string, not real malware. Heuristic matches
describe suspicious lexical combinations and may have legitimate explanations.

Absence of YARA matches is not proof that a document is benign.

## Trusted policy and release eligibility

Only the trusted application evaluates findings. The worker's legacy `score_delta` field is
required to be zero and is never authoritative. Policy version `1.0.1` maps every production
finding to one intentional contribution and optional decision floor or semantic hard block. Exact
coverage and a normalized fingerprint are required by readiness.

Scoring is once per stable finding code, plus each transparent compound rule at most once, and is
clamped to 100. Hard block, incomplete-analysis quarantine, and explicit minimum-decision rules take
precedence over score. A critical score made only from heuristics remains quarantine rather than
claiming high-confidence malware.

The final database transaction persists findings and the complete bounded policy evaluation before
`release_eligible` can become true. Policy exceptions fail to a persisted quarantine evaluation;
database rollback leaves the pre-existing non-release row. `REVIEW`, `QUARANTINE`, and `BLOCK` are
never release eligible. The only download endpoint serves a separately approved CDR artifact after
fresh authorization and integrity checks; it never serves the source.

Historical retrieval returns the persisted version/fingerprint and evaluation; it does not silently
reinterpret findings under current policy. See [Policy engine](docs/POLICY_ENGINE.md).

The DocGuard risk score is a deterministic policy score, not a probability that a file is
malicious. ALLOW means that the configured analysis completed without a finding requiring
containment under the active policy. ALLOW is not proof that a document is benign.

## Authentication and browser boundary

Local OPERATOR passwords use pinned Argon2id. Only canonical usernames and hashes are persisted.
Sessions use CSPRNG opaque bearer tokens; the database stores only SHA-256 token and CSRF digests.
Every request checks expiry, inactivity, revocation, role, and operator activation. Successful
session creation and its operator-attributed audit event commit together. Logout revokes first;
failed post-revocation audit does not keep a session alive.

Production configuration requires a Secure `__Host-` HttpOnly cookie, HTTPS application origin,
SameSite, and CSRF. Mutations require a constant-time session-bound CSRF comparison and reject a
foreign supplied Origin. There is no debug auth bypass, registration, default credential, anonymous
upload, API key, or trust of forwarded proxy headers. Login throttling is bounded and process-local,
so a multi-process deployment must add a reviewed edge/distributed control later.

Jinja templates use autoescape; attacker-controlled names/findings/audit values are text. Local
JavaScript never builds HTML from API strings. CSP denies objects, framing, remote assets, unsafe
inline code, and unsafe evaluation. Sensitive UI/API responses are `no-store`; approved artifact
downloads are `no-store, private`. Static assets are application-owned and disjoint from all raw,
quarantine, sanitized, database, and work storage.

## Approved artifact download

There is no source or raw quarantine download. An authenticated `ARTIFACT_READ` request accepts one
opaque trusted artifact ID and revalidates source/derived lineage, CDR type, derived ALLOW and release
eligibility, policy identity, size, and SHA-256. The opaque storage object is resolved below private
sanitized storage and opened read-only with symlink following disabled. Type, owner, mode `0400`,
link count, size, digest, and stable metadata are checked on the descriptor. A required
operator-attributed audit event commits before the response can emit bytes. Any uncertainty fails
closed.

An already-open descriptor prevents later pathname replacement from redirecting the stream, but a
privileged host administrator and the filesystem/database remain inside the operational trust
boundary. See [Authentication](docs/AUTHENTICATION.md) and [Web security](docs/WEB_SECURITY.md).

## Responsible testing

Use harmless generated fixtures only. The PE fixture contains inert identifying header bytes and is
never executed. Do not download malware or introduce real malicious payloads.
