# Operator Workflow

## 1. Login and dashboard

An administrator bootstraps an active OPERATOR with the CLI; there is no web registration. The
operator signs in at `/login`, receives an opaque server-side session, and lands on `/app`. The
dashboard summarizes persisted decisions and recent contained scans without exposing storage keys
or paths.

## 2. Upload and analysis

The dashboard upload control sends one raw body to `POST /api/v1/scans` with a bounded filename and
claimed client MIME as metadata. A session-bound CSRF header is required. The trusted API only
streams, counts, and hashes bytes into opaque private quarantine storage. Content identification,
parsing, YARA, and PDF rendering remain in disposable workers.

The synchronous V1 response and scan detail show lifecycle, observed type, findings, deterministic
policy contributions, risk band/score, decision reasons, and policy identity. Filename and client
MIME claims never override worker-observed content.

## 3. Decisions and containment

- `ALLOW`: analysis completed without a configured condition requiring review or containment.
- `REVIEW`: an operator should assess explainable characteristics before any later release process.
- `QUARANTINE`: significant risk or incomplete/uncertain analysis requires containment.
- `BLOCK`: an explicit policy violation prevents normal release and cannot be overridden in V1.

ALLOW is not proof that a document is benign. DocGuard's risk score is a deterministic policy score,
not a probability that a file is malicious. V1 provides no source/raw quarantine download at any
decision.

The Quarantine page lists REVIEW, QUARANTINE, and BLOCK scans newest first. It is a view over private
metadata; it never mounts or links raw storage.

## 4. Eligible PDF CDR

For a complete PDF with REVIEW or eligible QUARANTINE status, the detail page may show **Generate
sanitized PDF**. Button visibility is only presentation: the trusted service repeats eligibility,
integrity, and policy checks when the request arrives. ALLOW, BLOCK, non-PDF, incomplete, encrypted,
malformed, missing, changed, or over-limit sources cannot enter CDR.

CDR reduces active document functionality by reconstructing visual content. It does not prove the
output is benign. The renderer runs in the same isolated worker boundary, returns a candidate into
private storage, and never changes the source decision.

## 5. Derived scan and approval

The exact candidate becomes a distinct `CDR_DERIVED` quarantine scan linked to its source. The CDR
output is re-analyzed before approval: libmagic identification, structural PDF analysis, top-level
YARA, and current trusted policy all run again. Only complete ALLOW with matching candidate, derived,
and promoted hashes creates an approved `PDF_CDR` artifact. Repeated requests reuse the same approved
source/sanitizer-fingerprint lineage.

## 6. Approved artifact download

The Sanitized page lists only approved CDR artifacts whose derived scan remains ALLOW and release
eligible. Download uses a trusted artifact ID, re-checks source/derived lineage and persisted policy
identity, resolves the opaque key under private sanitized storage, opens with no symlink following,
and verifies owner, regular-file type, mode, link count, size, SHA-256, and stable file metadata.

DocGuard commits an `ARTIFACT_DOWNLOADED` operator audit event before returning any bytes. If audit
persistence, authorization, lineage, or integrity fails, the download fails closed. Responses use a
server-generated attachment name, `application/pdf`, `nosniff`, and `Cache-Control: no-store,
private`. Source and BLOCK documents never have a download action.

## 7. Evidence report

Any scan detail page has an **Evidence report** action at `GET
/app/scans/{scan_id}/report` — a standalone, printable page for the same
operator session and authorization as the scan detail page it links from
(no separate capability, no share token, no unauthenticated access).

Opening the report performs no analysis, re-evaluation, or worker
invocation: it renders the same persisted scan, findings, and policy
evaluation the scan detail page already shows, plus a server-generated
"Report generated at" timestamp that is presentation metadata only and is
not persisted. Essential evidence — document identity, decision, rationale,
findings, fallback-lexical-evidence distinction, and CDR lineage where
applicable — is present in the printable page by default, not gated behind
a collapsed disclosure. The **Print / Save as PDF** button uses the
browser's native print dialog; DocGuard does not generate PDFs server-side
and the report is never triggered automatically.

Like the scan detail page, the report never exposes raw/source document
bytes, a quarantine download link, or a BLOCK override/release affordance.
It is an authenticated presentation of already-persisted evidence, not a
cryptographically signed or tamper-evident certificate, and ALLOW shown on
a report carries the same limitation as everywhere else in DocGuard: it is
not proof that the document is benign.

## 8. Audit and logout

The Audit page and bounded API show newest-first application security events, including operator
identity for login, upload, CDR request, artifact download, and logout. Details are allowlisted and
never include passwords, document contents, parser excerpts, raw URLs, filenames, or storage keys.

Logout is a CSRF-protected POST. The server revokes the session before clearing the cookie. Reusing
the old token cannot access the UI or API, including through browser back-navigation followed by a
new server request.
