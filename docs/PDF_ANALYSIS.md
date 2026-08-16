# PDF Structural Analysis

## Parser selection

DocGuard uses worker-only **pikepdf 10.11.0**, backed by **qpdf 12.3.2**. The selected wheel supports
Python 3.14 and provides semantic access to catalogs, dictionaries, indirect objects, name trees,
attachments, forms, actions, encryption, and parser recovery warnings. It does not execute PDF
JavaScript.

The parser and its pinned transitive dependencies are installed from `requirements-worker.lock`
into a dedicated artifact. Bubblewrap mounts that artifact read-only at
`/opt/docguard-runtime/dependencies`. FastAPI, SQLAlchemy, and trusted orchestration neither depend
on nor import pikepdf.

## Routing and inspected structures

Libmagic must first classify the content family as `PDF`. Filename extension and HTTP
`Content-Type` do not participate in routing. The analyzer defensively rejects any direct call with
a non-PDF detected family.

Inspection covers:

- catalog `/OpenAction` and `/AA`;
- `/A` and `/AA` on page, annotation, form, and indirect dictionary structures;
- bounded `/Next` action chains;
- `/JavaScript` actions and the document JavaScript name tree;
- `/Launch`, `/URI`, `/GoTo`, `/GoToR`, `/GoToE`, `/SubmitForm`, `/ImportData`, and bounded unknown
  action classes;
- embedded-file name trees, file specifications, `/AF` references, and embedded-file streams;
- catalog AcroForm and XFA presence;
- encryption state, page count, object count, and qpdf recovery warnings.

The analyzer never renders pages, interprets page content streams for active capabilities, executes
scripts, extracts attachments, or rewrites the PDF.

## Stable findings

| Code | Structural condition | Severity |
|---|---|---|
| `PDF_JAVASCRIPT` | JavaScript action or JavaScript name-tree structure | MEDIUM |
| `PDF_OPEN_ACTION` | Catalog `/OpenAction`, recorded as destination or action | MEDIUM |
| `PDF_ADDITIONAL_ACTION` | One or more `/AA` dictionaries | MEDIUM |
| `PDF_LAUNCH_ACTION` | Action subtype `/Launch` | HIGH |
| `PDF_EMBEDDED_FILE` | Named attachment, `/EF` file specification, or embedded payload | MEDIUM |
| `PDF_ACROFORM` | Catalog AcroForm dictionary | LOW |
| `PDF_XFA` | `/XFA` under AcroForm | MEDIUM |
| `PDF_EXTERNAL_URI` | Action subtype `/URI` | LOW |
| `PDF_EXTERNAL_SUBMISSION` | Action subtype `/SubmitForm` whose `/F` target has an explicit URL scheme | MEDIUM |
| `PDF_ENCRYPTED` | PDF encryption/password protection | LOW |
| `PDF_PARTIAL_ANALYSIS` | Password, parser restriction, warning, or traversal budget prevented full coverage | MEDIUM |
| `PDF_MALFORMED` | qpdf rejected or recovered structurally damaged input | HIGH |
| `PDF_FALLBACK_INDICATOR` | Bounded lexical name-token scan found evidence a rejected/incomplete parse could not reach | MEDIUM |

These describe capabilities and limitations. JavaScript, forms, encryption, links, and attachments
all have legitimate uses; their presence is not a malware verdict.

Known action-type values reported in `PDF_OPEN_ACTION.action_type` and
`PDF_ADDITIONAL_ACTION.action_types` are the short codes `GoTo`, `GoToE`, `GoToR`, `ImportData`,
`JavaScript`, `Launch`, `SubmitForm`, and `URI`. `GoToE` (go-to-embedded — ISO 32000-2 §12.6.4.4)
navigates to a destination inside an embedded/attached PDF; DocGuard classifies it explicitly rather
than reporting it as an unrecognized action. An action subtype outside this fixed list is reported as
`Unknown:<name>`, bounded and capped as described below.

## Structural JavaScript behavior indicators

For a *structurally-confirmed* `/JS` action or name-tree entry only, `PDF_JAVASCRIPT.metadata`
carries a bounded `behavior_indicators` list drawn from a fixed, small category vocabulary:
`external_submission_api`, `external_url_open_api`, `external_network_api`, and
`document_content_access`. Each category is a plain substring match against a bounded prefix
(64 KiB) of the script text against a fixed API-name list (`submitForm`, `getURL`, `app.launchURL`,
`app.openDoc`, `importDataObject`, `fetch(`, `XMLHttpRequest`, `WebSocket`, `SOAP.*`, `getField`,
and similar) — never a JavaScript parser, interpreter, or deobfuscator. A match records that the
script text references an API *family*; it is not proof the script runs, succeeds, or is malicious.
The script text itself is never returned, persisted, or logged, in full or in part.

## Bounded lexical fallback evidence for incomplete/rejected PDFs

When structural coverage is not `COMPLETE` — the parser rejected the file outright, recovery
warnings occurred, or a traversal budget was hit — `worker.analyzers.pdf_fallback` additionally
performs one bounded, deterministic, non-executing pass over a size-capped byte prefix (8 MiB) of
the raw file, searching for a fixed vocabulary of 13 PDF name-object keywords (`/JavaScript`, `/JS`,
`/OpenAction`, `/AA`, `/AcroForm`, `/XFA`, `/Launch`, `/EmbeddedFile(s)`, `/ImportData`,
`/SubmitForm`, `/GoToE`, `/URI`). It decodes the standard PDF name `#XX` hex-escape syntax
(ISO 32000-1 §7.3.5) globally before searching, so a keyword hex-obfuscated in the raw bytes is
still recognized as the same lexical indicator.

This is a name-token scan, not a parser, and the distinction from structural confirmation is
enforced by construction, not just documentation:

- It never resolves indirect objects, applies stream filters, decompresses content, or distinguishes
  a real name-object delimiter context from an incidental byte sequence inside binary/compressed
  data — a false positive from binary data coincidentally spelling out a token is possible and
  accepted, because this evidence is additive, not authoritative.
- Every indicator token is a PDF *name object*, which always begins with `/`; ordinary document
  prose (a PDF *string*, never a name) does not match, so a page merely discussing "JavaScript" does
  not produce this finding.
- A hit is reported as `PDF_FALLBACK_INDICATOR`, never as `PDF_JAVASCRIPT`, `PDF_XFA`, or any other
  structurally-confirmed finding code. Its metadata carries an explicit `"confidence":
  "lexical_only"` marker and a bounded `indicators`/`indicator_counts` list — never raw matched
  bytes, surrounding context, or the full file.
- It performs no execution, evaluation, network access, or recursion, and never turns an
  incomplete/rejected parse into a complete one: `PDF_FALLBACK_INDICATOR` carries zero policy
  contribution (see `docs/POLICY_ENGINE.md`) and never appears when structural analysis is
  `COMPLETE`.

## Traversal and metadata limits

Production defaults are:

- 10,000 pages inspected;
- 100,000 indirect objects and 100,000 known direct/custom objects inspected;
- 512 unique action nodes;
- action depth 32;
- 32 distinct unknown action-class names;
- 128 URI actions parsed, with at most 32 lexical target summaries retained;
- 128 embedded-file descriptors, with at most 32 display names retained;
- 128 additional-action triggers, with at most 32 trigger names retained;
- 256 characters per analyzer-controlled metadata string;
- 256 findings per worker result;
- 16 KiB JSON per finding metadata object;
- 32 KiB analyzer metadata JSON;
- 64 KiB read of a structurally-confirmed JavaScript action's script text, for bounded behavior-
  indicator matching only;
- 8 MiB scanned prefix for the bounded lexical fallback scan, with per-token hit counts capped at
  9,999.

Indirect actions are deduplicated by PDF object number and generation. Direct action chains are
bounded by depth and node count. Only known semantic paths are followed; the analyzer does not
recursively walk arbitrary dictionary values. Exhausting a budget stops the affected traversal,
preserves prior observations, emits `PDF_PARTIAL_ANALYSIS`, and returns a failed/incomplete worker
status so the scan remains quarantined.

## JavaScript and URI data handling

JavaScript detection uses action dictionaries and name trees. Raw keyword scanning is not used: a
page content stream that merely discusses `/JavaScript` does not trigger the finding. Script bodies
are never returned, persisted, or logged.

URI actions, and a structurally-confirmed SubmitForm action's external `/F` target, are parsed
lexically with the standard library after truncation to the metadata limit. Only scheme, hostname,
parse status, and total count are retained. Query strings, fragments, credentials, and complete URLs
are discarded. No DNS resolution, socket connection, redirect, reputation request, or other fetch
occurs. A SubmitForm target without an explicit URL scheme is not reported as
`PDF_EXTERNAL_SUBMISSION`; the SubmitForm action type itself is still visible via
`PDF_OPEN_ACTION`/`PDF_ADDITIONAL_ACTION` regardless.

## Encryption and malformed input

An encrypted PDF that opens with an empty password can be structurally inspected and still receives
`PDF_ENCRYPTED`. A non-empty password requirement produces `PDF_ENCRYPTED` plus
`PDF_PARTIAL_ANALYSIS`; DocGuard does not request or brute-force passwords.

Pikepdf/qpdf parser rejection produces `PDF_MALFORMED` and `PDF_PARTIAL_ANALYSIS`. Recovery warnings
also make analysis partial because complete structural coverage cannot be asserted. Parser exception
class and warning count are bounded metadata; warning text is not persisted. Unexpected programming
errors are not broadly swallowed: the worker exits and trusted orchestration quarantines the scan.

In every one of these cases DocGuard still runs the bounded lexical fallback scan described above
and may additionally emit `PDF_FALLBACK_INDICATOR`. This never changes `PDF_MALFORMED` /
`PDF_PARTIAL_ANALYSIS`, the worker status, `analysis_complete`, or the mandatory `QUARANTINE` floor
those findings already carry — it only adds bounded supplementary evidence for a human reviewer.

## Blind spots and interpretation

- No JavaScript deobfuscation, script semantics, or execution — behavior indicators are bounded
  substring matches against a fixed API-name list, not proof of what a script actually does.
- No rendering, XFA execution, multimedia analysis, or content-stream behavioral analysis.
- No attachment extraction or recursive analysis of embedded documents.
- The separate Phase 6 YARA pass sees the original top-level PDF bytes only; it does not scan
  decoded streams, attachments, or other child objects.
- No password-assisted inspection.
- Unusual structures outside modeled semantic locations or beyond configured limits may be missed.
- The bounded lexical fallback scan cannot distinguish a real PDF name-object delimiter from an
  incidental byte sequence inside binary/compressed stream data; a false-positive lexical hit is
  possible and accepted, because the evidence is additive and carries zero policy weight.
- The fallback scan only recognizes its fixed 13-token vocabulary and the standard `#XX` name
  hex-escape; it is not a PDF recovery parser and does not attempt any other obfuscation technique
  (string encoding, stream re-compression, JavaScript payload staging, and similar remain
  unaddressed by this scan specifically).
- Pikepdf, qpdf, and their native/transitive dependencies remain parser attack surface contained by
  the existing namespace, mount, network, capability, cgroup, rlimit, timeout, and output controls.

Absence of PDF findings is not proof that the document is benign. Presence of a
`PDF_FALLBACK_INDICATOR` token is bounded lexical evidence only, not proof that the referenced
capability is present, reachable, or would execute in a real viewer.
