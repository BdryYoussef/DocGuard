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
- `/Launch`, `/URI`, `/GoTo`, `/GoToR`, `/SubmitForm`, `/ImportData`, and bounded unknown action
  classes;
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
| `PDF_ENCRYPTED` | PDF encryption/password protection | LOW |
| `PDF_PARTIAL_ANALYSIS` | Password, parser restriction, warning, or traversal budget prevented full coverage | MEDIUM |
| `PDF_MALFORMED` | qpdf rejected or recovered structurally damaged input | HIGH |

These describe capabilities and limitations. JavaScript, forms, encryption, links, and attachments
all have legitimate uses; their presence is not a malware verdict.

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
- 32 KiB analyzer metadata JSON.

Indirect actions are deduplicated by PDF object number and generation. Direct action chains are
bounded by depth and node count. Only known semantic paths are followed; the analyzer does not
recursively walk arbitrary dictionary values. Exhausting a budget stops the affected traversal,
preserves prior observations, emits `PDF_PARTIAL_ANALYSIS`, and returns a failed/incomplete worker
status so the scan remains quarantined.

## JavaScript and URI data handling

JavaScript detection uses action dictionaries and name trees. Raw keyword scanning is not used: a
page content stream that merely discusses `/JavaScript` does not trigger the finding. Script bodies
are never returned, persisted, or logged.

URI actions are parsed lexically with the standard library after truncation to the metadata limit.
Only scheme, hostname, parse status, and total count are retained. Query strings, fragments,
credentials, and complete URLs are discarded. No DNS resolution, socket connection, redirect,
reputation request, or other fetch occurs.

## Encryption and malformed input

An encrypted PDF that opens with an empty password can be structurally inspected and still receives
`PDF_ENCRYPTED`. A non-empty password requirement produces `PDF_ENCRYPTED` plus
`PDF_PARTIAL_ANALYSIS`; DocGuard does not request or brute-force passwords.

Pikepdf/qpdf parser rejection produces `PDF_MALFORMED` and `PDF_PARTIAL_ANALYSIS`. Recovery warnings
also make analysis partial because complete structural coverage cannot be asserted. Parser exception
class and warning count are bounded metadata; warning text is not persisted. Unexpected programming
errors are not broadly swallowed: the worker exits and trusted orchestration quarantines the scan.

## Blind spots and interpretation

- No JavaScript deobfuscation or script semantics.
- No rendering, XFA execution, multimedia analysis, or content-stream behavioral analysis.
- No attachment extraction or recursive analysis of embedded documents.
- The separate Phase 6 YARA pass sees the original top-level PDF bytes only; it does not scan
  decoded streams, attachments, or other child objects.
- No password-assisted inspection.
- Unusual structures outside modeled semantic locations or beyond configured limits may be missed.
- Pikepdf, qpdf, and their native/transitive dependencies remain parser attack surface contained by
  the existing namespace, mount, network, capability, cgroup, rlimit, timeout, and output controls.

Absence of PDF findings is not proof that the document is benign.
