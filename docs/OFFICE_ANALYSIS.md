# Office Structural Analysis

## Parser stack and isolation

Office interpretation exists only in the disposable worker dependency artifact:

- **oletools 0.60.2** for static VBA project/module extraction and semantic keyword categories;
- **olefile 0.47** for Compound File directory and stream structure;
- **defusedxml 0.7.1** for OOXML content-type and relationship XML;
- **pyparsing 3.2.5** as the warning-free oletools-compatible parser dependency on the inspected
  Python 3.14.4 host.

Oletools 0.60.2 package metadata describes a beta release and advertises Python support through
3.12. DocGuard therefore treats Python 3.14 compatibility as locally qualified by imports, generated
fixtures, static analysis, the complete test suite, and the real Bubblewrap integration suite—not as
an upstream compatibility guarantee. No Office package is present in `requirements.lock` or imported
from `app/`.

The worker never invokes Microsoft Office, LibreOffice, PowerShell, a shell, or an embedded control.
It does not decrypt, emulate, deobfuscate, or execute VBA.

## Routing and supported families

The filename and client MIME are metadata only. Libmagic must first classify content as ZIP/OOXML or
OLE Compound File. A Windows executable named `.docx` or `.xls` never reaches these parsers.

An OOXML package is assigned Word, Excel, or PowerPoint only when it contains:

1. a valid `[Content_Types].xml`;
2. `_rels/.rels`;
3. exactly one expected main part (`word/document.xml`, `xl/workbook.xml`, or
   `ppt/presentation.xml`) with a compatible content type; and
4. a root `officeDocument` relationship targeting that part.

This covers the structural families commonly named `.docx`, `.docm`, `.xlsx`, `.xlsm`, `.pptx`, and
`.pptm`. A generic ZIP remains ZIP. Inconsistent OPC structures produce malformed/partial analysis.

Classic OLE support recognizes Word's `WordDocument`, Excel's `Workbook`/`Book`, and PowerPoint's
`PowerPoint Document` streams. It also recognizes the `EncryptionInfo` plus `EncryptedPackage`
wrapper used by encrypted OOXML. This is not a full `.doc`, `.xls`, or `.ppt` binary-format parser.
Unknown OLE applications remain conservative and non-releasable.

## OOXML ZIP and XML safety

DocGuard reads the ZIP central directory, but never calls `extract`, `extractall`, or creates paths
from member names. Only known XML parts and selected VBA project members are opened. Embedded objects
and ActiveX members are counted from bounded package structure and are not read recursively.

Production defaults bound:

- 4,096 ZIP entries and 512 characters per member name;
- 8 MiB per selected member and 64 MiB total actual decompressed bytes read;
- 256 XML parts and 4 MiB aggregate XML bytes;
- 2,048 relationships and 256 external relationships;
- 256 embedded and 256 ActiveX structures;
- 8 VBA projects, 8 MiB per selected project, 128 modules, and 4 MiB inspected source;
- 256 characters per analyzer metadata string and 64 retained metadata entries.

Actual bytes consumed are authoritative; ZIP size fields are not. Duplicate member names are
ambiguous and make analysis malformed. CRC/deflate failures and limit exhaustion yield controlled
malformed or partial results. No selected member is materialized: the materialization count is zero,
so attacker-controlled member names cannot become filesystem paths.

Defusedxml forbids DTD/entity constructs, external entity resolution, expansion, local-file access,
and network-backed XML behavior. XML bodies never cross the JSON boundary.

## VBA analysis and privacy

Macro-enabled main content types and VBA project parts produce `OFFICE_MACRO_ENABLED`. Selected
`vbaProject.bin` bytes are streamed under the member/project limits and passed in memory to olevba.
Classic OLE files are passed only after a bounded whole-file read.

Olevba performs static extraction with P-code inspection disabled, XLM inspection disabled, and
expression deobfuscation disabled. DocGuard applies olevba's semantic scanner to each bounded module
and retains only:

- project/module counts;
- bounded, sanitized module names;
- recognized auto-exec trigger names;
- a curated set of process, command-shell, PowerShell, scripting-host, and COM-object indicator
  classes.

The curated mapping includes signals such as `Shell`, `WScript.Shell`, `CreateObject`, `Run`,
`ShellExecute`, PowerShell constructs, and `cmd.exe` when olevba reports them from VBA source. Visible
document text containing those words is not scanned and does not create a VBA finding.

Complete VBA source, decoded strings, full commands, and parser objects are never returned,
persisted, or logged. Presence of a macro or execution-capable API is not proof of maliciousness.

## Relationships, embedded objects, and ActiveX

Every selected `.rels` part is parsed without resolution. `TargetMode="External"` creates bounded
lexical metadata containing the relationship type, scheme, hostname, target length, and truncation
state. Full URLs, credentials, query strings, and fragments are discarded. No DNS, HTTP, SMB, UNC,
`file://`, redirect, or reputation request occurs.

Word `attachedTemplate` relationships receive the dedicated `OFFICE_EXTERNAL_TEMPLATE` finding.
Ordinary external hyperlinks receive `OFFICE_EXTERNAL_RELATIONSHIP`; neither finding claims malware.

Members under the expected `word|xl|ppt/embeddings/` and `activeX/` locations create presence/count
findings. Classic OLE `Ole10Native`, `Package`, `ObjectPool`, and limited ActiveX directory indicators
are also recognized. Embedded bytes are not extracted or recursively analyzed, and controls are not
instantiated.

## Findings and failure behavior

| Code | Condition |
|---|---|
| `OFFICE_MACRO_ENABLED` | Macro-enabled content type or VBA project structure |
| `OFFICE_VBA_MACRO` | One or more VBA project structures/modules |
| `OFFICE_VBA_AUTOEXEC` | Curated olevba auto-exec entry point |
| `OFFICE_VBA_EXECUTION_INDICATOR` | Curated static execution-capable VBA indicator |
| `OFFICE_EXTERNAL_RELATIONSHIP` | External OOXML relationship |
| `OFFICE_EXTERNAL_TEMPLATE` | External Word template relationship |
| `OFFICE_EMBEDDED_OBJECT` | Embedded/package object structure |
| `OFFICE_ACTIVEX` | ActiveX structure |
| `OFFICE_ENCRYPTED` | Encryption prevents complete inspection |
| `OFFICE_PARTIAL_ANALYSIS` | A parser or resource limit prevented complete coverage |
| `OFFICE_MALFORMED` | Required container/XML structure is malformed |

Encryption, malformed components, parser limitations, or resource exhaustion set worker status to
`FAILED`. The trusted completeness policy therefore persists `QUARANTINE`. Complete Office results
are evaluated under the versioned finding and compound policy. Unexpected programming errors still
terminate the worker and are quarantined by trusted orchestration.

## Limitations

- No XLM/Excel 4 macro analysis, P-code/stomping analysis, VBA deobfuscation, or full semantic engine.
- Olevba may miss obfuscated, malformed, novel, or unsupported VBA constructs and may report benign
  capabilities.
- Classic OLE application classification is stream-based and is not a complete binary Office parser.
- Parser-internal VBA decompression occurs within the Bubblewrap/cgroup/rlimit/time boundary; the
  source-byte limit applies immediately after extraction returns.
- No password-assisted inspection or decryption.
- No recursive embedded-document analysis, embedded-content YARA scan, execution, or sanitization.
  The separate Phase 6 YARA pass sees only the original top-level Office file bytes.
- Generated macro fixtures use a valid inert Compound File containing an orphan compressed VBA
  stream so no external binary fixture is required. Olevba recovers the controlled source, while
  DocGuard correctly marks the project structure partial. Fully Office-authored classic VBA fixture
  coverage remains a fixture gap; production formal-project paths are exercised by the same parser.

Absence of Office findings is not proof that the document is benign.
