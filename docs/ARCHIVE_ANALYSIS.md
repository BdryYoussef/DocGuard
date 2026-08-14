# ZIP Archive Analysis

## Scope and routing

Phase 5 supports generic ZIP only. RAR, 7z, TAR, self-extracting archives, password-assisted
inspection, and user-facing extraction are out of scope.

Libmagic first identifies ZIP/OOXML content inside the disposable worker. The Office gate then
validates OPC content types, root relationships, and an application main part. A valid DOCX, XLSX,
or PPTX remains Office; otherwise a valid ZIP enters the generic archive analyzer. Extensions and
HTTP `Content-Type` claims never route it, so a generic ZIP named `.docx` remains generic and an
executable named `.zip` never reaches `zipfile`.

## No extraction

The analyzer uses Python 3.14.4's standard `zipfile` module. It never calls `extract` or
`extractall`, never creates a filesystem path from a member name, and never follows links. Regular
members are opened as streams. Nested ZIPs are held only as bounded byte arrays inside the worker;
attacker-controlled names do not select a temporary filename.

## Paths, links, and duplicates

Path checks are deliberately portable:

- any exact `..` component after treating both slash styles as separators creates
  `ARCHIVE_PATH_TRAVERSAL`;
- leading slash/backslash, `C:\`-style drive roots, and UNC forms create
  `ARCHIVE_ABSOLUTE_PATH`;
- Unix symlinks are recognized from `create_system` plus external mode bits, reported as
  `ARCHIVE_SYMLINK`, and skipped without reading their target as a path.

Duplicate detection applies Unicode NFC, maps backslash to slash, and removes empty and `.` path
components. It does not case-fold names or resolve `..`. Exact and resulting conservative collisions
create `ARCHIVE_DUPLICATE_MEMBER`. This intentionally avoids broad cross-platform canonicalization
that would make ordinary case-distinct archives noisy.

## Member-name findings and privacy

The dangerous-extension registry is shared with top-level filename checks. Execution-capable final
extensions create `ARCHIVE_DANGEROUS_MEMBER`; a business-document extension followed by one of those
extensions creates `ARCHIVE_MEMBER_DOUBLE_EXTENSION`. Security-relevant bidirectional controls
create `ARCHIVE_MEMBER_BIDI_OVERRIDE` before display handling.

Finding metadata retains at most 32 suspicious-name records overall, 16 duplicate records, and 16
traversal/rooted-path records. Each display representation is at most 256 characters under the
default limits. Control and bidi characters are visibly escaped. Member contents and complete
inventories are never returned, persisted, or logged.

## Encryption and compression

The general-purpose bit flag marks encrypted members. DocGuard records `ARCHIVE_ENCRYPTED`, does not
open the member, request a password, decrypt it, or brute-force it, and marks coverage partial.

On the qualified Python 3.14.4 runtime, supported methods are stored (0), deflate (8, zlib 1.3.1),
bzip2 (12), LZMA (14), and Zstandard (93). A method outside the runtime-supported set is not sent to
fallback utilities; it creates `ARCHIVE_PARTIAL_ANALYSIS` with a bounded numeric method identifier.

## Nested ZIP behavior

A regular member is considered a nested ZIP only when its produced bytes begin with a local-file,
empty-archive, or spanning ZIP signature. The extension is irrelevant. Nested archives are inspected
to maximum depth three, and repeated nested content is suppressed by SHA-256 after the first
inspection. Exceeding depth creates `ARCHIVE_NESTING_LIMIT` and `ARCHIVE_PARTIAL_ANALYSIS`.

Recursion is archive-structure recursion only. Child PDFs, Office files, executables, scripts, and
other member content are not passed to their DocGuard analyzers in this phase.

## Actual-byte and resource enforcement

Default worker-side budgets are:

- 4,096 entries per ZIP and 8,192 members across the traversal;
- 128 MiB of actual container bytes considered across root and nested ZIPs;
- 32 MiB of actual output from one member;
- 128 MiB of aggregate actual decompressed output across every nesting level;
- 32 MiB of aggregate nested-ZIP bytes materialized;
- nesting depth three, 512 input-name characters considered for retained display, 64 archive
  findings, and the metadata record caps above.

Reads request at most 64 KiB and tighten to one byte beyond the remaining byte budget, allowing a
limit breach to be proven without trusting `ZipInfo.file_size`. `ARCHIVE_RESOURCE_LIMIT` and
`ARCHIVE_PARTIAL_ANALYSIS` are emitted and traversal stops. The trusted parent still enforces wall
time and stdout/stderr caps; cgroup memory/tasks/CPU, `prlimit`, and sized tmpfs remain defense in
depth around parser-internal allocation.

Compression ratio is not a security decision. Legitimate archives can compress extremely well, and
declared sizes are attacker-controlled. Phase 5 therefore does not emit a ratio-only finding; actual
bytes produced are authoritative.

## Malformed behavior

Invalid or truncated central directories, corrupt CRC/decompression output, and malformed nested
ZIPs create `ARCHIVE_MALFORMED` plus `ARCHIVE_PARTIAL_ANALYSIS`. Only expected parser/input failures
are converted into structured results. Unexpected programming failures exit the worker, after which
trusted orchestration preserves quarantine through its existing non-zero/malformed-output path.

Python constructs the central-directory entry list before DocGuard can apply its entry-count limit.
That parser-internal allocation is bounded by the worker cgroup, address-space rlimit, CPU limit, and
external timeout, but cannot be made proportional to the configured entry limit using `zipfile`.

## Interpretation limits

- No content identification for ordinary children beyond the bounded nested-ZIP signature check.
- No recursive PDF/Office analysis, archive-member YARA scan, antivirus, script semantics, or
  execution. The separate Phase 6 YARA pass sees only the original top-level ZIP bytes.
- No password-assisted inspection or non-ZIP archive formats.
- Filename checks can produce false positives for legitimate administrative/script bundles.
- Unusual encoding, unsupported link metadata, parser discrepancies, or structures beyond limits
  may be missed.
- Python, `zipfile`, and its compression libraries remain hostile-input attack surface contained by
  the existing production sandbox.

Absence of archive findings is not proof that the archive or its contents are benign.
