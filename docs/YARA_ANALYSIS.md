# YARA Analysis

## Purpose and trust boundary

YARA is a supplementary, deterministic detector for controlled lexical signatures and patterns in
the submitted file. It is not an antivirus replacement and does not prove that a file is benign.
The trusted FastAPI/database process never imports yara-python, compiles rules, or asks YARA to read
document bytes. Those operations occur once per job inside the disposable Bubblewrap worker.

The worker scans only the descriptor-bound top-level file mounted read-only at
`/input/document`. YARA runs after file identification and the applicable PDF, Office, or generic
ZIP structural analyzer. Its result supplements structural findings and cannot change an
unsupported, failed, malformed, encrypted, timed-out, or partial structural result into success.

## Runtime and rule-pack scope

The worker dependency artifact pins yara-python 4.5.4, embedding YARA 4.5.4. It compiles exactly one
product-owned source file, `worker/rules/docguard_v1.yar`, under the `docguard` namespace. The pack
version is `2026.08.1`; its SHA-256 is:

```text
7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7
```

The engine rejects missing or oversized rule source, fingerprint mismatch, duplicate or unexpected
rule declarations, manifest mismatch, `import`, `include`, and compilation failure. The worker
mount containing the rule source is read-only. Neither the API nor the worker JSON request contract
contains a rule path, rule source, namespace, or rule-selection field.

## Production rules

| Stable rule ID | Purpose | Confidence | Finding class | ATT&CK context |
|---|---|---|---|---|
| `DOCGUARD_EICAR_TEST` | Recognizes the standard controlled EICAR anti-malware test string | TEST | `YARA_TEST_SIGNATURE` | None |
| `DOCGUARD_POWERSHELL_ENCODED` | Requires a PowerShell executable reference, encoded-command argument, and substantial Base64-like value | HEURISTIC | `YARA_HEURISTIC_MATCH` | T1059.001 |
| `DOCGUARD_WSCRIPT_ENGINE_INVOCATION` | Requires a Windows Script Host invocation selecting a script engine and naming a supported script extension | HEURISTIC | `YARA_HEURISTIC_MATCH` | T1059.005 |
| `DOCGUARD_CMD_CHAIN_INVOCATION` | Requires a `cmd.exe` execution argument and chained command operator in a bounded command-line pattern | HEURISTIC | `YARA_HEURISTIC_MATCH` | T1059.003 |
| `DOCGUARD_MSHTA_SCRIPT_SCHEME` | Recognizes an `mshta` invocation followed by an inline JavaScript or VBScript scheme | HEURISTIC | `YARA_HEURISTIC_MATCH` | T1218.005 |
| `DOCGUARD_CERTUTIL_URLCACHE` | Requires certutil URL-cache and split arguments with an HTTP target | HEURISTIC | `YARA_HEURISTIC_MATCH` | T1105 |

EICAR is a safe testing convention, not real malware. The current production pack has no
non-test rule classified as a high-confidence signature; `YARA_SIGNATURE_MATCH` is a stable finding
class reserved for a future reviewed local signature whose manifest explicitly assigns that
confidence.

ATT&CK identifiers are contextual mappings supplied by DocGuard's trusted rule registry. A match is
not proof that an ATT&CK technique was successfully executed.

## Findings and trusted metadata

The stable finding codes are:

- `YARA_TEST_SIGNATURE`: controlled test-signature match.
- `YARA_SIGNATURE_MATCH`: reviewed high-confidence local signature match; currently unused by the
  production pack.
- `YARA_HEURISTIC_MATCH`: explainable combined lexical-pattern match.
- `YARA_PARTIAL_ANALYSIS`: a timeout, scanner warning/error, or reporting/resource limit prevented
  complete YARA coverage.

For each match, the worker returns only a trusted rule ID, bounded match count, bounded string
identifier names, bounded nonnegative offsets, top-level scope, and the fixed rule-pack version and
fingerprint. The trusted Pydantic contract then requires the exact registry-owned title,
explanation, category, confidence, severity, finding code, and ATT&CK list for that rule ID. Unknown
IDs or spoofed presentation data invalidate the entire worker result and preserve quarantine.

## Privacy and logging

DocGuard does not retain or expose matched bytes, complete scripts or commands, document excerpts,
YARA tags, arbitrary YARA rule metadata, or internal rule paths. The engine configures one byte as
the native maximum match-data capture and deliberately never accesses that captured data. API,
database, and structured-log tests use controlled secrets to verify that raw matches do not cross
the worker boundary.

Logs contain only bounded operational fields such as scan/job ID, event type, pack version,
matched-rule count, status, and duration. They never contain document strings or YARA payload data.

## Resource controls and incomplete analysis

The YARA engine has a three-second internal scan timeout. The trusted parent independently enforces
the whole-worker wall-clock timeout and kills the process group on expiry. Existing Bubblewrap,
network namespace, cgroup memory/process/CPU controls, `prlimit` limits, tmpfs sizes, and bounded
stdout/stderr capture remain authoritative around the native runtime.

The default reporting limits are 32 matched rules, 4,096 match instances per rule, 16 retained
string identifiers per rule, 16 retained offsets per rule, 12 KiB total YARA metadata, and one byte
of native match data. The overall worker finding and JSON limits also apply. Limit exhaustion,
native scan warnings, internal timeout, or a controlled scanner error produces
`YARA_PARTIAL_ANALYSIS`, worker status `FAILED`, and quarantine. Pack integrity, manifest, or unknown
rule failures terminate the worker and fail closed rather than falling back to a partial rule set.

## Production readiness

Readiness is not based on module or file presence. Inside the actual production sandbox the probe:

1. imports exactly yara-python 4.5.4 and YARA 4.5.4 from the worker dependency artifact;
2. verifies the source fingerprint and exact six-ID manifest;
3. compiles the complete fixed pack with an internal timeout available;
4. verifies that EICAR matches only `DOCGUARD_EICAR_TEST`;
5. verifies that a benign controlled fixture produces no match; and
6. proves that the mounted rule pack cannot be written.

Any failure makes production readiness false. Unit tests additionally prove that malformed packs
and unexpected added rules fail qualification. No partial pack is accepted.

## False positives and false negatives

The command-pattern rules are heuristics. Legitimate deployment scripts, incident-response notes,
administration guides, or security training material can contain matching combinations. Patterns
therefore require multiple contextual elements, and benign PowerShell, WScript, command-shell, and
ordinary prose fixtures guard against obvious noisy forms. A finding describes an observed pattern;
it does not claim malware or execution.

YARA can miss obfuscated, encrypted, fragmented, transformed, compressed, novel, or semantically
equivalent content. It does not parse document object graphs, emulate interpreters, execute content,
or establish intent. Structural analyzers remain separate and authoritative for their modeled
coverage.

## Deliberate exclusions

Phase 6 does not scan ZIP members, nested archives, OOXML parts, VBA project streams, PDF
attachments, embedded objects, or other child content. It performs no extraction or decompression
for YARA and does not recursively dispatch child objects. It also excludes community rules,
automatic downloads, VirusTotal rules, user-supplied rules, arbitrary imports/modules, threat-feed
updates, and API rule management. These exclusions keep rule provenance, native attack surface,
resource use, confidentiality, and finding semantics reviewable.

## Safe fixture policy

Tests generate controlled content locally: EICAR, combined PowerShell/WScript/cmd/mshta/certutil
patterns, benign prose near-misses, an inert PE-signature-like blob, and generated PDF, Office, and
ZIP documents. No fixture is executed, no malware is downloaded, and no submitted sample is sent to
a third party.

Absence of a YARA match is not proof that a document is benign. The permitted product statement is:

> DocGuard did not observe risky characteristics covered by the configured detection model.
