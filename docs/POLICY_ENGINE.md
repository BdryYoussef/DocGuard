# Policy and Risk Decision Engine

## Authority and version

Policy version `1.0.2` is trusted product code in `app/policies/`. It adds `PDF_EXTERNAL_SUBMISSION`
and `PDF_FALLBACK_INDICATOR` — both explanatory-only findings with `contribution=0`, no decision
floor, and no hard-block — for the PDF explainability enhancements described in
`docs/PDF_ANALYSIS.md`. Its normalized registry fingerprint is:

```text
c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b
```

Because both new codes contribute zero score and no decision floor, `1.0.1` and `1.0.2` produce
byte-identical `risk_score`, `risk_band`, `decision`, and `release_eligible` for every finding-code
combination that was reachable under `1.0.1` — the version changed because the registry's code
coverage changed, not because any decision behavior changed. See "Phase 11 comparability" below.

The worker observes characteristics. It does not choose weights, risk bands, decision floors,
hard-block behavior, release eligibility, policy identity, or the final decision. The legacy worker
`score_delta` contract field must be exactly zero; any other value invalidates worker output. The
trusted side persists the registry-owned contribution separately.

The policy registry is immutable and server-controlled. Readiness requires an exact mapping for
every registered finding code, no unknown or duplicate policy code, bounded contributions, valid
decision floors, valid compound references, unique compound names, and the expected fingerprint.
There is no partial policy loading or user-configurable policy input.

## Decision semantics and precedence

Evaluation uses this fixed order:

1. a semantic hard-block finding produces `BLOCK`;
2. incomplete analysis or a mandatory containment condition produces `QUARANTINE`;
3. otherwise the bounded score produces `QUARANTINE`, `REVIEW`, or `ALLOW`;
4. only `ALLOW` sets `release_eligible=true`.

The decisions mean:

- `ALLOW`: configured analysis completed for a release-supported content family, and no modeled
  condition requires review or containment. It is not proof of benignity.
- `REVIEW`: complete analysis found characteristics requiring human review. It is not release
  eligible in this phase.
- `QUARANTINE`: significant modeled risk exists or sufficient analysis could not be completed.
- `BLOCK`: a specific high-confidence policy violation prevents normal release. BLOCK is semantic,
  not a score threshold.

There is no source-release or raw-quarantine download endpoint. `release_eligible` is persisted
explicitly so code does not infer it from state strings. The controlled artifact endpoint serves
only a separately reconstructed and re-analyzed CDR output after fresh lineage, policy, filesystem,
and digest validation.

## Score and risk bands

The score is the sum of each distinct finding-code contribution plus each triggered compound bonus,
clamped to `100`. A repeated finding code contributes once, regardless of attacker-controlled
structure counts or the number of YARA rules mapped to the same finding class. Compounds operate on
code presence and trigger at most once.

| Score | Band | Score-based decision when no higher-precedence rule applies |
|---:|---|---|
| 0–19 | LOW | ALLOW |
| 20–39 | MODERATE | REVIEW |
| 40–69 | HIGH | QUARANTINE |
| 70–100 | CRITICAL | QUARANTINE |

The DocGuard risk score is a deterministic policy score, not a probability that a file is
malicious. High or critical collections of heuristics remain `QUARANTINE`; they do not become
`BLOCK` without a semantic hard-block definition.

## Finding policy registry

`Q` means a mandatory `QUARANTINE` floor. `B` means semantic hard `BLOCK`.

| Finding code | Score | Floor | Policy interpretation |
|---|---:|---|---|
| `FILE_DOUBLE_EXTENSION` | 24 | — | Dangerous extension after document extension |
| `FILE_BIDI_OVERRIDE` | 24 | — | Visual filename deception |
| `FILE_TYPE_MISMATCH` | 28 | — | Filename and observed family conflict |
| `FILE_EXECUTABLE_MASQUERADE` | 50 | B | Executable presented as business document |
| `FILE_CLIENT_MIME_MISMATCH` | 2 | — | Low-confidence client metadata discrepancy |
| `PDF_JAVASCRIPT` | 20 | — | JavaScript capability |
| `PDF_OPEN_ACTION` | 16 | — | Open-time action |
| `PDF_ADDITIONAL_ACTION` | 18 | — | Event-triggered action |
| `PDF_LAUNCH_ACTION` | 45 | Q | External launch capability |
| `PDF_EMBEDDED_FILE` | 24 | — | Non-recursively analyzed embedded content |
| `PDF_ACROFORM` | 8 | — | Interactive form |
| `PDF_XFA` | 24 | — | Unrendered/unexecuted XFA content |
| `PDF_EXTERNAL_URI` | 8 | — | Passive external URI reference |
| `PDF_EXTERNAL_SUBMISSION` | 0 | — | Explanatory only: SubmitForm target is external |
| `PDF_ENCRYPTED` | 8 | — | Encryption capability; completeness is separate |
| `PDF_PARTIAL_ANALYSIS` | 25 | Q | Incomplete PDF coverage |
| `PDF_MALFORMED` | 45 | Q | Unreliable malformed structure |
| `PDF_FALLBACK_INDICATOR` | 0 | — | Explanatory only: bounded lexical evidence from an incomplete parse |
| `OFFICE_MACRO_ENABLED` | 8 | — | Macro-enabled container |
| `OFFICE_VBA_MACRO` | 18 | — | VBA project present |
| `OFFICE_VBA_AUTOEXEC` | 28 | — | Automatic VBA entry point |
| `OFFICE_VBA_EXECUTION_INDICATOR` | 30 | — | Execution-capable VBA constructs |
| `OFFICE_EXTERNAL_RELATIONSHIP` | 8 | — | Passive external relationship |
| `OFFICE_EXTERNAL_TEMPLATE` | 42 | Q | Remote template reference |
| `OFFICE_EMBEDDED_OBJECT` | 24 | — | Non-recursively analyzed embedded object |
| `OFFICE_ACTIVEX` | 24 | — | ActiveX structure |
| `OFFICE_ENCRYPTED` | 8 | — | Encryption capability; completeness is separate |
| `OFFICE_PARTIAL_ANALYSIS` | 25 | Q | Incomplete Office coverage |
| `OFFICE_MALFORMED` | 45 | Q | Unreliable malformed structure |
| `ARCHIVE_PATH_TRAVERSAL` | 50 | B | Extraction-root traversal semantics |
| `ARCHIVE_ABSOLUTE_PATH` | 50 | B | Rooted member path |
| `ARCHIVE_SYMLINK` | 45 | B | Unsafe extraction-link semantics for V1 users |
| `ARCHIVE_DUPLICATE_MEMBER` | 20 | — | Ambiguous duplicate names |
| `ARCHIVE_DANGEROUS_MEMBER` | 42 | Q | Execution-capable member name |
| `ARCHIVE_MEMBER_DOUBLE_EXTENSION` | 32 | — | Deceptive execution-capable member |
| `ARCHIVE_MEMBER_BIDI_OVERRIDE` | 28 | — | Visual member-name deception |
| `ARCHIVE_ENCRYPTED` | 8 | — | Uninspected encrypted member; completeness is separate |
| `ARCHIVE_NESTING_LIMIT` | 25 | Q | Nesting limit stopped coverage |
| `ARCHIVE_RESOURCE_LIMIT` | 35 | Q | Resource budget stopped coverage |
| `ARCHIVE_MALFORMED` | 45 | Q | Unreliable malformed structure |
| `ARCHIVE_PARTIAL_ANALYSIS` | 25 | Q | Incomplete archive coverage |
| `YARA_TEST_SIGNATURE` | 50 | B | Controlled anti-malware test signature |
| `YARA_SIGNATURE_MATCH` | 50 | B | Reviewed high-confidence local signature |
| `YARA_HEURISTIC_MATCH` | 42 | Q | Significant local heuristic, not malware proof |
| `YARA_PARTIAL_ANALYSIS` | 25 | Q | Incomplete YARA coverage |

EICAR's hard block means a controlled anti-malware test signature was detected. It does not label
EICAR as real malware. The current pack has no non-test `YARA_SIGNATURE_MATCH` rule.

## Compound policies

| Stable compound code | Required finding codes | Bonus | Floor |
|---|---|---:|---|
| `POLICY_COMPOUND_PDF_AUTO_JS` | `PDF_JAVASCRIPT` + `PDF_OPEN_ACTION` | 20 | Q |
| `POLICY_COMPOUND_OFFICE_MACRO_EXECUTION_CHAIN` | `OFFICE_VBA_MACRO` + `OFFICE_VBA_AUTOEXEC` + `OFFICE_VBA_EXECUTION_INDICATOR` | 25 | Q |
| `POLICY_COMPOUND_OFFICE_AUTOEXEC_YARA` | `OFFICE_VBA_AUTOEXEC` + `YARA_HEURISTIC_MATCH` | 15 | Q |
| `POLICY_COMPOUND_ARCHIVE_MEMBER_MASQUERADE` | `ARCHIVE_DANGEROUS_MEMBER` + `ARCHIVE_MEMBER_DOUBLE_EXTENSION` | 18 | Q |
| `POLICY_COMPOUND_FILE_IDENTITY_DECEPTION` | `FILE_DOUBLE_EXTENSION` + `FILE_TYPE_MISMATCH` | 18 | Q |

Compound names, contributions, explanations, and decision floors are included in public evaluation
reasons and the policy fingerprint. No compound can create `BLOCK`.

## Analysis completeness

Completeness uses validated worker status, detected content family, orchestration failure status,
scan lifecycle, and partial/malformed findings. It is not inferred merely from an absent partial
finding. Timeout, failed or unsupported status, missing/malformed worker output, isolation failure,
unsupported detected type, resource exhaustion, and coverage-preventing encryption remain
non-release.

A contradictory `SUCCESS` result containing a `*_PARTIAL_ANALYSIS` or `*_MALFORMED` finding receives
`POLICY_ANALYSIS_CONTRADICTION` and is quarantined. Encryption alone is not a hard block: when
analysis is genuinely complete it contributes only its documented capability score; when it hides
content, the failed/partial result forces quarantine.

## Persistence and transaction behavior

The final scan transaction prepares findings, evaluates policy, then atomically persists score,
band, decision, release eligibility, policy version/fingerprint, and the bounded normalized
evaluation. `ALLOW` is never committed before that transaction succeeds. A policy exception creates
a persisted fail-closed quarantine evaluation. A database failure rolls the final transaction back,
leaving the earlier `ANALYZING` row with its original `QUARANTINE` decision and no release
eligibility.

`GET /api/v1/scans/{scan_id}` returns the persisted evaluation. It never silently applies the
current policy to historical evidence. Explicit policy re-evaluation is out of scope.

## Phase 11 comparability (policy `1.0.1` → `1.0.2`)

The `1.0.2` registry adds exactly two finding codes, both `contribution=0` with no decision floor
and no hard-block. For any finding-code combination reachable under `1.0.1`:

- neither new code can appear in a `1.0.1`-analyzed sample's findings (the analyzer changes that
  produce them shipped together with this policy version);
- when either new code is present under `1.0.2`, it adds `0` to the score sum and no mandatory
  floor, so `risk_score`, `risk_band`, `decision`, and `release_eligible` are unchanged from what the
  same underlying structural findings would have produced under `1.0.1`.

The published Phase 11 (`evaluation/results/phase11b/`) headline numbers were produced under policy
`1.0.1` and are not retroactively rewritten — they remain an accurate historical record of that run.
They remain directly comparable to a `1.0.2` run on the same corpus: per-sample decisions and risk
scores are provably identical, so a fresh Phase 11 execution was not required to validate this
change. A fresh run is still worth doing before the next official release cycle, purely so the
published headline artifacts reference the currently-shipped policy version string.

## API explanations and limitations

The API returns trusted bounded reasons and contribution values, never worker score claims or raw
parser/YARA content. Its standard disclaimer is:

> Absence of findings is not proof that a file is benign.

ALLOW means that the configured analysis completed without a finding requiring containment under
the active policy. It is not proof that the file is benign.

Policy weights encode product handling choices and can produce false-positive containment or miss
unmodeled threats. The model has no probability calibration, dynamic execution, reputation data,
AI/ML judgment, user policy editor, automatic rule update, recursive child analysis, or release
workflow.
