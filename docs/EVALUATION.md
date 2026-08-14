# DocGuard Phase 11 Evaluation

## 1. Objective

Phase 11 measures how well DocGuard's *existing, frozen* detection model (Phase 10)
performs against a controlled, ground-truthed, synthetic corpus of inert fixtures,
executed through the real production analysis path (Bubblewrap-isolated worker →
trusted policy engine).

## 2. Research question

> Does DocGuard reliably identify the risky document characteristics it claims to
> detect, avoid unnecessary escalation on controlled benign documents, operate within
> reasonable latency on the target host, and fail securely when analysis cannot safely
> complete?

## 3. Scope

Phase 11A (frozen) built the evaluation framework and a 59-case pre-registered corpus.
Phase 11B executed that frozen corpus once, officially, through the real Bubblewrap
production path, measured the results, evaluated the CDR subset, investigated every
discrepancy, and produced this report from the actual measured data. Both phases
evaluated the detector that already existed; neither phase added, removed, or tuned any
detection rule, policy threshold, YARA rule, or CDR behavior.

## 4. What DocGuard does NOT claim, and what this report does not prove

This is **not** a malware-detection benchmark. This report makes none of the following
claims:

- a malware detection rate;
- that DocGuard is a substitute for antivirus or EDR;
- zero-day or novel-threat detection capability;
- that `ALLOW` proves a document is benign — **ALLOW means no modeled risky
  characteristic was observed at the configured static-analysis depth, not that the
  document is safe**;
- general real-world detection accuracy against adversarial or live-malware samples.

## 5. Methodology

DocGuard's detector was evaluated, not redesigned. Ground truth was **pre-registered**
before the official run: cryptographic hashes of the corpus manifest and its defining
source were recorded (section 6) before a single official Bubblewrap execution, and
no label, expected finding, acceptable decision, fail-secure expectation, fixture
content, CDR flag, policy threshold, YARA rule, or detector behavior was changed after
observing official results. Section 23 discloses the one legitimate framework change
made before the official run (adding CDR execution capability to the runner, which
Phase 11A had only schema-prepared, never wired up), and confirms it did not touch the
corpus or ground truth.

## 6. Pre-registration / frozen ground truth

Recorded **before** the official Bubblewrap execution:

| Identity | Value |
| --- | --- |
| Git commit (corpus/ground-truth checkpoint) | `b94d373884fb4f737cdf4f07cc7eccf08ffb8252` |
| `evaluation/corpus_manifest.json` SHA-256 | `c7959cc3f1e28a2663ae06c6d1585624f1c542dea8493c6247aea70fe3e8afd0` |
| `evaluation/corpus.py` SHA-256 | `656bbec78e0fecaced9129054ba2f2f7a76123c66cc5cafa5609a75986ccad83` |
| `evaluation/models.py` SHA-256 | `e8824dac3650d63715b0b91eaa5a9fb44c1d3ab65fed8ec2ff23ea906c9c9191` |
| `evaluation/manifest.py` SHA-256 | `62f257276d1f403de9e0878d62833d9af642887be9ccce13912ac16c01affaaa` |
| Corpus version | `11A.1` |
| Corpus case count | 59 |

These four hashes were re-verified immediately before the official run and matched
exactly; none of these four files changed at any point during Phase 11B. Manifest
validation (`--validate-manifest`) and dry-run materialization (`--dry-run`) both passed
against this exact checkpoint, with zero duplicate case IDs.

## 7. Corpus composition

| Category | Count |
| --- | ---: |
| BENIGN_PDF | 4 |
| RISKY_PDF | 12 |
| BENIGN_OFFICE | 6 |
| RISKY_OFFICE | 10 |
| BENIGN_ARCHIVE | 5 |
| RISKY_ARCHIVE | 12 |
| FILE_IDENTITY | 5 |
| YARA | 5 |
| **Total** | **59** |

18 benign, 41 risky. 9 cases are pre-registered fail-secure. 3 cases are pre-registered
CDR cases (all PDF-family).

## 8. Corpus safety

Every fixture is generated locally, deterministically, and inertly by composing the
existing, already-reviewed `tests/fixtures/*` factories. No sample was downloaded from
any external source; no macro, script, embedded payload, archive member, or generated
document content was ever executed. See [evaluation/README.md](../evaluation/README.md)
and `evaluation/corpus.py` for details.

## 9. Execution architecture

The official runner (`evaluation/runner.py`, `python -m scripts.run_evaluation
--execute`) drives the real production path for every case:

```
fixture -> secure ingestion -> private temporary storage -> Bubblewrap worker
        -> content identification -> analyzer(s) -> YARA (top-level file)
        -> versioned worker contract -> trusted policy engine
        -> persisted findings/decision
```

Each case is a real `POST /api/v1/scans` call against a running `create_app(settings)`
instance behind an `httpx.ASGITransport`, through an authenticated operator session —
the same code path the production HTTP API and the integration test suite use. No
detector or analyzer helper function was called directly for official results.

The CDR subset additionally calls the real `POST /api/v1/scans/{id}/sanitize` endpoint
and reads back both the source and derived scans via `GET /api/v1/scans/{id}`.

## 10. Production Bubblewrap confirmation

The official run used `IsolationBackendName.BUBBLEWRAP` (the runner's default), **not**
`unsafe-development`. Evidence:

- `bubblewrap_version: "bubblewrap 0.11.1"` was captured in the run's reproducibility
  metadata by shelling out to the real `bwrap --version` binary — this value is only
  populated when the real backend executed real worker subprocesses.
- Each case's `worker_status` reflects a real analyzer/YARA run inside the sandbox
  (`SUCCESS`/`FAILED`), and latencies (136 ms–590 ms per case; see section 20) are
  consistent with real Bubblewrap sandbox setup/teardown overhead observed throughout
  Phase 10, not with the near-instant in-process dummy path `unsafe-development` uses.
- The isolated temporary SQLite database and storage root were created fresh under a
  `tempfile.TemporaryDirectory`, confirmed by a byte-identical `var/` directory
  checksum taken immediately before and after the run (no file under the repository's
  normal `var/` was created, modified, or read).

## 11. Reproducibility metadata

Captured automatically by `evaluation.runner.gather_reproducibility_metadata()` for the
official run (`evaluation/results/phase11b/metrics.json`):

| Field | Value |
| --- | --- |
| Timestamp | `2026-08-14T23:35:38.843095Z` |
| Git commit | `b94d373884fb4f737cdf4f07cc7eccf08ffb8252` |
| Policy version / fingerprint | `1.0.1` / `717ac1bbbea13acc61c47a241673ee05616c241318e2c0c691240995f2bf9333` |
| YARA rule pack version / SHA-256 | `2026.08.1` / `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` |
| Sanitizer version / fingerprint | `1.0.0` / `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` |
| Python version | `3.14.4` |
| Platform | `Linux-x86_64` (no hostname/username) |
| Bubblewrap version | `bubblewrap 0.11.1` |
| qpdf version | `qpdf version 12.3.2` |
| PyMuPDF (CDR renderer) | `1.28.2` |
| Other worker dependencies | pikepdf `10.11.0`, oletools `0.60.2`, olefile `0.47`, defusedxml `0.7.1`, yara-python `4.5.4` |

No username, home directory, temporary absolute path, password, or session token
appears in any retained artifact — verified programmatically
(`evaluation.reporting.find_private_path_leak`) against every file in
`evaluation/results/phase11b/`.

## 12. Risky-case detection recall

**41 / 41 = 100.0%.**

All 41 pre-registered risky cases with at least one mandatory expected finding had
every one of those findings observed by the real pipeline. **No risky case was missed.**

## 13. Finding-level recall

**Overall: 72 / 72 = 100.0%** (every individual expected finding, across all cases,
was observed).

By family:

| Family | Recall |
| --- | --- |
| PDF | 17/17 = 100.0% |
| Office | 27/27 = 100.0% |
| Archive | 17/17 = 100.0% |
| File Identity | 6/6 = 100.0% |
| YARA | 5/5 = 100.0% |

## 14. Benign escalation rate

**0 / 18 = 0.0%.** No benign case was escalated to REVIEW, QUARANTINE, or BLOCK; there
is no escalated-case list to report.

## 15. Benign ALLOW rate

**18 / 18 = 100.0%.** All 18 pre-registered benign cases received `ALLOW`.

**ALLOW is not proof of benignity.** It means the configured static analysis at its
current depth observed none of the risky characteristics this corpus's benign fixtures
were constructed to avoid; DocGuard does not execute, sandbox-detonate, or otherwise
prove document safety beyond structural/YARA inspection.

## 16. Decision compliance

**59 / 59 = 100.0%.** Every case's actual decision was a member of that case's
pre-registered `acceptable_decisions` set (never a numeric `ALLOW < REVIEW <
QUARANTINE < BLOCK` ranking — see `evaluation.metrics.decision_compliance_rate`). Zero
mismatches.

## 17. Analysis completeness

| Class | Count |
| --- | ---: |
| COMPLETE | 44 |
| INTENTIONAL_PARTIAL | 10 |
| PARSER_FAILURE | 3 |
| RESOURCE_LIMIT_FAILURE | 1 |
| OTHER_FAIL_CLOSED | 1 |

The single `OTHER_FAIL_CLOSED` case is `FID-004` (an inert Windows-executable payload
uploaded under a `.pdf` filename): its detected type (`WINDOWS_EXECUTABLE`) is not a
release-supported type, so `analysis_complete` is correctly `False` even though
`worker_status` is `SUCCESS` and all three expected findings
(`FILE_EXECUTABLE_MASQUERADE`, `FILE_TYPE_MISMATCH`, `FILE_CLIENT_MIME_MISMATCH`) were
observed exactly and the decision (`BLOCK`) was fully compliant. This is expected,
correct, fail-closed behavior for an unsupported release type, not a defect; the
evaluation framework's completeness-class heuristic simply has no more specific bucket
name for it than "other fail-closed."

## 18. Fail-secure results

**9 / 9 = 100.0%.** Every pre-registered fail-secure case (encrypted PDF, malformed
PDF, encrypted Office, inconsistent-package Office, encrypted archive member, archive
nesting-limit, archive resource-limit, malformed archive, unsupported-compression
archive) ended with `release_eligible: False`. No incomplete mandatory analysis
silently became an ordinary `ALLOW`. The trusted application remained healthy and
responsive after every one of these cases (see section 19).

## 19. Resilience sequence

Executed as a dedicated, ordered, single-session sequence through the real Bubblewrap
backend: `PDF-BEN-001` (valid) → `PDF-RISK-012` (malformed, pre-registered fail-secure)
→ `PDF-BEN-002` (valid). Result:

| Case | Decision | Worker status |
| --- | --- | --- |
| PDF-BEN-001 | ALLOW | SUCCESS |
| PDF-RISK-012 | QUARANTINE | FAILED (fail-closed, as pre-registered) |
| PDF-BEN-002 | ALLOW | SUCCESS |

The malformed case failed closed exactly as pre-registered; the application accepted
and correctly processed the next valid upload immediately afterward with no
degradation, restart, or manual intervention. Raw sequence retained at
`evaluation/results/phase11b/resilience_sequence.json`.

## 20. Latency / performance

Over all 59 official cases (real Bubblewrap sandbox setup + teardown included in every
measurement):

| Statistic | Value |
| --- | --- |
| count | 59 |
| mean | 288.9 ms |
| median | 317.0 ms |
| min | 136 ms |
| max | 590 ms |
| p95 (nearest-rank) | 386 ms |

This is a descriptive statistic over one run on one development host, not a
scientific microbenchmark; it should not be read as a production SLA. No per-category
timing pattern was investigated beyond the aggregate figures above — the corpus is too
small (59 cases across 8 categories) for per-category latency breakdowns to be
statistically meaningful, and none is claimed.

## 21. Resource behavior

**Peak worker memory was not measured reliably in Phase 11.** The existing
infrastructure does not expose a reliable, low-overhead cgroup memory-peak reading path
that Phase 11B's scope justified building; no such instrumentation was added, and no
value is fabricated or inferred. The only reliably observed resource signal is the
`ARCHIVE_RESOURCE_LIMIT` finding on `ARC-RISK-010` (the 4,200-entry archive), which
fired exactly as pre-registered, evidencing that the archive resource-limit path is
reachable and functions correctly under real execution.

## 22. CDR evaluation

Executed separately from detection recall, through the real Bubblewrap backend, for all
3 pre-registered CDR cases:

| Case | Source decision | CDR eligible | Request outcome | Derived scan | Derived decision | Derived release-eligible | Source decision unchanged |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PDF-RISK-003 | QUARANTINE | true | approved | `8a436e1d...` | ALLOW | true | **true** |
| PDF-RISK-006 | REVIEW | true | approved | `75ec16db...` | ALLOW | true | **true** |
| PDF-RISK-010 (EICAR-tainted PDF) | **BLOCK** | **false** | rejected (ineligible) | none | none | none | **true** |

**CDR recovery rate: 2 / 2 = 100.0%** (eligible controlled PDF cases attempted that
produced a release-eligible derived artifact / eligible controlled PDF cases attempted).

Verified directly from real API responses, not assumed:

- **The source scan's decision never changed because of CDR** — re-fetched via `GET
  /api/v1/scans/{source_id}` after the sanitize call for all 3 cases; all 3 matched the
  pre-sanitize decision exactly.
- **The source object never became release-eligible merely because CDR succeeded** —
  `PDF-RISK-003` and `PDF-RISK-006`'s source scans remained `QUARANTINE`/`REVIEW`
  respectively; only their *derived* scans (separate scan IDs) became `ALLOW`.
- **A BLOCK source cannot be CDR-released** — `PDF-RISK-010` (hard-blocked by the
  controlled EICAR test signature) was correctly rejected as CDR-ineligible; no derived
  scan was ever created.
- **The derived artifact is fully re-analyzed, not merely copied** — both successful
  cases produced a distinct `derived_scan_id` that was independently fetched and found
  to carry its own decision and release-eligibility, produced by the same trusted
  policy engine.
- **Only the derived, approved artifact is release-eligible** — the source's own
  `release_eligible` field was confirmed unchanged (`false`) in both successful cases.

## 23. Unexpected results

**None.** All 59 cases matched their pre-registered expectations exactly: 0 missing
expected findings, 0 unexpected findings, 100% decision compliance, 100% fail-secure
containment, 100% CDR-eligibility/outcome match. No classification exercise (fixture
defect / ground-truth defect / evaluator defect / documented conservative behavior /
documented limitation / real bug) was required because no discrepancy occurred.

## 24. Bugs discovered

**None discovered.**

## 25. Limitations

See section 26 for the full methodological-limitations list required by the Phase 11B
brief. In addition:

- The evaluation framework's `completeness_class` heuristic
  (`evaluation.runner._infer_completeness_class`) is a coarse, evaluation-side
  classifier over finding-code suffixes; it is not part of DocGuard's trusted policy
  output and should not be read as a DocGuard-native completeness taxonomy (see
  section 17).
- Latency and CDR-recovery figures come from a single official run on a single
  development host; no repeated-trial variance estimate exists.

## 26. Interpretation

Within this controlled 59-case corpus and the explicitly covered static detection
model, DocGuard detected all mandatory expected characteristics in every evaluable
risky case, produced zero unnecessary escalations on the controlled benign set,
remained decision-compliant on every case, kept every fail-secure case non-release-
eligible, demonstrated CDR immutability and BLOCK-ineligibility exactly as designed,
and recovered from an induced parser failure without any loss of service. These results
are internally consistent with Phase 10's frozen, already-reviewed detection and policy
logic, and were pre-registered before the official run.

## 27. What results do NOT prove

- Not a malware detection rate.
- Not evidence against adversarially crafted or obfuscated real-world attack
  documents, which this synthetic corpus does not contain.
- Not proof that `ALLOW` implies a document is safe to open blindly.
- Not a general accuracy claim outside the eight covered categories.
- Not a production-scale performance guarantee (single host, single run, 59 cases).

## 28. Reproduction instructions

```bash
# safe, no-execution modes
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --list-cases
python -m scripts.run_evaluation --dry-run

# official execution (real Bubblewrap backend, requires explicit case IDs)
python -m scripts.run_evaluation --execute --case-id PDF-BEN-001 --case-id PDF-RISK-003 \
    --output-dir evaluation/results/phase11b
```

Verify pre-registration integrity before trusting any run's results:

```bash
sha256sum evaluation/corpus_manifest.json evaluation/corpus.py evaluation/models.py evaluation/manifest.py
```

Compare against section 6. Retained official artifacts:
`evaluation/results/phase11b/{results.json,results.csv,metrics.json,report.md,resilience_sequence.json}`.

## 29. Disclosed methodological limitation: Phase 11A ad hoc run

While authoring ground truth in Phase 11A, the full 59-case corpus was run once, ad
hoc, through the `unsafe-development` isolation backend (not Bubblewrap) purely to
confirm that hand-derived ground truth matched real DocGuard behavior before freezing
it. That run:

- was **not** the official benchmark;
- did **not** use production Bubblewrap isolation;
- produced **no retained report artifacts** (nothing was written to
  `evaluation/results/`);
- is **not** presented anywhere in this document as Phase 11 evidence.

The official Phase 11B benchmark reported above began only after that ground truth was
frozen (section 6) and used exclusively the real Bubblewrap-isolated production path.
