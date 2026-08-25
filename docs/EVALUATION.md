# DocGuard Phase 11 Evaluation

This document has three parts, kept clearly separate:

- **Part A — §1–29, Historical Phase 11B.** The original official controlled
  benchmark, executed once under policy `1.0.1`. Frozen, immutable evidence —
  never edited, rewritten, or re-labeled after the fact. Read it as a record
  of what was true at that commit and policy version, not as a description
  of the current release.
- **Part B — §30–43, Phase 11C current-release revalidation.** A *new*,
  separate run of the identical frozen 59-case corpus against v1.1.0 (current
  HEAD at the time) and policy `1.0.2`, added to check whether that release
  still behaves the way Phase 11B measured. Does not replace or supersede
  Part A — a compatibility check, reported alongside the original.
- **Part C — §44–52, Phase 11D hotfix revalidation.** A *new*, separate run
  of the identical frozen 59-case corpus against the v1.1.1 session-lifecycle
  hotfix candidate, still under policy `1.0.2`. Performed as release-integrity
  discipline after an auth-only fix — not because analysis behavior was
  expected to change. Does not replace or supersede Parts A or B.

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

---

# Part B — Phase 11C: current-release revalidation

## 30. Objective and scope

Phase 11C answers a narrower, different question than Phase 11B: **does the current
release (current Git commit, policy `1.0.2`, current analyzers, real Bubblewrap
isolation) still reproduce the controlled behavior Phase 11B measured under policy
`1.0.1`, on the identical frozen corpus?** It is a compatibility/regression check, not
a new benchmark. No corpus case, fixture, ground-truth expectation, CDR flag, or
finding requirement was added, removed, or altered. No policy weight or threshold was
changed to make results match — the run either reproduced the historical behavior or
it did not, and it did (section 34).

## 31. Frozen corpus identity re-verification

Recomputed immediately before the Phase 11C run and compared against the section 6
values recorded before Phase 11B:

| File | SHA-256 | Matches section 6 |
| --- | --- | --- |
| `evaluation/corpus_manifest.json` | `c7959cc3f1e28a2663ae06c6d1585624f1c542dea8493c6247aea70fe3e8afd0` | Yes |
| `evaluation/corpus.py` | `656bbec78e0fecaced9129054ba2f2f7a76123c66cc5cafa5609a75986ccad83` | Yes |
| `evaluation/models.py` | `e8824dac3650d63715b0b91eaa5a9fb44c1d3ab65fed8ec2ff23ea906c9c9191` | Yes |
| `evaluation/manifest.py` | `62f257276d1f403de9e0878d62833d9af642887be9ccce13912ac16c01affaaa` | Yes |

All four files are byte-for-byte identical to the Phase 11B checkpoint. `--validate-manifest`
passed (59 cases, zero duplicate case IDs) before execution.

## 32. Current release identity

| Identity | Value |
| --- | --- |
| Git commit | `f18961ccee2ba6215befabddd3275b93e16271f2` |
| Application version | `1.0.0` (`pyproject.toml`; unchanged — see `docs/RELEASE_NOTES.md` and the recommendation in the Phase 11C completion report) |
| Policy version / fingerprint | `1.0.2` / `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` |
| YARA rule pack version / SHA-256 | `2026.08.1` / `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` (unchanged from Phase 11B) |
| Sanitizer version / fingerprint | `1.0.0` / `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` (unchanged from Phase 11B) |
| Isolation backend | `bubblewrap` (confirmed real: `bubblewrap 0.11.1` captured by shelling out to the real binary, not the `unsafe-development` interface-smoke-test backend) |
| Python version | `3.14.4` |

## 33. Execution

Executed with the same runner used for Phase 11B, against all 59 case IDs explicitly
(the runner has no "run everything" flag by design — see `evaluation/README.md`):

```bash
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --execute --case-id <all 59 case IDs> \
    --output-dir evaluation/results/phase11c
```

The dedicated resilience-sequence check (section 38) was run separately, calling
`evaluation.runner.execute_mode(["PDF-BEN-001", "PDF-RISK-012", "PDF-BEN-002"])` and
writing it with the same `write_results_json()` helper Phase 11B used — the identical
method, not a new one. Every case is a real `POST /api/v1/scans` call through
`create_app(settings)` behind an `httpx.ASGITransport`, using the real Bubblewrap
backend; no detector or analyzer helper function was called directly.

## 34. Results summary

| Metric | Phase 11B (1.0.1) | Phase 11C (1.0.2) |
| --- | --- | --- |
| Cases completed | 59/59 | 59/59 |
| Decision compliance | 59/59 (100%) | 59/59 (100%) |
| Risky-case detection recall | 41/41 (100%) | 41/41 (100%) |
| Finding-level recall | 72/72 (100%) | 72/72 (100%) |
| Benign ALLOW rate | 18/18 (100%) | 18/18 (100%) |
| Benign escalation rate | 0/18 (0%) | 0/18 (0%) |
| Fail-secure rate | 9/9 (100%) | 9/9 (100%) |
| CDR recovery rate | 2/2 (100%) | 2/2 (100%) |
| Completeness — COMPLETE | 44 | 44 |
| Completeness — INTENTIONAL_PARTIAL | 10 | 10 |
| Completeness — PARSER_FAILURE | 3 | 3 |
| Completeness — RESOURCE_LIMIT_FAILURE | 1 | 1 |
| Completeness — OTHER_FAIL_CLOSED | 1 | 1 |

Every decision-affecting metric reproduced **exactly**, case for case — not merely the
same aggregate percentages, but zero missing expected findings and zero unexpected
findings on any of the 59 cases (verified directly from `results.json`, not inferred
from the summary alone).

## 35. Latency comparison

| Statistic | Phase 11B (1.0.1) | Phase 11C (1.0.2) |
| --- | --- | --- |
| count | 59 | 59 |
| mean | 288.9 ms | 228.2 ms |
| median | 317.0 ms | 252.0 ms |
| min | 136 ms | 115 ms |
| max | 590 ms | 452 ms |
| p95 | 386 ms | 300 ms |

Phase 11C was measurably faster across every statistic on this run. Per the same
caveat as Phase 11B (section 20): this is a descriptive statistic from one run on one
shared development host, not a controlled microbenchmark — the difference is plausibly
ordinary host load/cache variance between two separate sessions, not a claimed
performance improvement. No causal interpretation is drawn from it.

## 36. Explainability deltas observed

Policy/analyzer `1.0.2` added two zero-contribution, no-hard-block, no-decision-floor
finding codes: `PDF_FALLBACK_INDICATOR` and `PDF_EXTERNAL_SUBMISSION` (see
`docs/POLICY_ENGINE.md` §"Phase 11 comparability"). **Neither code appeared in any of
the 59 Phase 11C results** (`grep`-verified against the raw `results.json`, zero
matches). The frozen corpus's fixtures do not happen to exercise the specific new
lexical-fallback or external-SubmitForm code paths these two codes cover. This is an
honest, checked observation, not an assumption: the explainability additions exist and
are exercised elsewhere (see `tests/unit/test_pdf_explainability_enhancements.py` and
`tests/integration/test_pdf_explainability_policy_impact.py`), but this specific
59-case corpus does not happen to trigger them, so Phase 11C provides no evidence
either way about their detection behavior — only that their presence causes no
regression on the cases that don't trigger them.

## 37. CDR outcomes

| Case | Source decision | CDR eligible | Derived decision | Derived release-eligible | Source decision unchanged |
| --- | --- | --- | --- | --- | --- |
| PDF-RISK-003 | QUARANTINE | true | ALLOW | true | **true** |
| PDF-RISK-006 | REVIEW | true | ALLOW | true | **true** |
| PDF-RISK-010 (BLOCK) | BLOCK | **false** | — | — | **true** |

Identical outcome shape to Phase 11B section 22: both eligible cases recovered to a
release-eligible derived ALLOW artifact, the BLOCK case was correctly CDR-ineligible
with no derived scan ever created, and all three source decisions were re-confirmed
unchanged after the CDR request.

## 38. Resilience sequence

Re-run as the same dedicated three-case ordered sequence (not part of the 59-case
aggregate metrics):

| Case | Decision | Worker status |
| --- | --- | --- |
| PDF-BEN-001 | ALLOW | SUCCESS |
| PDF-RISK-012 | QUARANTINE | FAILED (fail-closed, as pre-registered) |
| PDF-BEN-002 | ALLOW | SUCCESS |

Identical result shape to Phase 11B section 19: the induced malformed-PDF failure
failed closed exactly as pre-registered, and the very next valid upload processed
normally immediately afterward, with no degradation or manual intervention.

## 39. Historical artifact integrity verification

Before and after the Phase 11C run, `evaluation/results/phase11b/` was verified
byte-for-byte unchanged against the version already committed at `HEAD` (`git diff
--quiet HEAD -- evaluation/results/phase11b/` reported no difference). Nothing under
that directory was read-modified, rewritten, re-labeled, or touched by this task.

## 40. Unexpected results

**None.** All 59 cases matched their pre-registered expectations exactly — the same
outcome as Phase 11B section 23. No discrepancy requiring classification occurred.

## 41. What Phase 11C does NOT prove, and its relationship to Phase 11B

Everything in Part A section 4 and section 27 applies identically here — Phase 11C is
**not** a malware-detection benchmark, **not** evidence against adversarial or
real-world samples, and **not** proof that `ALLOW` implies a document is safe to open.
In addition:

- Phase 11C does **not** replace, invalidate, or supersede Phase 11B. Phase 11B remains
  the original official evaluation of the release it measured; Phase 11C is later
  evidence that the *current* release still behaves the same way on the same corpus.
- Phase 11C provides no detection-behavior evidence for the two new `1.0.2`
  explainability finding codes, since this corpus does not exercise them (section 36).
- Both phases share the same known limitation: a synthetic, self-constructed,
  59-case corpus, not an independent or adversarial benchmark. External malicious-PDF
  validation work, where it exists, is deliberately kept separate and is never blended
  into these percentages — see `docs/DEFENSE_GUIDE.md` §N/O.

**Preferred summary wording:** "Within the frozen 59-case controlled synthetic corpus
and documented detection model, the current release preserved all pre-registered
decision expectations and covered all pre-registered risky characteristics." Not:
"100% detection rate," "DocGuard detects all malicious PDFs," or "all files were safe."

## 42. Result artifact hashes

`evaluation/results/phase11c/` (new; `evaluation/results/phase11b/` is untouched):

| Artifact | SHA-256 |
| --- | --- |
| `metrics.json` | `137d28563e14f39091f4d6cf1ee1b96ac40e459925c6a422c8602525a3ce6f66` |
| `results.json` | `50be15085490e89a132c1125b875c9e349b31a6d3a320b5c5c662c19039fc30e` |
| `results.csv` | `d9663e36a05b5ccb0585e876c3cf155450875391858cb9f4c70e4b47080a570e` |
| `report.md` | `a0692b331c60ffb568ab96971987aded91228e54d877cf676f1565e50e2b7334` |
| `resilience_sequence.json` | `66b6b78ccc227d4cb408bc5a81b3933d2ffd78b207da981ae1d15dd9da73dd53` |

A future reviewer can verify the exact code, policy, and corpus evaluated by
recomputing section 31's four hashes, comparing `git_commit`/`policy_fingerprint` in
`metrics.json` against `git rev-parse HEAD` and `app.policies.registry.POLICY_FINGERPRINT`
at that commit, and recomputing this table's hashes over the retained files.

## 43. Reproduction instructions (Phase 11C)

```bash
# safe, no-execution verification
sha256sum evaluation/corpus_manifest.json evaluation/corpus.py evaluation/models.py evaluation/manifest.py
python -m scripts.run_evaluation --validate-manifest

# official execution (real Bubblewrap backend, all 59 case IDs)
python -m scripts.run_evaluation --list-cases   # to obtain the current case-id list
python -m scripts.run_evaluation --execute --case-id <...59 ids...> \
    --output-dir evaluation/results/phase11c
```

Compare the resulting `metrics.json`/`results.json` against section 34 and against
`evaluation/results/phase11b/` for the historical comparison — never overwrite either
directory when reproducing this.

---

# Part C — Phase 11D: v1.1.1 hotfix revalidation

## 44. Objective

Phase 11D was performed as a release-integrity revalidation after the v1.1.1
session-lifecycle hotfix. The hotfix does not alter document analysis or policy
behavior; the frozen controlled corpus was rerun to verify that those invariants
remained unchanged. This was a deliberate choice — evidence discipline, not a
response to any expectation that analysis behavior would differ. The hotfix
(commit `0b06cd6d2beb95eb35cf23a6ddc6712962544fae`) is scoped entirely to
`app/main.py`'s browser session middleware (see `docs/RELEASE_NOTES.md` "1.1.1");
it touches no analyzer, policy, YARA, or CDR code path.

## 45. Frozen corpus identity re-verification

Recomputed immediately before the Phase 11D run and compared against the section 6
pre-registration values — identical to the Phase 11C re-verification (section 31):

| File | SHA-256 | Matches section 6 |
| --- | --- | --- |
| `evaluation/corpus_manifest.json` | `c7959cc3f1e28a2663ae06c6d1585624f1c542dea8493c6247aea70fe3e8afd0` | Yes |
| `evaluation/corpus.py` | `656bbec78e0fecaced9129054ba2f2f7a76123c66cc5cafa5609a75986ccad83` | Yes |
| `evaluation/models.py` | `e8824dac3650d63715b0b91eaa5a9fb44c1d3ab65fed8ec2ff23ea906c9c9191` | Yes |
| `evaluation/manifest.py` | `62f257276d1f403de9e0878d62833d9af642887be9ccce13912ac16c01affaaa` | Yes |

`--validate-manifest` passed (59 cases, zero duplicate case IDs) before execution.

## 46. Evaluated release identity

| Identity | Value |
| --- | --- |
| Git commit (v1.1.1 candidate) | `b8ab859d684f9142ec56e8a139737f8a86ba2dc8` |
| Application version | `1.1.1` (`pyproject.toml`; bumped from `1.1.0`) |
| Hotfix commit under evaluation | `0b06cd6d2beb95eb35cf23a6ddc6712962544fae` |
| Policy version / fingerprint | `1.0.2` / `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` (unchanged from Phase 11C) |
| YARA rule pack version / SHA-256 | `2026.08.1` / `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` (unchanged) |
| Sanitizer version / fingerprint | `1.0.0` / `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` (unchanged) |
| Isolation backend | `bubblewrap` (confirmed real: `bubblewrap 0.11.1`) |

## 47. Execution

Identical method to Phase 11C (section 33): all 59 case IDs explicit, real
Bubblewrap backend, output to `evaluation/results/phase11d/`, resilience sequence
run separately via `evaluation.runner.execute_mode()` with the same
`write_results_json()` helper.

## 48. Results summary — Phase 11C vs. Phase 11D

| Metric | Phase 11C (v1.1.0) | Phase 11D (v1.1.1) |
| --- | --- | --- |
| Cases completed | 59/59 | 59/59 |
| Decision compliance | 59/59 (100%) | 59/59 (100%) |
| Risky-case detection recall | 41/41 (100%) | 41/41 (100%) |
| Finding-level recall | 72/72 (100%) | 72/72 (100%) |
| Benign ALLOW rate | 18/18 (100%) | 18/18 (100%) |
| Benign escalation rate | 0/18 (0%) | 0/18 (0%) |
| Fail-secure rate | 9/9 (100%) | 9/9 (100%) |
| CDR recovery rate | 2/2 (100%) | 2/2 (100%) |
| Completeness — COMPLETE | 44 | 44 |
| Completeness — INTENTIONAL_PARTIAL | 10 | 10 |
| Completeness — PARSER_FAILURE | 3 | 3 |
| Completeness — RESOURCE_LIMIT_FAILURE | 1 | 1 |
| Completeness — OTHER_FAIL_CLOSED | 1 | 1 |

Every decision-affecting metric reproduced **exactly** — zero missing expected
findings, zero unexpected findings across all 59 cases (verified directly from
`results.json`). This is the expected result for an auth-only hotfix and is
reported as confirmation, not as evidence the fix "improved detection" — it did
not touch detection at all.

## 49. Latency

| Statistic | Phase 11C (v1.1.0) | Phase 11D (v1.1.1) |
| --- | --- | --- |
| count | 59 | 59 |
| mean | 228.2 ms | 296.0 ms |
| median | 252.0 ms | 316.0 ms |
| min | 115 ms | 150 ms |
| max | 452 ms | 621 ms |
| p95 | 300 ms | 414 ms |

Slower on this run than Phase 11C, faster than Phase 11B — consistent with ordinary
shared-development-host variance across separate sessions, not a regression. Same
caveat as sections 20/35: single-host, single-run descriptive statistics, not a
performance claim.

## 50. CDR outcomes

| Case | Source decision | CDR eligible | Derived decision | Derived release-eligible | Source decision unchanged |
| --- | --- | --- | --- | --- | --- |
| PDF-RISK-003 | QUARANTINE | true | ALLOW | true | **true** |
| PDF-RISK-006 | REVIEW | true | ALLOW | true | **true** |
| PDF-RISK-010 (BLOCK) | BLOCK | **false** | — | — | **true** |

Identical outcome shape to Phase 11B and Phase 11C.

## 51. Resilience sequence

| Case | Decision | Worker status |
| --- | --- | --- |
| PDF-BEN-001 | ALLOW | SUCCESS |
| PDF-RISK-012 | QUARANTINE | FAILED (fail-closed, as pre-registered) |
| PDF-BEN-002 | ALLOW | SUCCESS |

Identical result shape to Phase 11B and Phase 11C.

## 52. Historical artifact integrity and result hashes

`evaluation/results/phase11b/` and `evaluation/results/phase11c/` were verified
byte-for-byte unchanged against the committed `HEAD` both before and after the
Phase 11D run (`git diff --quiet HEAD -- <path>` reported no difference each time).

New retained artifacts (`evaluation/results/phase11d/`):

| Artifact | SHA-256 |
| --- | --- |
| `metrics.json` | `c03a339b9ca143415635ff7c9c459bdbd40e0b9f900f1a83e6fe9b74bc701c7b` |
| `results.json` | `aa47b1888434a5629d7501946a9e9e5a77f98eab349e373efbddfcca49eeaeb4` |
| `results.csv` | `31e04898b688aa379cd33e80b6ee3386e6f8feb57d32e08efeaaffc1c37ea3b7` |
| `report.md` | `4a9e56e222cfdb29435ce2d1ead5d4c32178156cff85596faf2a5aa51ac2c56b` |
| `resilience_sequence.json` | `c18f680295a06315d935ab86764612aef69205ae55f94e72dd625eeaba5d0359` |

No unexpected results occurred. No regression, missing finding, unexpected finding,
decision-compliance failure, or CDR-invariant violation was observed. Everything in
Part A section 4/27 and Part B section 41 about what these results do NOT prove
applies identically here — this remains a controlled, self-constructed synthetic
corpus, not an independent adversarial benchmark, and `ALLOW` does not establish
that a document is benign.

# Part D — Phase 11E (v1.1.2 UI-polish candidate revalidation)

## 53. Objective

Phase 11E is a **revalidation, not a new benchmark**. It reruns the identical,
frozen, controlled, synthetic, self-constructed 59-case corpus (`11A.1`) used by
Phase 11B/11C/11D against the DocGuard v1.1.2 UI-polish release-candidate commit,
to confirm that the candidate change had zero effect on detection, policy, or CDR
behavior.

The v1.1.1 → v1.1.2 change is **presentation/usability-oriented only**: operator
web-UI template/CSS/JS wording, finding-metadata humanization, decision-panel
hierarchy, audit-detail presentation, an inert-sanitization quiet state, a
confidence-neutral lexical-evidence note color, a zero-JS mobile navigation
disclosure, narrow strict-mypy typing cleanup of post-release tooling, the
canonical application-version bump (`1.1.1` → `1.1.2`), and two further,
sequential manual-visual-review corrections folded into this same candidate
before tagging:

1. Corrected, format-neutral Sanitization (CDR) wording for release-eligible
   (ALLOW) scans — the panel previously and incorrectly told an ALLOW scan "the
   original document must remain unavailable", contradicting its own "Release
   eligible: Yes" field.
2. A mobile-responsive fix removing genuine horizontal overflow at 375 CSS px
   on the dashboard ("Needs attention" queue rows and "Decision activity"
   rows both blew out a CSS Grid track that lacked `minmax(0, 1fr)`), plus an
   adjacent nav "More" disclosure-panel alignment fix found while re-testing
   every breakpoint.

Both corrections are presentation-only — Jinja conditional wording and CSS
`grid-template-columns`/positioning changes — touching no analyzer, policy, or
CDR code path. Two earlier evaluation attempts, against
`d5f42fb4f6f44eb3b962c9d74723da8cc751b748` (pre ALLOW-wording-fix) and
`44eff36a42e180d520538897a0a150488ac22b82` (pre responsive-overflow-fix), were
each superseded before being recorded as official evidence. **This section
reports only the run against the final corrected candidate**,
`02e6ef48ad96232dffaef05ab6beb41eb18e2847`.

Detection, policy, CDR processing, authentication, and audit persistence
semantics were **intentionally left unchanged** throughout; this phase exists to
verify that intention against the real pipeline rather than merely assert it.

As with every prior phase, no independent adversarial benchmark is claimed here,
and an `ALLOW` decision does not establish that any document is benign — it means
no risky characteristic covered by the configured detection model was observed.
Everything in Part A section 4/27 and Part B section 41 about what these results
do NOT prove applies identically to Phase 11E.

## 54. Frozen corpus identity re-verification

Recomputed immediately before the Phase 11E run and compared against the section 6
pre-registration values — identical to the Phase 11C/11D re-verifications (sections
31, 45):

| File | SHA-256 | Matches section 6 |
| --- | --- | --- |
| `evaluation/corpus_manifest.json` | `c7959cc3f1e28a2663ae06c6d1585624f1c542dea8493c6247aea70fe3e8afd0` | Yes |
| `evaluation/corpus.py` | `656bbec78e0fecaced9129054ba2f2f7a76123c66cc5cafa5609a75986ccad83` | Yes |
| `evaluation/models.py` | `e8824dac3650d63715b0b91eaa5a9fb44c1d3ab65fed8ec2ff23ea906c9c9191` | Yes |
| `evaluation/manifest.py` | `62f257276d1f403de9e0878d62833d9af642887be9ccce13912ac16c01affaaa` | Yes |

`--validate-manifest` passed (59 cases, zero duplicate case IDs) before execution.

## 55. Evaluated release identity

| Identity | Value |
| --- | --- |
| Git commit (v1.1.2 candidate, untagged) | `02e6ef48ad96232dffaef05ab6beb41eb18e2847` |
| Superseded prior candidates (not recorded as evidence) | `d5f42fb4f6f44eb3b962c9d74723da8cc751b748`, `44eff36a42e180d520538897a0a150488ac22b82` |
| Application version | `1.1.2` (`pyproject.toml`; bumped from `1.1.1`) |
| Policy version / fingerprint | `1.0.2` / `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` (unchanged from Phase 11D) |
| YARA rule pack version / SHA-256 | `2026.08.1` / `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` (unchanged) |
| Sanitizer version / fingerprint | `1.0.0` / `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` (unchanged) |
| Isolation backend | `bubblewrap` (confirmed real: `bubblewrap 0.11.1`) |

This commit is a release **candidate**: it has not been tagged `v1.1.2`, and the
`v1.1.1` tag (`48b08fb`) was neither moved nor amended.

## 56. Execution

Identical method to Phase 11C/11D (sections 33, 47): all 59 case IDs explicit, real
Bubblewrap backend, output to `evaluation/results/phase11e/`, resilience sequence
run separately via `evaluation.runner.execute_mode(["PDF-BEN-001", "PDF-RISK-012",
"PDF-BEN-002"])` with the same `write_results_json()` helper.

```bash
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --execute --case-id <all 59 case IDs> \
    --isolation-backend bubblewrap --output-dir evaluation/results/phase11e
```

## 57. Results summary — Phase 11D vs. Phase 11E

| Metric | Phase 11D (v1.1.1) | Phase 11E (v1.1.2 candidate) |
| --- | --- | --- |
| Cases completed | 59/59 | 59/59 |
| Decision compliance | 59/59 (100%) | 59/59 (100%) |
| Risky-case detection recall | 41/41 (100%) | 41/41 (100%) |
| Finding-level recall | 72/72 (100%) | 72/72 (100%) |
| Benign ALLOW rate | 18/18 (100%) | 18/18 (100%) |
| Benign escalation rate | 0/18 (0%) | 0/18 (0%) |
| Fail-secure rate | 9/9 (100%) | 9/9 (100%) |
| CDR recovery rate | 2/2 (100%) | 2/2 (100%) |
| Completeness — COMPLETE | 44 | 44 |
| Completeness — INTENTIONAL_PARTIAL | 10 | 10 |
| Completeness — PARSER_FAILURE | 3 | 3 |
| Completeness — RESOURCE_LIMIT_FAILURE | 1 | 1 |
| Completeness — OTHER_FAIL_CLOSED | 1 | 1 |

Every decision-affecting metric reproduced **exactly** — zero missing expected
findings, zero unexpected findings across all 59 cases (verified directly from
`results.json`). This is the expected result for a presentation-only UI-polish
candidate and is reported as confirmation, not as evidence the change "improved
detection" — it did not touch detection at all.

## 58. Latency

| Statistic | Phase 11D (v1.1.1) | Phase 11E (v1.1.2 candidate) |
| --- | --- | --- |
| count | 59 | 59 |
| mean | 296.0 ms | 227.4 ms |
| median | 316.0 ms | 252.0 ms |
| min | 150 ms | 109 ms |
| max | 621 ms | 457 ms |
| p95 | 414 ms | 315 ms |

Phase 11E showed different latency from Phase 11D on the same development host.
Because all functional outputs were reproduced exactly and latency was not
evaluated under a controlled performance-isolation protocol, the difference is
treated as host/session variance rather than evidence of a functional
regression — or, in this direction, evidence of an improvement. The UI-polish
change touches no request-handling, worker, or analysis code path, and latency
variation alone is explicitly outside this phase's pass/fail criteria.

## 59. CDR outcomes

| Case | Source decision | CDR eligible | Derived decision | Derived release-eligible | Source decision unchanged |
| --- | --- | --- | --- | --- | --- |
| PDF-RISK-003 | QUARANTINE | true | ALLOW | true | **true** |
| PDF-RISK-006 | REVIEW | true | ALLOW | true | **true** |
| PDF-RISK-010 (BLOCK) | BLOCK | **false** | — | — | **true** |

Identical outcome shape to Phase 11B, Phase 11C, and Phase 11D.

## 60. Resilience sequence

Reproduces the historical valid → malformed/fail-closed → valid sequence
(`evaluation.runner.execute_mode(["PDF-BEN-001", "PDF-RISK-012", "PDF-BEN-002"])`,
run in that literal order; `results.json`/`resilience_sequence.json` re-sort by
`case_id` for deterministic diffing, which is why the table above and the stored
JSON list PDF-BEN-002 before PDF-RISK-012):

| Case | Decision | Worker status |
| --- | --- | --- |
| PDF-BEN-001 | ALLOW | SUCCESS |
| PDF-RISK-012 | QUARANTINE | FAILED (fail-closed, as pre-registered) |
| PDF-BEN-002 | ALLOW | SUCCESS |

Identical result shape to Phase 11B, Phase 11C, and Phase 11D. The final valid
scan (`PDF-BEN-002`) completed normally (`ALLOW`/`SUCCESS`) immediately after the
fail-closed `PDF-RISK-012` scan in the same application/worker-pool instance,
confirming no persistent contamination from the failed worker/input carried
forward into the next request.

## 61. Historical artifact integrity and result hashes

`evaluation/results/phase11b/`, `evaluation/results/phase11c/`, and
`evaluation/results/phase11d/` were verified byte-for-byte unchanged against the
committed `HEAD` both before and after the Phase 11E run (`git diff --quiet HEAD
-- <path>` reported no difference each time).

New retained artifacts (`evaluation/results/phase11e/`), generated against the
final corrected candidate `02e6ef48ad96232dffaef05ab6beb41eb18e2847`:

| Artifact | SHA-256 |
| --- | --- |
| `metrics.json` | `f700b63423435b20d4678f415b2f23ffbc19bf4438c0ab628e490052b6d0c130` |
| `results.json` | `ca189e07de4d1159b9858141381adeeb14ea8ccdea023b1aee9cf543deaa4aef` |
| `results.csv` | `dda403780e8b50826685e087cb27a77399ed0f9101b4ca42a6155918e2f1d1ae` |
| `report.md` | `f9c31ba15747357311cb961954d8092b57f047ccdaa544a314695ac1c2f99d9b` |
| `resilience_sequence.json` | `71296d9a2472ffc3b50fe11bd78a3eac4da07b98314244bf5611da732cacc671` |

No unexpected results occurred. No regression, missing finding, unexpected
finding, decision-compliance failure, or CDR-invariant violation was observed.
This remains a controlled, self-constructed synthetic corpus, not an independent
adversarial benchmark; `ALLOW` does not establish that a document is benign; and
this phase confirms — rather than merely asserts — that the presentation/
usability-oriented v1.1.2 UI-polish candidate left detection, policy, and CDR
semantics unchanged. The candidate commit above is a **release candidate**, not
the tagged `v1.1.2` release; tagging and the canonical report-screenshot
regeneration are deliberately deferred to a later, separate step.
