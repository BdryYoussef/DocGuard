# DocGuard Phase 11 Evaluation

## 1. Objective

Phase 11 measures how well DocGuard's *existing, frozen* detection model (Phase 10)
performs against a controlled, ground-truthed corpus of inert fixtures. It answers
questions like "does the risky-active-content detector actually fire on the structures
it claims to detect?" and "how often does a benign document get escalated?" with
reproducible evidence instead of anecdote.

**Phase 11A** (this phase) builds the evaluation framework: the corpus, its manifest,
the result schema, metric calculations, and reporting — everything Phase 11B needs to
execute the real benchmark. **Phase 11A does not report benchmark numbers.** Every
metric in a Phase-11A-only report reads "not applicable" / "pending Phase 11B" (see
[reporting.py](../evaluation/reporting.py)); no number here has been fabricated.

**Phase 11B** (not started) will run the full corpus through the real, Bubblewrap-
isolated production pipeline, collect results, and publish the actual metric values.

## 2. What Phase 11 is not

- Not a redesign of DocGuard's detection or policy logic. Phase 11 evaluates the
  detector that exists; see AGENTS.md's "Freeze the detection model" for what is
  explicitly out of scope.
- Not a malware research exercise. No real malware is downloaded, sourced, or executed
  — see section 4.
- Not a live-tuning loop. If a fixture reveals a possible defect, it is documented for
  review, not silently patched to make a metric look better.

## 3. Controlled corpus methodology

The corpus lives in [evaluation/corpus.py](../evaluation/corpus.py) as typed Python
(`EvaluationCase` objects), not hand-written JSON — this makes ground truth reviewable
as code and lets fixture reuse be expressed as ordinary function calls. It is dumped to
the canonical, machine-readable [evaluation/corpus_manifest.json](../evaluation/corpus_manifest.json)
via `evaluation.manifest.generate_default_manifest()`; regenerate it after any change to
`evaluation/corpus.py` or `evaluation/models.py` (both `test_evaluation_manifest.py` and
`--validate-manifest` will fail if the checked-in file drifts from the code).

The corpus currently defines **59 cases** across the eight coverage categories described
in the Phase 11A brief:

| Category | Count | Notes |
| --- | ---: | --- |
| BENIGN_PDF | 4 | Zero-finding PDFs only; see limitation in section 9 |
| RISKY_PDF | 12 | Includes 2 fail-secure (encrypted, malformed) and 3 CDR-prepared |
| BENIGN_OFFICE | 6 | |
| RISKY_OFFICE | 10 | Includes 2 fail-secure (encrypted, inconsistent package) |
| BENIGN_ARCHIVE | 5 | |
| RISKY_ARCHIVE | 12 | Includes 5 fail-secure (encrypted, nesting/resource limit, malformed, unsupported method) |
| FILE_IDENTITY | 5 | 4 risky + 1 negative control |
| YARA | 5 | 3 risky + 2 negative controls |

9 cases are marked fail-secure; 3 are marked CDR-prepared (all PDF-family, per
AGENTS.md's requirement that CDR only ever applies to PDFs).

## 4. Safe fixture generation

Every fixture is generated **locally, deterministically, and inertly** by composing the
existing, already-reviewed factories under `tests/fixtures/` (`pdf_factory.py`,
`office_factory.py`, `archive_factory.py`, `yara_factory.py`) plus `inert_pe_fixture()`
from `tests/unit/test_file_identification.py`. Two narrow local helpers in
`evaluation/corpus.py` (`many_entries_archive_fixture`, `pdf_with_eicar_fixture`) compose
those same factories for two cases the existing factories didn't already cover; neither
adds new parsing or execution logic.

Nothing here:

- downloads a sample from VirusTotal, MalwareBazaar, ANY.RUN, Hybrid Analysis, an
  exploit repository, or any other external source;
- executes a macro, script, embedded payload, archive member, or generated Office/PDF
  content;
- fetches a network resource.

The EICAR standard antivirus test string is used exactly as intended: as a controlled,
industry-standard trigger for the local YARA test signature, never as or alongside real
malicious content.

`evaluation.corpus.materialize_case()` resolves each case's `FixtureGenerator` reference
(`module` + `attribute` + how to call it) dynamically via `importlib`, so the manifest
stays data and the corpus never needs to re-implement factory logic.

## 5. Ground-truth model

Ground truth for every case was derived directly from the **frozen Phase 10 policy
registry** (`app.policies.registry.FINDING_POLICIES` / `COMPOUND_POLICIES`), not
guessed: each case's expected decision was computed from the same contribution/
hard-block/mandatory-minimum arithmetic the trusted policy engine uses
(`app.policies.engine.evaluate_policy`), and cross-checked against the existing,
already-reviewed unit and integration tests that exercise the same fixtures.

Where a fixture can legitimately produce more than one policy-consistent finding
combination — e.g. a bidirectional-override filename may or may not also trip a
type-mismatch check depending on how the claimed final extension resolves —
`acceptable_decisions` lists every policy-consistent outcome (never a single arbitrary
guess), and `allow_any_additional_findings` is set instead of enumerating an uncertain
finding set. This is the "acceptable decision set" mechanism required in place of a
simplistic `ALLOW < REVIEW < QUARANTINE < BLOCK` ordering (see section 8).

**A case is labeled `BENIGN` only if it intentionally contains none of the risky
characteristics under evaluation** — per DocGuard's documented threat model, not
conventional end-user intuition. An ordinary passive external URI or AcroForm is
labeled `RISKY` (with `ALLOW` as its acceptable decision) because the policy registry
tracks it as a monitored characteristic, even though its low contribution means the
document is still released. This mirrors AGENTS.md section 17 precisely.

Each `EvaluationCase` (see `evaluation/models.py`) carries: `case_id`, `category`,
`case_class`, `description`, `filename`, `claimed_content_type`, `generator`,
`expected_findings`, `acceptable_additional_findings` /
`allow_any_additional_findings`, `acceptable_decisions`, `expected_analysis_complete`,
`fail_secure`, `cdr_case` / `cdr_expected_outcome`, and free-text `notes`.

### Known fixture-generator characteristic

The macro-enabled OOXML fixtures built via `write_ooxml(..., macro_source=...)` write a
synthetic `vbaProject.bin` stream (`build_compound_file`), not a fully real VBA project
container, so `oletools` reports an "orphan VBA stream" and `OFFICE_PARTIAL_ANALYSIS`
always accompanies macro findings from this factory. This is documented on each
affected case's `notes` field; it is a known characteristic of the shared test-fixture
factory, not a detector defect, and Phase 11B should not mistake it for one.

## 6. Manifest validation

`evaluation.manifest` enforces, in addition to each case's own pydantic-level schema
(unknown category/class/finding codes, malformed finding collections, contradictory
CDR/fail-secure flags — all rejected at construction time):

- duplicate `case_id`s;
- generator references that do not actually import (`check_generator_resolvable`);
- a case whose expected findings include a hard-block code but whose
  `acceptable_decisions` isn't exactly `(BLOCK,)` — consulting the real
  `FINDING_POLICIES` registry rather than a second, competing implementation
  (`check_hard_block_decision_consistency`).

`evaluation.manifest.load_manifest()` fails closed on any of the above, on malformed
JSON, and on a non-array root.

## 7. Planned metrics

All nine metrics from the Phase 11A brief are implemented in `evaluation/metrics.py`
exactly as specified there (risky-case detection recall, finding-level recall with
per-category breakdown, benign escalation rate, benign ALLOW rate, decision compliance,
fail-secure rate, analysis-completeness counts, latency statistics, and CDR-recovery
data-model support). See the module docstrings for the precise mathematical definition
of each. None of them are populated with real numbers until Phase 11B runs the corpus.

### Zero-denominator handling

Every rate metric returns a `Rate(numerator, denominator, value)` dataclass. When the
denominator is zero, `value` is `None` — never a fabricated `0%` or `100%`. Reporting
renders this as "not applicable (0 evaluable cases)". This applies uniformly to metrics
A, C, D, E, G, and I.

## 8. Decision compliance without a numeric ordering

`decision_compliance_rate` checks membership in each case's own `acceptable_decisions`
set — it never imposes `ALLOW < REVIEW < QUARANTINE < BLOCK`. A case whose
`acceptable_decisions` is `(QUARANTINE, REVIEW)` counts either outcome as compliant; a
benign case whose `acceptable_decisions` is `(ALLOW,)` counts an unexpected `BLOCK` as
non-compliant even though `BLOCK` is "more severe" than `ALLOW` on a naive ordering.

## 9. Fail-secure model

A case is `fail_secure=True` when its ground truth is specifically about DocGuard
staying fail-closed under an incomplete-analysis condition (encrypted document,
malformed structure, nesting/resource limit, unsupported compression). For such a case,
Phase 11B considers it contained when `release_eligible` is explicitly `False`; `None`
(never ran / unknown) does not count as contained. `fail_secure_rate` in
`evaluation/metrics.py` implements exactly this.

## 10. Latency model

`evaluation.metrics.latency_stats()` computes count, mean, median, min, max, and a
nearest-rank p95 over whatever `latency_ms` values are present in the results. This is a
plain descriptive statistic over the observed sample, not a claim of statistical
significance — Phase 11B should not present it as one, especially given the corpus's
modest size.

## 11. Execution path (Phase 11B)

The runner (`evaluation/runner.py`, wrapped by `scripts/run_evaluation.py`) is built
around the **real** DocGuard pipeline, the same one the integration test suite already
exercises: `app.main.create_app(settings)` behind an `httpx.ASGITransport`, an
authenticated operator session, a real `POST /api/v1/scans` upload, and the trusted
policy engine's persisted decision. It is not a thin wrapper around worker analyzer
helper functions — the intended path is:

```
fixture -> secure ingestion -> isolation backend (Bubblewrap in production)
        -> worker analyzers -> versioned contract -> trusted policy engine
        -> persisted scan result
```

Safe modes (never invoke the pipeline, never write into `var/`):

```bash
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --list-cases
python -m scripts.run_evaluation --dry-run
```

Execution mode (invokes the real pipeline; requires explicit case IDs — there is no
"run everything" flag, so the full corpus cannot be triggered by accident):

```bash
python -m scripts.run_evaluation --execute --case-id PDF-BEN-001 --case-id PDF-RISK-003
```

Add `--output-dir <path>` to also write `results.json`, `results.csv`, `metrics.json`,
and `report.md`. `--isolation-backend unsafe-development` exists only for interface
smoke-testing and prints a prominent warning; it must never be used to draw conclusions
about real detection behavior, and the production Phase 11B benchmark must use the
default `bubblewrap` backend.

## 12. Reproducibility model

Every execution run captures `ReproducibilityMetadata`: timestamp, git commit, corpus
version and case count, policy version/fingerprint, YARA rule-pack version/SHA-256,
sanitizer version/fingerprint, Python version, a privacy-safe `platform` string
(`{system}-{machine}`, no hostname), and best-effort Bubblewrap/qpdf/worker-dependency
versions. It never includes a username, home directory, temporary absolute path,
password, or environment secret — see `evaluation/reporting.find_private_path_leak()`,
which the reporting tests apply to every generated artifact.

## 13. Limitations

- **BENIGN_PDF has only 4 cases**, below the 7-9 suggested in the brief. Zero-finding
  PDF fixture diversity beyond page count and false-positive-keyword text would require
  materially new generator logic rather than a narrow composition of the existing
  factory, which Phase 11A deliberately avoided (see AGENTS.md "reuse existing fixture
  infrastructure"). Worth expanding in a later phase if broader benign-PDF coverage is
  wanted.
- Two archive fail-secure cases (`ARC-RISK-011` corrupt CRC, `OFF-RISK-008` classic-OLE
  macro) use `allow_any_additional_findings=True` because the exact accompanying finding
  set is plausible but not pinned down by an existing test; Phase 11B should tighten
  these once real results are observed.
- `FID-001` and `FID-002` (double-extension and bidi-override filenames) list two
  acceptable decisions each because whether `FILE_TYPE_MISMATCH` co-triggers depends on
  claimed-extension-family resolution that this phase did not trace line-by-line through
  `worker/analyzers/filename.py`; both listed outcomes are policy-consistent.
- Latency and CDR-recovery metrics have no real numbers yet; their code paths are
  exercised only by synthetic unit-test data.

## 14. Corpus authoring verification (not a benchmark result)

While building the manifest, the full 59-case corpus was run once, ad hoc, through the
real `create_app` pipeline using the `unsafe-development` isolation backend (not
Bubblewrap) purely to confirm every case's ground truth actually matches DocGuard's real
behavior before committing it. All 59 cases matched (no missing findings, no unexpected
findings, decision-compliant). Nothing from that run was persisted as a report artifact,
and it does not substitute for the Phase 11B benchmark, which must use the production
Bubblewrap backend and produce a committed, reproducible report.

## 15. Getting started

```bash
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --list-cases
python -m scripts.run_evaluation --dry-run
```

See [evaluation/README.md](../evaluation/README.md) for a developer-facing quick
reference to the package layout.
