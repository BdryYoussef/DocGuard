# DocGuard Demonstration Script

A predictable, ~5-8 minute walkthrough for a live defense/demo. It reuses the existing
Phase 11 controlled evaluation fixtures — no second demo corpus, no live malware, no
network dependency. No demo-only bypass exists anywhere in the product; every step
below exercises the real, unmodified production code path.

## Fixtures used (frozen Phase 11 corpus, `evaluation/corpus.py`)

| Role | Case ID | Filename | Why |
| --- | --- | --- | --- |
| Benign ALLOW | `PDF-BEN-001` | `quarterly-summary.pdf` | Structurally plain PDF, no active content. |
| CDR-eligible suspicious | `PDF-RISK-003` | `javascript-open.pdf` | JavaScript + auto-open action → QUARANTINE; pre-registered `RECONSTRUCT_SUCCESS`. |
| BLOCK | `PDF-RISK-010` | `invoice-eicar.pdf` | Structurally benign PDF with a trailing EICAR test signature → hard-block. |

These three case IDs are pulled unmodified from the pre-registered, already-executed
Phase 11B corpus (see `docs/EVALUATION.md`); their real outcomes are already measured
and reproducible, not staged for the demo.

### Materializing the demo files

Generate the three fixture files deterministically into a scratch directory (never
committed, never a repository runtime path):

```bash
PYTHONPATH=.python-deps:.worker-deps:. python3 -c "
from pathlib import Path
from evaluation.corpus import CASES, materialize_case

demo_dir = Path('/tmp/docguard-demo')
demo_dir.mkdir(exist_ok=True)
for case_id in ('PDF-BEN-001', 'PDF-RISK-003', 'PDF-RISK-010'):
    case = next(c for c in CASES if c.case_id == case_id)
    path = materialize_case(case, demo_dir)
    print(case_id, '->', path)
"
```

This produces `quarterly-summary.pdf`, `javascript-open.pdf`, and `invoice-eicar.pdf`
under `/tmp/docguard-demo/`, ready to upload through the operator UI.

## Prerequisites

- DocGuard running against a qualified environment (see `docs/RELEASE_CHECKLIST.md`);
  a temporary qualification instance is sufficient for a demo, it does not need to be
  the production deployment.
- One bootstrapped OPERATOR account (`python -m scripts.create_operator`).
- The three demo files materialized as above.

## Demo 1 — Benign document (~1.5 min)

1. Log in as the demo operator.
2. Upload `quarterly-summary.pdf`.
3. Point out: the file was streamed to private storage and analyzed inside an isolated,
   disposable Bubblewrap worker — the trusted application process never parsed it.
4. Show the result: **ALLOW**, zero findings.
5. Say explicitly: *"ALLOW means DocGuard did not observe risky characteristics covered
   by the configured detection model — it is not a claim that the file is safe."*

## Demo 2 — Suspicious PDF and CDR (~3 min)

1. Upload `javascript-open.pdf`.
2. Show the result: **QUARANTINE**, with findings `PDF_JAVASCRIPT` and
   `PDF_OPEN_ACTION` and the explanation that the compound "auto-JS" rule escalated it.
3. Explain: this is not release-eligible in its current form.
4. Request PDF CDR (raster reconstruction) on this scan.
5. Show: the source PDF is re-rendered to flat raster images inside a fresh isolated
   worker (no JavaScript, no actions can survive rasterization), producing a new PDF.
6. Show: the reconstructed output is **re-ingested as its own scan** and re-analyzed by
   the same trusted pipeline — it does not inherit trust from being "the CDR output."
7. Show: the derived scan is **ALLOW** and release-eligible; an approved artifact
   download is now available.
8. Show: the **original** `javascript-open.pdf` scan is still `QUARANTINE` — its
   decision never changed, and it remains non-downloadable.

## Demo 3 — BLOCK case (~1.5 min)

1. Upload `invoice-eicar.pdf`.
2. Show the result: **BLOCK**, finding `YARA_TEST_SIGNATURE` (the standard,
   industry-recognized EICAR anti-malware test string — a controlled test artifact,
   not real malware).
3. Explain: BLOCK is a semantic hard block; it cannot be overridden by an operator in
   this release, and it is not a numeric threshold that a low score could avoid.
4. Attempt to request CDR on this scan and show it is refused as ineligible — a
   hard-blocked source can never be CDR-released.
5. Confirm no artifact download exists for this scan.

## Demo 4 — Audit trail (~1-2 min)

Open the audit view for the session and show, with timestamps and the operator's
identity attached to each event:

- login;
- the three uploads/analyses;
- the CDR request, render completion, and approval for `javascript-open.pdf`;
- the artifact download (if performed live).

Point out that audit entries never contain document content, matched YARA bytes, VBA
source, or raw filenames beyond bounded display text.

## Timing budget

| Segment | Time |
| --- | --- |
| Demo 1 — Benign | ~1.5 min |
| Demo 2 — Suspicious + CDR | ~3 min |
| Demo 3 — BLOCK | ~1.5 min |
| Demo 4 — Audit | ~1.5 min |
| **Total** | **~7.5 min** |

## What not to do during a demo

- Do not use a real client document — use only the fixtures above.
- Do not disable CSRF, authentication, or Bubblewrap "to save time" — the demo must run
  the real production path or it proves nothing.
- Do not claim ALLOW means "safe" or "malware-free" during narration.
- Do not rely on internet connectivity; nothing in this flow calls out to a network.
