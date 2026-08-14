# evaluation/

Phase 11 evaluation framework. See [docs/EVALUATION.md](../docs/EVALUATION.md) for the
full methodology; this file is a quick developer reference.

Not a production dependency: nothing under `app/`, `worker/`, or `docguard_contract/`
imports this package.

## Layout

- `models.py` — typed, serializable case/result/reproducibility schemas (pydantic,
  reusing `app.models.domain.Decision` and `docguard_contract.findings` rather than
  duplicating them).
- `corpus.py` — the 59 `EvaluationCase` ground-truth definitions plus
  `materialize_case()`, which deterministically writes one case's fixture bytes by
  composing the existing `tests/fixtures/*` factories.
- `manifest.py` — strict validation, and load/dump to/from the canonical
  `corpus_manifest.json`.
- `metrics.py` — pure functions computing every Phase 11 metric over
  `(cases, results)`.
- `reporting.py` — JSON/CSV/Markdown report writers, plus `find_private_path_leak()`.
- `runner.py` — safe modes (`validate_manifest_mode`, `list_cases_mode`,
  `dry_run_mode`) and the real-pipeline `execute_mode()`.
- `corpus_manifest.json` — generated; **do not hand-edit**. Regenerate with:

  ```bash
  python -c "from evaluation.manifest import generate_default_manifest as g; g()"
  ```

  Regenerate and re-commit it after any change to `corpus.py` or `models.py`; stale
  drift between the manifest and the code is caught by
  `tests/unit/test_evaluation_manifest.py::test_repository_manifest_file_is_valid` and
  by `python -m scripts.run_evaluation --validate-manifest`.

## Running

```bash
python -m scripts.run_evaluation --validate-manifest
python -m scripts.run_evaluation --list-cases
python -m scripts.run_evaluation --dry-run
python -m scripts.run_evaluation --execute --case-id PDF-BEN-001 --output-dir /tmp/eval-out
```

`--execute` always requires explicit `--case-id` values; there is no "run everything"
flag in Phase 11A. Full-corpus execution against the production Bubblewrap backend is
Phase 11B's job.

## Tests

```bash
pytest tests/unit/test_evaluation_models.py tests/unit/test_evaluation_manifest.py \
       tests/unit/test_evaluation_metrics.py tests/unit/test_evaluation_corpus.py \
       tests/unit/test_evaluation_reporting.py tests/unit/test_evaluation_runner.py
```
