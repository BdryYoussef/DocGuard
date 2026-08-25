# DocGuard Release Manifest

This file is cumulative release history. Earlier sections are preserved exactly as
originally recorded — read each as a record of that release, not the current one.
Current release: **v1.1.2** (this section). `v1.1.1` and `v1.1.0` remain
historical and unchanged.

---

## v1.1.2 release manifest

### Release identity

| Identity | Value |
| --- | --- |
| Application release version | `1.1.2` (`pyproject.toml`, FastAPI app metadata) — bumped from `1.1.1` |
| Release/evidence commit | this commit (`git log -1` / `git show v1.1.2 --no-patch`) |
| Evaluated application candidate | `02e6ef48ad96232dffaef05ab6beb41eb18e2847` — "fix: prevent mobile dashboard horizontal overflow" (frozen; no application-runtime change between this candidate and the release/evidence commit above) |
| Prior candidate commits (UI-polish sequence, on top of `v1.1.1`) | `d5f42fb4f6f44eb3b962c9d74723da8cc751b748` ("feat: polish DocGuard operator UI for v1.1.2"), `44eff36a42e180d520538897a0a150488ac22b82` ("fix: correct ALLOW sanitization guidance") |
| Alembic migration head | unchanged from `v1.1.1` — no new migration in this release |
| Python version | `3.14.4` |

### What this release is

A **presentation/usability patch** for the operator web UI: format-neutral
Sanitization (CDR) wording (including a release-eligible/ALLOW correction),
humanized finding metadata, a stronger decision-evidence hierarchy, compact
audit-detail presentation, a confidence-neutral lexical-evidence note color,
a zero-JS mobile navigation disclosure, and a mobile dashboard
horizontal-overflow fix — plus narrow strict-mypy typing cleanup of tracked
post-release tooling. No analyzer, policy, YARA, CDR, authentication,
authorization, database, or API code changed. See `docs/RELEASE_NOTES.md`
"1.1.2" for the full defect/correction narrative, and `docs/EVALUATION.md`
Part D (Phase 11E) for the frozen-corpus revalidation this manifest
summarizes below.

### Detection/integrity identities (unchanged from v1.1.1)

| Identity | Version | Fingerprint |
| --- | --- | --- |
| Policy registry | `1.0.2` | `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` |
| YARA rule pack | `2026.08.1` | `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` |
| PDF CDR sanitizer | `1.0.0` | `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` |

### Test result (pre-tag quality gate)

Full suite: **530 passed** (baseline `520` at `v1.1.1` + 10 new UI-polish
presentation regression tests in `tests/integration/test_ui_polish_presentation.py`
— one existing test in that file was later extended with an additional
ALLOW/release-eligible case rather than adding an 11th test item). `ruff format
--check` clean, `ruff check` clean, `mypy --strict app worker docguard_contract
evaluation scripts` clean (0 issues, 105 source files). Real Bubblewrap
isolation suite: **10 passed, 0 skipped**.

### Controlled validation basis — Phase 11E

| Identity | Value |
| --- | --- |
| Corpus version | `11A.1` |
| Corpus case count | 59 |
| Frozen corpus-definition hashes | unchanged — re-verified byte-for-byte before Phase 11E (`docs/EVALUATION.md` §54) |
| Historical evaluation (unchanged) | `evaluation/results/phase11b/` — policy `1.0.1`, commit `b94d373` |
| Prior current-release revalidation (unchanged) | `evaluation/results/phase11c/` — policy `1.0.2`, commit `f18961c` (v1.1.0) |
| Hotfix revalidation (unchanged) | `evaluation/results/phase11d/` — policy `1.0.2`, commit `b8ab859` (v1.1.1) |
| UI-polish revalidation (new) | `evaluation/results/phase11e/` — policy `1.0.2`, commit `02e6ef48ad96232dffaef05ab6beb41eb18e2847` (v1.1.2 candidate) |

Phase 11E reproduced every Phase 11D metric exactly: decision compliance 59/59,
risky-case recall 41/41, finding recall 72/72, benign ALLOW 18/18, benign
escalation 0/18, fail-secure 9/9, CDR recovery 2/2, identical completeness
distribution (44/10/3/1/1). This was expected — the change is
presentation-only and touches no analysis code path — and is reported as
confirmation, not as an improvement claim. Latency differed from Phase 11D
(mean 227.4 ms vs. 296.0 ms) but was not measured under a controlled
performance-isolation protocol on this shared development host, so the
difference is treated as host/session variance, not a performance claim in
either direction. Full detail: `docs/EVALUATION.md` Part D.

Phase 11E artifact hashes (`evaluation/results/phase11e/`):

| Artifact | SHA-256 |
| --- | --- |
| `metrics.json` | `f700b63423435b20d4678f415b2f23ffbc19bf4438c0ab628e490052b6d0c130` |
| `results.json` | `ca189e07de4d1159b9858141381adeeb14ea8ccdea023b1aee9cf543deaa4aef` |
| `results.csv` | `dda403780e8b50826685e087cb27a77399ed0f9101b4ca42a6155918e2f1d1ae` |
| `report.md` | `f9c31ba15747357311cb961954d8092b57f047ccdaa544a314695ac1c2f99d9b` |
| `resilience_sequence.json` | `71296d9a2472ffc3b50fe11bd78a3eac4da07b98314244bf5611da732cacc671` |

### What did not change in v1.1.2

Everything listed under `v1.1.1`'s "What did not change", plus: detection,
policy, CDR processing, authentication, authorization, the database schema,
API contracts, audit persistence semantics, release eligibility, and risk
scoring are all unchanged. The canonical report screenshots
(`docs/screenshots/report/`) were regenerated against this release to reflect
the UI changes; `docs/screenshots/SCREENSHOT_MANIFEST.md` records the
capture identity and viewport/dimension details.

---

## v1.1.1 release manifest

### Release identity

| Identity | Value |
| --- | --- |
| Application release version | `1.1.1` (`pyproject.toml`, FastAPI app metadata) — bumped from `1.1.0` |
| Release/evidence commit | this commit (`git log -1` / `git show v1.1.1 --no-patch`) |
| Hotfix commit | `0b06cd6d2beb95eb35cf23a6ddc6712962544fae` — "fix: preserve authenticated sessions across static asset requests" |
| Version-preparation commit | `b8ab859d684f9142ec56e8a139737f8a86ba2dc8` — "chore: prepare DocGuard v1.1.1 hotfix release" |
| Phase 11D evaluated application candidate | `b8ab859d684f9142ec56e8a139737f8a86ba2dc8` (same commit as version-preparation — no further runtime changes between candidate and evaluation) |
| Alembic migration head | unchanged from `v1.1.0` — no new migration in this release |
| Python version | `3.14.4` |

### What this release is

A patch release containing exactly one change from `v1.1.0`: the session-lifecycle
hotfix (`0b06cd6d`). No analyzer, policy, YARA, or CDR code changed. See
`docs/RELEASE_NOTES.md` "1.1.1" for the defect description and correction, and
`docs/EVALUATION.md` Part C (Phase 11D) for the frozen-corpus revalidation this
manifest summarizes below.

### Detection/integrity identities (unchanged from v1.1.0)

| Identity | Version | Fingerprint |
| --- | --- | --- |
| Policy registry | `1.0.2` | `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` |
| YARA rule pack | `2026.08.1` | `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` |
| PDF CDR sanitizer | `1.0.0` | `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` |

### Test result (pre-tag quality gate)

Full suite: **520 passed**. `ruff format --check` clean, `ruff check` clean,
`mypy --strict app worker docguard_contract evaluation scripts` clean. Real
Bubblewrap isolation suite: **10 passed, 0 skipped**.

### Controlled validation basis — Phase 11D

| Identity | Value |
| --- | --- |
| Corpus version | `11A.1` |
| Corpus case count | 59 |
| Frozen corpus-definition hashes | unchanged — re-verified byte-for-byte before Phase 11D (`docs/EVALUATION.md` §45) |
| Historical evaluation (unchanged) | `evaluation/results/phase11b/` — policy `1.0.1`, commit `b94d373` |
| Prior current-release revalidation (unchanged) | `evaluation/results/phase11c/` — policy `1.0.2`, commit `f18961c` (v1.1.0) |
| Hotfix revalidation (new) | `evaluation/results/phase11d/` — policy `1.0.2`, commit `b8ab859d684f9142ec56e8a139737f8a86ba2dc8` (v1.1.1 candidate) |

Phase 11D reproduced every Phase 11C metric exactly: decision compliance 59/59,
risky-case recall 41/41, finding recall 72/72, benign ALLOW 18/18, benign
escalation 0/18, fail-secure 9/9, CDR recovery 2/2, identical completeness
distribution (44/10/3/1/1). This was expected — the hotfix is auth-only and
touches no analysis code path — and is reported as confirmation, not as an
improvement claim. Full detail: `docs/EVALUATION.md` Part C.

### What did not change in v1.1.1

Everything listed under `v1.1.0`'s "What did not change" below, plus: the
session-lifecycle fix touches only `app/main.py`'s browser session middleware —
no change to CSRF, Origin enforcement, cookie flags, session expiry semantics,
detection, policy, or CDR.

---

## v1.1.0 release manifest

### Release identity

| Identity | Value |
| --- | --- |
| Application release version | `1.1.0` (`pyproject.toml`, FastAPI app metadata) — bumped from `1.0.0` |
| Release commit | this commit (`git log -1` / `git show v1.1.0 --no-patch`) — a self-referencing commit cannot record its own hash in advance |
| Evaluated application-code commit | `f18961ccee2ba6215befabddd3275b93e16271f2` |
| Evaluation-evidence commit | `99a32e557b1139204901ea2bd720db513bd02c8e` (Phase 11C completion) |
| Alembic migration head | unchanged from `v1.0.0` — no new migration in this release |
| Python version | `3.14.4` |

**Important**: the release commit itself contains only release-metadata/documentation
changes (this manifest, release notes, version strings) staged on top of the
evaluation-evidence commit `99a32e5`. It is **not** the commit Phase 11C evaluated —
that was `f18961c`. Verified before recording this manifest: `git diff --stat f18961c
HEAD` between the evaluated commit and the pre-release-commit HEAD touched only
`docs/EVALUATION.md` and `evaluation/results/phase11c/*` — zero changes under `app/`,
`worker/`, `docguard_contract/`, `tests/`, or `scripts/`. No runtime/application code
changed between the evaluated commit and this release.

Application release version remains a **separate identity** from the three detection/
integrity identities below.

### Detection/integrity identities

| Identity | Version | Fingerprint | Changed from v1.0.0? |
| --- | --- | --- | --- |
| Policy registry | `1.0.2` | `c6d18b6f67b79a91151567c99c8844c741820935ab9d4ad32bb131a30412469b` | Yes — see `docs/POLICY_ENGINE.md` §"Phase 11 comparability" |
| YARA rule pack | `2026.08.1` | `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` | No |
| PDF CDR sanitizer | `1.0.0` | `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` | No |

### Test result (pre-release-commit quality gate)

Full suite: **516 passed**. `ruff format --check` clean, `ruff check` clean,
`mypy --strict app worker docguard_contract evaluation scripts` clean. Real Bubblewrap
isolation suite: **10 passed, 0 skipped**
(`tests/integration/test_bubblewrap_isolation.py`).

### Controlled validation basis

| Identity | Value |
| --- | --- |
| Corpus version | `11A.1` |
| Corpus case count | 59 |
| Frozen corpus-definition hashes | unchanged from `v1.0.0` — re-verified byte-for-byte before Phase 11C (see `docs/EVALUATION.md` §31) |
| Historical evaluation (unchanged) | `evaluation/results/phase11b/` — policy `1.0.1`, commit `b94d373` |
| Current-release revalidation (new) | `evaluation/results/phase11c/` — policy `1.0.2`, commit `f18961c` |

Within the frozen 59-case controlled synthetic corpus and documented detection model,
DocGuard policy `1.0.2` reproduced all pre-registered decision expectations and
covered all pre-registered risky characteristics: decision compliance 59/59,
risky-case recall 41/41, finding recall 72/72, benign ALLOW 18/18, benign escalation
0/18, fail-secure 9/9, CDR recovery 2/2 — identical to Phase 11B's historical result.
This is a controlled, self-constructed synthetic corpus, not an independent
adversarial benchmark; `ALLOW` does not establish that a document is benign. Full
detail: `docs/EVALUATION.md` Part B; historical Phase 11B evidence is untouched.

### What did not change in v1.1.0

No change to authentication, session/CSRF handling, CSP, worker isolation, the
Bubblewrap sandbox profile, CDR semantics, audit semantics, dependency locks, or the
qualified production topology. See `docs/RELEASE_NOTES.md` "Security invariants
preserved" for the v1.1.0 entry.

---

## v1.0.0 release manifest (historical)

Recorded at Phase 12 qualification time for the `v1.0.0` academic release. No secrets or
private host paths are included below.

## Release identity

| Identity | Value |
| --- | --- |
| Application release version | `1.0.0` (`pyproject.toml`, FastAPI app metadata) |
| Git branch | `phase12-release` |
| Git commit at qualification time | `7874e2d437d8128ba9d66f2cc05277a1882f2576` (Phase 11B completion; Phase 12 doc/version-only changes are staged on top, uncommitted at qualification time — see completion report) |
| Alembic migration head | `0005_operator_auth` |
| Python version | `3.14.4` |

Application release version is a **separate identity** from the three detection/
integrity identities below — bumping `1.0.0` never implies, and never triggers, any
change to policy, YARA, or sanitizer identity.

## Detection/integrity identities (unchanged from Phase 11)

| Identity | Version | Fingerprint |
| --- | --- | --- |
| Policy registry | `1.0.1` | `717ac1bbbea13acc61c47a241673ee05616c241318e2c0c691240995f2bf9333` |
| YARA rule pack | `2026.08.1` | `7b9bab1889c4db6ead3b49263e93c10b138d2b8496668791b7ca8363c5385fe7` |
| PDF CDR sanitizer | `1.0.0` | `46ceaaa938031df4952fbbf9fa23c374ed516be648456fdd256bcd5fcfd73bf2` |

(The sanitizer version happens to also read `1.0.0` — this is coincidental string
overlap with the new application release version, not a shared identity; each is
computed and validated independently — see `app.policies.registry`,
`docguard_contract.yara_rules`, and `docguard_contract.cdr`.)

## Dependency lock identity

| Lock file | SHA-256 |
| --- | --- |
| `requirements.lock` (trusted application) | `2a5119964edb00c99cf332672afce73a0f85b8f109ee83fdff1471db075ed963` |
| `requirements-worker.lock` (isolated worker) | `2469e16d3a95f8ab15bb10f2633946191df2c50123e5c7730df4f5ef95f197b7` |

Both locks are unchanged from the frozen Phase 10/11 baseline; Phase 12 performed no
dependency upgrades (release freeze — see `docs/RELEASE_NOTES.md` "Dependency
freeze").

## Test result

Full suite: **403 passed** (396 at the Phase 12 qualification snapshot above, plus 7
regression tests added by two narrow post-release fixes: the login `Referrer-Policy`
same-origin-form-submission fix, and the operator dashboard double-`session.expunge()`
fix. Neither fix touched detection/policy/YARA/CDR code — see their respective
completion reports for exact commands and results).

## Phase 11 corpus identity (evaluation basis)

| Identity | Value |
| --- | --- |
| Corpus version | `11A.1` |
| Corpus case count | 59 |
| `evaluation/corpus_manifest.json` SHA-256 | `c7959cc3f1e28a2663ae06c6d1585624f1c542dea8493c6247aea70fe3e8afd0` |
| `evaluation/corpus.py` SHA-256 | `656bbec78e0fecaced9129054ba2f2f7a76123c66cc5cafa5609a75986ccad83` |
| `evaluation/models.py` SHA-256 | `e8824dac3650d63715b0b91eaa5a9fb44c1d3ab65fed8ec2ff23ea906c9c9191` |
| `evaluation/manifest.py` SHA-256 | `62f257276d1f403de9e0878d62833d9af642887be9ccce13912ac16c01affaaa` |
| Git commit at official Phase 11B benchmark | `b94d373884fb4f737cdf4f07cc7eccf08ffb8252` |

All four hashes were re-verified identical during Phase 12 (no drift since the official
Phase 11B benchmark).

## Evaluation result summary (Phase 11B, unchanged/re-verified)

- 59 total cases — 41 risky, 18 benign.
- Risky-case detection recall: 41/41 (100%).
- Finding-level recall: 72/72 (100%).
- Benign escalation: 0/18 (0%).
- Benign ALLOW rate: 18/18 (100%).
- Decision compliance: 59/59 (100%).
- Fail-secure rate: 9/9 (100%).
- CDR recovery: 2/2 eligible cases; 1 BLOCK case correctly CDR-ineligible.
- Latency: mean 288.9 ms, median 317.0 ms, p95 386 ms.

Full detail, methodology, and reproduction instructions: `docs/EVALUATION.md`. Retained
artifacts: `evaluation/results/phase11b/`.

## Phase 12 deployment qualification result (temporary environment)

Executed against a fresh temporary SQLite database and private storage root, real
Bubblewrap isolation backend, `DOCGUARD_ENV=production`:

| Check | Result |
| --- | --- |
| `alembic upgrade head` | PASS |
| `python -m scripts.production_preflight` | **PASS 48/48** (after bootstrapping a temporary qualification operator and setting private directory modes) |
| `python -m scripts.check_database --full` | PASS (SQLite full integrity check) |
| `python -m scripts.check_storage --include-quarantine` | PASS (0 objects inspected, fresh store) |
| `python -m scripts.reconcile_state` (dry-run) | PASS (mode=DRY-RUN, 0 inspected — fresh store; `--apply` was **not** run) |
| Live Uvicorn (production mode) `/health/live`, `/health/ready` | PASS (`{"status":"alive"}`, `{"status":"ready"}`) |
| Unexpected `Host` header | Rejected (400 `invalid host`) |
| `/docs`, `/redoc`, `/openapi.json` | Disabled (404) |
| Security headers (CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS, `no-store`) | Present on every response |
| Static-mount path traversal toward storage | Blocked (404) |

## Phase 12 demo/smoke qualification result (same temporary environment)

| Step | Result |
| --- | --- |
| Benign upload (`PDF-BEN-001`) | `ALLOW`, `release_eligible=true` |
| Suspicious upload (`PDF-RISK-003`) | `QUARANTINE`, findings `PDF_JAVASCRIPT`+`PDF_OPEN_ACTION` |
| CDR request on suspicious scan | `200`, `approved=true`, derived scan created |
| Derived scan re-check | `ALLOW`, `release_eligible=true` |
| Source scan re-check after CDR | Still `QUARANTINE` (decision immutable) |
| BLOCK upload (`PDF-RISK-010`) | `BLOCK` |
| CDR request on BLOCK scan | `409`, `failure_code=ineligible`, no derived scan |
| Approved-artifact download (derived, ALLOW artifact) | `200`, bytes streamed |
| Logout | `303` |
| Authenticated request with the old session after logout | `401` |

## Supported production topology

One TLS-terminating Nginx process → loopback-only single Uvicorn worker → local SQLite
(WAL, `synchronous=FULL`) and private filesystem storage → disposable per-document
Bubblewrap workers. Multi-Uvicorn-worker and multi-node deployments are not qualified
(abuse-rate-limit counters are process-local). See `docs/PRODUCTION_HARDENING.md`.

## Known deployment responsibilities (not part of this manifest's PASS results)

Dedicated service account creation, `/opt`/`/var/lib` ownership, protected `.env`
installation, TLS certificate provisioning, Nginx installation, systemd unit
installation, backup scheduling, and log collection/retention are the deploying
administrator's responsibility — see `docs/OPERATIONS.md` and
`docs/RELEASE_CHECKLIST.md`.
