# DocGuard Release Manifest

This file is cumulative release history. The `v1.0.0` manifest below is preserved
exactly as originally recorded — read as a record of that release, not the current
one. Current release: **v1.1.0** (this section).

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
