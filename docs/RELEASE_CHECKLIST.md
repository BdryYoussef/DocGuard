# DocGuard Release Checklist

For the `v1.0.0` academic release. Each item states whether it was executed during
Phase 12 qualification (with the result) or is an administrator action to perform at
actual deployment time — this checklist does not claim an item ran if it did not.

## Source and version control

- [x] Correct branch: `phase12-release`.
- [x] Clean Git working tree confirmed before starting Phase 12 changes.
- [x] Current Git commit recorded (see `docs/RELEASE_MANIFEST.md`).
- [x] Dependency locks unchanged from the frozen baseline (`requirements.lock`,
      `requirements-worker.lock`) — no opportunistic upgrades performed.
- [x] Alembic migration head confirmed (`0005_operator_auth`).

## Code quality gate

- [x] `ruff format --check .`
- [x] `ruff check .`
- [x] `mypy --strict app worker docguard_contract evaluation scripts`
- [x] `pytest -q` — full suite passing (see `docs/RELEASE_MANIFEST.md` for the exact
      count recorded at qualification time).

## Identity fingerprints

- [x] Policy version/fingerprint recorded and internally consistent
      (`app.policies.registry.validate_policy_registry()` passes).
- [x] YARA rule pack version/fingerprint recorded.
- [x] Sanitizer (CDR) version/fingerprint recorded.
- [x] Application release version established (`1.0.0`) and distinguished from the
      three identities above — see `docs/RELEASE_NOTES.md` §"Version identities."

## Deployment qualification (temporary environment)

Executed in a fresh, temporary, non-production-data environment during Phase 12 — see
`docs/RELEASE_MANIFEST.md` for exact PASS/FAIL results:

- [x] `alembic upgrade head` against a fresh SQLite database.
- [x] `python -m scripts.production_preflight`.
- [x] `python -m scripts.check_database`.
- [x] `python -m scripts.check_storage`.
- [x] `python -m scripts.reconcile_state` (dry-run only; `--apply` was **not** run
      against any real/default data).
- [x] Bubblewrap `ANALYZE` self-test (real backend, not `unsafe-development`).
- [x] SANITIZE_PDF qualification via the existing worker self-test mechanism.
- [x] Live Uvicorn production-mode process: health endpoints, unexpected-Host
      rejection, `/docs`/`/redoc`/`/openapi.json` disabled, security headers present.
- [x] Artifact/quarantine path isolation from any static/public route.
- [x] Temporary controlled operator bootstrapped for qualification only (not a
      production credential).

## Operator/environment readiness (administrator responsibility at real deployment)

These are **not** executed by Phase 12 — they depend on the actual target host and are
explicitly the deploying administrator's responsibility (see `docs/OPERATIONS.md`):

- [ ] Dedicated unprivileged service account created on the target host.
- [ ] `/opt/docguard` and `/var/lib/docguard` ownership/permissions set per
      `docs/PRODUCTION_HARDENING.md`.
- [ ] Production `.env` installed at mode `0600` with real secrets (never committed).
- [ ] TLS certificate obtained and installed for the real Nginx virtual host.
- [ ] Nginx reverse proxy installed/configured from
      `deploy/nginx/docguard.conf.example`.
- [ ] systemd unit installed from `deploy/systemd/docguard.service` and enabled on the
      real host (the reference unit was syntactically verified during Phase 10; it was
      not installed as a running production service during this project).
- [ ] Backup policy scheduled per `docs/OPERATIONS.md`.
- [ ] Log collection/retention/alerting configured per the operator's own policy.

## Evaluation and documentation

- [x] Phase 11 evaluation artifacts present and internally consistent
      (`evaluation/results/phase11b/*`, `docs/EVALUATION.md`).
- [x] Phase 11 corpus/manifest hashes re-verified unchanged during Phase 12.
- [x] README/architecture/threat-model/operations documentation reviewed for
      consistency with the current implementation; stale references corrected.
- [x] Known limitations consolidated and explicit (`docs/DEFENSE_GUIDE.md` §N,
      `docs/EVALUATION.md` §25/26).
- [x] Demo fixtures verified to materialize deterministically
      (`docs/DEMO.md`).
- [x] Demo smoke flow executed once in a temporary qualification environment (benign
      ALLOW, CDR-eligible QUARANTINE→ALLOW, BLOCK, logout) — see
      `docs/RELEASE_MANIFEST.md`.

## Release tag

- [ ] Release tag **not** created automatically. See `docs/RELEASE_NOTES.md` for the
      exact command the user may run after reviewing this checklist and the final
      completion report.
