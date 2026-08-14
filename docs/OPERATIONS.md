# Operations

## Deployment sequence

1. Install root-owned application source and pinned trusted/worker environments below `/opt/docguard`.
2. Create the unprivileged `docguard` account and private mode-0700 `/var/lib/docguard` state root.
3. Install a mode-0600 environment file based on `deploy/docguard.env.example`.
4. Enable the service account's user manager/cgroup delegation as required by the existing
   `systemd-run --user` isolation launcher; confirm `/run/user/<uid>/bus` is usable.
5. Take a protected maintenance-window backup, then run `alembic upgrade head` explicitly.
6. Bootstrap an operator with `python -m scripts.create_operator`; no default account exists.
7. Run `python -m scripts.production_preflight` and resolve every failure.
8. Install/review Nginx TLS configuration and the systemd unit, then start the service.

Do not run Uvicorn as root or expose port 8000 beyond loopback. The reverse proxy runs under its own
account and owns TLS access; DocGuard owns only its database and private state. Do not place SSH/GPG,
unrelated user data, proxy configuration, or TLS keys in the DocGuard account.

## Health and logs

`/health/live` indicates process life. `/health/ready` is a minimal ready/not-ready production signal;
detailed failures appear in local JSON logs and preflight output. Route logs use server request IDs.
Journald/log rotation, access policy, retention, clock synchronization, and alerting on readiness,
sandbox, integrity, repeated-auth, and rate-limit events are operational responsibilities. No external
telemetry is built in.

## Database

SQLite uses foreign keys, a 5-second configurable busy timeout, WAL, and `synchronous=FULL`. WAL creates
private `docguard.db-wal` and `docguard.db-shm` sidecars. Copying only the live main file is not a valid
backup. Run `python -m scripts.check_database` for bounded quick check or add `--full` for an explicit
maintenance integrity scan.

This phase does not claim an atomic database-plus-object backup. Use a maintenance window: stop
DocGuard and Nginx access, confirm no worker/reconciliation process remains, use SQLite's backup API or
a consistent closed-database copy including the database state, copy the private object tree with
modes/ownership preserved, protect/encrypt the backup, then restart and verify preflight/integrity.
Test restoration separately.

## Maintenance commands

- `python -m scripts.reconcile_state` is bounded and dry-run by default. `--apply` only quarantines
  stale ANALYZING rows. `--apply --cleanup-temporary` additionally removes strictly qualified stale
  application temp files; it never deletes orphan business objects.
- `python -m scripts.check_storage --batch-size 500` verifies approved artifact objects. Add
  `--include-quarantine` for bounded source verification. It is read-only.
- `python -m scripts.cleanup_sessions --limit 500` is dry-run. Add `--apply` to delete only expired or
  revoked sessions. It never prints tokens.

Only one reconciliation apply process may run. Non-zero status means failure, contention, or truncated
inspection as documented by command output.

## Retention

V1 has no automatic business-document retention/deletion. Original quarantined objects, approved
private sanitized artifacts, and audit rows remain until a future approved retention workflow exists.
Session and qualified temporary-file cleanup are maintenance, not business-data retention. This is
not by itself a claim of GDPR, Morocco Law 09-08, or other legal compliance.
