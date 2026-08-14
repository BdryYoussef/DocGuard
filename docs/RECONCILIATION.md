# Reconciliation

DocGuard uses atomic file finalization and database transactions, but a process/host crash can still
occur between filesystem and database commits. Reconciliation reports these gaps without interpreting
document bytes and without making any document releasable.

The default dry run inspects bounded batches for stale ANALYZING scans, missing/invalid scan objects,
quarantine orphans, missing/tampered approved artifacts, sanitized orphans, stale recognized temp
objects, and broken derived-parent references. Orphans are reported, never automatically deleted.

`--apply` rechecks each stale row under a transaction, then sets it to QUARANTINED, worker FAILED,
`release_eligible=false`, decision QUARANTINE, and the stable recovery reason. It fabricates neither
findings nor a successful policy evaluation and appends a SYSTEM recovery audit event. The default
15-minute threshold comfortably exceeds analysis/CDR timeouts and is bounded to 60–86400 seconds.

Temporary cleanup is separately opted into with `--apply --cleanup-temporary`. Eligible files must be
direct children of `incoming` or `work`, match DocGuard's exact upload/CDR temporary naming grammar,
be owned regular single-link files with mode 0400/0600, and be older than the threshold. Symlinks,
directories, hardlinks, unknown names, and business objects are untouched.

Apply runs take a nonblocking `flock` on the private mode-0600 `.reconcile.lock`. The lock file may
persist safely; kernel lock ownership ends on process exit, so there is no stale-forever state. A
second process fails rather than racing. Run reconciliation under the dedicated service account and
review dry-run output before apply.
