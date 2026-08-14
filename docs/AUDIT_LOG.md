# Security Audit Events

Phase 10 reserves stable SYSTEM recovery/integrity event codes. Applied stale recovery appends
`RECOVERY_STALE_SCAN_QUARANTINED` in the transaction that forces non-release state; qualified temp
cleanup appends `TEMP_OBJECT_CLEANED`. Dry runs do not mutate audit history. Operational request JSON
logs use separate server request IDs and do not replace the append-only security audit.

DocGuard has an application security audit trail separate from debug logs. Stable CDR codes are
`CDR_ELIGIBILITY_CHECKED`, `CDR_STARTED`, `CDR_RENDER_COMPLETED`, `CDR_RENDER_FAILED`,
`CDR_DERIVED_SCAN_CREATED`, `CDR_RESCAN_COMPLETED`, `CDR_APPROVED`, `CDR_REJECTED`, and
`CDR_PROMOTION_FAILED`. Phase 9 adds `AUTH_LOGIN_SUCCESS`, `AUTH_LOGIN_FAILURE`, `AUTH_LOGOUT`,
`SCAN_UPLOAD_REQUESTED`, `CDR_REQUESTED`, `ARTIFACT_DOWNLOADED`, and
`ARTIFACT_DOWNLOAD_DENIED`.

Events have an opaque ID, optional scan/artifact linkage, actor type and optional actor ID, outcome,
bounded reason, bounded JSON details, and aware timestamp. Internal pipeline events use `SYSTEM`.
Authenticated actions use `OPERATOR` plus the immutable operator ID; read views may join the current
canonical username. Failed authentication uses `ANONYMOUS` and never records the submitted username
or password.

Details are limited to 4 KiB finite JSON with bounded keys, strings, lists, and nesting. Trusted
IDs, versions/fingerprints, decisions, counts, and durations are permitted. Document bytes/text,
scripts, VBA, YARA matched bytes, full URLs, pixels, secrets, filenames, and parser diagnostics are
not.

Application code exposes append only and no generic update/delete. Artifact creation and
`CDR_APPROVED` share one database transaction; failure removes the promoted file when possible and
leaves no approved artifact. Successful session creation and `AUTH_LOGIN_SUCCESS` also share one
transaction, so no usable login cookie is issued if that audit commit fails. Logout prioritizes
revocation: its audit is attempted only after revocation commits. An approved-artifact download
requires `ARTIFACT_DOWNLOADED` to commit before bytes are sent; audit failure denies download.

Authenticated OPERATORs can read newest-first bounded pages through the UI/API. The response model
and UI allowlist details and never expose document bytes/text, secrets, passwords, untrusted
filenames, raw URLs, parser diagnostics, or storage paths. No audit mutation route exists.

Append-only at the application layer; database administrators remain within the trusted operational
boundary. This is not tamper-proof. Cryptographic chaining, external shipping, retention policy,
and SIEM integration are future work.
