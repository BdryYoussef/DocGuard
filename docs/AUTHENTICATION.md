# Authentication

## Phase 10 edge and abuse rules

Production login and mutations require the canonical HTTPS Origin even across the loopback proxy.
Login peer identity uses the centralized one-hop resolver. Separate process-local operator buckets
bound uploads, CDR, downloads, and costly reads. This is qualified only with one Uvicorn worker;
multi-process or multi-node deployment needs shared enforcement. Session cleanup is bounded and
dry-run by default; `--apply` deletes only revoked or expired sessions and prints no token material.

## Operator model

DocGuard V1 uses local, database-backed accounts with one `OPERATOR` role. There is no public
registration, web account administration, password reset, OAuth, SSO, API key, or anonymous upload.
An operator can upload and read scans, request eligible PDF CDR, read approved artifact metadata and
bytes, and read the audit trail. No V1 capability exists for raw quarantine download, policy or rule
editing, decision override, or BLOCK override.

Usernames are canonical lowercase identifiers containing only ASCII letters, digits, `.`, `_`, and
`-`, bounded to 64 characters. Operators are disabled by setting `is_active=false`; deactivation is
checked on every authenticated request and immediately invalidates use of existing sessions.
Deactivation is preferred to deletion because audit actor IDs remain meaningful.

## Passwords

Passwords are hashed with Argon2id through `argon2-cffi`, pinned to time cost 3, memory cost 65,536
KiB, parallelism 4, a 32-byte hash, and a 16-byte salt. Hash parameters are explicit and upgraded on
successful login when the configured policy changes. Passwords must be 12–128 characters and may not
be blank or whitespace-only. They are never logged, audited, stored, or sent to a worker.

Unknown usernames and known usernames follow the same generic browser error. A fixed dummy Argon2id
hash is verified when no eligible account exists, reducing obvious username-enumeration timing
differences. This is mitigation, not proof of identical timing across every database and host state.

## Server-side sessions

A successful login creates 32 random bytes with the operating-system CSPRNG and encodes them as an
opaque 43-character URL-safe token. Only its SHA-256 digest is stored in `auth_sessions`; the raw
token exists only in the browser cookie. Token hashes are unique. CSRF material is deterministically
derived from the raw session token with an HMAC context and only its SHA-256 digest is persisted.

Session creation, operator last-login update, password-hash upgrade, previous-session revocation,
and `AUTH_LOGIN_SUCCESS` audit insertion commit in one database transaction. A commit failure sends
no usable cookie. A new successful login rotates the browser session and revokes its prior valid
token, preventing session fixation.

Defaults are an eight-hour absolute lifetime and a 30-minute inactivity lifetime. `last_seen_at` is
updated at a bounded interval rather than on every request. Expired, inactive, revoked, malformed,
unknown, or deactivated-user sessions fail authentication and are cleared from the browser. The
bounded maintenance command removes expired/revoked rows:

```bash
python -m scripts.cleanup_sessions --limit 500
```

Logout is POST-only and CSRF protected. Session revocation commits before a best-effort logout audit;
if the audit database write fails after revocation, invalidating the session takes priority.

## Cookie and CSRF boundary

Production uses `__Host-docguard_session` with `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and no
Domain attribute. Production configuration rejects an insecure cookie, a non-`__Host-` name, an
HTTP application origin, or disabled CSRF. Development/test use a clearly different non-Secure
cookie so local HTTP remains possible.

Every cookie-authenticated mutation requires a session-bound CSRF token. API JavaScript sends it in
`X-CSRF-Token`; logout submits the same token as a bounded URL-encoded field. Tokens are compared in
constant time. If an `Origin` header is supplied, it must exactly match the configured application
origin after removal of a trailing slash. DocGuard does not trust `X-Forwarded-*` headers.

## Login throttling and audit

The process-local limiter independently bounds attempts by direct peer address and by a SHA-256 key
derived from the canonical username. Defaults are five attempts per minute and 50 per hour. State is
bounded in memory and is intentionally not a distributed brute-force control; multi-process or
multi-host deployments need an external, reviewed edge control in a later phase.

Successful login, failed login, rate limiting, and logout produce bounded audit events. Failed login
events use actor type `ANONYMOUS`, contain no username or password, and are best-effort when the
database is unavailable. Authentication itself still fails closed when the session database is
unavailable.

## Bootstrap

There is deliberately no first-run web registration screen. For production:

1. apply migrations with `alembic upgrade head`;
2. set the production database/storage/origin/isolation environment;
3. run `python -m scripts.create_operator --username <name>` and enter the password through the
   terminal prompt;
4. start DocGuard and visit `/login`.

Controlled deployment automation may use `--password-stdin`; command-line password arguments and
default credentials are not supported. Duplicate usernames are rejected. Production readiness is
false until migration `0005`, the auth runtime, the session store, and at least one active operator
are available. Public production readiness returns only a bounded status and never usernames.

## Limitations

V1 has one role and local passwords only. It has no MFA, WebAuthn, central identity, recovery flow,
password history, distributed rate limiter, administrative browser workflow, session browser, or
forced global logout control. TLS termination and trusted reverse-proxy topology are deployment
responsibilities; until explicit proxy trust is implemented, pass the original origin directly and
do not rely on forwarded scheme or client-address headers for security.
