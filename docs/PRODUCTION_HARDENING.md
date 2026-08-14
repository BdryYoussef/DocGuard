# Production Hardening

## Qualified V1 topology

The supported topology is one browser-facing HTTPS origin, terminated by a trusted Nginx process,
forwarded over loopback HTTP to one Uvicorn worker, with local SQLite/private storage and disposable
Bubblewrap workers. Uvicorn is not a network edge and must bind only `127.0.0.1`. Multiple Uvicorn
workers and multi-node deployments are not qualified because abuse-control counters are process-local.

Nginx overwrites `X-Real-IP` with the direct TLS peer and preserves one fixed canonical Host. DocGuard
trusts that header only when the ASGI socket peer is an exact IP in `DOCGUARD_TRUSTED_PROXY_IPS`.
Comma-separated values, malformed IPs, `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and
`X-Forwarded-Proto` never influence security decisions. The canonical configured HTTPS origin—not
the loopback transport scheme—governs Host and CSRF checks.

The reference files are [docguard.service](../deploy/systemd/docguard.service),
[docguard.conf.example](../deploy/nginx/docguard.conf.example), and
[docguard.env.example](../deploy/docguard.env.example). Certificates, DNS, the default rejecting TLS
virtual host, installation, and OS patching remain operator responsibilities.

## HTTP and browser boundary

Production rejects unexpected Host values and requires the exact configured `Origin` on mutations.
The service has no permissive CORS middleware. Unsupported TRACE, CONNECT, PUT, PATCH, DELETE, and
OPTIONS methods cannot mutate state. Login forms are streamed into a 4 KiB bound; uploads retain the
actual-byte 25 MiB bound. Query and pagination fields remain typed and bounded.

Every request receives a fresh server-generated `X-Request-ID`. JSON request logs contain the route
template, method, status, duration, actor ID when authenticated, and resolved client address. They do
not contain query strings, cookies, passwords, CSRF/session tokens, request bodies, raw filenames, or
document-derived content. JSON encoding prevents control characters from forging log records.
The reference service disables Uvicorn's raw access log so query strings cannot bypass this bounded
route-template logger.

Operator limits default to 60 uploads/hour, 20 CDR requests/hour, 200 downloads/hour, and 300 costly
reads/minute. Rejection is HTTP 429 and never changes document policy/lifecycle state. Nginx adds a
coarse peer-based layer. These controls are deliberately single-process; scaling requires a shared
limiter or equivalent edge enforcement.

## Filesystem and runtime qualification

Private directories must be owned by the service UID, real (not symlinked), and mode 0700. SQLite is
mode 0600 or stricter; finalized quarantine/sanitized objects are mode 0400 and checked with
`O_NOFOLLOW`. Static assets must be application-owned and separate from storage. Worker dependencies
and rules must be non-writable outside their owner. Production deployment should make `/opt/docguard`
root-owned/read-only to the service while `/var/lib/docguard` is service-owned/writable. Development
source remains writable and is not a production deployment.

The systemd reference sets `UMask=0077`, `NoNewPrivileges`, empty capabilities, `ProtectHome`,
`PrivateTmp`, `ProtectSystem=strict`, a single writable state root, and conservative task/FD bounds.
It intentionally does not enable `PrivateUsers`, `RestrictNamespaces`, `ProtectControlGroups`,
`RestrictSUIDSGID`, or a system-call allowlist: those can break the qualified Bubblewrap/user-namespace
and user-systemd cgroup launcher. The host must provide a usable lingering user manager for `docguard`
and `/run/user/<uid>/bus`; this is verified by the sandbox self-test, not assumed.

On the inspected systemd 259 host, an adapted unit passed `systemd-analyze verify`; the unadapted
reference correctly reported only that the not-yet-installed `/opt/docguard/.venv/bin/python` was
absent. `systemd-analyze security --offline=yes` rated the adapted unit 5.4/MEDIUM. That score is not
optimized by enabling namespace/cgroup restrictions that would defeat the worker boundary. A
transient user service then ran the complete production preflight and Bubblewrap self-test under
`NoNewPrivileges`, empty capabilities, `PrivateTmp`, `ProtectSystem=strict`, the address-family list,
`LockPersonality`, FD/task limits, read-only source, and one writable state bind. `ProtectHome=true`
was live-tested separately with the same controls because this development checkout is under `/home`;
the reference `/opt/docguard` layout is outside that mask. Installation-specific unit launch remains
an operator acceptance test.

## Preflight and dependencies

Run `python -m scripts.production_preflight` after migrations and operator bootstrap and before service
start. It is read-only with respect to business data and prints only safe PASS/FAIL check names. It
checks Python, exact trusted/worker versions, exact lock pins, storage/static modes, SQLite, migration
head, registries/fingerprints, auth configuration and active operator, and the complete sandbox probe.
Any mandatory failure exits non-zero. Startup never auto-migrates, creates users, reconciles, or
deletes files.

Dependency vulnerability review is a release-time task requiring an explicitly updated advisory
database. Production startup performs no internet lookup and uploads no dependency inventory.

## Remaining assumptions

The Linux kernel, Bubblewrap, systemd/cgroups, Nginx/OpenSSL, SQLite, Python, native parser libraries,
and host administration remain trusted. `systemd-analyze verify/security` is useful qualification,
not proof of isolation. TLS private keys belong to Nginx, not DocGuard. Local logs/audit storage and
their retention must be protected by the operator.
