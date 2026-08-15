# Web Security

## Production proxy qualification

The browser uses the canonical HTTPS origin while Nginx talks loopback HTTP. Host is validated
against that origin and mutation Origin is required exactly; forwarding proto/host/chains are
non-authoritative. Only an exact trusted socket peer may provide one valid `X-Real-IP`. The API is
same-origin with no permissive CORS. Every response, including errors, gets browser headers and a
fresh server request ID. Static serving remains application-owned and readiness rejects
static/private overlap or symlinks.

## Rendering and XSS boundary

DocGuard uses server-rendered Jinja2 templates with explicit HTML/XML autoescape. Attacker-controlled
filenames, findings, and bounded audit values are rendered as text, not marked safe. Application
JavaScript creates no HTML from response strings and does not use `innerHTML`. JSON APIs use typed,
allowlisted response models and never expose storage keys or paths.

The content-security policy is:

```text
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self';
frame-ancestors 'none'; form-action 'self'
```

There is no `unsafe-inline`, `unsafe-eval`, remote script/style origin, CDN, analytics tag, or
third-party font. CSP is defense in depth; escaping and strict data handling remain primary.

## Authentication, CSRF, and origin

The browser carries only an HttpOnly opaque session token. Every authenticated request is resolved
against the server-side session database and active operator state. State-changing requests require
a token cryptographically bound to that session. Foreign supplied `Origin` values are rejected;
absence of Origin does not bypass CSRF. The configured `application_origin` must be one exact HTTP(S)
origin, and production requires HTTPS.

DocGuard reads the direct ASGI peer and URL. It does not trust arbitrary `Host` rewriting or
`X-Forwarded-For`, `X-Forwarded-Host`, or `X-Forwarded-Proto`. A future reverse-proxy deployment must
explicitly restrict trusted proxies and preserve the configured origin; Phase 9 includes no proxy
trust switch.

## Response headers and caching

Application pages, login, logout, and operator APIs use `Cache-Control: no-store`. Approved artifact
downloads use `Cache-Control: no-store, private`. All responses receive `X-Content-Type-Options:
nosniff`, `Referrer-Policy: same-origin`, a restrictive `Permissions-Policy`, and the CSP above.
Production HTTPS responses include one-year HSTS with subdomains. Deployers must ensure HTTPS is
genuinely end to end for the application origin before relying on HSTS; local HTTP development does
not send it.

`same-origin` (rather than `no-referrer`) is required so that a same-origin, non-GET/HEAD browser
request — such as the login form's POST — keeps a real `Origin` header. Per the Fetch standard, a
same-origin request whose governing referrer policy is `no-referrer` serializes its `Origin` header
as the literal string `null`, which then fails the exact same-origin comparison in
`app.auth.http._enforce_origin` with `403 foreign origin rejected`. `same-origin` still sends no
referrer at all cross-origin.

Production disables Swagger UI, ReDoc, and the OpenAPI JSON endpoint. Anonymous surface is limited
to login, liveness/readiness, and application-owned static assets. Detailed readiness names appear
only in development/test; production returns a bounded status and logs details server-side.

## Static assets and browser code

Only `app/web/static` is mounted at `/static`. It contains local CSS and minimal JavaScript. Incoming,
quarantine, sanitized, database, and runtime work directories are outside and disjoint from this
mount. No user-generated object is copied into static storage.

The upload script streams a raw body through the existing bounded ingestion endpoint and provides
CSRF and claimed MIME metadata. CDR uses the same authenticated fetch pattern. UI visibility never
authorizes an operation: server-side capabilities, CSRF, eligibility, lineage, and policy checks are
repeated even if a browser user changes the DOM.

## Artifact downloads

Downloads accept only the validated opaque artifact ID. The service queries approved lineage,
resolves a persisted opaque key inside private sanitized storage, opens the object with
`O_NOFOLLOW`, and validates immutable filesystem and cryptographic metadata using the open descriptor.
The required successful audit write occurs before the `StreamingResponse` can emit bytes. The
descriptor stays open through streaming and is closed in a `finally` block, limiting path-replacement
races. A privileged administrator or writable underlying storage remains inside the operational
trust boundary; there is an unavoidable interval between final file-stat verification and the last
descriptor read, although path replacement cannot redirect an already-open descriptor.

There is no raw source/quarantine download, BLOCK override, policy editor, or rule upload route.

## Limitations

V1 has no nonce-based inline asset system because it needs no inline scripts/styles. It does not
implement MFA, SSO, per-object tenant authorization, distributed login throttling, WebSocket policy,
service-worker/offline support, external browser telemetry, or trusted-proxy parsing. Security also
depends on a supported browser, TLS deployment, host/database/storage access control, and timely
framework and dependency updates.
