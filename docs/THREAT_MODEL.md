# DocGuard Threat Model

Status legend: **Implemented** is enforced and tested in the current release; **Residual risk** is an
accepted, documented limitation rather than a gap to be silently assumed closed.

## Assets

- Confidential business documents submitted for analysis (raw quarantine bytes and any derived
  sanitized artifact).
- Operator credentials (Argon2id password hashes) and active sessions (bearer tokens/CSRF secrets).
- Sanitized (CDR-derived) artifacts approved for release.
- Policy, YARA rule pack, and sanitizer identity/integrity (version and fingerprint).
- Audit log integrity (append-only accountability record of who did what, when).

| Threat | Impact | Mitigation | Status |
|---|---|---|---|
| Malicious parser input | Trusted-process compromise | Trusted side only streams/hashes; libmagic and pikepdf/qpdf run in disposable worker | Implemented |
| Worker escape | Host compromise or secret access | User/PID/network/IPC/UTS/cgroup/mount namespaces, dropped capabilities, minimal mounts, no home/secrets | Implemented; kernel remains trusted |
| Network/SSRF | Internal access or exfiltration | New network namespace, no live URL logic, self-test probes route denial | Implemented |
| Resource exhaustion | Host CPU/memory/process/disk/output exhaustion | Per-job cgroup, rlimits, sized tmpfs, parent wall timeout, bounded pipe draining | Implemented foundation |
| Environment leakage | Database/API credentials exposed to worker | Explicit launcher environment plus Bubblewrap `--clearenv`; sentinel probe | Implemented |
| Filesystem leakage | Database, quarantine, source, or credentials readable | Descriptor-bound single input; allowlisted read-only runtime/worker mounts; root read-only | Implemented |
| Input replacement/symlink | Analyze or expose unintended host file | Opaque direct-child storage, `O_NOFOLLOW`, regular-file check, `--ro-bind-fd` | Implemented |
| Path traversal | Arbitrary write/read | Server-generated storage keys; filename metadata never forms paths | Implemented |
| Oversized/chunked upload | Disk exhaustion or bypass | Actual streamed count; bounded slices; early `Content-Length` only advisory | Implemented |
| Partial/orphan upload | Ambiguous completed object | Exclusive temporary object, cleanup, fsync, atomic rename | Implemented; crash orphan reconciliation planned |
| Malicious filename | Visual deception or traversal | Separate raw/security and display forms; double-extension and bidi findings | Implemented |
| MIME/extension masquerade | Executable presented as document | Worker-side observed type, deterministic mismatch and executable findings | Implemented |
| PDF active actions | JavaScript, Launch, URI, or automatic viewer behavior | Semantic catalog/action/name-tree inspection; capability findings; nothing executed or fetched | Implemented |
| PDF object cycles | Infinite recursion or CPU exhaustion | Indirect-object visited sets plus action depth/node and object budgets | Implemented |
| Encrypted PDF | Hidden structures evade inspection | Encryption and partial-analysis findings; no password guessing; quarantine | Implemented |
| Malformed PDF | Parser crash or misleading incomplete result | Parser-specific exceptions/warnings become malformed/partial findings; outer isolation remains authoritative | Implemented |
| Worker metadata flood | Trusted memory/database exhaustion | Parent output cap, finding-count cap, per-finding and analyzer JSON byte limits | Implemented |
| Malformed worker output | Policy bypass | Strict Pydantic contract/schema validation and quarantine | Implemented |
| Worker crash/timeout | Ambiguous analysis | Persisted non-release lifecycle and quarantine | Implemented |
| Unsupported/libmagic failure | Unsafe fallback | No fallback; `UNSUPPORTED`/`FAILED` remain quarantined | Implemented |
| Unsafe backend selection | Unisolated production parsing | Dual opt-in outside production; constructor/config validation and CRITICAL log | Implemented |
| OOXML traversal/bomb | Filesystem/resource exhaustion | No extraction; selected exact members only; actual-byte, entry, XML, relationship, VBA, tmpfs, memory, and timeout limits | Implemented for Office packages |
| OOXML XML entities/XXE | Local-file access, SSRF, expansion exhaustion | Defused XML parsing, no entity resolution, no network, bounded XML bytes | Implemented |
| Generic archive traversal | Unsafe downstream extraction outside an intended root | Worker recognizes parent components and POSIX/Windows/UNC rooted names; no DocGuard extraction occurs | Implemented for ZIP |
| Archive symlink abuse | Downstream link traversal or host path access | Unix symlink metadata is reported; target bytes are neither followed nor interpreted as a path | Implemented for ZIP |
| Archive decompression/resource bomb | Worker/host memory, CPU, or output exhaustion | Actual per-member/aggregate reads, entry/member/container/nesting/materialization limits plus outer cgroup/rlimit/timeout | Implemented for ZIP; parser central-directory allocation remains outer-boundary controlled |
| Nested archive recursion | Unbounded depth or repeated work | Content-signature routing, depth three, shared budgets, bounded in-memory materialization, SHA-256 repeated-content suppression | Implemented for nested ZIP only |
| Encrypted/unsupported ZIP member | Hidden content or unsafe fallback | Metadata finding, no passwords/decryption/fallback tool, partial result and quarantine | Implemented |
| Malformed ZIP | Crash or misleading complete result | Expected central-directory/CRC/decompression errors become malformed/partial; unexpected errors crash worker and fail closed | Implemented |
| VBA active content | Command/process capability after user opens document | Static bounded olevba analysis in sandbox; nothing executed; macro source discarded | Implemented detection; semantic blind spots remain |
| Office external relationships | SSRF, credential leakage, remote template delivery | Lexical-only summaries; no DNS/HTTP/SMB/file resolution; query/credentials discarded | Implemented |
| Office embedded objects/ActiveX | Nested payload or active-control execution | Structural counting only; no extraction, recursion, instantiation, or execution | Implemented detection; recursive analysis planned |
| Encrypted Office input | Hidden structures evade inspection | Encryption and partial-analysis findings; no passwords/brute force/decryption; quarantine | Implemented |
| Malformed Office input | Parser crash or misleading incomplete result | Controlled malformed/partial findings for expected parser errors; outer isolation for unexpected failures | Implemented |
| Malicious YARA scan input | Native scanner crash or resource exhaustion | Pinned worker-only yara-python/libyara, disposable Bubblewrap worker, internal timeout, outer wall timeout, cgroup/rlimits, and bounded output | Implemented for top-level input |
| Untrusted or altered YARA rules | Arbitrary native modules, excessive matching, false findings, or policy manipulation | Exactly one product-owned pack; SHA-256 pin; import/include rejection; exact rule-manifest comparison; read-only worker mount; no API or contract field for supplied rules | Implemented |
| Spoofed YARA result metadata | Worker output invents trusted severity, explanation, confidence, or ATT&CK context | Trusted Pydantic validation derives the complete expected presentation from a shared immutable registry and rejects unknown or inconsistent rule IDs | Implemented |
| YARA match-data disclosure | Document content leaks through API, database, or logs | Matched bytes and arbitrary tags/metadata are never read or serialized; only bounded trusted IDs, counts, string identifiers, and offsets cross the contract | Implemented |
| YARA match flood | Trusted memory, JSON, log, or database exhaustion | Limits on rules, instances, identifiers, offsets, finding count, analyzer metadata, stdout, and total worker JSON; overflow produces partial analysis and quarantine | Implemented |
| YARA timeout or scanner warning | Incomplete scan mistaken for successful coverage | Internal timeout/errors/warnings produce `YARA_PARTIAL_ANALYSIS`; outer timeout still terminates the job; scan remains quarantined | Implemented |
| YARA lexical false positive | Legitimate administrative or educational text is treated as malicious | Small conjunctive rule patterns, explicit heuristic confidence, benign-prose regression fixtures, explainable policy contribution, and quarantine rather than semantic BLOCK | Reduced; residual risk |
| YARA signature/heuristic evasion | Obfuscated, encoded, fragmented, compressed, or novel content is missed | YARA is supplementary and never a benignity proof; structural status is preserved; absence language is constrained | Residual risk |
| Hidden child content not YARA-scanned | Archive member, PDF attachment, OOXML part, embedded object, or nested document evades top-level lexical rules | Scope is explicit in results/docs; structural analyzers remain independent; no implicit recursive scan or unsafe extraction | Residual risk; recursive child analysis is out of scope |
| Worker-controlled scoring | Compromised worker lowers risk or chooses release | Worker score must be exactly zero; trusted immutable registry owns all weights, floors, hard blocks, policy identity, and release eligibility | Implemented |
| Missing policy coverage | New detection silently has zero policy effect | Readiness requires exact bidirectional coverage between all finding and policy codes; evaluation also validates the registry | Implemented |
| Policy tampering or partial load | Altered weights weaken containment or audit history | Normalized SHA-256 fingerprint, semantic version, immutable definitions, strict validation, no dynamic/user policy input, no partial loading | Implemented; source/deployment integrity remains an operator responsibility |
| Duplicate-finding score inflation | Attacker creates thousands of repeated structures to inflate or manipulate score | One contribution per stable finding code; compound rules use presence and trigger once; overall findings remain bounded | Implemented |
| Heuristic score presented as malware certainty | Misleading BLOCK or user claim | BLOCK requires semantic hard rule; score-only high/critical results quarantine; API/docs state score is not probability | Implemented |
| Incomplete analysis released | Timeout, unsupported, malformed, encrypted, or limited input reaches ALLOW | Status, failure code, lifecycle, supported family, and partial/malformed findings all participate in completeness; contradictions quarantine | Implemented |
| Policy evaluation failure | Exception leaves an earlier ALLOW value | Initial and ANALYZING rows are non-release; controlled fallback persists QUARANTINE and false release eligibility | Implemented |
| Policy persistence failure | Findings or decision commit partially | One final transaction persists findings and evaluation; rollback leaves earlier ANALYZING/QUARANTINE state | Implemented; operational reconciliation remains needed |
| Historical silent reinterpretation | Audit outcome changes after deployment | Policy version/fingerprint and normalized evaluation are persisted; GET never re-evaluates | Implemented |
| Unauthorized source release | `ALLOW` becomes an implicit source-download bypass | No raw/source route or capability; only separately approved CDR artifacts can be served after download-time revalidation | Implemented |
| Unsupported PDF semantics | Missed risky structures outside modeled locations | Bounded documented coverage; never claim benignity | Residual risk |
| Unsupported Office semantics | Missed risky structures or VBA behavior beyond modeled indicators | Conservative bounded coverage, curated indicators, no benignity claim | Residual risk |
| Unsupported archive semantics | Missed content semantics, filename encodings, link types, or non-ZIP formats | Narrow documented ZIP model, bounded metadata, no benignity claim | Residual risk |
| Third-party confidentiality loss | Submitted document disclosure | No external uploads or threat-intelligence integrations | Implemented policy |
| Compromised PDF renderer | Arbitrary output or escape while parsing hostile PDF | Disposable Bubblewrap, no network/home/secrets/trusted source/storage, cgroup+rlimit+timeout, one descriptor-bound output | Implemented; renderer/kernel remain attack surface |
| Trusted-generated-output assumption | CDR output bypasses detection | Output becomes a derived quarantine scan and must pass libmagic, PDF analysis, YARA, and current policy ALLOW | Implemented |
| CDR override of hard block | Raster output rehabilitates an executable/signature BLOCK | Trusted eligibility categorically excludes BLOCK; source history is immutable | Implemented |
| Pathological PDF geometry | Huge pages exhaust memory/CPU | Page/point/pixel/raster/output limits plus outer memory/CPU/wall-clock controls | Implemented; native allocation may precede Python checks |
| CDR artifact tampering | Candidate differs from analyzed/promoted bytes | Mode-0400 opaque objects and candidate/derived/promoted SHA-256+size equality | Implemented; privileged administrators remain trusted |
| Concurrent CDR duplication | Repeated work creates unlimited approved artifacts | In-process serialization, unique source/fingerprint constraint, and conflict reuse | Implemented; crash windows can leave derived/orphan objects |
| Audit mutation or leakage | History rewritten or contains document material | Append-only service, bounded metadata, no update/delete API, artifact+approval-event transaction | Application-layer only; DB administrators can alter data |
| Filesystem/database crash window | Orphan files diverge from rows | Atomic opaque storage, handled-failure cleanup, lineage suitable for reconciliation | Partial; no background reconciler yet |
| Password database theft | Offline recovery of operator passwords | Per-account Argon2id with explicit memory/time/parallelism costs; bounded password policy; rehash-on-login | Implemented; password strength remains operator responsibility |
| Username enumeration | Account discovery through errors or obvious hash timing | Generic response, anonymous bounded audit, and fixed dummy Argon2 verification for missing/ineligible users | Reduced; database/host timing can still vary |
| Credential brute force | Account takeover or resource exhaustion | Per-peer and hashed-username process-local minute/hour limits; Argon2 cost; no default accounts | Implemented for one process; distributed edge control planned |
| Session database disclosure | Bearer-token recovery | CSPRNG 256-bit raw tokens; database stores SHA-256 only; no raw token in logs/audit | Implemented; active browser cookie theft remains a bearer-token risk |
| Session fixation/replay | Attacker preserves or reuses a known session | Rotate on successful login, revoke prior valid browser token, absolute/inactivity expiry, active-user checks, POST logout | Implemented |
| CSRF | Cross-origin upload, CDR, or logout | Session-derived constant-time CSRF token plus exact configured-Origin rejection when Origin is supplied; SameSite cookie | Implemented |
| XSS through hostile metadata | Session/action compromise | Jinja autoescape, text-only rendering, no `innerHTML`, restrictive self-only CSP, no remote/inline active content | Implemented; framework/browser remain trusted |
| Clickjacking/browser capability abuse | Operator induced to trigger action | CSP `frame-ancestors 'none'`, `form-action 'self'`, restrictive Permissions-Policy | Implemented |
| Sensitive browser caching | Scan/audit/artifact data retained in shared caches | `no-store` for authenticated UI/API; `no-store, private` for artifacts | Implemented; browser/host storage remains operational boundary |
| Unauthorized API/CDR access | Anonymous or insufficient principal changes state | Central capability dependencies on every operator API; session validation on every request; CSRF on mutations | Implemented |
| Raw quarantine exposure | Hostile source is downloaded/opened from product UI | No route, link, static mount, or V1 capability for source/raw bytes | Implemented |
| Approved artifact TOCTOU/tampering | Changed or substituted bytes served after approval | Re-query lineage/policy; opaque key; `O_NOFOLLOW`; descriptor type/owner/mode/link/size/hash/stability checks; stream same open FD | Implemented; privileged host admin remains trusted |
| Download without audit | Sensitive bytes leave without accountable actor event | Required operator audit commits before streaming response; audit failure closes download | Implemented |
| Operator deactivation delay | Disabled account retains access | Active state and role joined and checked on every session authentication | Implemented |
| Auth bootstrap omission | Healthy-looking service with no usable account | Production readiness requires migration/auth schema/session store/hasher and an active OPERATOR; CLI-only bootstrap | Implemented |
| Reverse-proxy header spoofing | Peer attribution or origin bypass | Exact direct-proxy allowlist; one valid overwritten X-Real-IP; no chains/forwarded authority; canonical origin | Implemented Phase 10 |
| Host poisoning | Reset/redirect/cache/origin confusion | Exact canonical authority validation before auth/routing; relative redirects | Implemented Phase 10 |
| Expensive authenticated request abuse | CPU/disk/worker exhaustion | Process-local operator upload/CDR/download/read limits plus proxy coarse limits | Implemented for qualified one-worker topology |
| Log injection and request confusion | Forged records or secret disclosure | Server request IDs, route-template JSON logs, escaped controls, no query/body/token fields | Implemented Phase 10 |
| Permissive private filesystem | Cross-account disclosure or replacement | Ownership/mode/no-symlink/static-separation qualification and strict umask | Implemented; OS admin remains trusted |
| SQLite crash/corruption | Lost or inconsistent policy/audit state | WAL, FULL synchronous, busy timeout, foreign keys, integrity commands, exact migration head | Implemented; DB+object atomic backup remains operational |
| Crash window divergence | Stale ANALYZING rows or orphan objects | Bounded dry-run reconciliation; locked fail-closed stale repair; report-only business orphans | Implemented Phase 10 |

## Host assumptions

DocGuard trusts the Linux kernel, Bubblewrap, systemd/cgroup implementation, util-linux, libmagic,
Python runtime, pikepdf/qpdf, PyMuPDF/MuPDF, oletools/olefile, defusedxml, libmagic,
yara-python/libyara, and
trusted application dependencies. Administrators must run DocGuard as a
dedicated unprivileged account and maintain those components. The built-in self-test detects missing
capability but is not proof that the kernel or isolation tools are vulnerability-free.

User-systemd delegation is a deployment prerequisite for the current per-job resource strategy.
Containers, restricted CI sandboxes, or services without a user bus may be unable to establish it;
that condition intentionally makes readiness false.
